#include "ttd_replay_bridge.h"

#include <algorithm>
#include <cwchar>
#include <iterator>
#include <limits>
#include <mutex>
#include <string>

namespace {
thread_local std::string g_last_error;

void set_error(char const* message) noexcept {
    g_last_error = message == nullptr ? "unknown error" : message;
}
}

#if defined(TTD_MCP_USE_TTD_REPLAY)
#ifndef DBG_ASSERT
#define DBG_ASSERT(cond) do {} while (false)
#endif
#ifndef DBG_ASSERT_MSG
#define DBG_ASSERT_MSG(cond, ...) DBG_ASSERT(cond)
#endif

#include <TTD/ErrorReporting.h>
#include <TTD/IReplayEngineStl.h>

namespace {
TtdMcpPosition to_bridge_position(TTD::Replay::Position const& position) noexcept {
    return TtdMcpPosition{
        static_cast<uint64_t>(position.Sequence),
        static_cast<uint64_t>(position.Steps),
    };
}

TTD::Replay::Position to_replay_position(TtdMcpPosition position) noexcept {
    return TTD::Replay::Position(
        static_cast<TTD::SequenceId>(position.sequence),
        static_cast<TTD::Replay::StepCount>(position.steps));
}

TtdMcpPosition to_bridge_position(TTD::SequenceId sequence) noexcept {
    return TtdMcpPosition{ static_cast<uint64_t>(sequence), 0 };
}

bool is_valid_sequence(TTD::SequenceId sequence) noexcept {
    return sequence != TTD::SequenceId::Invalid;
}

void copy_wide(wchar_t* destination, size_t capacity, wchar_t const* source, size_t length) noexcept {
    if (destination == nullptr || capacity == 0) {
        return;
    }

    destination[0] = L'\0';
    if (source == nullptr || length == 0) {
        return;
    }

    size_t const copied = std::min(length, capacity - 1);
    std::wmemcpy(destination, source, copied);
    destination[copied] = L'\0';
}

TtdMcpStatus validate_list_request(void const* trace, void const* buffer, uint32_t capacity, uint32_t* count) noexcept {
    if (trace == nullptr || count == nullptr) {
        set_error("trace and count pointers are required");
        return TTD_MCP_INVALID_ARGUMENT;
    }

    if (capacity > 0 && buffer == nullptr) {
        set_error("output buffer is required when capacity is non-zero");
        return TTD_MCP_INVALID_ARGUMENT;
    }

    return TTD_MCP_OK;
}

TtdMcpStatus set_required_count(size_t required, uint32_t* count) noexcept {
    if (required > std::numeric_limits<uint32_t>::max()) {
        set_error("native list is too large for the bridge ABI");
        return TTD_MCP_ERROR;
    }

    *count = static_cast<uint32_t>(required);
    return TTD_MCP_OK;
}
}

struct TtdMcpTrace {
    TTD::Replay::UniqueReplayEngine engine;
    std::wstring symbol_path;
    std::wstring image_path;
    std::wstring symbol_cache_dir;
    std::wstring symbol_runtime_dir;
    std::mutex mutex;
};

struct TtdMcpCursor {
    TtdMcpTrace* trace;
    TTD::Replay::UniqueCursor cursor;
};

class BridgeErrorReporting final : public TTD::ErrorReporting {
public:
    void __fastcall VPrintError(char const* const format, va_list args) override {
        char buffer[2048] = {};
        vsprintf_s(buffer, format, args);
        set_error(buffer);
    }
};

TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_open_trace(const wchar_t* trace_path, const TtdMcpSymbolConfig* symbols, TtdMcpTrace** trace) {
    if (trace_path == nullptr || trace == nullptr) {
        set_error("trace_path and trace output pointer are required");
        return TTD_MCP_INVALID_ARGUMENT;
    }

    auto [engine, result] = TTD::Replay::MakeReplayEngine();
    if (result != 0 || engine == nullptr) {
        set_error("failed to create TTD replay engine");
        return TTD_MCP_ERROR;
    }

    static BridgeErrorReporting error_reporting;
    engine->RegisterDebugModeAndLogging(TTD::Replay::DebugModeType::None, &error_reporting);

    if (!engine->Initialize(trace_path)) {
        set_error("failed to initialize TTD replay engine with trace file");
        return TTD_MCP_ERROR;
    }

    auto* owned = new TtdMcpTrace{
        std::move(engine),
        symbols != nullptr && symbols->symbol_path != nullptr ? symbols->symbol_path : L"",
        symbols != nullptr && symbols->image_path != nullptr ? symbols->image_path : L"",
        symbols != nullptr && symbols->symbol_cache_dir != nullptr ? symbols->symbol_cache_dir : L"",
        symbols != nullptr && symbols->symbol_runtime_dir != nullptr ? symbols->symbol_runtime_dir : L"",
        {}
    };
    *trace = owned;
    return TTD_MCP_OK;
}

TTD_MCP_EXPORT void ttd_mcp_close_trace(TtdMcpTrace* trace) {
    delete trace;
}

TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_trace_info(TtdMcpTrace* trace, TtdMcpTraceInfo* info) {
    if (trace == nullptr || info == nullptr) {
        set_error("trace and info pointers are required");
        return TTD_MCP_INVALID_ARGUMENT;
    }

    std::scoped_lock lock(trace->mutex);
    auto const& first = trace->engine->GetFirstPosition();
    auto const& last = trace->engine->GetLastPosition();
    auto const& system_info = trace->engine->GetSystemInfo();

    *info = TtdMcpTraceInfo{
        to_bridge_position(first),
        to_bridge_position(last),
        static_cast<uint64_t>(trace->engine->GetPebAddress()),
        system_info.ProcessId,
        static_cast<uint32_t>(trace->engine->GetThreadCount()),
        static_cast<uint32_t>(trace->engine->GetModuleCount()),
        static_cast<uint32_t>(trace->engine->GetModuleInstanceCount()),
        static_cast<uint32_t>(trace->engine->GetExceptionEventCount()),
        static_cast<uint32_t>(trace->engine->GetKeyframeCount()),
    };
    return TTD_MCP_OK;
}

TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_list_threads(TtdMcpTrace* trace, TtdMcpThreadInfo* threads, uint32_t capacity, uint32_t* count) {
    TtdMcpStatus const request_status = validate_list_request(trace, threads, capacity, count);
    if (request_status != TTD_MCP_OK) {
        return request_status;
    }

    std::scoped_lock lock(trace->mutex);
    size_t const required = trace->engine->GetThreadCount();
    TtdMcpStatus const count_status = set_required_count(required, count);
    if (count_status != TTD_MCP_OK) {
        return count_status;
    }

    if (capacity < required) {
        return TTD_MCP_OK;
    }

    TTD::Replay::ThreadInfo const* const source = trace->engine->GetThreadList();
    for (size_t index = 0; index < required; ++index) {
        TTD::Replay::ThreadInfo const& thread = source[index];
        threads[index] = TtdMcpThreadInfo{
            static_cast<uint64_t>(thread.UniqueId),
            static_cast<uint32_t>(thread.Id),
            to_bridge_position(thread.Lifetime.Min),
            to_bridge_position(thread.Lifetime.Max),
            to_bridge_position(thread.ActiveTime.Min),
            to_bridge_position(thread.ActiveTime.Max),
            thread.ActiveTime.IsValid() ? static_cast<uint8_t>(1) : static_cast<uint8_t>(0),
        };
    }

    return TTD_MCP_OK;
}

TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_list_modules(TtdMcpTrace* trace, TtdMcpModuleInfo* modules, uint32_t capacity, uint32_t* count) {
    TtdMcpStatus const request_status = validate_list_request(trace, modules, capacity, count);
    if (request_status != TTD_MCP_OK) {
        return request_status;
    }

    std::scoped_lock lock(trace->mutex);
    size_t const required = trace->engine->GetModuleInstanceCount();
    TtdMcpStatus const count_status = set_required_count(required, count);
    if (count_status != TTD_MCP_OK) {
        return count_status;
    }

    if (capacity < required) {
        return TTD_MCP_OK;
    }

    TTD::Replay::ModuleInstance const* const source = trace->engine->GetModuleInstanceList();
    for (size_t index = 0; index < required; ++index) {
        TTD::Replay::ModuleInstance const& instance = source[index];
        TTD::Replay::Module const* const module = instance.pModule;
        TtdMcpModuleInfo output = {};

        if (module != nullptr) {
            wchar_t const* const base_name = TTD::Replay::GetModuleBaseName(module->pName, module->NameLength);
            size_t const base_name_length = module->NameLength - static_cast<size_t>(base_name - module->pName);
            copy_wide(output.name, std::size(output.name), base_name, base_name_length);
            copy_wide(output.path, std::size(output.path), module->pName, module->NameLength);
            output.base_address = static_cast<uint64_t>(module->Address);
            output.size = module->Size;
        }

        output.load_position = to_bridge_position(instance.LoadTime);
        output.unload_position = to_bridge_position(instance.UnloadTime);
        output.has_unload_position = is_valid_sequence(instance.UnloadTime) ? static_cast<uint8_t>(1) : static_cast<uint8_t>(0);
        modules[index] = output;
    }

    return TTD_MCP_OK;
}

TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_list_exceptions(TtdMcpTrace* trace, TtdMcpExceptionInfo* exceptions, uint32_t capacity, uint32_t* count) {
    TtdMcpStatus const request_status = validate_list_request(trace, exceptions, capacity, count);
    if (request_status != TTD_MCP_OK) {
        return request_status;
    }

    std::scoped_lock lock(trace->mutex);
    size_t const required = trace->engine->GetExceptionEventCount();
    TtdMcpStatus const count_status = set_required_count(required, count);
    if (count_status != TTD_MCP_OK) {
        return count_status;
    }

    if (capacity < required) {
        return TTD_MCP_OK;
    }

    TTD::Replay::ExceptionEvent const* const source = trace->engine->GetExceptionEventList();
    for (size_t index = 0; index < required; ++index) {
        TTD::Replay::ExceptionEvent const& exception = source[index];
        TtdMcpExceptionInfo output = {};
        output.position = to_bridge_position(exception.Position);
        output.thread_unique_id = exception.pThreadInfo != nullptr ? static_cast<uint64_t>(exception.pThreadInfo->UniqueId) : 0;
        output.code = exception.Code;
        output.flags = exception.Flags;
        output.program_counter = static_cast<uint64_t>(exception.ProgramCounter);
        output.record_address = static_cast<uint64_t>(exception.RecordAddress);
        output.parameter_count = std::min(exception.ParameterCount, static_cast<uint32_t>(std::size(output.parameters)));
        for (uint32_t parameter_index = 0; parameter_index < output.parameter_count; ++parameter_index) {
            output.parameters[parameter_index] = exception.Parameters[parameter_index];
        }
        exceptions[index] = output;
    }

    return TTD_MCP_OK;
}

TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_new_cursor(TtdMcpTrace* trace, TtdMcpCursor** cursor) {
    if (trace == nullptr || cursor == nullptr) {
        set_error("trace and cursor output pointer are required");
        return TTD_MCP_INVALID_ARGUMENT;
    }

    std::scoped_lock lock(trace->mutex);
    TTD::Replay::UniqueCursor owned_cursor(trace->engine->NewCursor());
    if (owned_cursor == nullptr) {
        set_error("failed to create replay cursor");
        return TTD_MCP_ERROR;
    }

    *cursor = new TtdMcpCursor{ trace, std::move(owned_cursor) };
    return TTD_MCP_OK;
}

TTD_MCP_EXPORT void ttd_mcp_free_cursor(TtdMcpCursor* cursor) {
    delete cursor;
}

TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_cursor_position(TtdMcpCursor* cursor, TtdMcpPosition* position) {
    if (cursor == nullptr || position == nullptr) {
        set_error("cursor and position pointers are required");
        return TTD_MCP_INVALID_ARGUMENT;
    }

    auto const current = cursor->cursor->GetPosition();
    *position = to_bridge_position(current);
    return TTD_MCP_OK;
}

TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_set_position(TtdMcpCursor* cursor, TtdMcpPosition position) {
    if (cursor == nullptr) {
        set_error("cursor pointer is required");
        return TTD_MCP_INVALID_ARGUMENT;
    }

    cursor->cursor->SetPosition(to_replay_position(position));
    return TTD_MCP_OK;
}
#else
struct TtdMcpTrace {};
struct TtdMcpCursor {};

TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_open_trace(const wchar_t*, const TtdMcpSymbolConfig*, TtdMcpTrace**) {
    set_error("TTD_MCP_USE_TTD_REPLAY is not enabled for this bridge build");
    return TTD_MCP_NOT_IMPLEMENTED;
}

TTD_MCP_EXPORT void ttd_mcp_close_trace(TtdMcpTrace*) {}

TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_trace_info(TtdMcpTrace*, TtdMcpTraceInfo*) {
    set_error("TTD replay bridge is not implemented in this build");
    return TTD_MCP_NOT_IMPLEMENTED;
}

TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_list_threads(TtdMcpTrace*, TtdMcpThreadInfo*, uint32_t, uint32_t*) {
    set_error("TTD replay bridge is not implemented in this build");
    return TTD_MCP_NOT_IMPLEMENTED;
}

TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_list_modules(TtdMcpTrace*, TtdMcpModuleInfo*, uint32_t, uint32_t*) {
    set_error("TTD replay bridge is not implemented in this build");
    return TTD_MCP_NOT_IMPLEMENTED;
}

TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_list_exceptions(TtdMcpTrace*, TtdMcpExceptionInfo*, uint32_t, uint32_t*) {
    set_error("TTD replay bridge is not implemented in this build");
    return TTD_MCP_NOT_IMPLEMENTED;
}

TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_new_cursor(TtdMcpTrace*, TtdMcpCursor**) {
    set_error("TTD replay bridge is not implemented in this build");
    return TTD_MCP_NOT_IMPLEMENTED;
}

TTD_MCP_EXPORT void ttd_mcp_free_cursor(TtdMcpCursor*) {}

TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_cursor_position(TtdMcpCursor*, TtdMcpPosition*) {
    set_error("TTD replay bridge is not implemented in this build");
    return TTD_MCP_NOT_IMPLEMENTED;
}

TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_set_position(TtdMcpCursor*, TtdMcpPosition) {
    set_error("TTD replay bridge is not implemented in this build");
    return TTD_MCP_NOT_IMPLEMENTED;
}
#endif

TTD_MCP_EXPORT const char* ttd_mcp_last_error(void) {
    return g_last_error.c_str();
}
