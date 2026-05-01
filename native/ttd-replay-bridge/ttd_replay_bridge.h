#pragma once

#include <stdint.h>
#include <wchar.h>

#ifdef _WIN32
#define TTD_MCP_EXPORT __declspec(dllexport)
#else
#define TTD_MCP_EXPORT
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct TtdMcpTrace TtdMcpTrace;
typedef struct TtdMcpCursor TtdMcpCursor;

typedef struct TtdMcpPosition {
    uint64_t sequence;
    uint64_t steps;
} TtdMcpPosition;

typedef struct TtdMcpTraceInfo {
    TtdMcpPosition first_position;
    TtdMcpPosition last_position;
    uint64_t peb_address;
    uint32_t process_id;
    uint32_t thread_count;
    uint32_t module_count;
    uint32_t module_instance_count;
    uint32_t exception_count;
    uint32_t keyframe_count;
} TtdMcpTraceInfo;

typedef struct TtdMcpSymbolConfig {
    const wchar_t* symbol_path;
    const wchar_t* image_path;
    const wchar_t* symbol_cache_dir;
    const wchar_t* symbol_runtime_dir;
} TtdMcpSymbolConfig;

typedef struct TtdMcpThreadInfo {
    uint64_t unique_id;
    uint32_t thread_id;
    TtdMcpPosition lifetime_start;
    TtdMcpPosition lifetime_end;
    TtdMcpPosition active_start;
    TtdMcpPosition active_end;
    uint8_t has_active_time;
} TtdMcpThreadInfo;

typedef struct TtdMcpModuleInfo {
    wchar_t name[260];
    wchar_t path[1024];
    uint64_t base_address;
    uint64_t size;
    TtdMcpPosition load_position;
    TtdMcpPosition unload_position;
    uint8_t has_unload_position;
} TtdMcpModuleInfo;

typedef struct TtdMcpExceptionInfo {
    TtdMcpPosition position;
    uint64_t thread_unique_id;
    uint32_t code;
    uint32_t flags;
    uint64_t program_counter;
    uint64_t record_address;
    uint32_t parameter_count;
    uint64_t parameters[15];
} TtdMcpExceptionInfo;

typedef enum TtdMcpStatus {
    TTD_MCP_OK = 0,
    TTD_MCP_ERROR = 1,
    TTD_MCP_NOT_IMPLEMENTED = 2,
    TTD_MCP_INVALID_ARGUMENT = 3,
} TtdMcpStatus;

TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_open_trace(const wchar_t* trace_path, const TtdMcpSymbolConfig* symbols, TtdMcpTrace** trace);
TTD_MCP_EXPORT void ttd_mcp_close_trace(TtdMcpTrace* trace);
TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_trace_info(TtdMcpTrace* trace, TtdMcpTraceInfo* info);
TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_list_threads(TtdMcpTrace* trace, TtdMcpThreadInfo* threads, uint32_t capacity, uint32_t* count);
TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_list_modules(TtdMcpTrace* trace, TtdMcpModuleInfo* modules, uint32_t capacity, uint32_t* count);
TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_list_exceptions(TtdMcpTrace* trace, TtdMcpExceptionInfo* exceptions, uint32_t capacity, uint32_t* count);
TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_new_cursor(TtdMcpTrace* trace, TtdMcpCursor** cursor);
TTD_MCP_EXPORT void ttd_mcp_free_cursor(TtdMcpCursor* cursor);
TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_cursor_position(TtdMcpCursor* cursor, TtdMcpPosition* position);
TTD_MCP_EXPORT TtdMcpStatus ttd_mcp_set_position(TtdMcpCursor* cursor, TtdMcpPosition position);
TTD_MCP_EXPORT const char* ttd_mcp_last_error(void);

#ifdef __cplusplus
}
#endif
