use anyhow::{bail, ensure, Context};
use serde_json::{json, Value};
use std::path::Path;

const IMAGE_DIRECTORY_ENTRY_EXPORT: usize = 0;
const IMAGE_DIRECTORY_ENTRY_DEBUG: usize = 6;
const IMAGE_DEBUG_TYPE_CODEVIEW: u32 = 2;
const OPTIONAL_HEADER_PE32: u16 = 0x10b;
const OPTIONAL_HEADER_PE32_PLUS: u16 = 0x20b;

#[derive(Debug, Clone)]
struct Section {
    name: String,
    virtual_address: u32,
    virtual_size: u32,
    raw_offset: u32,
    raw_size: u32,
}

#[derive(Debug, Clone)]
pub struct ExportSymbol {
    pub name: Option<String>,
    pub ordinal: u32,
    pub rva: u32,
    pub rva_hex: String,
    pub forwarder: Option<String>,
}

pub fn diagnose_pe(path: &Path) -> anyhow::Result<Value> {
    let data = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let pe_offset = read_u32(&data, 0x3c)? as usize;
    ensure!(
        read_bytes(&data, pe_offset, 4)? == b"PE\0\0",
        "missing PE signature"
    );

    let file_header = pe_offset + 4;
    let machine = read_u16(&data, file_header)?;
    let section_count = read_u16(&data, file_header + 2)? as usize;
    let timestamp = read_u32(&data, file_header + 4)?;
    let optional_size = read_u16(&data, file_header + 16)? as usize;
    let characteristics = read_u16(&data, file_header + 18)?;

    let optional = file_header + 20;
    let magic = read_u16(&data, optional)?;
    let data_dir_base = match magic {
        OPTIONAL_HEADER_PE32 => optional + 96,
        OPTIONAL_HEADER_PE32_PLUS => optional + 112,
        _ => bail!("unsupported PE optional header magic 0x{magic:04x}"),
    };
    let size_of_image = read_u32(&data, optional + 56)?;
    let checksum = read_u32(&data, optional + 64)?;

    let section_table = optional + optional_size;
    let sections = read_sections(&data, section_table, section_count)?;
    let export_dir = data_dir_base + IMAGE_DIRECTORY_ENTRY_EXPORT * 8;
    let export_rva = read_u32(&data, export_dir)?;
    let export_size = read_u32(&data, export_dir + 4)?;
    let exports = read_exports(&data, &sections, export_rva, export_size)?;

    let debug_dir = data_dir_base + IMAGE_DIRECTORY_ENTRY_DEBUG * 8;
    let debug_rva = read_u32(&data, debug_dir)?;
    let debug_size = read_u32(&data, debug_dir + 4)?;
    let codeview = if debug_rva == 0 || debug_size == 0 {
        None
    } else {
        let offset = rva_to_file_offset(debug_rva, &sections)
            .with_context(|| format!("mapping debug directory RVA 0x{debug_rva:x}"))?;
        read_codeview(&data, offset as usize, debug_size as usize)?
    };

    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    let image_key = format!("{timestamp:X}{size_of_image:X}");
    let image_symbol_store_path = if file_name.is_empty() {
        None
    } else {
        Some(format!("{file_name}\\{image_key}\\{file_name}"))
    };

    Ok(json!({
        "path": path,
        "machine": machine_name(machine),
        "machine_value": machine,
        "characteristics": format!("0x{characteristics:04X}"),
        "timestamp": timestamp,
        "timestamp_hex": format!("{timestamp:08X}"),
        "checksum": checksum,
        "checksum_hex": format!("{checksum:08X}"),
        "size_of_image": size_of_image,
        "size_of_image_hex": format!("{size_of_image:X}"),
        "image_symbol_store_key": image_key,
        "image_symbol_store_path": image_symbol_store_path,
        "exports": export_summary(&exports),
        "sections": sections.iter().map(section_value).collect::<Vec<_>>(),
        "codeview": codeview,
    }))
}

pub fn read_export_symbols(path: &Path) -> anyhow::Result<Vec<ExportSymbol>> {
    let data = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let pe_offset = read_u32(&data, 0x3c)? as usize;
    ensure!(
        read_bytes(&data, pe_offset, 4)? == b"PE\0\0",
        "missing PE signature"
    );
    let file_header = pe_offset + 4;
    let section_count = read_u16(&data, file_header + 2)? as usize;
    let optional_size = read_u16(&data, file_header + 16)? as usize;
    let optional = file_header + 20;
    let magic = read_u16(&data, optional)?;
    let data_dir_base = match magic {
        OPTIONAL_HEADER_PE32 => optional + 96,
        OPTIONAL_HEADER_PE32_PLUS => optional + 112,
        _ => bail!("unsupported PE optional header magic 0x{magic:04x}"),
    };
    let section_table = optional + optional_size;
    let sections = read_sections(&data, section_table, section_count)?;
    let export_dir = data_dir_base + IMAGE_DIRECTORY_ENTRY_EXPORT * 8;
    let export_rva = read_u32(&data, export_dir)?;
    let export_size = read_u32(&data, export_dir + 4)?;
    read_exports(&data, &sections, export_rva, export_size)
}

fn read_sections(data: &[u8], section_table: usize, count: usize) -> anyhow::Result<Vec<Section>> {
    let mut sections = Vec::with_capacity(count);
    for index in 0..count {
        let offset = section_table + index * 40;
        let name_bytes = read_bytes(data, offset, 8)?;
        let name_end = name_bytes
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(name_bytes.len());
        let name = String::from_utf8_lossy(&name_bytes[..name_end]).into_owned();
        sections.push(Section {
            name,
            virtual_size: read_u32(data, offset + 8)?,
            virtual_address: read_u32(data, offset + 12)?,
            raw_size: read_u32(data, offset + 16)?,
            raw_offset: read_u32(data, offset + 20)?,
        });
    }
    Ok(sections)
}

fn read_codeview(
    data: &[u8],
    directory_offset: usize,
    directory_size: usize,
) -> anyhow::Result<Option<Value>> {
    let entry_count = directory_size / 28;
    for index in 0..entry_count {
        let offset = directory_offset + index * 28;
        let debug_type = read_u32(data, offset + 12)?;
        if debug_type != IMAGE_DEBUG_TYPE_CODEVIEW {
            continue;
        }
        let size = read_u32(data, offset + 16)? as usize;
        let raw_offset = read_u32(data, offset + 24)? as usize;
        let payload = read_bytes(data, raw_offset, size)?;
        if payload.len() >= 24 && &payload[..4] == b"RSDS" {
            let guid = pdb_guid_string(&payload[4..20]);
            let age = read_u32(payload, 20)?;
            let pdb_path = read_null_terminated_string(&payload[24..]);
            let pdb_name = Path::new(&pdb_path)
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or(pdb_path.as_str());
            let pdb_key = format!("{guid}{age:X}");
            let pdb_symbol_store_path = if pdb_name.is_empty() {
                None
            } else {
                Some(format!("{pdb_name}\\{pdb_key}\\{pdb_name}"))
            };
            return Ok(Some(json!({
                "format": "RSDS",
                "guid": guid,
                "age": age,
                "age_hex": format!("{age:X}"),
                "pdb_path": pdb_path,
                "pdb_name": pdb_name,
                "pdb_symbol_store_key": pdb_key,
                "pdb_symbol_store_path": pdb_symbol_store_path,
            })));
        }
        if payload.len() >= 16 && &payload[..4] == b"NB10" {
            let timestamp = read_u32(payload, 8)?;
            let age = read_u32(payload, 12)?;
            let pdb_path = read_null_terminated_string(&payload[16..]);
            return Ok(Some(json!({
                "format": "NB10",
                "timestamp": timestamp,
                "timestamp_hex": format!("{timestamp:08X}"),
                "age": age,
                "pdb_path": pdb_path,
            })));
        }
    }
    Ok(None)
}

fn read_exports(
    data: &[u8],
    sections: &[Section],
    export_rva: u32,
    export_size: u32,
) -> anyhow::Result<Vec<ExportSymbol>> {
    if export_rva == 0 || export_size == 0 {
        return Ok(Vec::new());
    }
    let export_offset = rva_to_file_offset(export_rva, sections)? as usize;
    let ordinal_base = read_u32(data, export_offset + 16)?;
    let function_count = read_u32(data, export_offset + 20)? as usize;
    let name_count = read_u32(data, export_offset + 24)? as usize;
    let functions_rva = read_u32(data, export_offset + 28)?;
    let names_rva = read_u32(data, export_offset + 32)?;
    let ordinals_rva = read_u32(data, export_offset + 36)?;
    if function_count == 0 {
        return Ok(Vec::new());
    }

    let functions_offset = rva_to_file_offset(functions_rva, sections)? as usize;
    let names_offset = if name_count == 0 {
        None
    } else {
        Some(rva_to_file_offset(names_rva, sections)? as usize)
    };
    let ordinals_offset = if name_count == 0 {
        None
    } else {
        Some(rva_to_file_offset(ordinals_rva, sections)? as usize)
    };

    let mut names_by_index = vec![None; function_count];
    if let (Some(names_offset), Some(ordinals_offset)) = (names_offset, ordinals_offset) {
        for index in 0..name_count {
            let name_rva = read_u32(data, names_offset + index * 4)?;
            let function_index = read_u16(data, ordinals_offset + index * 2)? as usize;
            if function_index >= function_count {
                continue;
            }
            let name = read_rva_c_string(data, sections, name_rva)?;
            names_by_index[function_index] = Some(name);
        }
    }

    let export_end = export_rva.saturating_add(export_size);
    let mut exports = Vec::with_capacity(function_count);
    for (index, name) in names_by_index.into_iter().enumerate() {
        let rva = read_u32(data, functions_offset + index * 4)?;
        if rva == 0 {
            continue;
        }
        let forwarder = if rva >= export_rva && rva < export_end {
            Some(read_rva_c_string(data, sections, rva)?)
        } else {
            None
        };
        exports.push(ExportSymbol {
            name,
            ordinal: ordinal_base + index as u32,
            rva,
            rva_hex: format!("{rva:X}"),
            forwarder,
        });
    }
    Ok(exports)
}

fn export_summary(exports: &[ExportSymbol]) -> Value {
    let named_count = exports
        .iter()
        .filter(|export| export.name.is_some())
        .count();
    let forwarded_count = exports
        .iter()
        .filter(|export| export.forwarder.is_some())
        .count();
    json!({
        "count": exports.len(),
        "named_count": named_count,
        "ordinal_only_count": exports.len().saturating_sub(named_count),
        "forwarded_count": forwarded_count,
        "sample": exports.iter().take(16).map(export_symbol_value).collect::<Vec<_>>(),
        "sample_limit": 16,
        "truncated": exports.len() > 16,
    })
}

pub fn export_symbol_value(export: &ExportSymbol) -> Value {
    json!({
        "name": export.name.as_deref(),
        "ordinal": export.ordinal,
        "rva": export.rva,
        "rva_hex": export.rva_hex,
        "forwarder": export.forwarder.as_deref(),
    })
}

fn rva_to_file_offset(rva: u32, sections: &[Section]) -> anyhow::Result<u32> {
    for section in sections {
        let span = section.virtual_size.max(section.raw_size);
        let start = section.virtual_address;
        let end = start.saturating_add(span);
        if rva >= start && rva < end {
            return Ok(section.raw_offset + (rva - start));
        }
    }
    bail!("RVA 0x{rva:x} is not covered by any section")
}

fn read_rva_c_string(data: &[u8], sections: &[Section], rva: u32) -> anyhow::Result<String> {
    let offset = rva_to_file_offset(rva, sections)? as usize;
    Ok(read_null_terminated_string(read_bytes(
        data,
        offset,
        data.len().saturating_sub(offset),
    )?))
}

fn pdb_guid_string(bytes: &[u8]) -> String {
    let data1 = u32::from_le_bytes(bytes[0..4].try_into().expect("slice length checked"));
    let data2 = u16::from_le_bytes(bytes[4..6].try_into().expect("slice length checked"));
    let data3 = u16::from_le_bytes(bytes[6..8].try_into().expect("slice length checked"));
    let data4 = &bytes[8..16];
    format!(
        "{data1:08X}{data2:04X}{data3:04X}{}",
        data4
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect::<String>()
    )
}

fn section_value(section: &Section) -> Value {
    json!({
        "name": section.name,
        "virtual_address": section.virtual_address,
        "virtual_address_hex": format!("{:X}", section.virtual_address),
        "virtual_size": section.virtual_size,
        "raw_offset": section.raw_offset,
        "raw_size": section.raw_size,
    })
}

fn machine_name(machine: u16) -> &'static str {
    match machine {
        0x014c => "x86",
        0x8664 => "x64",
        0xaa64 => "arm64",
        0x01c0 => "arm",
        _ => "unknown",
    }
}

fn read_null_terminated_string(bytes: &[u8]) -> String {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

fn read_bytes(data: &[u8], offset: usize, size: usize) -> anyhow::Result<&[u8]> {
    let end = offset
        .checked_add(size)
        .with_context(|| format!("file offset overflow at 0x{offset:x} for {size} bytes"))?;
    data.get(offset..end)
        .with_context(|| format!("reading {size} bytes at file offset 0x{offset:x}"))
}

fn read_u16(data: &[u8], offset: usize) -> anyhow::Result<u16> {
    Ok(u16::from_le_bytes(read_bytes(data, offset, 2)?.try_into()?))
}

fn read_u32(data: &[u8], offset: usize) -> anyhow::Result<u32> {
    Ok(u32::from_le_bytes(read_bytes(data, offset, 4)?.try_into()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(windows)]
    #[test]
    fn parses_current_exe_pe_identity() -> anyhow::Result<()> {
        let info = diagnose_pe(&std::env::current_exe()?)?;
        assert!(info["timestamp"].is_u64(), "{info}");
        assert!(info["size_of_image"].is_u64(), "{info}");
        assert!(info["image_symbol_store_key"].is_string(), "{info}");
        Ok(())
    }
}
