use std::collections::HashMap;

use winapi::um::winnt::{IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_EXPORT_DIRECTORY};

use crate::pe64::PE64;

pub struct ExportDirectory {
    pub rva: usize,
    pub size: usize,
    pub ordinal_base: u32,
    pub name_ordinals: Vec<(u16, String)>,
    pub functions: Vec<u32>,
}

impl ExportDirectory {
    pub fn get_export_offset_from_name(&self, name: &str) -> Option<u32> {
        self.name_ordinals.iter().find_map(|(ordinal, n)| {
            if n == name {
                Some(self.functions[*ordinal as usize])
            } else {
                None
            }
        })
    }
    pub fn get_export_offset_from_ordinal(&self, ordinal: u16) -> Option<u32> {
        let offset = (ordinal as u32 - self.ordinal_base) as usize;

        if offset < self.functions.len() {
            return Some(self.functions[offset]);
        }

        None
    }

    pub fn get_export_directory(pe64: &PE64) -> Option<Self> {
        let optional_header = &pe64.nt64().OptionalHeader;
        let export_data_directory = &optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize];

        if export_data_directory.VirtualAddress == 0 || export_data_directory.Size == 0 {
            return None;
        }

        let entry: Option<&IMAGE_EXPORT_DIRECTORY> = pe64.get_ref_from_rva(export_data_directory.VirtualAddress as usize);

        if let Some(entry) = entry {
            let mut export_dir = ExportDirectory {
                rva: export_data_directory.VirtualAddress as usize,
                size: export_data_directory.Size as usize,
                ordinal_base: entry.Base,
                name_ordinals: Vec::new(),
                functions: Vec::new(),
            };

            for i in 0..entry.NumberOfNames {
                let name_rva = pe64.get_ref_from_rva::<u32>((entry.AddressOfNames as usize) + (i * 4) as usize)?;
                let name_offset = pe64.rva_to_offset(*name_rva as usize)?;

                let mut size = 0;
                while pe64._raw[name_offset + size] != 0 {
                    size += 1;
                }

                let name = String::from_utf8(pe64._raw[name_offset..name_offset + size].to_vec()).ok()?;
                let ordinal = pe64.get_ref_from_rva::<u16>((entry.AddressOfNameOrdinals as usize) + (i * 2) as usize)?;

                export_dir.name_ordinals.push((*ordinal, name));
            }

            export_dir.functions = unsafe { std::slice::from_raw_parts(pe64.get_ref_from_rva(entry.AddressOfFunctions as usize)? as *const u32, entry.NumberOfFunctions as usize).to_vec()};

            return Some(export_dir);
        }

        None
    }
}