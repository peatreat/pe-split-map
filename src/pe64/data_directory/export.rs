use winapi::um::winnt::IMAGE_DIRECTORY_ENTRY_EXPORT;

use crate::pe64::PE64;

pub struct ExportDirectory {
    pub rva: usize,
    pub size: usize,
}

impl ExportDirectory {
    pub fn get_export_directory(pe64: &PE64) -> Option<Self> {
        let optional_header = &pe64.nt64().OptionalHeader;
        let export_data_directory = &optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize];

        if export_data_directory.VirtualAddress == 0 || export_data_directory.Size == 0 {
            return None;
        }

        Some(Self {
            rva: export_data_directory.VirtualAddress as usize,
            size: export_data_directory.Size as usize,
        })
    }
}