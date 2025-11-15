use std::mem;
use winapi::um::winnt::{IMAGE_DIRECTORY_ENTRY_EXCEPTION, IMAGE_RUNTIME_FUNCTION_ENTRY};

use crate::pe64::PE64;

pub struct ExceptionDirectory;

#[repr(C)]
union UnwindCode {
    pub code: u16,
    pub frame_offset: u16,
}

#[repr(C)]
struct UnwindInfo {
    pub version_and_flags: u8,
    pub size_of_prolog: u8,
    pub count_of_codes: u8,
    pub frame_register_and_offset: u8,
    pub unwind_code: [UnwindCode; 1],
}

pub struct UnwindBlock {
    pub rva: usize,
    pub size: usize,
}

impl ExceptionDirectory {
    pub fn get_unwind_blocks(pe64: &PE64) -> Vec<UnwindBlock> {
        let optional_header = &pe64.nt64().OptionalHeader;
        let exception_data_directory = &optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION as usize];

        if exception_data_directory.VirtualAddress == 0 || exception_data_directory.Size == 0 {
            return Vec::new();
        }

        let exception_dir_rva = exception_data_directory.VirtualAddress as usize;
        let exception_dir_size = exception_data_directory.Size as usize;

        let number_of_entries = exception_dir_size / mem::size_of::<IMAGE_RUNTIME_FUNCTION_ENTRY>();

        let mut unwind_blocks = Vec::new();

        for i in 0..number_of_entries {
            let entry: Option<&IMAGE_RUNTIME_FUNCTION_ENTRY> = pe64.get_ref_from_rva(exception_dir_rva + i * mem::size_of::<IMAGE_RUNTIME_FUNCTION_ENTRY>());

            if let Some(entry) = entry {
                let unwind_info: Option<&UnwindInfo> = pe64.get_ref_from_rva(*unsafe { entry.u.UnwindData() } as usize);

                if let Some(unwind_info) = unwind_info {
                    let block_rva = *unsafe { entry.u.UnwindInfoAddress() } as usize;
                    let block_size = mem::size_of::<UnwindInfo>() - mem::size_of::<UnwindCode>() + (unwind_info.count_of_codes as usize * mem::size_of::<UnwindCode>());

                    unwind_blocks.push(UnwindBlock {
                        rva: block_rva,
                        size: block_size,
                    });
                }
            }
        }

        unwind_blocks
    }
}