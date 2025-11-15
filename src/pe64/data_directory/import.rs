use std::mem::{self, offset_of};

use winapi::um::winnt::{IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_IMPORT_BY_NAME, IMAGE_IMPORT_DESCRIPTOR, IMAGE_ORDINAL_FLAG, IMAGE_THUNK_DATA};

use crate::pe64::{PE64, data_directory::import};

pub struct ImportDirectory {
    pub dir_rva: usize,
    pub dir_size: usize,
    pub dll_name_rva_and_size: Option<(usize, usize)>, // (rva, size)
    pub thunks: Vec<ThunkData>,
}

pub struct ThunkData {
    pub rva: usize,
    pub size: usize,
    pub name_rva_and_size: Option<(usize, usize)>, // (rva, size)
}

impl ImportDirectory {
    fn get_string_size(pe64: &PE64, rva: usize) -> Option<usize> {
        let mut offset = pe64.rva_to_offset(rva)?;

        let mut size = 1; // start with 1 to account for null terminator
        
        while offset < pe64._raw.len() {
            let byte = pe64._raw.get(offset)?;
            if *byte == 0 {
                break;
            }

            size += 1;
            offset += 1;
        }

        Some(size)
    }

    pub fn get_import_directory(pe64: &PE64) -> Option<ImportDirectory> {
        let optional_header = &pe64.nt64().OptionalHeader;
        let import_directory = &optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT as usize];

        if import_directory.VirtualAddress == 0 || import_directory.Size == 0 {
            return None;
        }

        let import_dir_rva = import_directory.VirtualAddress as usize;
        let import_dir_size = import_directory.Size as usize;

        let mut import_directory = ImportDirectory {
            dir_rva: import_dir_rva,
            dir_size: import_dir_size,
            dll_name_rva_and_size: None,
            thunks: Vec::new(),
        };

        let number_of_entries = import_dir_size / std::mem::size_of::<IMAGE_IMPORT_DESCRIPTOR>();

        for i in 0..number_of_entries {
            let entry: Option<&IMAGE_IMPORT_DESCRIPTOR> = pe64.get_ref_from_rva(import_dir_rva + i * std::mem::size_of::<IMAGE_IMPORT_DESCRIPTOR>());

            if let Some(entry) = entry {
                if entry.Name != 0 {
                    if let Some(size) = Self::get_string_size(pe64, entry.Name as usize) {
                        import_directory.dll_name_rva_and_size = Some((entry.Name as usize, size));
                    }
                }

                let mut original_thunk_rva = *unsafe { entry.u.OriginalFirstThunk() } as usize;
                let original_thunk: Option<&IMAGE_THUNK_DATA> = pe64.get_ref_from_rva(original_thunk_rva);

                if let Some(mut original_thunk) = original_thunk {
                    unsafe {
                        while *original_thunk.u1.AddressOfData() != 0 {
                            let mut thunk_data = ThunkData {
                                rva: original_thunk_rva,
                                size: mem::size_of::<IMAGE_THUNK_DATA>(),
                                name_rva_and_size: None,
                            };

                            if *original_thunk.u1.Ordinal() & IMAGE_ORDINAL_FLAG == 0 { // import by name
                                let import_by_name_rva = *original_thunk.u1.AddressOfData() as usize;
                                let mut import_size = mem::size_of::<u16>(); // Hint is u16

                                if let Some(mut size) = Self::get_string_size(pe64, import_by_name_rva + offset_of!(IMAGE_IMPORT_BY_NAME, Name)) {
                                    size = size.max(2); // at least 2 bytes for the name for alignment
                                    import_size += size; // add size of name
                                }

                                thunk_data.name_rva_and_size = Some((import_by_name_rva, import_size));
                            }

                            import_directory.thunks.push(thunk_data);

                            original_thunk = &*(original_thunk as *const IMAGE_THUNK_DATA).add(1);
                            original_thunk_rva += mem::size_of::<IMAGE_THUNK_DATA>();
                        }
                    }
                }
            }
        }

        Some(import_directory)
    }
}