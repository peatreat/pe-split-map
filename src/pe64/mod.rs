use std::{fs, io, mem::{self, offset_of}};

use winapi::um::winnt::{IMAGE_DOS_HEADER, IMAGE_NT_HEADERS64, IMAGE_NT_OPTIONAL_HDR64_MAGIC, IMAGE_SECTION_HEADER};

use crate::pe64::section::Section;

mod section;
pub mod data_directory;

pub struct PE64 {
    _raw: Vec<u8>,
}

impl PE64 {
    pub fn new(path: &str) -> Result<Self, std::io::Error> {
        let bytes = fs::read(path)?;

        // check if valid pe by checking e_magic in DOS header
        if bytes.len() < mem::size_of::<IMAGE_DOS_HEADER>() || bytes[0] != 0x4D || bytes[1] != 0x5A {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "File is not a valid PE",
            ));
        }

        let pe = PE64 { _raw: bytes };

        // check if 64-bit
        if !pe.is_64() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "File is not a valid PE64",
            ));
        }

        Ok (pe)
    }

    pub fn dos<'a>(&self) -> &'a IMAGE_DOS_HEADER {
        // parse dos
        unsafe { &*(self._raw.as_ptr() as *const IMAGE_DOS_HEADER) }
    }

    pub fn nt64<'a>(&self) -> &'a IMAGE_NT_HEADERS64 {
        // parse nt 64-bit
        unsafe { &*(self._raw.as_ptr().add(self.dos().e_lfanew as usize) as *const IMAGE_NT_HEADERS64) }
    }

    fn is_64(&self) -> bool {
        self.nt64().OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC
    }

    pub fn rva_to_offset(&self, rva: usize) -> Option<usize> {
        self.iter_find_section(|section| section.contains_rva(rva))
            .map(|section| {
                let offset_within_section = rva - section.virtual_address;
                let section_raw_offset = section._raw.as_ptr() as usize - self._raw.as_ptr() as usize;
                section_raw_offset + offset_within_section
            })
    }

    pub fn get_ref_from_rva<'a, T>(&'a self, rva: usize) -> Option<&'a T> {
        let offset = self.rva_to_offset(rva)?;

        if offset + mem::size_of::<T>() > self._raw.len() {
            return None;
        }

        Some(unsafe { &*(self._raw.as_ptr().add(offset) as *const T) })
    }

    pub fn iter_find_section<F>(&self, mut closure: F) -> Option<Section<'_>>
        where F: FnMut(&Section) -> bool,
    {
        let number_of_sections = self.nt64().FileHeader.NumberOfSections;

        let first_section_offset = self.dos().e_lfanew as usize
            + offset_of!(IMAGE_NT_HEADERS64, OptionalHeader) as usize
            + self.nt64().FileHeader.SizeOfOptionalHeader as usize;
        
        let section_size = mem::size_of::<IMAGE_SECTION_HEADER>();

        for i in 0..number_of_sections {
            let section_offset = first_section_offset + (i as usize * section_size);
            let section = unsafe {
                &*(self._raw.as_ptr().add(section_offset) as *const IMAGE_SECTION_HEADER)
            };

            let section = Section::from((self._raw.as_slice(), section));

            if closure(&section) {
                return Some(section);
            }
        }

        None
    }
}