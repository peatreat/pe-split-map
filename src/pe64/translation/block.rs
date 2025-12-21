use iced_x86::{Encoder, IcedError, MemoryOperand, code_asm::tr};

use crate::{heap::Heap, pe64::{mapper::{MappedBlock, Mapper}, translation::{self, Translation}}};

pub struct TranslationBlock {
    translations: Vec<usize>
}

impl TranslationBlock {
    pub fn new() -> Self {
        TranslationBlock { translations: Vec::new() }
    }

    pub fn add_translation(&mut self, translation_index: usize) {
        self.translations.push(translation_index);
    }

    pub fn is_empty(&self) -> bool {
        self.translations.is_empty()
    }

    pub fn len(&self) -> u64 {
        self.translations.len() as u64
    }

    pub fn address(&self, all_translations: &mut [Translation]) -> Option<u64> {
        self.translations.first().map(|t| all_translations[*t].mapped())
    }

    pub fn buffer(&self, all_translations: &mut [Translation], assume_jumps_are_near: bool, next_block: Option<&TranslationBlock>) -> Option<Vec<u8>> {
        let mut data: Vec<u8> = Vec::new();

        for index in &self.translations {
            data.extend_from_slice(&all_translations[*index].buffer(assume_jumps_are_near).ok()?);
        }

        if let Some(next_block_address) = next_block.and_then(|block| block.address(all_translations)) {
            if assume_jumps_are_near {
                let mut jmp_buffer = [0u8; 5];
                jmp_buffer[0] = 0xE9;

                let next_rip = self.address(all_translations)? + self.byte_size(all_translations, assume_jumps_are_near)?;

                let rel_offset = Translation::get_rel_offset_near(next_block_address, next_rip)?;
                
                jmp_buffer[1..5].copy_from_slice(&(rel_offset as u32).to_le_bytes());
                data.extend_from_slice(&jmp_buffer);
            } else {
                let mut jmp_buffer = [0u8; 14];
                jmp_buffer[0] = 0xFF;
                jmp_buffer[1] = 0x25;

                jmp_buffer[6..14].copy_from_slice(&next_block_address.to_le_bytes());
                data.extend_from_slice(&jmp_buffer);
            }
        }

        Some(data)
    }

    pub fn byte_size(&self, all_translations: &mut [Translation], assume_jumps_are_near: bool) -> Option<u64> {
        let mut total_size: u64 = self.translations.iter()
            .map(|t| all_translations[*t].buffer(assume_jumps_are_near)
            .and_then(|buffer| Ok(buffer.len() as u64)).ok())
            .into_iter().collect::<Option<Vec<_>>>()?
            .iter().sum();
        
        // add extra space for abs jump to next block
        total_size += if assume_jumps_are_near { 5 } else { 14 };

        Some(total_size)
    }

    pub fn reserve(&mut self, all_translations: &mut [Translation], heap: &mut Heap, alignment: u64, assume_jumps_are_near: bool) -> Option<()> {
        let total_size = self.byte_size(all_translations, assume_jumps_are_near)?;

        let reserved_va = heap.reserve(total_size as u64, alignment)?;
        let mut offset = 0u64;

        for index in &self.translations {
            let translation = &mut all_translations[*index];
            *translation.mapped_mut() = reserved_va + offset;
            offset += translation.buffer(assume_jumps_are_near).ok()?.len() as u64;
        }

        Some(())
    }

    pub fn resolve(&mut self, all_translations: &mut [Translation], symbols: &[(std::ops::Range<usize>, MappedBlock)]) -> Option<()> {
        for index in &self.translations {
            if let Some(rel_op_rva) = &all_translations[*index].rel_op_rva() {
                let rel_op_ip = Translation::translate_rva_to_mapped(&all_translations, symbols, *rel_op_rva)?;
                all_translations[*index].resolve(rel_op_ip);
            }
        }

        Some(())
    }
}