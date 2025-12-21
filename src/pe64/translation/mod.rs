pub mod relative;
pub mod raw;
pub mod control;
pub mod jcc;
pub mod block;
pub mod near;

use iced_x86::{Encoder, Instruction};
pub use relative::RelativeTranslation;
pub use control::ControlTranslation;
pub use jcc::JCCTranslation;

use crate::{psm_error::PSMError, pe64::{mapper::{MappedBlock, Mapper}, translation::near::NearTranslation}};

pub enum Translation {
    Default(DefaultTranslation),
    Jcc(JCCTranslation),
    Control(ControlTranslation),
    Relative(RelativeTranslation),
    Near(NearTranslation),
}

impl Translation {
    pub fn rva(&self) -> u64 {
        self.instruction().ip()
    }
    
    pub fn buffer(&self, assume_jumps_are_near: bool) -> Result<Vec<u8>, iced_x86::IcedError> {
        match self {
            Translation::Default(default_translation) => default_translation.buffer(),
            Translation::Jcc(jcc_translation) => jcc_translation.buffer(assume_jumps_are_near),
            Translation::Control(control_translation) => control_translation.buffer(assume_jumps_are_near),
            Translation::Relative(relative_translation) => relative_translation.buffer(),
            Translation::Near(near_translation) => near_translation.buffer(),
        }
    }

    pub fn resolve(&mut self, rel_op_ip: u64) {
        match self {
            Translation::Default(default_translation) => default_translation.resolve(rel_op_ip),
            Translation::Jcc(jcc_translation) => jcc_translation.resolve(rel_op_ip),
            Translation::Control(control_translation) => control_translation.resolve(rel_op_ip),
            Translation::Relative(relative_translation) => relative_translation.resolve(rel_op_ip),
            Translation::Near(near_translation) => near_translation.resolve(rel_op_ip),
        }
    }

    pub fn instruction(&self) -> Instruction {
        match self {
            Translation::Default(default_translation) => default_translation.instruction(),
            Translation::Jcc(jcc_translation) => jcc_translation.instruction(),
            Translation::Control(control_translation) => control_translation.instruction(),
            Translation::Relative(relative_translation) => relative_translation.instruction(),
            Translation::Near(near_translation) => near_translation.instruction(),
        }
    }

    pub fn mapped(&self) -> u64 {
        match self {
            Translation::Default(default_translation) => default_translation.mapped(),
            Translation::Jcc(jcc_translation) => jcc_translation.mapped(),
            Translation::Control(control_translation) => control_translation.mapped(),
            Translation::Relative(relative_translation) => relative_translation.mapped(),
            Translation::Near(near_translation) => near_translation.mapped(),
        }
    }

    pub fn mapped_mut(&mut self) -> &mut u64 {
        match self {
            Translation::Default(default_translation) => default_translation.mapped_mut(),
            Translation::Jcc(jcc_translation) => jcc_translation.mapped_mut(),
            Translation::Control(control_translation) => control_translation.mapped_mut(),
            Translation::Relative(relative_translation) => relative_translation.mapped_mut(),
            Translation::Near(near_translation) => near_translation.mapped_mut(),
        }
    }

    pub fn rel_op_rva(&self) -> Option<u64> {
        match self {
            Translation::Default(default_translation) => default_translation.rel_op_rva(),
            Translation::Jcc(jcc_translation) => jcc_translation.rel_op_rva(),
            Translation::Control(control_translation) => control_translation.rel_op_rva(),
            Translation::Relative(relative_translation) => relative_translation.rel_op_rva(),
            Translation::Near(near_translation) => near_translation.rel_op_rva(),
        }
    }

    pub fn find_first_translation_rva<'a>(translations: &'a [Self], rva_to_find: u64) -> Option<&'a Self> {
        let mut first = 0isize;
        let mut last = translations.len() as isize - 1;
        let mut first_occurrence = None;

        while first <= last {
            let mid_index = (first + last) / 2;
            let cur_rva = translations[mid_index as usize].rva();

            if cur_rva == rva_to_find {
                first_occurrence = Some(&translations[mid_index as usize]);
                last = mid_index - 1;
            } else if cur_rva < rva_to_find {
                first = mid_index + 1;
            } else {
                last = mid_index - 1;
            }
        }

        return first_occurrence;
    }

    pub fn get_rel_offset_near(target_address: u64, next_ip: u64) -> Result<i32, PSMError> {
        let rel_offset = target_address.wrapping_sub(next_ip);
        let is_valid = (rel_offset as i64) >= (i32::MIN as i64) && (rel_offset as i64) <= (i32::MAX as i64);

        is_valid.then_some(rel_offset as i32).ok_or(PSMError::BadRelativeOffset(next_ip, target_address, rel_offset))
    }

    pub fn translate_rva_to_mapped(translations: &[Self], symbols: &[(std::ops::Range<usize>, MappedBlock)], rva_to_find: u64) -> Result<u64, PSMError> {
        Translation::find_first_translation_rva(translations, rva_to_find)
            .and_then(|translation| Some(translation.mapped()))
            .or(
                Mapper::find_symbol_by_rva(symbols, rva_to_find as usize)
                .map(|(rva_range, mapped_block)| mapped_block.address + (rva_to_find as usize - rva_range.start) as u64)
            )
            .ok_or(PSMError::TranslationFail(rva_to_find))
    }
}

#[derive(Clone)]
pub struct DefaultTranslation {
    mapped_va: u64,
    pub instruction: iced_x86::Instruction,
}

impl DefaultTranslation {
    pub fn new(instruction: iced_x86::Instruction) -> Self {
        Self { mapped_va: 0, instruction }
    }

    pub fn resolve(&mut self, rel_op_ip: u64) {}

    pub fn rel_op_rva(&self) -> Option<u64> {
        None
    }

    pub fn instruction(&self) -> iced_x86::Instruction {
        self.instruction
    }

    pub fn mapped(&self) -> u64 {
        self.mapped_va
    }

    pub fn mapped_mut(&mut self) -> &mut u64 {
        &mut self.mapped_va
    }
    
    pub fn buffer(&self) -> Result<Vec<u8>, iced_x86::IcedError> {
        let mut encoder = Encoder::new(64);
        //println!("{}", &self.instruction);
        encoder.encode(&self.instruction, self.instruction.ip())?;
        Ok(encoder.take_buffer())
    }
}