pub mod relative;
pub mod raw;
pub mod control;
pub mod jcc;
pub mod block;

use iced_x86::{Encoder, Instruction};
pub use relative::RelativeTranslation;
pub use control::ControlTranslation;
pub use jcc::JCCTranslation;

pub enum Translation {
    Default(DefaultTranslation),
    Jcc(JCCTranslation),
    Control(ControlTranslation),
    Relative(RelativeTranslation),
}

impl Translation {
    pub fn rva(&self) -> u64 {
        self.instruction().ip()
    }
    
    pub fn buffer(&self) -> Result<Vec<u8>, iced_x86::IcedError> {
        match self {
            Translation::Default(default_translation) => default_translation.buffer(),
            Translation::Jcc(jcc_translation) => jcc_translation.buffer(),
            Translation::Control(control_translation) => control_translation.buffer(),
            Translation::Relative(relative_translation) => relative_translation.buffer(),
        }
    }

    pub fn resolve(&mut self, rel_op_ip: u64) {
        match self {
            Translation::Default(default_translation) => default_translation.resolve(rel_op_ip),
            Translation::Jcc(jcc_translation) => jcc_translation.resolve(rel_op_ip),
            Translation::Control(control_translation) => control_translation.resolve(rel_op_ip),
            Translation::Relative(relative_translation) => relative_translation.resolve(rel_op_ip),
        }
    }

    pub fn instruction(&self) -> Instruction {
        match self {
            Translation::Default(default_translation) => default_translation.instruction(),
            Translation::Jcc(jcc_translation) => jcc_translation.instruction(),
            Translation::Control(control_translation) => control_translation.instruction(),
            Translation::Relative(relative_translation) => relative_translation.instruction(),
        }
    }

    pub fn mapped(&self) -> u64 {
        match self {
            Translation::Default(default_translation) => default_translation.mapped(),
            Translation::Jcc(jcc_translation) => jcc_translation.mapped(),
            Translation::Control(control_translation) => control_translation.mapped(),
            Translation::Relative(relative_translation) => relative_translation.mapped(),
        }
    }

    pub fn mapped_mut(&mut self) -> &mut u64 {
        match self {
            Translation::Default(default_translation) => default_translation.mapped_mut(),
            Translation::Jcc(jcc_translation) => jcc_translation.mapped_mut(),
            Translation::Control(control_translation) => control_translation.mapped_mut(),
            Translation::Relative(relative_translation) => relative_translation.mapped_mut(),
        }
    }

    pub fn rel_op_rva(&self) -> Option<u64> {
        match self {
            Translation::Default(default_translation) => default_translation.rel_op_rva(),
            Translation::Jcc(jcc_translation) => jcc_translation.rel_op_rva(),
            Translation::Control(control_translation) => control_translation.rel_op_rva(),
            Translation::Relative(relative_translation) => relative_translation.rel_op_rva(),
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