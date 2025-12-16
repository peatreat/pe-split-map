pub mod relative;
pub mod raw;
pub mod control;
pub mod jcc;
use iced_x86::{Encoder, Instruction};
pub use relative::RelativeTranslation;
pub use control::ControlTranslation;
pub use jcc::JCCTranslation;

#[derive(Clone)]
pub enum Translation {
    Default(DefaultTranslation),
    Jcc(JCCTranslation),
    Control(ControlTranslation),
    Relative(RelativeTranslation),
}

impl Translation {
    pub fn rva(&self) -> u32 {
        self.instruction().ip() as u32
    }
    
    pub fn buffer(&self) -> Result<Vec<u8>, iced_x86::IcedError> {
        match self {
            Translation::Default(default_translation) => default_translation.buffer(),
            Translation::Jcc(jcc_translation) => jcc_translation.buffer(),
            Translation::Control(control_translation) => control_translation.buffer(),
            Translation::Relative(relative_translation) => relative_translation.buffer(),
        }
    }

    //pub fn resolve(&mut self, ip: u64) {
    //    match self {
    //        Translation::Default(default_translation) => default_translation.resolve(ip),
    //        Translation::Jcc(jcctranslation) => jcctranslation.resolve(ip),
    //        Translation::Control(control_translation) => control_translation.resolve(ip),
    //        Translation::Relative(relative_translation) => relative_translation.resolve(ip),
    //    }
    //}

    pub fn instruction(&self) -> Instruction {
        match self {
            Translation::Default(default_translation) => default_translation.instruction(),
            Translation::Jcc(jcc_translation) => jcc_translation.instruction(),
            Translation::Control(control_translation) => control_translation.instruction(),
            Translation::Relative(relative_translation) => relative_translation.instruction(),
        }
    }
}

#[derive(Clone)]
pub struct DefaultTranslation {
    pub instruction: iced_x86::Instruction,
}

impl DefaultTranslation {
    pub fn resolve(&mut self, ip: u64) {
        //self.instruction.set_ip(ip);
    }

    pub fn instruction(&self) -> iced_x86::Instruction {
        self.instruction
    }
    
    pub fn buffer(&self) -> Result<Vec<u8>, iced_x86::IcedError> {
        let mut encoder = Encoder::new(64);
        //println!("{}", &self.instruction);
        encoder.encode(&self.instruction, self.instruction.ip())?;
        Ok(encoder.take_buffer())
    }
}