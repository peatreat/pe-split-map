mod relative;
mod raw;
mod control;
mod jcc;
use iced_x86::Encoder;
pub use relative::RelativeTranslation;
pub use control::ControlTranslation;
pub use jcc::JCCTranslation;

pub trait Translation {
    fn rva(&self) -> u32 {
        self.instruction().ip() as u32
    }
    
    fn buffer(&mut self) -> Result<Vec<u8>, iced_x86::IcedError>;
    fn resolve(&self);
    fn instruction(&self) -> iced_x86::Instruction;
}

pub struct DefaultTranslation {
    pub instruction: iced_x86::Instruction,
}

impl Translation for DefaultTranslation {
    fn resolve(&self) {}

    fn instruction(&self) -> iced_x86::Instruction {
        self.instruction
    }
    
    fn buffer(&mut self) -> Result<Vec<u8>, iced_x86::IcedError> {
        let mut encoder = Encoder::new(64);
        encoder.encode(&self.instruction, self.instruction.ip())?;
        Ok(encoder.take_buffer())
    }
}