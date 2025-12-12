use iced_x86::Encoder;

use super::Translation;

pub struct ControlTranslation {
    pub mov_instruction: iced_x86::Instruction,
    pub control_instruction: iced_x86::Instruction,
}

impl Translation for ControlTranslation {
    fn resolve(&self) {
        // Implementation for resolving the relative translation
    }

    fn instruction(&self) -> iced_x86::Instruction {
        self.mov_instruction
    }
    
    fn buffer(&mut self) -> Result<Vec<u8>, iced_x86::IcedError> {
        let mut encoder = Encoder::new(64);

        encoder.encode(&self.mov_instruction, self.mov_instruction.ip())?;
        encoder.encode(&self.control_instruction, self.control_instruction.ip())?;
        
        Ok(encoder.take_buffer())
    }
}