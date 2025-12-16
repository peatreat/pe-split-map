use iced_x86::Encoder;

use super::Translation;

#[derive(Clone)]
pub struct ControlTranslation {
    pub mov_instruction: iced_x86::Instruction,
    pub control_instruction: iced_x86::Instruction,
}

impl ControlTranslation {
    pub fn resolve(&mut self, ip: u64) {
        // Implementation for resolving the relative translation
        self.mov_instruction.set_immediate64(ip);
    }

    pub fn instruction(&self) -> iced_x86::Instruction {
        self.mov_instruction
    }
    
    pub fn buffer(&self) -> Result<Vec<u8>, iced_x86::IcedError> {
        let mut encoder = Encoder::new(64);

        encoder.encode(&self.mov_instruction, self.mov_instruction.ip())?;
        encoder.encode(&self.control_instruction, self.control_instruction.ip())?;
        
        //println!("{}", &self.mov_instruction);
        //println!("{}", &self.control_instruction);

        Ok(encoder.take_buffer())
    }
}