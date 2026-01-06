use iced_x86::Encoder;

pub struct RelativeTranslation {
    mapped_va: u64,
    pub instruction: iced_x86::Instruction,
}

impl RelativeTranslation {
    pub fn new(instruction: iced_x86::Instruction) -> Self {
        Self { instruction, mapped_va: 0 }
    }

    pub fn resolve(&mut self, rel_op_ip: u64) {
        // 2nd operand should be immediate that contains the original ip_rel_operand() value and in here that immediate gets replaced with the reserved memory address
        self.instruction.set_immediate64(rel_op_ip);
    }

    pub fn rel_op_rva(&self) -> Option<u64> {
        Some(self.instruction.immediate64())
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
        encoder.encode(&self.instruction, self.instruction.ip())?;
        Ok(encoder.take_buffer())
    }
}