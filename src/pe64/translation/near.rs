use iced_x86::Encoder;

pub struct NearTranslation {
    mapped_va: u64,
    pub instruction: iced_x86::Instruction,
}

impl NearTranslation {
    pub fn new(instruction: iced_x86::Instruction) -> Self {
        Self { instruction, mapped_va: 0 }
    }

    pub fn resolve(&mut self, rel_op_ip: u64) {
        self.instruction.set_memory_displacement64(rel_op_ip);
    }

    pub fn rel_op_rva(&self) -> Option<u64> {
        Some(self.instruction.ip_rel_memory_address())
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
        let mut instr = self.instruction.clone();
        
        instr.as_near_branch();
        encoder.encode(&instr, self.mapped())?;

        Ok(encoder.take_buffer())
    }
}