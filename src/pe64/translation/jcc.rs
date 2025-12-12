use iced_x86::{Code, Encoder, Instruction, MemoryOperand, Register};

use super::Translation;

pub struct JCCTranslation {
    pub jcc_instruction: iced_x86::Instruction,
    pub branch_target: u64,
}

impl JCCTranslation {
    pub fn new(mut jcc_instruction: iced_x86::Instruction) -> Result<Self, iced_x86::IcedError> {
        let branch_target = jcc_instruction.near_branch64();

        jcc_instruction.as_short_branch();
        jcc_instruction.set_near_branch64(0);

        Ok (
            JCCTranslation {
                jcc_instruction,
                branch_target,
            }
        )
    }

    fn get_instruction_size(&self, instruction: &Instruction) -> Result<u64, iced_x86::IcedError> {
        let mut encoder = Encoder::new(64);
        encoder.encode(instruction, instruction.ip()).and_then(|size| Ok(size as u64))
    }
}

impl Translation for JCCTranslation {
    fn resolve(&self) {
        // take rva stored in branch target and then replace branch target with absolute address of the reserved memory for that rva's translation
    }

    fn instruction(&self) -> iced_x86::Instruction {
        self.jcc_instruction
    }
    
    fn buffer(&mut self) -> Result<Vec<u8>, iced_x86::IcedError> {
        let mut encoder = Encoder::new(64);

        self.jcc_instruction.set_ip(0);

        let mut skip_instruction = Instruction::with_branch(Code::Jmp_rel8_64, 0)?;
        skip_instruction.set_ip(self.jcc_instruction.ip() + self.get_instruction_size(&self.jcc_instruction)?);

        let mut branch_instruction = Instruction::with1(Code::Jmp_rm64, MemoryOperand::new(Register::RIP, Register::None, 1, 0, 4, false, Register::None))?;
        branch_instruction.set_ip(skip_instruction.ip() + self.get_instruction_size(&skip_instruction)?);

        let branch_instruction_size = self.get_instruction_size(&branch_instruction)?;

        branch_instruction.set_memory_displacement32((branch_instruction.ip() + branch_instruction_size) as u32);

        skip_instruction.set_near_branch64(branch_instruction.ip() + branch_instruction_size + std::mem::size_of_val(&self.branch_target) as u64);

        self.jcc_instruction.set_near_branch64(branch_instruction.ip());

        encoder.encode(&self.jcc_instruction, self.jcc_instruction.ip())?;
        encoder.encode(&skip_instruction, skip_instruction.ip())?;
        encoder.encode(&branch_instruction, branch_instruction.ip())?;
        
        Ok (
            [ encoder.take_buffer(), self.branch_target.to_le_bytes().to_vec() ].concat()
        )
    }
}