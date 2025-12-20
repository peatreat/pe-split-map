use iced_x86::code_asm::bl;
use rand::seq::SliceRandom;

use crate::{heap::{self, Heap}, pe64::{PE64, symbols::Symbol, translation::{Translation, block::TranslationBlock}}};

pub struct Mapper;

#[derive(Default)]
pub struct MappedBlock {
    pub address: u64,
    pub data: Vec<u8>,
}

pub enum TranslationBlockSize {
    MaxByteSize(u64),
    MaxNumberInstructions(u64),
}

impl Mapper {
    pub fn find_symbol_by_rva(symbols: &Vec<(std::ops::Range<usize>, MappedBlock)>, rva: usize) -> Option<&(std::ops::Range<usize>, MappedBlock)> {
        let mut first = 0isize;
        let mut last = symbols.len() as isize - 1;

        while (first <= last) {
            let mid_index = (first + last) / 2;
            let mid = &symbols[mid_index as usize];

            if (mid.0.contains(&rva)) {
                return Some(mid);
            } else if (rva < mid.0.start) {
                last = mid_index - 1;
            } else {
                first = mid_index + 1;
            }
        }

        None
    }

    fn map_symbols(pe: &PE64, heap: &mut Heap, symbols: &Vec<(usize, Symbol)>) -> Option<Vec<(std::ops::Range<usize>, MappedBlock)>> {
        // filter out ignored symbols
        let mut symbols = symbols.iter()
        .filter(|(rva, symbol)| !symbol.should_ignore && symbol.max_operation_size > 0)
        .map(|(rva, symbol)| (*rva..(*rva + symbol.max_operation_size as usize), MappedBlock::default()))
        .collect::<Vec<_>>();

        // allocate in random order
        let mut symbols_shuffled = symbols.iter_mut().collect::<Vec<_>>();
        let mut rng = rand::thread_rng();
        symbols_shuffled.shuffle(&mut rng);

        for (rva_range, mapped_block) in &mut symbols_shuffled {
            let symbol_size = (rva_range.end - rva_range.start) as usize;

            mapped_block.address = heap.reserve_with_same_alignment(rva_range.start as u64, (rva_range.end - rva_range.start) as u64, Some(32))?;

            mapped_block.data = pe.get_data_from_rva(rva_range.start, symbol_size)
            .and_then(|slice| Some(slice.to_vec()))
            .unwrap_or(vec![0u8; symbol_size]);
        }

        Some(symbols)
    }

    pub fn map(pe: &PE64, code_heap: &mut Heap, symbol_heap: &mut Heap, translations: &mut Vec<Translation>, symbols: &Vec<(usize, Symbol)>, block_size: TranslationBlockSize, assume_jumps_are_near: bool) -> Option<Vec<MappedBlock>> {
        // map symbols
        let symbols = Mapper::map_symbols(pe, symbol_heap, symbols)?;

        // create our blocks
        let mut blocks: Vec<TranslationBlock> = Vec::new();

        let mut current_block = TranslationBlock::new();

        for index in 0..translations.len() {
            current_block.add_translation(index);

            match block_size {
                TranslationBlockSize::MaxByteSize(size) => {
                    if current_block.byte_size(translations, assume_jumps_are_near)? >= size {
                        blocks.push(current_block);
                        current_block = TranslationBlock::new();
                    }
                }
                TranslationBlockSize::MaxNumberInstructions(size) => {
                    if current_block.len() >= size {
                        blocks.push(current_block);
                        current_block = TranslationBlock::new();
                    }
                }
            }
        }

        if !current_block.is_empty() {
            blocks.push(current_block);
        }

        // allocate blocks in a random order
        let mut blocks_shuffled = blocks.iter_mut().collect::<Vec<_>>();
        let mut rng = rand::thread_rng();
        blocks_shuffled.shuffle(&mut rng);

        for block in &mut blocks_shuffled {
            block.reserve(translations, code_heap, 0x10, assume_jumps_are_near)?;
        }

        // resolve blocks
        for block in blocks.iter_mut() {
            block.resolve(translations, &symbols)?;
        }

        // create mapped blocks
        let mut mapped_blocks: Vec<MappedBlock> = Vec::new();

        for (index, block) in blocks.iter().enumerate() {
            mapped_blocks.push(MappedBlock {
                address: block.address(translations)?,
                data: block.buffer(translations, assume_jumps_are_near, blocks.get(index + 1))?,
            });
        }

        mapped_blocks.reserve(symbols.len());

        mapped_blocks.append(&mut symbols.into_iter().map(|(_, mapped_block)| mapped_block).collect());

        // shuffle to mix up the order of writes being transmitted
        mapped_blocks.shuffle(&mut rng);

        Some(mapped_blocks)
    }
}