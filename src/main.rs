mod pe64;

use std::collections::HashMap;

use pe64::PE64;
use iced_x86::{self, Decoder};

use crate::pe64::data_directory::{DebugDirectory, ExceptionDirectory, ExportDirectory, ImportDirectory, RelocDirectory, reloc};

#[derive(Copy, Clone)]
struct Symbol {
    max_operation_size: u32,
    is_ptr_reference: bool,
    is_directory_symbol: bool,
}

impl Symbol {
    pub fn update_or_insert(
        symbols: &mut HashMap<usize, Symbol>,
        rva: usize,
        operation_size: u32,
        is_ptr_reference: bool,
        is_directory_symbol: bool,
    ) {
        symbols.entry(rva)
            .and_modify(|symbol| {
                if operation_size > symbol.max_operation_size {
                    symbol.max_operation_size = operation_size;
                }

                if is_ptr_reference {
                    symbol.is_ptr_reference = true;
                }

                if is_directory_symbol {
                    symbol.is_directory_symbol = true;
                }
            })
            .or_insert_with(|| Symbol {
                max_operation_size: operation_size,
                is_ptr_reference,
                is_directory_symbol,
            });
    }
}

fn main() {
    /*
        todo smap:
         - add instruction splitting up to certain max size (like 16 bytes)
         - create our own heap allocator to avoid fragmentation from many small allocations
         - if symbol is in a section that contains initialized data and the symbol rva < section va + SizeOfRawData, write bytes from in the raw section data, else write null bytes

        todo:
         - support base relocations
         - for base relocations that are 8 bytes apart, have them treated as 1 block of 8 * count bytes in size
         - set all ptr reference symbols to max(symbol_size, next_symbol_rva - current_symbol_rva)
         - do the same thing as overlapping intervals on leetcode for merging overlapping symbols (sort by rva, store first symbol rva and size in new vector, then for each next symbol in sorted vector we will check if the rva is between last item in new list's rva and rva + size, if it is then we update max of last entry in new list but if not then we add current symbol to new list)
    
        updates:
            - right now it works pretty good at getting the bounds right but some things it splits up incorrectly
            0x2E26D gets split up
            0x2eeae gets split up (the obfstr after this 1 doesnt have a lea and there is a byte ref in this array also, this tells us that there can be instructions that ref different offsets of an array that aren't contiguous but the symbol still needs to be together because the array also gets accessed at runtime by a register offset)
            // we need to fix our merging logic to handle these cases better
            - what i think we can do is after we do the overlapping merge, we can do another pass where for each ptr ref symbol, we extend its size to cover all contiguous non ptr ref symbols after it until we hit another ptr ref symbol

            i think the issue is with the end tags that get referenced in the obfuscated strings/bytes that mess up the symbol size calculation
            what i did should have merged symbols while they were contiguous and not ptr refs that were after a ptr ref symbol, but i think the merging logic was flawed

            i think it's better now, still need to take another scan through and see with the eye check
            .data symbols are just completely messed up idk why. i think maybe with the section segregation stuff
            at the end it just includes all the directory based symbols into 1 big symbol, idk if it's because those are missing or because of the new stuff i added for merging

            maybe for merging non-ptr refs between ptr refs we should add another check
            if it's a non-ptr ref that came from a regular instruction like mov ... then we do what we normally do by merging it to prev ptr ref symbol
            but if it's a non-ptr ref that we are 100% sure of the size (reloc ref sym, or data directory symbols), then split symbol there
    */

    let pe = PE64::new("test.dll").unwrap();

    let mut symbols: HashMap<usize, Symbol> = HashMap::new();

    pe.iter_find_section(|section| {
        println!("section: {}, raw size: {:p}, virt size: {:p}", section.name, section._raw.len() as *const usize, section.virtual_size as *const usize);

        if section.is_executable() {
            let mut decoder = Decoder::new(64, section._raw, iced_x86::DecoderOptions::NONE);

            //decoder.set_ip(pe.image_base() + section.virtual_address as u64);

            while decoder.can_decode() {
                let instruction = decoder.decode();

                if instruction.is_ip_rel_memory_operand() {
                    println!("{:p} | {:p}", instruction.ip() as *const usize, instruction.ip_rel_memory_address() as *const usize);
                    let operand_section = pe.iter_find_section(|s| s.contains_rva(section.virtual_address + instruction.ip_rel_memory_address() as usize));
                    
                    if let Some(operand_section) = operand_section {
                        if operand_section.is_executable() {
                            // if operand referenced is in an executable section, skip symbol storage
                            continue;
                        }

                        let operand_size = instruction.memory_size().size();
                        let is_lea_instruction = instruction.mnemonic() == iced_x86::Mnemonic::Lea;

                        // update if already exists with larger size else insert new
                        Symbol::update_or_insert(
                            &mut symbols,
                            section.virtual_address + instruction.ip_rel_memory_address() as usize,
                            operand_size as u32,
                            is_lea_instruction,
                            false,
                        );
                    }
                    //println!("instruction: {} | rva: {:p} | symbol rva: {:p} | size: {:?}", instruction, (section.virtual_address as u64 + instruction.ip()) as *const usize, (section.virtual_address as u64 + instruction.ip_rel_memory_address()) as *const usize, instruction.memory_size().size());
                }
            }

            return true;
        }

        false
    });

    DebugDirectory::get_debug_directories(&pe).iter().for_each(|debug_dir| {
        Symbol::update_or_insert(
            &mut symbols,
            debug_dir.dir_rva,
            debug_dir.dir_size as u32,
            false,
            true,
        );

        Symbol::update_or_insert(
            &mut symbols,
            debug_dir.data_rva,
            debug_dir.data_size as u32,
            false,
            true,
        );

        //println!("debug dir rva: {:p} | size: 0x{:X} ", (debug_dir.dir_rva as *const usize), debug_dir.dir_size);
        //println!("debug data rva: {:p} | size: 0x{:X} ", (debug_dir.data_rva as *const usize), debug_dir.data_size);
    });

    ExceptionDirectory::get_unwind_blocks(&pe).iter().for_each(|unwind_block| {
        Symbol::update_or_insert(
            &mut symbols,
            unwind_block.rva,
            unwind_block.size as u32,
            false,
            true,
        );

        //println!("unwind block rva: {:p} | size: 0x{:X} ", (unwind_block.rva as *const usize), unwind_block.size);
    });

    if let Some(export_dir) = ExportDirectory::get_export_directory(&pe) {
        Symbol::update_or_insert(
            &mut symbols,
            export_dir.rva,
            export_dir.size as u32,
            false,
            true,
        );

        println!("export dir rva: {:p} | size: 0x{:X} ", (export_dir.rva as *const usize), export_dir.size);
    };

    if let Some(import_dir) = ImportDirectory::get_import_directory(&pe) {
        Symbol::update_or_insert(
            &mut symbols,
            import_dir.dir_rva,
            import_dir.dir_size as u32,
            false,
            true,
        );

        println!("import dir rva: {:p} | size: 0x{:X} ", (import_dir.dir_rva as *const usize), import_dir.dir_size);

        if let Some((dll_name_rva, dll_name_size)) = import_dir.dll_name_rva_and_size {
            Symbol::update_or_insert(
                &mut symbols,
                dll_name_rva,
                dll_name_size as u32,
                false,
            true,
            );

            println!("import dll name rva: {:p} | size: 0x{:X} ", (dll_name_rva as *const usize), dll_name_size);
        }

        import_dir.thunks.iter().for_each(|thunk| {
            Symbol::update_or_insert(
                &mut symbols,
                thunk.rva,
                thunk.size as u32,
                false,
            true,
            );
            
            println!("import thunk rva: {:p} | size: 0x{:X} ", (thunk.rva as *const usize), thunk.size);

            if let Some((name_rva, name_size)) = thunk.name_rva_and_size {
                Symbol::update_or_insert(
                    &mut symbols,
                    name_rva,
                    name_size as u32,
                    false,
            true,
                );

                println!("import thunk name rva: {:p} | size: 0x{:X} ", (name_rva as *const usize), name_size);
            }
        });
    }

    if let Some(reloc_symbols) = RelocDirectory::get_reloc_symbols(&pe) {
        // for relocation symbols, merge symbols that are <= 0x10 bytes apart into one symbol so vtables don't get split up

        if !reloc_symbols.is_empty() {
            let mut reloc_symbols = reloc_symbols.into_iter().collect::<Vec<_>>();
            reloc_symbols.sort_by_key(|s| s.rva);

            let mut merged_reloc_symbols = Vec::new();

            merged_reloc_symbols.push(reloc_symbols[0].clone());

            for i in 1..reloc_symbols.len() {
                let last_symbol = merged_reloc_symbols.last_mut().unwrap();
                let current_symbol = &reloc_symbols[i];

                if current_symbol.size.is_none() || last_symbol.size.is_none() {
                    merged_reloc_symbols.push(current_symbol.clone());
                    continue;
                }

                if current_symbol.rva <= last_symbol.rva + last_symbol.size.unwrap_or(0) + 0x10 {
                    // merge symbols by updating size
                    let new_size = (current_symbol.rva + current_symbol.size.unwrap_or(0)) - last_symbol.rva;
                    last_symbol.size = Some(new_size);
                } else {
                    merged_reloc_symbols.push(current_symbol.clone());
                }
            }

            for reloc_symbol in merged_reloc_symbols {
                let symbol_section = pe.iter_find_section(|s| s.contains_rva(reloc_symbol.rva)).unwrap();

                if symbol_section.is_executable() {
                    // if relocation is in an executable section, skip symbol storage
                    continue;
                }

                Symbol::update_or_insert(
                    &mut symbols,
                    reloc_symbol.rva,
                    reloc_symbol.size.unwrap_or(0) as u32,
                    reloc_symbol.size.is_none(),
            true,
                );

                println!("reloc symbol rva: {:p} | size: {:?}", (reloc_symbol.rva as *const usize), reloc_symbol.size);
            }
        }
    }

    let mut sorted_symbols = symbols.iter().map(|(key, value)| (*key, *value)).collect::<Vec<_>>();
    sorted_symbols.sort_by_key(| (k, _) | *k);

    // update ptr reference symbols to have size = next_symbol_rva - current_symbol_rva if larger than current size, but clamp to section size
    for i in 0..sorted_symbols.len() - 1 {
        let next_rva = sorted_symbols[i + 1].0;
        let (current_rva, current_symbol) = &mut sorted_symbols[i];

        if current_symbol.is_ptr_reference {
            let symbol_section = pe.iter_find_section(|s| s.contains_rva(*current_rva)).unwrap();
            let section_end_rva = symbol_section.virtual_address + symbol_section.virtual_size;

            let calculated_size = next_rva.saturating_sub(*current_rva);
            let new_size = calculated_size.min(section_end_rva.saturating_sub(*current_rva));

            if new_size as u32 > current_symbol.max_operation_size {
                sorted_symbols[i].1.max_operation_size = new_size as u32;
            }
        }
    }

    // update last if is ptr reference to section end
    if let Some((last_rva, last_symbol)) = sorted_symbols.last_mut() {
        if last_symbol.is_ptr_reference {
            let symbol_section = pe.iter_find_section(|s| s.contains_rva(*last_rva)).unwrap();
            let section_end_rva = symbol_section.virtual_address + symbol_section.virtual_size;

            let calculated_size = section_end_rva.saturating_sub(*last_rva);

            last_symbol.max_operation_size = calculated_size as u32;
        }
    }

    // merge overlapping symbols
    // if cur rva is between last rva and last rva + size, update last size to max(last size, cur rva + cur size - last rva), else add new symbol to merged list
    let mut merged_symbols: Vec<(usize, Symbol)> = Vec::new();

    for (rva, symbol) in sorted_symbols {
        if let Some((last_rva, last_symbol)) = merged_symbols.last_mut() {
            if rva >= *last_rva && rva < (*last_rva + last_symbol.max_operation_size as usize) {
                // overlapping, update size
                let new_size = (rva + symbol.max_operation_size as usize).saturating_sub(*last_rva);
                if new_size as u32 > last_symbol.max_operation_size {
                    last_symbol.max_operation_size = new_size as u32;
                }

                last_symbol.is_ptr_reference |= symbol.is_ptr_reference;
            } else {
                // non-overlapping, add new symbol
                merged_symbols.push((rva, symbol));
            }
        } else {
            // first symbol, add directly
            merged_symbols.push((rva, symbol));
        }
    }

    // for all contiguous symbols after a ptr ref symbol, merge the ptr ref symbol to cover all contiguous symbols that are not ptr ref symbols
    let mut final_symbols: Vec<(usize, Symbol)> = Vec::new();
    let mut i = 0;
    while i < merged_symbols.len() {
        let (rva, symbol) = merged_symbols[i];

        if symbol.is_ptr_reference {
            let mut combined_size = symbol.max_operation_size as usize;
            let mut j = i + 1;

            while j < merged_symbols.len() {
                let (next_rva, next_symbol) = merged_symbols[j];

                if !next_symbol.is_ptr_reference && !next_symbol.is_directory_symbol/* && next_rva == rva + combined_size*/ {
                    //combined_size = next_symbol.max_operation_size as usize;
                    j += 1;
                }
                /*else if next_symbol.is_ptr_reference {
                    combined_size += next_rva - (rva + combined_size);
                    break;
                }*/
                else {
                    combined_size = next_rva - rva;
                    break;
                }
            }

            if j == merged_symbols.len() {
                // reached end, extend to last symbol
                let (last_rva, last_symbol) = merged_symbols[j - 1];
                combined_size = (last_rva + last_symbol.max_operation_size as usize) - rva;
            }

            final_symbols.push((rva, Symbol {
                max_operation_size: combined_size as u32,
                is_ptr_reference: true,
                is_directory_symbol: symbol.is_directory_symbol,
            }));

            i = j;
        } else {
            final_symbols.push((rva, symbol));
            i += 1;
        }
    }

    for (rva, symbol) in final_symbols {
        //println!("symbol rva: {:p} | end rva: {:p}", (rva as *const usize), (rva + symbol.max_operation_size as usize) as *const usize);
    }

    pe.get_translations();
}
