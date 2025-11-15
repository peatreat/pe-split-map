mod pe64;

use std::collections::HashMap;

use pe64::PE64;
use iced_x86::{self, Decoder};

use crate::pe64::data_directory::{DebugDirectory, ExceptionDirectory, ExportDirectory, ImportDirectory};

struct Symbol {
    max_operation_size: u32,
    is_ptr_reference: bool,
}

impl Symbol {
    pub fn update_or_insert(
        symbols: &mut HashMap<usize, Symbol>,
        rva: usize,
        operation_size: u32,
        is_ptr_reference: bool,
    ) {
        symbols.entry(rva)
            .and_modify(|symbol| {
                if operation_size > symbol.max_operation_size {
                    symbol.max_operation_size = operation_size;
                }

                if is_ptr_reference {
                    symbol.is_ptr_reference = true;
                }
            })
            .or_insert_with(|| Symbol {
                max_operation_size: operation_size,
                is_ptr_reference,
            });
    }
}

fn main() {
    let pe = PE64::new("test.dll").unwrap();

    let mut symbols: HashMap<usize, Symbol> = HashMap::new();

    pe.iter_find_section(|section| {
        println!("section: {}, raw size: {:p}, virt size: {:p}", section.name, section._raw.len() as *const usize, section.virtual_size as *const usize);

        if section.is_executable() {
            let mut decoder = Decoder::new(64, section._raw, iced_x86::DecoderOptions::NONE);

            while decoder.can_decode() {
                let instruction = decoder.decode();

                if instruction.is_ip_rel_memory_operand() {
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
        );

        Symbol::update_or_insert(
            &mut symbols,
            debug_dir.data_rva,
            debug_dir.data_size as u32,
            false,
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
        );

        //println!("unwind block rva: {:p} | size: 0x{:X} ", (unwind_block.rva as *const usize), unwind_block.size);
    });

    if let Some(export_dir) = ExportDirectory::get_export_directory(&pe) {
        Symbol::update_or_insert(
            &mut symbols,
            export_dir.rva,
            export_dir.size as u32,
            false,
        );

        println!("export dir rva: {:p} | size: 0x{:X} ", (export_dir.rva as *const usize), export_dir.size);
    };

    if let Some(import_dir) = ImportDirectory::get_import_directory(&pe) {
        Symbol::update_or_insert(
            &mut symbols,
            import_dir.dir_rva,
            import_dir.dir_size as u32,
            false,
        );

        println!("import dir rva: {:p} | size: 0x{:X} ", (import_dir.dir_rva as *const usize), import_dir.dir_size);

        if let Some((dll_name_rva, dll_name_size)) = import_dir.dll_name_rva_and_size {
            Symbol::update_or_insert(
                &mut symbols,
                dll_name_rva,
                dll_name_size as u32,
                false,
            );

            println!("import dll name rva: {:p} | size: 0x{:X} ", (dll_name_rva as *const usize), dll_name_size);
        }

        import_dir.thunks.iter().for_each(|thunk| {
            Symbol::update_or_insert(
                &mut symbols,
                thunk.rva,
                thunk.size as u32,
                false,
            );
            
            println!("import thunk rva: {:p} | size: 0x{:X} ", (thunk.rva as *const usize), thunk.size);

            if let Some((name_rva, name_size)) = thunk.name_rva_and_size {
                Symbol::update_or_insert(
                    &mut symbols,
                    name_rva,
                    name_size as u32,
                    false,
                );

                println!("import thunk name rva: {:p} | size: 0x{:X} ", (name_rva as *const usize), name_size);
            }
        });
    }

    let mut sorted_symbols = symbols.iter().collect::<Vec<_>>();
    sorted_symbols.sort_by_key(| (k, _) | *k);

    for (rva, symbol) in sorted_symbols {
        //println!("symbol rva: {:p} | max size: {} | is ptr: {}", (*rva as *const usize), symbol.max_operation_size, symbol.is_ptr_reference);
    }
}
