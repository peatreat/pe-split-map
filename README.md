# PE Split Map

A Rust library for manual mapping 64-bit PE (Portable Executable) files with advanced code obfuscation through instruction and symbol splitting across randomized memory locations.

## Overview

PE Split Map takes a standard 64-bit PE executable and manually maps it into memory by:
- **Splitting instructions** across multiple memory regions
- **Randomizing symbol locations** to prevent pattern recognition
- **Maintaining execution integrity** through custom relocation and translation logic

This approach provides enhanced security through memory layout randomization and makes reverse engineering significantly more difficult.

## Features

- ✅ 256-bit AVX symbol support
- ✅ Randomizes instruction and symbol memory locations
- ✅ Performs precise symbol boundary analysis to safely split symbols
- ✅ Control-flow obfuscation with optimization support
- ✅ Relocation and import table processing
- ✅ Removes unnecessary data directories and headers
- ✅ Bypasses memory signature checks via modified memory ordering
- ✅ Fixes up all references and branch targets after address relocation

## Project Structure

```
src/
├── heap.rs              # Memory heap management
├── lib.rs               # Library entry point
├── psm_error.rs         # Error handling
└── pe64/                # 64-bit PE processing
    ├── headers.rs       # PE header parsing
    ├── section.rs       # Section handling
    ├── symbols.rs       # Symbol processing
    ├── data_directory/  # Data directory handlers
    │   ├── debug.rs
    │   ├── exception.rs
    │   ├── export.rs
    │   ├── import.rs
    │   └── reloc.rs
    └── translation/     # Instruction translation
        ├── block.rs
        ├── control.rs
        ├── jcc.rs
        ├── near.rs
        └── relative.rs
```

## Usage

```rust
use pe_split_map::PE64;

use pe_split_map::Heap;
use pe_split_map::HeapPage;

use pe_split_map::symbols;

use pe_split_map::mapper::Mapper;
use pe_split_map::mapper::TranslationBlockSize;

use pe_split_map::data_directory::DllImport;

fn main() {
    const MAX_CODE_BLOCK_BYTE_SIZE: u64 = 0x20; // Set this to however many bytes you want to use per reserved block of instructions
    const ASSUME_NEAR: bool = true; // True if code and symbol pages are guaranteed to all be near each other for near branches or relative references

    let dll = std::fs::read("PATH_TO_DLL").unwrap();

    let pe = PE64::new_from_bytes(dll).unwrap();
    let symbols = symbols::split_symbols(&pe).unwrap();

    let mut code_pages = Vec::new(); // Add HeapPage objects that specify the available memory regions you can map executable memory to
    let mut symbol_pages = Vec::new(); // Add HeapPage objects that specify the available memory regions you can map read/write memory to

    // Initialize heap objects
    let mut code_heap = Heap::new(code_pages);
    let mut symbol_heap = Heap::new(symbol_pages);

    // Create translations
    let mut translations = pe.get_translations(ASSUME_NEAR);

    let mut dll_imports = Vec::new(); // Add DllImport objects that specify the disk path and memory base address of each imported library

    // Map the DLL
    let mapped = Mapper::map(&pe, &dll_imports, &mut code_heap, &mut symbol_heap, &mut translations, &symbols, TranslationBlockSize::MaxByteSize(MAX_CODE_BLOCK_BYTE_SIZE), ASSUME_NEAR).unwrap();
    ...
}
```

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
pe-split-map = { path = "./pe-split-map" }
```

## Building

```bash
cargo build --release
```

## Inspiration

Inspired by [smap](https://github.com/btbd/smap).
