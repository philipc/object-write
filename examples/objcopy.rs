use std::collections::HashMap;
use std::{env, fs, process};

use object::{Object, ObjectSection, SectionKind, SymbolKind};
use object_write as write;

fn main() {
    let mut args = env::args();
    if args.len() != 3 {
        eprintln!("Usage: {} <infile> <outfile>", args.next().unwrap());
        process::exit(1);
    }

    args.next();
    let in_file_path = args.next().unwrap();
    let out_file_path = args.next().unwrap();

    let in_file = match fs::File::open(&in_file_path) {
        Ok(file) => file,
        Err(err) => {
            eprintln!("Failed to open file '{}': {}", in_file_path, err,);
            process::exit(1);
        }
    };
    let in_file = match unsafe { memmap::Mmap::map(&in_file) } {
        Ok(mmap) => mmap,
        Err(err) => {
            eprintln!("Failed to map file '{}': {}", in_file_path, err,);
            process::exit(1);
        }
    };
    let in_object = match object::File::parse(&*in_file) {
        Ok(object) => object,
        Err(err) => {
            eprintln!("Failed to parse file '{}': {}", in_file_path, err);
            process::exit(1);
        }
    };

    let mut out_object = write::Object::new(
        in_object.format(),
        in_object.endianness(),
        in_object.pointer_width(),
        in_object.architecture(),
    );
    out_object.entry = in_object.entry();

    let mut out_sections = HashMap::new();
    for in_section in in_object.sections() {
        if in_section.kind() == SectionKind::Metadata {
            continue;
        }
        let data = in_section.uncompressed_data();
        let mut size = in_section.size();
        if size < data.len() as u64 {
            size = data.len() as u64;
        }
        let out_section = write::Section {
            name: in_section.name().unwrap_or("").as_bytes().to_vec(),
            segment_name: in_section.segment_name().unwrap_or("").as_bytes().to_vec(),
            kind: in_section.kind(),
            address: in_section.address(),
            size: size,
            align: in_section.align(),
            data: data.into(),
            relocations: Vec::new(),
            symbol: None,
        };
        let section_id = out_object.add_section(out_section);
        out_sections.insert(in_section.index(), section_id);
    }

    let mut out_symbols = HashMap::new();
    for (symbol_index, in_symbol) in in_object.symbols() {
        if in_symbol.kind() == SymbolKind::Null {
            continue;
        }
        let out_symbol = write::Symbol {
            name: in_symbol.name().unwrap_or("").as_bytes().to_vec(),
            value: in_symbol.address(),
            size: in_symbol.size(),
            kind: in_symbol.kind(),
            binding: in_symbol.binding(),
            visibility: in_symbol.visibility(),
            section: in_symbol
                .section_index()
                .map(|s| *out_sections.get(&s).unwrap()),
        };
        let symbol_id = out_object.add_symbol(out_symbol);
        out_symbols.insert(symbol_index.0, symbol_id);
    }

    for in_section in in_object.sections() {
        if in_section.kind() == SectionKind::Metadata {
            continue;
        }
        let out_section =
            &mut out_object.sections[out_sections.get(&in_section.index()).unwrap().0];
        for (offset, in_relocation) in in_section.relocations() {
            let out_relocation = write::Relocation {
                offset,
                symbol: *out_symbols.get(&in_relocation.symbol().0).unwrap(),
                kind: in_relocation.kind(),
                size: in_relocation.size(),
                addend: in_relocation.addend(),
            };
            out_section.relocations.push(out_relocation);
        }
    }

    out_object.finalize();
    let out_data = out_object.write();
    if let Err(err) = fs::write(&out_file_path, out_data) {
        eprintln!("Failed to write file '{}': {}", out_file_path, err);
        process::exit(1);
    }
}
