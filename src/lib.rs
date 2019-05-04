pub use object::{Binding, Format, Machine, RelocationKind, SectionKind, SymbolKind};

mod coff;
mod elf;
mod util;

#[derive(Debug)]
pub struct Object {
    // endian/word size/..?
    //encoding: Encoding,
    // e_ident
    // EI_MAG*: constant
    // EI_CLASS
    // EI_DATA
    // EI_VERSION: constant
    // EI_OSABI
    // EI_ABIVERSION
    // TODO: e_type
    //type_: u16,
    // e_machine
    pub machine: Machine,
    // e_version: constant
    // e_entry
    pub entry: u64,
    // e_flags
    //flags: u32,
    // e_ehsize: constant
    // e_phentsize: constant
    // e_phnum: calculated
    //segments: Vec<Segment>,
    // e_shentsize: constant
    // e_shnum
    pub sections: Vec<Section>,
    // e_shstrndx: calculated (or maybe preserve?)

    // derived:
    // SHT_SYMTAB
    pub symbols: Vec<Symbol>,
    // TODO: more special segments/sections
    // TODO: PT_DYNAMIC
    // TODO: PT_INTERP
    // TODO: PT_NOTE
    // TODO: .note.GNU-stack
}

impl Object {
    pub fn new(machine: Machine) -> Object {
        Object {
            machine,
            entry: 0,
            sections: Vec::new(),
            symbols: Vec::new(),
        }
    }

    pub fn add_section(&mut self, section: Section) -> SectionId {
        let id = self.sections.len();
        self.sections.push(section);
        SectionId(id)
    }

    pub fn add_symbol(&mut self, symbol: Symbol) -> SymbolId {
        let id = self.symbols.len();
        self.symbols.push(symbol);
        SymbolId(id)
    }

    pub fn write(&mut self, format: Format) -> Vec<u8> {
        match format {
            Format::Elf64 => self.write_elf(),
            Format::Coff => self.write_coff(),
            _ => unimplemented!(),
        }
    }
}

/*
// Probably not needed
#[derive(Debug)]
pub struct SegmentId(usize);

#[derive(Debug)]
pub struct Segment {
    // p_type
    // TODO: only PT_LOAD, rest handled elsewhere?
    // type_: u32,
    // p_offset: calculated
    // p_vaddr
    address: u64
    // p_paddr: not needed?
    // p_filesz: calculated
    // p_memsz: calculated
    // TODO: p_flags: R/W/X
    // p_align

    // Mach-O
    name: Vec<u8>,
}
*/

#[derive(Debug, Clone, Copy)]
pub struct SectionId(pub usize);

#[derive(Debug)]
pub struct Section {
    // sh_name
    pub name: Vec<u8>,
    // Mach-O
    pub segment_name: Vec<u8>,
    // sh_type: constant
    // sh_flags
    pub kind: SectionKind,
    // sh_addr
    pub address: u64,
    // sh_offset: calculated
    // sh_size
    pub size: u64,
    // TODO: sh_link
    // TODO: sh_info
    // sh_addralign
    pub align: u64,
    // sh_entsize: constant

    // derived:
    // TODO: Cow
    pub data: Vec<u8>,
    // SHT_RELA, SHT_REL
    pub relocations: Vec<Relocation>,
}

#[derive(Debug, Clone, Copy)]
pub struct SymbolId(pub usize);

#[derive(Debug)]
pub struct Symbol {
    // st_name
    pub name: Vec<u8>,
    // st_value
    pub value: u64,
    // st_size
    pub size: u64,
    // st_info/ST_BIND: local/global/weak
    pub binding: Binding,
    // st_info/ST_TYPE: notype/object/func/section/file/common/tls
    pub kind: SymbolKind,
    // st_other/ST_VISIBILITY: default/internal/hidden/protected
    //pub vis: u8,
    // st_shndx
    pub section: Option<SectionId>,
}

#[derive(Debug)]
pub struct Relocation {
    // r_offset
    pub offset: u64,
    // r_info/R_SYM
    pub symbol: SymbolId,
    // r_info/R_TYPE
    pub kind: RelocationKind,
    // r_info/R_TYPE
    pub size: u8,
    // r_addend
    pub addend: i64,
}
