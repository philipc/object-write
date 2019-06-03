#![allow(clippy::collapsible_if)]
#![allow(clippy::cyclomatic_complexity)]
#![allow(clippy::module_inception)]

use std::collections::HashMap;

// Re-export for now, until we merge with the object crate.
pub use object::{Binding, RelocationKind, RelocationSubkind, SectionKind, SymbolKind, Visibility};

// target-lexicon types form part of the public API.
pub use object::target_lexicon;
use object::target_lexicon::{Architecture, BinaryFormat, Endianness, PointerWidth};

mod coff;
mod elf;
mod macho;
mod util;

#[derive(Debug)]
pub struct Object {
    pub format: BinaryFormat,
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
    pub architecture: Architecture,
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
    // FIXME
    //pub section_symbols: Vec<SymbolId>,
    // e_shstrndx: calculated (or maybe preserve?)

    // derived:
    // SHT_SYMTAB
    pub symbols: Vec<Symbol>,
    // TODO: more special segments/sections
    // TODO: PT_DYNAMIC
    // TODO: PT_INTERP
    // TODO: PT_NOTE
    // TODO: .note.GNU-stack
    pub standard_sections: HashMap<StandardSection, SectionId>,
    pub subsection_via_symbols: bool,
}

impl Object {
    pub fn new(format: BinaryFormat, architecture: Architecture) -> Object {
        Object {
            format,
            architecture,
            entry: 0,
            sections: Vec::new(),
            symbols: Vec::new(),
            standard_sections: HashMap::new(),
            subsection_via_symbols: false,
        }
    }

    pub fn segment_name(&self, segment: StandardSegment) -> &'static [u8] {
        match self.format {
            BinaryFormat::Elf | BinaryFormat::Coff => &[],
            BinaryFormat::Macho => self.macho_segment_name(segment),
            _ => unimplemented!(),
        }
    }

    pub fn section_id(&mut self, section: StandardSection) -> SectionId {
        self.standard_sections
            .get(&section)
            .cloned()
            .unwrap_or_else(|| {
                let (segment, name, kind) = self.section_info(section);
                let new_section =
                    Section::new(segment.to_vec(), name.to_vec(), kind, Vec::new(), 1);
                let section_id = self.add_section(new_section);
                self.standard_sections.insert(section, section_id);
                section_id
            })
    }

    /// Returns the standard segment and section names for the given section.
    pub fn section_info(
        &self,
        section: StandardSection,
    ) -> (&'static [u8], &'static [u8], SectionKind) {
        match self.format {
            BinaryFormat::Elf => self.elf_section_info(section),
            BinaryFormat::Coff => self.coff_section_info(section),
            BinaryFormat::Macho => self.macho_section_info(section),
            _ => unimplemented!(),
        }
    }

    pub fn subsection_info(
        &self,
        section: StandardSection,
        value: &[u8],
    ) -> (&'static [u8], Vec<u8>, SectionKind) {
        let (segment, section, kind) = self.section_info(section);
        let name = self.subsection_name(section, value);
        (segment, name, kind)
    }

    pub fn subsection_name(&self, section: &[u8], value: &[u8]) -> Vec<u8> {
        debug_assert!(!self.has_subsection_via_symbols());
        match self.format {
            BinaryFormat::Elf => self.elf_subsection_name(section, value),
            BinaryFormat::Coff => self.coff_subsection_name(section, value),
            _ => unimplemented!(),
        }
    }

    pub fn has_subsection_via_symbols(&self) -> bool {
        match self.format {
            BinaryFormat::Elf | BinaryFormat::Coff => false,
            BinaryFormat::Macho => true,
            _ => unimplemented!(),
        }
    }

    pub fn add_section(&mut self, section: Section) -> SectionId {
        let id = self.sections.len();
        self.sections.push(section);
        // TODO: do we need to add to standard_sections too?
        // TODO: always add a section symbol too?
        SectionId(id)
    }

    /// Append data to an existing section. Returns of the section offset of the data.
    pub fn append_section_data(&mut self, section: SectionId, data: &[u8], align: u64) -> u64 {
        debug_assert_eq!(align & (align - 1), 0);
        let section = &mut self.sections[section.0];
        if section.align < align {
            section.align = align;
        }
        let align = align as usize;
        let mut offset = section.data.len();
        if offset & (align - 1) != 0 {
            offset += align - (offset & (align - 1));
            section.data.resize(offset, 0);
        }
        section.data.extend(data);
        section.size = section.data.len() as u64;
        offset as u64
    }

    /// Add a subsection. Returns the section id and section offset of the data.
    pub fn add_subsection(
        &mut self,
        section: StandardSection,
        name: &[u8],
        data: &[u8],
        align: u64,
    ) -> (SectionId, u64) {
        if self.has_subsection_via_symbols() {
            self.subsection_via_symbols = true;
            let section_id = self.section_id(section);
            let offset = self.append_section_data(section_id, data, align);
            println!("name: {} offset: {}", String::from_utf8_lossy(name), offset);
            (section_id, offset)
        } else {
            let (segment, name, kind) = self.subsection_info(section, name);
            let section = Section::new(segment.to_vec(), name, kind, data.to_vec(), align);
            let section_id = self.add_section(section);
            (section_id, 0)
        }
    }

    pub fn add_symbol(&mut self, symbol: Symbol) -> SymbolId {
        if symbol.kind == SymbolKind::Section {
            return self.add_section_symbol(symbol.section.unwrap());
        }
        let symbol_id = SymbolId(self.symbols.len());
        self.symbols.push(symbol);
        symbol_id
    }

    pub fn add_section_symbol(&mut self, section: SectionId) -> SymbolId {
        match self.sections[section.0].symbol {
            Some(symbol_id) => symbol_id,
            None => {
                let symbol_id = SymbolId(self.symbols.len());
                self.symbols.push(Symbol {
                    name: Vec::new(),
                    value: 0,
                    size: 0,
                    kind: SymbolKind::Section,
                    binding: Binding::Local,
                    visibility: Visibility::Default,
                    section: Some(section),
                });
                self.sections[section.0].symbol = Some(symbol_id);
                symbol_id
            }
        }
    }

    /// Add a relocation to a section.
    pub fn add_relocation(&mut self, section: SectionId, mut relocation: Relocation) {
        let constant = match self.format {
            BinaryFormat::Elf => self.elf_fixup_relocation(&mut relocation),
            BinaryFormat::Coff => self.coff_fixup_relocation(&mut relocation),
            BinaryFormat::Macho => self.macho_fixup_relocation(&mut relocation),
            _ => unimplemented!(),
        };
        if constant != 0 {
            // TODO: write to the section data.
            unimplemented!();
        }
        self.sections[section.0].relocations.push(relocation);
    }

    pub fn finalize(&mut self) {
        match self.format {
            BinaryFormat::Elf => {}
            BinaryFormat::Coff => self.coff_finalize(),
            BinaryFormat::Macho => {}
            _ => unimplemented!(),
        }
    }

    pub fn write(&self) -> Vec<u8> {
        match self.format {
            BinaryFormat::Elf => self.elf_write(),
            BinaryFormat::Coff => self.coff_write(),
            BinaryFormat::Macho => self.macho_write(),
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StandardSegment {
    Text,
    Data,
    Debug,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StandardSection {
    Text,
    Data,
    ReadOnlyData,
    ReadOnlyString,
}

impl StandardSection {
    pub fn kind(self) -> SectionKind {
        match self {
            StandardSection::Text => SectionKind::Text,
            StandardSection::Data => SectionKind::Data,
            StandardSection::ReadOnlyData => SectionKind::ReadOnlyData,
            StandardSection::ReadOnlyString => SectionKind::ReadOnlyString,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SectionId(pub usize);

#[derive(Debug)]
pub struct Section {
    // Mach-O
    pub segment: Vec<u8>,
    // sh_name
    pub name: Vec<u8>,
    // sh_type: constant
    // sh_flags
    // TODO: probably need extra format-specific flags
    pub kind: SectionKind,
    // sh_addr
    // TODO: don't use this for object files?
    pub address: u64,
    // sh_offset: calculated
    // sh_size
    pub size: u64,
    // sh_addralign
    pub align: u64,
    // sh_entsize: constant

    // derived:
    // TODO: Cow
    pub data: Vec<u8>,
    // SHT_RELA, SHT_REL
    pub relocations: Vec<Relocation>,
    // For convenience, not emitted.
    pub symbol: Option<SymbolId>,
}

impl Section {
    pub fn new(
        segment: Vec<u8>,
        name: Vec<u8>,
        kind: SectionKind,
        data: Vec<u8>,
        align: u64,
    ) -> Self {
        Section {
            segment,
            name,
            kind,
            address: 0,
            size: data.len() as u64,
            align,
            data,
            relocations: Vec::new(),
            symbol: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SymbolId(pub usize);

#[derive(Debug)]
pub struct Symbol {
    // st_name
    pub name: Vec<u8>,
    // st_value
    pub value: u64,
    // st_size
    pub size: u64,
    // st_info/ST_TYPE: notype/object/func/section/file/common/tls
    pub kind: SymbolKind,
    // st_info/ST_BIND: local/global/weak
    pub binding: Binding,
    // st_other/ST_VISIBILITY: default/internal/hidden/protected
    pub visibility: Visibility,
    // TODO: translation/linkage/global
    // pub scope: Scope,
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
    pub subkind: RelocationSubkind,
    // r_info/R_TYPE
    pub size: u8,
    // r_addend
    pub addend: i64,
}
