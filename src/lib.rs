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
    format: BinaryFormat,
    architecture: Architecture,
    sections: Vec<Section>,
    standard_sections: HashMap<StandardSection, SectionId>,
    symbols: Vec<Symbol>,
    stub_symbols: HashMap<SymbolId, SymbolId>,
    subsection_via_symbols: bool,
}

impl Object {
    pub fn new(format: BinaryFormat, architecture: Architecture) -> Object {
        Object {
            format,
            architecture,
            sections: Vec::new(),
            standard_sections: HashMap::new(),
            symbols: Vec::new(),
            stub_symbols: HashMap::new(),
            subsection_via_symbols: false,
        }
    }

    #[inline]
    pub fn format(&self) -> BinaryFormat {
        self.format
    }

    #[inline]
    pub fn architecture(&self) -> Architecture {
        self.architecture
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
                let new_section = Section::new(segment.to_vec(), name.to_vec(), kind);
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

    #[inline]
    pub fn section(&self, section: SectionId) -> &Section {
        &self.sections[section.0]
    }

    #[inline]
    pub fn section_mut(&mut self, section: SectionId) -> &mut Section {
        &mut self.sections[section.0]
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
        self.sections[section.0].append_data(data, align)
    }

    /// Append zero-initialized data to an existing section. Returns of the section offset of the data.
    pub fn append_section_bss(&mut self, section: SectionId, size: u64, align: u64) -> u64 {
        self.sections[section.0].append_bss(size, align)
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
            let mut section = Section::new(segment.to_vec(), name, kind);
            section.append_data(data, align);
            let section_id = self.add_section(section);
            (section_id, 0)
        }
    }

    #[inline]
    pub fn symbol(&self, symbol: SymbolId) -> &Symbol {
        &self.symbols[symbol.0]
    }

    #[inline]
    pub fn symbol_mut(&mut self, symbol: SymbolId) -> &mut Symbol {
        &mut self.symbols[symbol.0]
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
    ///
    /// Relocations must only be added after all symbols have been added and defined.
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

    pub fn write(&self) -> Vec<u8> {
        match self.format {
            BinaryFormat::Elf => self.elf_write(),
            BinaryFormat::Coff => self.coff_write(),
            BinaryFormat::Macho => self.macho_write(),
            _ => unimplemented!(),
        }
    }
}

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
pub struct SectionId(usize);

#[derive(Debug)]
pub struct Section {
    segment: Vec<u8>,
    name: Vec<u8>,
    kind: SectionKind,
    size: u64,
    align: u64,
    data: Vec<u8>,
    relocations: Vec<Relocation>,
    // For convenience, not emitted.
    symbol: Option<SymbolId>,
}

impl Section {
    pub fn new(segment: Vec<u8>, name: Vec<u8>, kind: SectionKind) -> Self {
        Section {
            segment,
            name,
            kind,
            size: 0,
            align: 1,
            data: Vec::new(),
            relocations: Vec::new(),
            symbol: None,
        }
    }

    #[inline]
    pub fn is_bss(&self) -> bool {
        self.kind == SectionKind::UninitializedData || self.kind == SectionKind::UninitializedTls
    }

    pub fn set_data(&mut self, data: Vec<u8>, align: u64) {
        debug_assert!(!self.is_bss());
        debug_assert_eq!(align & (align - 1), 0);
        debug_assert!(self.data.is_empty());
        self.size = data.len() as u64;
        self.data = data;
        self.align = align;
    }

    pub fn append_data(&mut self, data: &[u8], align: u64) -> u64 {
        debug_assert!(!self.is_bss());
        debug_assert_eq!(align & (align - 1), 0);
        if self.align < align {
            self.align = align;
        }
        let align = align as usize;
        let mut offset = self.data.len();
        if offset & (align - 1) != 0 {
            offset += align - (offset & (align - 1));
            self.data.resize(offset, 0);
        }
        self.data.extend(data);
        self.size = self.data.len() as u64;
        offset as u64
    }

    pub fn append_bss(&mut self, size: u64, align: u64) -> u64 {
        debug_assert!(self.is_bss());
        debug_assert_eq!(align & (align - 1), 0);
        if self.align < align {
            self.align = align;
        }
        let mut offset = self.size;
        if offset & (align - 1) != 0 {
            offset += align - (offset & (align - 1));
            self.size = offset;
        }
        self.size += size;
        offset as u64
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SymbolId(usize);

#[derive(Debug)]
pub struct Symbol {
    pub name: Vec<u8>,
    pub value: u64,
    pub size: u64,
    pub kind: SymbolKind,
    pub binding: Binding,
    pub visibility: Visibility,
    pub section: Option<SectionId>,
}

#[derive(Debug)]
pub struct Relocation {
    pub offset: u64,
    pub size: u8,
    pub kind: RelocationKind,
    pub subkind: RelocationSubkind,
    pub symbol: SymbolId,
    pub addend: i64,
}
