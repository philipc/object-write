use scroll::IOwrite;

use crate::util::*;
use crate::*;

mod elf {
    pub use goblin::elf::header::header64::Header as Header64;
    pub use goblin::elf::header::Header;
    pub use goblin::elf::header::ELFMAG;
    pub use goblin::elf::header::{EI_CLASS, ELFCLASS64};
    pub use goblin::elf::header::{EI_DATA, ELFDATA2LSB};

    pub const EI_VERSION: usize = 6;
    pub const EV_CURRENT: u8 = 1;

    pub const EI_OSABI: usize = 7;
    pub const ELFOSABI_NONE: u8 = 0;

    pub const EI_ABIVERSION: usize = 8;

    pub use goblin::elf::header::ET_REL;
    pub use goblin::elf::header::{EM_386, EM_X86_64};

    pub use goblin::elf::header::header64::SIZEOF_EHDR as SIZEOF_EHDR64;
    pub use goblin::elf::program_header::program_header64::ProgramHeader as ProgramHeader64;
    pub use goblin::elf::program_header::program_header64::SIZEOF_PHDR as SIZEOF_PHDR64;
    pub use goblin::elf::program_header::ProgramHeader;
    pub use goblin::elf::section_header::section_header64::SectionHeader as SectionHeader64;
    pub use goblin::elf::section_header::section_header64::SIZEOF_SHDR as SIZEOF_SHDR64;
    pub use goblin::elf::section_header::SectionHeader;
    pub use goblin::elf::section_header::SHN_ABS;
    pub use goblin::elf::section_header::{
        SHF_ALLOC, SHF_EXECINSTR, SHF_INFO_LINK, SHF_MERGE, SHF_STRINGS, SHF_TLS, SHF_WRITE,
    };
    pub use goblin::elf::section_header::{
        SHT_NOBITS, SHT_PROGBITS, SHT_RELA, SHT_STRTAB, SHT_SYMTAB,
    };

    pub use goblin::elf::sym::sym64::SIZEOF_SYM as SIZEOF_SYM64;
    pub use goblin::elf::sym::Sym;
    pub use goblin::elf::sym::{STB_GLOBAL, STB_LOCAL, STB_WEAK};
    pub use goblin::elf::sym::{
        STT_COMMON, STT_FILE, STT_FUNC, STT_NOTYPE, STT_OBJECT, STT_SECTION, STT_TLS,
    };

    pub use goblin::elf::reloc;
    pub use goblin::elf::reloc::reloc64::SIZEOF_RELA as SIZEOF_RELA64;
    pub use goblin::elf::reloc::Reloc;
}

impl Object {
    pub(crate) fn write_elf(&self) -> Vec<u8> {
        // Calculate offsets of everything, and build strtab/shstrtab.
        let mut offset = 0;
        // TODO: avoid duplicate strings in strtab/shstrtab
        let mut strtab = Vec::new();
        let mut shstrtab = Vec::new();

        // ELF header.
        // TODO: other formats
        let e_ehsize = elf::SIZEOF_EHDR64;
        offset += e_ehsize;

        // Calculate size of section data.
        let mut section_offsets = vec![SectionOffsets::default(); self.sections.len()];
        // Null section.
        let mut e_shnum = 1;
        shstrtab.push(0);
        for (index, section) in self.sections.iter().enumerate() {
            section_offsets[index].str_offset = shstrtab.len();
            shstrtab.extend_from_slice(&section.name);
            shstrtab.push(0);

            section_offsets[index].index = e_shnum;
            e_shnum += 1;

            let len = section.data.len();
            if len != 0 {
                offset = align(offset, section.align as usize);
                section_offsets[index].offset = offset;
                offset += len;
            } else {
                section_offsets[index].offset = offset;
            }

            let count = section.relocations.len();
            if count != 0 {
                section_offsets[index].reloc_str_offset = shstrtab.len();
                shstrtab.extend_from_slice(&b".rela"[..]);
                shstrtab.extend_from_slice(&section.name);
                shstrtab.push(0);

                section_offsets[index].reloc_index = e_shnum;
                e_shnum += 1;
            }
        }

        // Calculate size of symbols and add symbol strings to strtab.
        let mut symbol_offsets = vec![SymbolOffsets::default(); self.symbols.len()];
        // Null symbol.
        let mut symtab_count = 1;
        // Name for null symbol and section symbols, must come first in strtab.
        strtab.push(0);
        let mut calc_symbol = |index: usize, symbol: &Symbol, symtab_count: &mut usize| {
            symbol_offsets[index].index = *symtab_count;
            if !symbol.name.is_empty() {
                symbol_offsets[index].str_offset = strtab.len();
                strtab.extend_from_slice(&symbol.name);
                strtab.push(0);
            }
            *symtab_count += 1;
        };
        for (index, symbol) in self.symbols.iter().enumerate() {
            if symbol.binding == Binding::Unknown || symbol.binding == Binding::Local {
                calc_symbol(index, symbol, &mut symtab_count);
            }
        }
        let symtab_count_local = symtab_count;
        for (index, symbol) in self.symbols.iter().enumerate() {
            if symbol.binding != Binding::Unknown && symbol.binding != Binding::Local {
                calc_symbol(index, symbol, &mut symtab_count);
            }
        }

        // Calculate size of symtab.
        let symtab_str_offset = shstrtab.len();
        shstrtab.extend_from_slice(&b".symtab\0"[..]);
        offset = align(offset, 8);
        let symtab_offset = offset;
        // TODO: other formats
        let symtab_len = symtab_count * elf::SIZEOF_SYM64;
        offset += symtab_len;
        let symtab_index = e_shnum;
        e_shnum += 1;

        // Calculate size of strtab.
        let strtab_str_offset = shstrtab.len();
        shstrtab.extend_from_slice(&b".strtab\0"[..]);
        let strtab_offset = offset;
        offset += strtab.len();
        let strtab_index = e_shnum;
        e_shnum += 1;

        // Calculate size of relocations.
        for (index, section) in self.sections.iter().enumerate() {
            let count = section.relocations.len();
            if count != 0 {
                offset = align(offset, 8);
                section_offsets[index].reloc_offset = offset;
                // TODO: other formats
                let len = count * elf::SIZEOF_RELA64;
                section_offsets[index].reloc_len = len;
                offset += len;
            }
        }

        // Calculate size of shstrtab.
        let shstrtab_str_offset = shstrtab.len();
        shstrtab.extend_from_slice(&b".shstrtab\0"[..]);
        let shstrtab_offset = offset;
        offset += shstrtab.len();
        let shstrtab_index = e_shnum;
        e_shnum += 1;

        // Calculate size of section headers.
        offset = align(offset, 8);
        let e_shoff = offset;
        // TODO: other formats
        let e_shentsize = elf::SIZEOF_SHDR64;
        offset += e_shnum * e_shentsize;

        // Start writing.
        let mut buffer = Vec::with_capacity(offset);

        // TODO: other formats
        let ctx = goblin::container::Ctx::new(
            goblin::container::Container::Big,
            goblin::container::Endian::Little,
        );

        // Write file header.
        let mut header = elf::Header {
            e_ident: [0; 16],
            // TODO: other formats
            e_type: elf::ET_REL,
            // TODO: other formats
            e_machine: match self.machine {
                Machine::X86 => elf::EM_386,
                Machine::X86_64 => elf::EM_X86_64,
                _ => unimplemented!(),
            },
            // FIXME: validate input
            e_version: elf::EV_CURRENT.into(),
            e_entry: self.entry,
            // TODO: other formats
            e_phoff: 0,
            e_shoff: e_shoff as u64,
            // FIXME: validate input
            e_flags: 0,
            e_ehsize: e_ehsize as u16,
            // TODO: other formats
            e_phentsize: 0,
            // TODO: other formats
            e_phnum: 0,
            e_shentsize: e_shentsize as u16,
            e_shnum: e_shnum as u16,
            e_shstrndx: shstrtab_index as u16,
        };
        header.e_ident[0..4].copy_from_slice(elf::ELFMAG);
        // TODO: other formats
        header.e_ident[elf::EI_CLASS] = elf::ELFCLASS64;
        // FIXME: validate input
        header.e_ident[elf::EI_DATA] = elf::ELFDATA2LSB;
        // FIXME: validate input
        header.e_ident[elf::EI_VERSION] = elf::EV_CURRENT;
        // FIXME: validate input
        header.e_ident[elf::EI_OSABI] = elf::ELFOSABI_NONE;
        // FIXME: validate input
        header.e_ident[elf::EI_ABIVERSION] = 0;
        buffer.iowrite_with(header, ctx).unwrap();

        // TODO: group sections into segments
        // TODO: write program headers

        // Write section data.
        for (index, section) in self.sections.iter().enumerate() {
            let len = section.data.len();
            if len != 0 {
                write_align(&mut buffer, section.align as usize);
                debug_assert_eq!(section_offsets[index].offset, buffer.len());
                buffer.extend(&section.data);
            }
        }

        // Write symbols.
        write_align(&mut buffer, 8);
        debug_assert_eq!(symtab_offset, buffer.len());
        buffer
            .iowrite_with(
                elf::Sym {
                    st_name: 0,
                    st_info: 0,
                    st_other: 0,
                    st_shndx: 0,
                    st_value: 0,
                    st_size: 0,
                },
                ctx,
            )
            .unwrap();
        let mut write_symbol = |index: usize, symbol: &Symbol| {
            let st_bind = match symbol.binding {
                Binding::Unknown | Binding::Local => elf::STB_LOCAL,
                Binding::Global => elf::STB_GLOBAL,
                Binding::Weak => elf::STB_WEAK,
            };
            let st_type = match symbol.kind {
                SymbolKind::Unknown | SymbolKind::Null => elf::STT_NOTYPE,
                SymbolKind::Text => elf::STT_FUNC,
                SymbolKind::Data => elf::STT_OBJECT,
                SymbolKind::Section => elf::STT_SECTION,
                SymbolKind::File => elf::STT_FILE,
                SymbolKind::Common => elf::STT_COMMON,
                SymbolKind::Tls => elf::STT_TLS,
            };
            // TODO: vis
            let st_other = 0;
            let st_shndx = if symbol.kind == SymbolKind::File {
                elf::SHN_ABS as usize
            } else {
                symbol
                    .section
                    .map(|s| section_offsets[s.0].index)
                    .unwrap_or(0)
            };
            buffer
                .iowrite_with(
                    elf::Sym {
                        st_name: symbol_offsets[index].str_offset,
                        st_info: (st_bind << 4) + st_type,
                        st_other,
                        st_shndx,
                        st_value: symbol.value,
                        st_size: symbol.size,
                    },
                    ctx,
                )
                .unwrap();
        };
        for (index, symbol) in self.symbols.iter().enumerate() {
            if symbol.binding == Binding::Unknown || symbol.binding == Binding::Local {
                write_symbol(index, symbol);
            }
        }
        for (index, symbol) in self.symbols.iter().enumerate() {
            if symbol.binding != Binding::Unknown && symbol.binding != Binding::Local {
                write_symbol(index, symbol);
            }
        }

        // Write strtab section.
        debug_assert_eq!(strtab_offset, buffer.len());
        buffer.extend(&strtab);

        // Write relocations.
        for (index, section) in self.sections.iter().enumerate() {
            if !section.relocations.is_empty() {
                write_align(&mut buffer, 8);
                debug_assert_eq!(section_offsets[index].reloc_offset, buffer.len());
                for reloc in &section.relocations {
                    // TODO: other formats
                    let r_type = match (reloc.kind, reloc.size) {
                        (RelocationKind::Absolute, 64) => elf::reloc::R_X86_64_64,
                        (RelocationKind::Relative, 32) => elf::reloc::R_X86_64_PC32,
                        (RelocationKind::GotOffset, 32) => elf::reloc::R_X86_64_GOT32,
                        (RelocationKind::PltRelative, 32) => elf::reloc::R_X86_64_PLT32,
                        (RelocationKind::GotRelative, 32) => elf::reloc::R_X86_64_GOTPCREL,
                        (RelocationKind::Absolute, 32) => elf::reloc::R_X86_64_32,
                        (RelocationKind::AbsoluteSigned, 32) => elf::reloc::R_X86_64_32S,
                        (RelocationKind::Absolute, 16) => elf::reloc::R_X86_64_16,
                        (RelocationKind::Relative, 16) => elf::reloc::R_X86_64_PC16,
                        (RelocationKind::Absolute, 8) => elf::reloc::R_X86_64_8,
                        (RelocationKind::Relative, 8) => elf::reloc::R_X86_64_PC8,
                        (RelocationKind::Other(x), _) => x,
                        _ => unimplemented!(),
                    };
                    let r_sym = symbol_offsets[reloc.symbol.0].index;
                    buffer
                        .iowrite_with(
                            elf::Reloc {
                                r_offset: reloc.offset,
                                r_addend: Some(reloc.addend),
                                r_sym,
                                r_type,
                            },
                            (true, ctx),
                        )
                        .unwrap();
                }
            }
        }

        // Write shstrtab section.
        debug_assert_eq!(shstrtab_offset, buffer.len());
        buffer.extend(&shstrtab);

        // Write section headers.
        write_align(&mut buffer, 8);
        debug_assert_eq!(e_shoff, buffer.len());
        buffer
            .iowrite_with(
                elf::SectionHeader {
                    sh_name: 0,
                    sh_type: 0,
                    sh_flags: 0,
                    sh_addr: 0,
                    sh_offset: 0,
                    sh_size: 0,
                    sh_link: 0,
                    sh_info: 0,
                    sh_addralign: 0,
                    sh_entsize: 0,
                },
                ctx,
            )
            .unwrap();
        for (index, section) in self.sections.iter().enumerate() {
            let sh_type = match section.kind {
                SectionKind::UninitializedData | SectionKind::UninitializedTls => elf::SHT_NOBITS,
                _ => elf::SHT_PROGBITS,
            };
            let sh_flags = match section.kind {
                SectionKind::Text => elf::SHF_ALLOC | elf::SHF_EXECINSTR,
                SectionKind::Data => elf::SHF_ALLOC | elf::SHF_WRITE,
                SectionKind::Tls => elf::SHF_ALLOC | elf::SHF_WRITE | elf::SHF_TLS,
                SectionKind::UninitializedData => elf::SHF_ALLOC | elf::SHF_WRITE,
                SectionKind::UninitializedTls => elf::SHF_ALLOC | elf::SHF_WRITE | elf::SHF_TLS,
                SectionKind::ReadOnlyData => elf::SHF_ALLOC,
                SectionKind::ReadOnlyString => elf::SHF_ALLOC | elf::SHF_STRINGS | elf::SHF_MERGE,
                SectionKind::OtherString => elf::SHF_STRINGS | elf::SHF_MERGE,
                SectionKind::Other | SectionKind::Unknown | SectionKind::Metadata => 0,
            };
            let sh_entsize = match section.kind {
                SectionKind::ReadOnlyString | SectionKind::OtherString => 1,
                _ => 0,
            };
            buffer
                .iowrite_with(
                    elf::SectionHeader {
                        sh_name: section_offsets[index].str_offset,
                        sh_type,
                        sh_flags: sh_flags.into(),
                        sh_addr: section.address,
                        sh_offset: section_offsets[index].offset as u64,
                        sh_size: section.size,
                        sh_link: 0,
                        sh_info: 0,
                        sh_addralign: section.align,
                        sh_entsize,
                    },
                    ctx,
                )
                .unwrap();

            if !section.relocations.is_empty() {
                buffer
                    .iowrite_with(
                        elf::SectionHeader {
                            sh_name: section_offsets[index].reloc_str_offset,
                            sh_type: elf::SHT_RELA,
                            sh_flags: elf::SHF_INFO_LINK.into(),
                            sh_addr: 0,
                            sh_offset: section_offsets[index].reloc_offset as u64,
                            sh_size: section_offsets[index].reloc_len as u64,
                            sh_link: symtab_index as u32,
                            sh_info: section_offsets[index].index as u32,
                            sh_addralign: 8,
                            sh_entsize: elf::SIZEOF_RELA64 as u64,
                        },
                        ctx,
                    )
                    .unwrap();
            }
        }

        // Write symtab section header.
        buffer
            .iowrite_with(
                elf::SectionHeader {
                    sh_name: symtab_str_offset,
                    sh_type: elf::SHT_SYMTAB,
                    sh_flags: 0,
                    sh_addr: 0,
                    sh_offset: symtab_offset as u64,
                    sh_size: symtab_len as u64,
                    sh_link: strtab_index as u32,
                    sh_info: symtab_count_local as u32,
                    sh_addralign: 8,
                    sh_entsize: elf::SIZEOF_SYM64 as u64,
                },
                ctx,
            )
            .unwrap();

        // Write strtab section header.
        buffer
            .iowrite_with(
                elf::SectionHeader {
                    sh_name: strtab_str_offset,
                    sh_type: elf::SHT_STRTAB,
                    sh_flags: 0,
                    sh_addr: 0,
                    sh_offset: strtab_offset as u64,
                    sh_size: strtab.len() as u64,
                    sh_link: 0,
                    sh_info: 0,
                    sh_addralign: 1,
                    sh_entsize: 0,
                },
                ctx,
            )
            .unwrap();

        // Write shstrtab section header.
        buffer
            .iowrite_with(
                elf::SectionHeader {
                    sh_name: shstrtab_str_offset,
                    sh_type: elf::SHT_STRTAB,
                    // FIXME
                    sh_flags: 0,
                    sh_addr: 0,
                    sh_offset: shstrtab_offset as u64,
                    sh_size: shstrtab.len() as u64,
                    sh_link: 0,
                    sh_info: 0,
                    sh_addralign: 1,
                    sh_entsize: 0,
                },
                ctx,
            )
            .unwrap();

        buffer
    }
}