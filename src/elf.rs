use scroll::ctx::SizeWith;
use scroll::IOwrite;

use crate::util::*;
use crate::*;

mod elf {
    pub use goblin::elf::header::*;
    pub use goblin::elf::program_header::*;
    pub use goblin::elf::reloc::*;
    pub use goblin::elf::section_header::*;
    pub use goblin::elf::sym::*;
}

#[derive(Default, Clone, Copy)]
struct SectionOffsets {
    index: usize,
    offset: usize,
    str_offset: usize,
    reloc_index: usize,
    reloc_offset: usize,
    reloc_len: usize,
    reloc_str_offset: usize,
}

#[derive(Default, Clone, Copy)]
struct SymbolOffsets {
    index: usize,
    str_offset: usize,
}

impl Object {
    pub(crate) fn elf_section_info(
        &self,
        section: StandardSection,
    ) -> (&'static [u8], &'static [u8], SectionKind) {
        match section {
            StandardSection::Text => (&[], &b".text"[..], SectionKind::Text),
            StandardSection::Data => (&[], &b".data"[..], SectionKind::Data),
            StandardSection::ReadOnlyData | StandardSection::ReadOnlyString => {
                (&[], &b".rodata"[..], SectionKind::ReadOnlyData)
            }
        }
    }

    pub(crate) fn elf_subsection_name(&self, section: &[u8], value: &[u8]) -> Vec<u8> {
        let mut name = section.to_vec();
        name.push(b'.');
        name.extend(value);
        name
    }

    fn elf_has_relocation_addend(&self) -> bool {
        match self.architecture {
            Architecture::Arm => false,
            Architecture::Aarch64 => false,
            Architecture::I386 => false,
            Architecture::X86_64 => true,
            _ => unimplemented!(),
        }
    }

    pub(crate) fn elf_fixup_relocation(&mut self, mut relocation: &mut Relocation) -> i64 {
        // Return true if we should use a section symbol to avoid preemption.
        fn want_section_symbol(relocation: &Relocation, symbol: &Symbol) -> bool {
            if symbol.scope != SymbolScope::Dynamic {
                // Only dynamic symbols can be preemptible.
                return false;
            }
            match symbol.kind {
                SymbolKind::Text | SymbolKind::Data => {}
                _ => return false,
            }
            match relocation.kind {
                // Anything using GOT or PLT is preemptible.
                // We also require that `Other` relocations must already be correct.
                RelocationKind::Got
                | RelocationKind::GotRelative
                | RelocationKind::GotBaseRelative
                | RelocationKind::PltRelative
                | RelocationKind::Other(_) => return false,
                // Absolute relocations are preemptible for non-local data.
                // TODO: not sure if this rule is exactly correct
                // This rule was added to handle global data references in debuginfo.
                // Maybe this should be a new relocation kind so that the caller can decide.
                RelocationKind::Absolute => {
                    if symbol.kind == SymbolKind::Data {
                        return false;
                    }
                }
                _ => {}
            }
            true
        }

        // Use section symbols for relocations where required to avoid preemption.
        // Otherwise, the linker will fail with:
        //     relocation R_X86_64_PC32 against symbol `SomeSymbolName' can not be used when
        //     making a shared object; recompile with -fPIC
        let symbol = &self.symbols[relocation.symbol.0];
        if want_section_symbol(relocation, symbol) {
            if let Some(section) = symbol.section {
                relocation.symbol = self.sections[section.0].symbol.unwrap();
                relocation.addend += symbol.value as i64;
            }
        }

        // Determine whether the addend is stored in the relocation or the data.
        if self.elf_has_relocation_addend() {
            0
        } else {
            let constant = relocation.addend;
            relocation.addend = 0;
            constant
        }
    }

    pub(crate) fn elf_write(&self) -> Vec<u8> {
        let (container, pointer_align) = match self.architecture.pointer_width().unwrap() {
            PointerWidth::U16 | PointerWidth::U32 => (goblin::container::Container::Little, 4),
            PointerWidth::U64 => (goblin::container::Container::Big, 8),
        };
        let endian = match self.architecture.endianness().unwrap() {
            Endianness::Little => goblin::container::Endian::Little,
            Endianness::Big => goblin::container::Endian::Big,
        };
        let ctx = goblin::container::Ctx::new(container, endian);
        let is_rela = self.elf_has_relocation_addend();
        let reloc_ctx = (is_rela, ctx);

        // Calculate offsets of everything, and build strtab/shstrtab.
        let mut offset = 0;

        // ELF header.
        let e_ehsize = elf::Header::size_with(&ctx);
        offset += e_ehsize;

        // Calculate size of section data.
        let mut shstrtab = Vec::new();
        // Null name.
        shstrtab.push(0);
        let mut section_offsets = vec![SectionOffsets::default(); self.sections.len()];
        // Null section.
        let mut e_shnum = 1;
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
                shstrtab.extend_from_slice(&b".rel"[..]);
                if is_rela {
                    shstrtab.push(b'a');
                }
                shstrtab.extend_from_slice(&section.name);
                shstrtab.push(0);

                section_offsets[index].reloc_index = e_shnum;
                e_shnum += 1;
            }
        }

        // Calculate index of symbols and add symbol strings to strtab.
        // TODO: avoid duplicate strings in strtab/shstrtab
        let mut strtab = Vec::new();
        // Name for null symbol and section symbols, must come first in strtab.
        strtab.push(0);
        let mut symbol_offsets = vec![SymbolOffsets::default(); self.symbols.len()];
        // Null symbol.
        let mut symtab_count = 1;
        let mut calc_symbol = |index: usize, symbol: &Symbol, symtab_count: &mut usize| {
            symbol_offsets[index].index = *symtab_count;
            if symbol.kind != SymbolKind::Section {
                symbol_offsets[index].str_offset = strtab.len();
                strtab.extend_from_slice(&symbol.name);
                strtab.push(0);
            }
            *symtab_count += 1;
        };
        // Local symbols must come before global.
        for (index, symbol) in self.symbols.iter().enumerate() {
            if symbol.is_local() {
                calc_symbol(index, symbol, &mut symtab_count);
            }
        }
        let symtab_count_local = symtab_count;
        for (index, symbol) in self.symbols.iter().enumerate() {
            if !symbol.is_local() {
                calc_symbol(index, symbol, &mut symtab_count);
            }
        }

        // Calculate size of symtab.
        let symtab_str_offset = shstrtab.len();
        shstrtab.extend_from_slice(&b".symtab\0"[..]);
        offset = align(offset, pointer_align);
        let symtab_offset = offset;
        let symtab_len = symtab_count * elf::Sym::size_with(&ctx);
        offset += symtab_len;
        let symtab_index = e_shnum;
        e_shnum += 1;

        // Calculate size of symtab_shndx.
        let mut need_symtab_shndx = false;
        for symbol in &self.symbols {
            let index = symbol
                .section
                .map(|s| section_offsets[s.0].index)
                .unwrap_or(0);
            if index >= elf::SHN_LORESERVE as usize {
                need_symtab_shndx = true;
            }
        }
        let symtab_shndx_str_offset = shstrtab.len();
        let symtab_shndx_offset = offset;
        let mut symtab_shndx_len = 0;
        if need_symtab_shndx {
            shstrtab.extend_from_slice(&b".symtab_shndx\0"[..]);
            symtab_shndx_len = symtab_count * 4;
            offset += symtab_shndx_len;
            e_shnum += 1;
        }

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
                offset = align(offset, pointer_align);
                section_offsets[index].reloc_offset = offset;
                let len = count * elf::Reloc::size_with(&reloc_ctx);
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
        offset = align(offset, pointer_align);
        let e_shoff = offset;
        let e_shentsize = elf::SectionHeader::size_with(&ctx);
        offset += e_shnum * e_shentsize;

        // Start writing.
        let mut buffer = Vec::with_capacity(offset);

        // Write file header.
        let e_machine = match self.architecture {
            Architecture::Arm => elf::EM_ARM,
            Architecture::Aarch64 => elf::EM_AARCH64,
            Architecture::I386 => elf::EM_386,
            Architecture::X86_64 => elf::EM_X86_64,
            _ => unimplemented!(),
        };
        let mut header = elf::Header {
            e_ident: [0; 16],
            e_type: elf::ET_REL,
            e_machine,
            e_version: elf::EV_CURRENT.into(),
            e_entry: 0,
            e_phoff: 0,
            e_shoff: e_shoff as u64,
            e_flags: 0,
            e_ehsize: e_ehsize as u16,
            e_phentsize: 0,
            e_phnum: 0,
            e_shentsize: e_shentsize as u16,
            e_shnum: if e_shnum >= elf::SHN_LORESERVE as usize {
                0
            } else {
                e_shnum as u16
            },
            e_shstrndx: if shstrtab_index >= elf::SHN_LORESERVE as usize {
                elf::SHN_XINDEX as u16
            } else {
                shstrtab_index as u16
            },
        };
        header.e_ident[0..4].copy_from_slice(elf::ELFMAG);
        header.e_ident[elf::EI_CLASS] = if container.is_big() {
            elf::ELFCLASS64
        } else {
            elf::ELFCLASS32
        };
        header.e_ident[elf::EI_DATA] = if endian.is_little() {
            elf::ELFDATA2LSB
        } else {
            elf::ELFDATA2MSB
        };
        header.e_ident[elf::EI_VERSION] = elf::EV_CURRENT;
        header.e_ident[elf::EI_OSABI] = elf::ELFOSABI_NONE;
        header.e_ident[elf::EI_ABIVERSION] = 0;
        buffer.iowrite_with(header, ctx).unwrap();

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
        write_align(&mut buffer, pointer_align);
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
        let mut symtab_shndx = Vec::new();
        if need_symtab_shndx {
            symtab_shndx.iowrite_with(0, ctx.le).unwrap();
        }
        let mut write_symbol = |index: usize, symbol: &Symbol| {
            let st_type = match symbol.kind {
                SymbolKind::Unknown | SymbolKind::Null => elf::STT_NOTYPE,
                SymbolKind::Text => {
                    if symbol.is_undefined() {
                        elf::STT_NOTYPE
                    } else {
                        elf::STT_FUNC
                    }
                }
                SymbolKind::Data => {
                    if symbol.is_undefined() {
                        elf::STT_NOTYPE
                    } else {
                        elf::STT_OBJECT
                    }
                }
                SymbolKind::Section => elf::STT_SECTION,
                SymbolKind::File => elf::STT_FILE,
                SymbolKind::Common => elf::STT_COMMON,
                SymbolKind::Tls => elf::STT_TLS,
                SymbolKind::Label => unimplemented!(),
            };
            let st_bind = if symbol.is_undefined() {
                elf::STB_GLOBAL
            } else if symbol.is_local() {
                elf::STB_LOCAL
            } else if symbol.weak {
                elf::STB_WEAK
            } else {
                elf::STB_GLOBAL
            };
            let st_other = if symbol.scope == SymbolScope::Linkage {
                elf::STV_HIDDEN
            } else {
                elf::STV_DEFAULT
            };
            let st_shndx = match symbol.kind {
                SymbolKind::File => {
                    if need_symtab_shndx {
                        symtab_shndx.iowrite_with(0, ctx.le).unwrap();
                    }
                    elf::SHN_ABS as usize
                }
                _ => {
                    let index = symbol
                        .section
                        .map(|s| section_offsets[s.0].index)
                        .unwrap_or(elf::SHN_UNDEF as usize);
                    if need_symtab_shndx {
                        symtab_shndx.iowrite_with(index as u32, ctx.le).unwrap();
                    }
                    if index >= elf::SHN_LORESERVE as usize {
                        elf::SHN_XINDEX as usize
                    } else {
                        index
                    }
                }
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
            if symbol.is_local() {
                write_symbol(index, symbol);
            }
        }
        for (index, symbol) in self.symbols.iter().enumerate() {
            if !symbol.is_local() {
                write_symbol(index, symbol);
            }
        }
        if need_symtab_shndx {
            debug_assert_eq!(symtab_shndx_offset, buffer.len());
            debug_assert_eq!(symtab_shndx_len, symtab_shndx.len());
            buffer.extend(&symtab_shndx);
        }

        // Write strtab section.
        debug_assert_eq!(strtab_offset, buffer.len());
        buffer.extend(&strtab);

        // Write relocations.
        for (index, section) in self.sections.iter().enumerate() {
            if !section.relocations.is_empty() {
                write_align(&mut buffer, pointer_align);
                debug_assert_eq!(section_offsets[index].reloc_offset, buffer.len());
                for reloc in &section.relocations {
                    let r_type = match self.architecture {
                        Architecture::I386 => match (reloc.kind, reloc.size) {
                            (RelocationKind::Absolute, 32) => elf::R_386_32,
                            (RelocationKind::Relative, 32) => elf::R_386_PC32,
                            (RelocationKind::Got, 32) => elf::R_386_GOT32,
                            (RelocationKind::PltRelative, 32) => elf::R_386_PLT32,
                            (RelocationKind::GotBaseOffset, 32) => elf::R_386_GOTOFF,
                            (RelocationKind::GotBaseRelative, 32) => elf::R_386_GOTPC,
                            (RelocationKind::Absolute, 16) => elf::R_386_16,
                            (RelocationKind::Relative, 16) => elf::R_386_PC16,
                            (RelocationKind::Absolute, 8) => elf::R_386_8,
                            (RelocationKind::Relative, 8) => elf::R_386_PC8,
                            (RelocationKind::Other(x), _) => x,
                            _ => unimplemented!("{:?}", reloc),
                        },
                        Architecture::X86_64 => match (reloc.kind, reloc.encoding, reloc.size) {
                            (RelocationKind::Absolute, RelocationEncoding::Generic, 64) => {
                                elf::R_X86_64_64
                            }
                            (RelocationKind::Relative, _, 32) => elf::R_X86_64_PC32,
                            (RelocationKind::Got, _, 32) => elf::R_X86_64_GOT32,
                            (RelocationKind::PltRelative, _, 32) => elf::R_X86_64_PLT32,
                            (RelocationKind::GotRelative, _, 32) => elf::R_X86_64_GOTPCREL,
                            (RelocationKind::Absolute, RelocationEncoding::Generic, 32) => {
                                elf::R_X86_64_32
                            }
                            (RelocationKind::Absolute, RelocationEncoding::X86Signed, 32) => {
                                elf::R_X86_64_32S
                            }
                            (RelocationKind::Absolute, _, 16) => elf::R_X86_64_16,
                            (RelocationKind::Relative, _, 16) => elf::R_X86_64_PC16,
                            (RelocationKind::Absolute, _, 8) => elf::R_X86_64_8,
                            (RelocationKind::Relative, _, 8) => elf::R_X86_64_PC8,
                            (RelocationKind::Other(x), _, _) => x,
                            _ => unimplemented!("{:?}", reloc),
                        },
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
                            reloc_ctx,
                        )
                        .unwrap();
                }
            }
        }

        // Write shstrtab section.
        debug_assert_eq!(shstrtab_offset, buffer.len());
        buffer.extend(&shstrtab);

        // Write section headers.
        write_align(&mut buffer, pointer_align);
        debug_assert_eq!(e_shoff, buffer.len());
        buffer
            .iowrite_with(
                elf::SectionHeader {
                    sh_name: 0,
                    sh_type: 0,
                    sh_flags: 0,
                    sh_addr: 0,
                    sh_offset: 0,
                    sh_size: if e_shnum >= elf::SHN_LORESERVE as usize {
                        e_shnum as u64
                    } else {
                        0
                    },
                    sh_link: if shstrtab_index >= elf::SHN_LORESERVE as usize {
                        shstrtab_index as u32
                    } else {
                        0
                    },
                    // TODO: e_phnum overflow
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
                SectionKind::Other
                | SectionKind::Debug
                | SectionKind::Unknown
                | SectionKind::Metadata
                | SectionKind::Linker => 0,
                SectionKind::TlsVariables => unimplemented!(),
            };
            // TODO: not sure if this is correct, maybe user should determine this
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
                        sh_addr: 0,
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
                            sh_type: if is_rela { elf::SHT_RELA } else { elf::SHT_REL },
                            sh_flags: elf::SHF_INFO_LINK.into(),
                            sh_addr: 0,
                            sh_offset: section_offsets[index].reloc_offset as u64,
                            sh_size: section_offsets[index].reloc_len as u64,
                            sh_link: symtab_index as u32,
                            sh_info: section_offsets[index].index as u32,
                            sh_addralign: pointer_align as u64,
                            sh_entsize: elf::Reloc::size_with(&reloc_ctx) as u64,
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
                    sh_addralign: pointer_align as u64,
                    sh_entsize: elf::Sym::size_with(&ctx) as u64,
                },
                ctx,
            )
            .unwrap();

        // Write symtab_shndx section header.
        if need_symtab_shndx {
            buffer
                .iowrite_with(
                    elf::SectionHeader {
                        sh_name: symtab_shndx_str_offset,
                        sh_type: elf::SHT_SYMTAB_SHNDX,
                        sh_flags: 0,
                        sh_addr: 0,
                        sh_offset: symtab_shndx_offset as u64,
                        sh_size: symtab_shndx_len as u64,
                        sh_link: strtab_index as u32,
                        sh_info: symtab_count_local as u32,
                        sh_addralign: pointer_align as u64,
                        sh_entsize: elf::Sym::size_with(&ctx) as u64,
                    },
                    ctx,
                )
                .unwrap();
        }

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
