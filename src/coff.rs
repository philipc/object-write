use crc32fast;
use scroll::ctx::SizeWith;
use scroll::IOwrite;
use std::iter;

use crate::util::*;
use crate::*;

mod coff {
    pub use goblin::pe::characteristic::*;
    pub use goblin::pe::header::*;
    pub use goblin::pe::relocation::*;
    pub use goblin::pe::section_table::*;
    pub use goblin::pe::symbol::*;
}

#[derive(Default, Clone, Copy)]
struct SectionOffsets {
    offset: usize,
    str_offset: usize,
    reloc_offset: usize,
}

#[derive(Default, Clone, Copy)]
struct SymbolOffsets {
    index: usize,
    str_offset: usize,
    aux_count: u8,
}

impl Object {
    pub(crate) fn finalize_coff(&mut self) {
        // Set the section names expected by the linker.
        for section in &mut self.sections {
            if section.name.is_empty() || section.name[0] != b'.' {
                let base = match section.kind {
                    SectionKind::Text => &b".text"[..],
                    SectionKind::Data => &b".data"[..],
                    SectionKind::ReadOnlyData | SectionKind::ReadOnlyString => &b".rdata"[..],
                    _ => continue,
                };
                let mut name = base.to_vec();
                if !section.name.is_empty() {
                    name.push(b'$');
                    name.extend(&section.name);
                }
                section.name = name;
            }
        }

        // Determine which symbols need a refptr.
        let mut need_refptr = vec![false; self.symbols.len()];
        let mut refptr_count = 0;
        for section in &self.sections {
            for reloc in &section.relocations {
                if reloc.kind == RelocationKind::GotRelative {
                    if !need_refptr[reloc.symbol.0] {
                        need_refptr[reloc.symbol.0] = true;
                        refptr_count += 1;
                    }
                }
            }
        }
        // Create the refptr sections and symbols.
        let mut refptr_sections = Vec::with_capacity(refptr_count);
        let mut refptr_symbols = Vec::with_capacity(refptr_count);
        let mut refptr_symbol_ids = Vec::with_capacity(self.symbols.len());
        for (index, symbol) in self.symbols.iter().enumerate() {
            if need_refptr[index] {
                let section_id = SectionId(self.sections.len() + refptr_sections.len());
                let mut name = b".rdata$.refptr.".to_vec();
                name.extend(&symbol.name);
                refptr_sections.push(Section {
                    name,
                    segment_name: Vec::new(),
                    kind: SectionKind::ReadOnlyData,
                    address: 0,
                    // TODO: pointer size
                    size: 8,
                    align: 8,
                    data: vec![0; 8],
                    relocations: vec![Relocation {
                        offset: 0,
                        symbol: SymbolId(index),
                        kind: RelocationKind::Absolute,
                        // TODO: pointer size
                        size: 64,
                        addend: 0,
                    }],
                    symbol: None,
                });
                let symbol_id = SymbolId(self.symbols.len() + refptr_symbols.len());
                let mut name = b".refptr.".to_vec();
                name.extend(&symbol.name);
                refptr_symbols.push(Symbol {
                    name,
                    value: 0,
                    size: 8,
                    kind: SymbolKind::Data,
                    binding: Binding::Local,
                    visibility: Visibility::Default,
                    section: Some(section_id),
                });
                refptr_symbol_ids.push(symbol_id);
            } else {
                // Placeholder.
                refptr_symbol_ids.push(SymbolId(index));
            }
        }
        // Fix the relocations to use the refptr.
        for section in &mut self.sections {
            for reloc in &mut section.relocations {
                match reloc.kind {
                    RelocationKind::GotRelative => {
                        reloc.kind = RelocationKind::Relative;
                        reloc.symbol = refptr_symbol_ids[reloc.symbol.0];
                    }
                    RelocationKind::PltRelative => {
                        // Windows doesn't need a separate relocation type for
                        // references to functions in import libraries.
                        // For convenience, treat this the same as Relative.
                        reloc.kind = RelocationKind::Relative;
                    }
                    _ => {}
                }
            }
        }
        self.sections.extend(refptr_sections);
        self.symbols.extend(refptr_symbols);
    }

    pub(crate) fn write_coff(&self) -> Vec<u8> {
        // Calculate offsets of everything, and build strtab.
        let mut offset = 0;
        // First 4 bytes of strtab are the length.
        // TODO: avoid duplicate strings in strtab
        let mut strtab = vec![0; 4];

        // COFF header.
        let ctx = scroll::LE;
        offset += coff::CoffHeader::size_with(&ctx);

        // Section headers.
        offset += self.sections.len() * coff::SectionTable::size_with(&ctx);

        // Calculate size of section data and add section strings to strtab.
        let mut section_offsets = vec![SectionOffsets::default(); self.sections.len()];
        for (index, section) in self.sections.iter().enumerate() {
            if section.name.len() > 8 {
                section_offsets[index].str_offset = strtab.len();
                strtab.extend_from_slice(&section.name);
                strtab.push(0);
            }

            let len = section.data.len();
            if len != 0 {
                // TODO: not sure what alignment is required here, but this seems to match LLVM
                offset = align(offset, 4);
                section_offsets[index].offset = offset;
                offset += len;
            } else {
                section_offsets[index].offset = offset;
            }

            // Calculate size of relocations.
            let count = section.relocations.len();
            if count != 0 {
                section_offsets[index].reloc_offset = offset;
                offset += count * coff::Relocation::size_with(&ctx);
            }
        }

        // Calculate size of symbols and add symbol strings to strtab.
        let mut symbol_offsets = vec![SymbolOffsets::default(); self.symbols.len()];
        let mut symtab_count = 0;
        for (index, symbol) in self.symbols.iter().enumerate() {
            symbol_offsets[index].index = symtab_count;
            symtab_count += 1;
            match symbol.kind {
                SymbolKind::File => {
                    // Name goes in auxilary symbol records.
                    let aux_count =
                        (symbol.name.len() + coff::COFF_SYMBOL_SIZE - 1) / coff::COFF_SYMBOL_SIZE;
                    symbol_offsets[index].aux_count = aux_count as u8;
                    symtab_count += aux_count;
                    // Don't add name to strtab.
                    continue;
                }
                SymbolKind::Section => {
                    symbol_offsets[index].aux_count = 1;
                    symtab_count += 1;
                }
                _ => {}
            }
            if symbol.name.len() > 8 {
                symbol_offsets[index].str_offset = strtab.len();
                strtab.extend_from_slice(&symbol.name);
                strtab.push(0);
            }
        }

        // Calculate size of symtab.
        let symtab_offset = offset;
        let symtab_len = symtab_count * coff::COFF_SYMBOL_SIZE;
        offset += symtab_len;

        // Calculate size of strtab.
        let strtab_len = strtab.len();
        let strtab_offset = offset;
        offset += strtab_len;

        // Start writing.
        let mut buffer = Vec::with_capacity(offset);

        // Write file header.
        let header = coff::CoffHeader {
            machine: match self.architecture {
                Architecture::I386 => coff::COFF_MACHINE_X86,
                Architecture::X86_64 => coff::COFF_MACHINE_X86_64,
                _ => unimplemented!(),
            },
            number_of_sections: self.sections.len() as u16,
            time_date_stamp: 0,
            pointer_to_symbol_table: symtab_offset as u32,
            number_of_symbol_table: symtab_count as u32,
            size_of_optional_header: 0,
            characteristics: 0,
        };
        assert_eq!(self.entry, 0);
        buffer.iowrite_with(header, ctx).unwrap();

        // Write section headers.
        for (index, section) in self.sections.iter().enumerate() {
            // TODO: IMAGE_SCN_LNK_COMDAT
            let characteristics = match section.kind {
                SectionKind::Text => {
                    coff::IMAGE_SCN_CNT_CODE
                        | coff::IMAGE_SCN_MEM_EXECUTE
                        | coff::IMAGE_SCN_MEM_READ
                }
                SectionKind::Data => {
                    coff::IMAGE_SCN_CNT_INITIALIZED_DATA
                        | coff::IMAGE_SCN_MEM_READ
                        | coff::IMAGE_SCN_MEM_WRITE
                }
                SectionKind::UninitializedData => {
                    coff::IMAGE_SCN_CNT_UNINITIALIZED_DATA
                        | coff::IMAGE_SCN_MEM_READ
                        | coff::IMAGE_SCN_MEM_WRITE
                }
                SectionKind::ReadOnlyData | SectionKind::ReadOnlyString => {
                    coff::IMAGE_SCN_CNT_INITIALIZED_DATA | coff::IMAGE_SCN_MEM_READ
                }
                SectionKind::Other | SectionKind::OtherString => {
                    coff::IMAGE_SCN_CNT_INITIALIZED_DATA
                        | coff::IMAGE_SCN_MEM_READ
                        | coff::IMAGE_SCN_MEM_DISCARDABLE
                }
                SectionKind::Linker => coff::IMAGE_SCN_LNK_INFO | coff::IMAGE_SCN_LNK_REMOVE,
                SectionKind::Tls
                | SectionKind::UninitializedTls
                | SectionKind::Unknown
                | SectionKind::Metadata => unimplemented!("{:?}", section),
            };
            let align = match section.align {
                1 => coff::IMAGE_SCN_ALIGN_1BYTES,
                2 => coff::IMAGE_SCN_ALIGN_2BYTES,
                4 => coff::IMAGE_SCN_ALIGN_4BYTES,
                8 => coff::IMAGE_SCN_ALIGN_8BYTES,
                16 => coff::IMAGE_SCN_ALIGN_16BYTES,
                32 => coff::IMAGE_SCN_ALIGN_32BYTES,
                64 => coff::IMAGE_SCN_ALIGN_64BYTES,
                128 => coff::IMAGE_SCN_ALIGN_128BYTES,
                256 => coff::IMAGE_SCN_ALIGN_256BYTES,
                512 => coff::IMAGE_SCN_ALIGN_512BYTES,
                1024 => coff::IMAGE_SCN_ALIGN_1024BYTES,
                2048 => coff::IMAGE_SCN_ALIGN_2048BYTES,
                4096 => coff::IMAGE_SCN_ALIGN_4096BYTES,
                8192 => coff::IMAGE_SCN_ALIGN_8192BYTES,
                _ => unimplemented!(),
            };
            let mut coff_section = coff::SectionTable {
                name: [0; 8],
                real_name: None,
                virtual_size: if section.data.is_empty() {
                    section.size as u32
                } else {
                    0
                },
                virtual_address: section.address as u32,
                size_of_raw_data: section.data.len() as u32,
                pointer_to_raw_data: if section.data.is_empty() {
                    0
                } else {
                    section_offsets[index].offset as u32
                },
                pointer_to_relocations: section_offsets[index].reloc_offset as u32,
                pointer_to_linenumbers: 0,
                number_of_relocations: section.relocations.len() as u16,
                number_of_linenumbers: 0,
                characteristics: characteristics | align,
            };
            if section.name.len() <= 8 {
                coff_section.name[..section.name.len()].copy_from_slice(&section.name);
            } else {
                coff_section
                    .set_name_offset(section_offsets[index].str_offset)
                    .unwrap();
            }
            buffer.iowrite_with(coff_section, ctx).unwrap();
        }

        // Write section data and relocations.
        for (index, section) in self.sections.iter().enumerate() {
            let len = section.data.len();
            if len != 0 {
                write_align(&mut buffer, 4);
                debug_assert_eq!(section_offsets[index].offset, buffer.len());
                buffer.extend(&section.data);
            }

            if !section.relocations.is_empty() {
                debug_assert_eq!(section_offsets[index].reloc_offset, buffer.len());
                for reloc in &section.relocations {
                    //assert!(reloc.implicit_addend);
                    // TODO: other machines
                    let typ = match self.architecture {
                        Architecture::I386 => match (reloc.kind, reloc.size, reloc.addend) {
                            (RelocationKind::Absolute, 16, 0) => coff::IMAGE_REL_I386_DIR16,
                            (RelocationKind::Relative, 16, 0) => coff::IMAGE_REL_I386_REL16,
                            (RelocationKind::Absolute, 32, 0) => coff::IMAGE_REL_I386_DIR32,
                            (RelocationKind::ImageOffset, 32, 0) => coff::IMAGE_REL_I386_DIR32NB,
                            (RelocationKind::SectionOffset, 32, 0) => coff::IMAGE_REL_I386_SECREL,
                            (RelocationKind::SectionOffset, 7, 0) => coff::IMAGE_REL_I386_SECREL7,
                            (RelocationKind::Relative, 32, -4) => coff::IMAGE_REL_I386_REL32,
                            (RelocationKind::Other(x), _, _) => x as u16,
                            _ => unimplemented!(),
                        },
                        Architecture::X86_64 => match (reloc.kind, reloc.size, reloc.addend) {
                            (RelocationKind::Absolute, 64, 0) => coff::IMAGE_REL_AMD64_ADDR64,
                            (RelocationKind::Absolute, 32, 0) => coff::IMAGE_REL_AMD64_ADDR32,
                            (RelocationKind::ImageOffset, 32, 0) => coff::IMAGE_REL_AMD64_ADDR32NB,
                            (RelocationKind::Relative, 32, -4) => coff::IMAGE_REL_AMD64_REL32,
                            (RelocationKind::Relative, 32, -5) => coff::IMAGE_REL_AMD64_REL32_1,
                            (RelocationKind::Relative, 32, -6) => coff::IMAGE_REL_AMD64_REL32_2,
                            (RelocationKind::Relative, 32, -7) => coff::IMAGE_REL_AMD64_REL32_3,
                            (RelocationKind::Relative, 32, -8) => coff::IMAGE_REL_AMD64_REL32_4,
                            (RelocationKind::Relative, 32, -9) => coff::IMAGE_REL_AMD64_REL32_5,
                            (RelocationKind::SectionOffset, 32, 0) => coff::IMAGE_REL_AMD64_SECREL,
                            (RelocationKind::SectionOffset, 7, 0) => coff::IMAGE_REL_AMD64_SECREL7,
                            (RelocationKind::Other(x), _, _) => x as u16,
                            _ => unimplemented!("{:?}", reloc),
                        },
                        _ => unimplemented!(),
                    };
                    buffer
                        .iowrite_with(
                            coff::Relocation {
                                virtual_address: reloc.offset as u32,
                                symbol_table_index: symbol_offsets[reloc.symbol.0].index as u32,
                                typ,
                            },
                            ctx,
                        )
                        .unwrap();
                }
            }
        }

        // Write symbols.
        debug_assert_eq!(symtab_offset, buffer.len());
        for (index, symbol) in self.symbols.iter().enumerate() {
            let mut name = &symbol.name[..];
            let mut section_number = symbol.section.map(|x| x.0 + 1).unwrap_or(0) as i16;
            let typ = if symbol.kind == SymbolKind::Text {
                coff::IMAGE_SYM_DTYPE_FUNCTION << coff::IMAGE_SYM_DTYPE_SHIFT
            } else {
                coff::IMAGE_SYM_TYPE_NULL
            };
            let storage_class = match symbol.kind {
                SymbolKind::File => {
                    // Name goes in auxilary symbol records.
                    name = b".file";
                    section_number = coff::IMAGE_SYM_DEBUG;
                    coff::IMAGE_SYM_CLASS_FILE
                }
                SymbolKind::Section => coff::IMAGE_SYM_CLASS_STATIC,
                SymbolKind::Label => coff::IMAGE_SYM_CLASS_LABEL,
                SymbolKind::Text | SymbolKind::Data => {
                    match symbol.binding {
                        Binding::Local => coff::IMAGE_SYM_CLASS_STATIC,
                        Binding::Global => coff::IMAGE_SYM_CLASS_EXTERNAL,
                        // TODO: does this need aux symbol records too?
                        Binding::Weak => coff::IMAGE_SYM_CLASS_WEAK_EXTERNAL,
                        Binding::Unknown => unimplemented!(),
                    }
                }
                _ => unimplemented!("{:?}", symbol),
            };
            let number_of_aux_symbols = symbol_offsets[index].aux_count;
            let mut coff_symbol = coff::Symbol {
                name: [0; 8],
                value: symbol.value as u32,
                section_number,
                typ,
                storage_class,
                number_of_aux_symbols,
            };
            if name.len() <= 8 {
                coff_symbol.name[..name.len()].copy_from_slice(name);
            } else {
                coff_symbol.set_name_offset(symbol_offsets[index].str_offset as u32);
            }
            buffer.iowrite_with(coff_symbol, ctx).unwrap();

            match symbol.kind {
                SymbolKind::File => {
                    let aux_len = number_of_aux_symbols as usize * coff::COFF_SYMBOL_SIZE;
                    debug_assert!(aux_len >= symbol.name.len());
                    buffer.extend(&symbol.name);
                    buffer.extend(iter::repeat(0).take(aux_len - symbol.name.len()));
                }
                SymbolKind::Section => {
                    debug_assert_eq!(number_of_aux_symbols, 1);
                    let section = &self.sections[symbol.section.unwrap().0];
                    buffer
                        .iowrite_with(
                            coff::AuxSectionDefinition {
                                length: section.data.len() as u32,
                                number_of_relocations: section.relocations.len() as u16,
                                number_of_line_numbers: 0,
                                checksum: checksum(&section.data),
                                number: section_number as u16,
                                // TODO: COMDAT
                                selection: 0,
                                unused: [0; 3],
                            },
                            ctx,
                        )
                        .unwrap();
                }
                _ => {
                    debug_assert_eq!(number_of_aux_symbols, 0);
                }
            }
        }

        // Write strtab section.
        debug_assert_eq!(strtab_offset, buffer.len());
        buffer.iowrite_with(strtab_len as u32, ctx).unwrap();
        buffer.extend(&strtab[4..]);

        buffer
    }
}

// JamCRC
fn checksum(data: &[u8]) -> u32 {
    let mut hasher = crc32fast::Hasher::new_with_initial(0xffff_ffff);
    hasher.update(data);
    !hasher.finalize()
}
