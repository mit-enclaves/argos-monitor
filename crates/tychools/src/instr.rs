use object::read::elf::{FileHeader, ProgramHeader, SectionHeader};
use object::{elf, Endian, Endianness};

#[derive(Debug)]
pub struct ModifiedSection {
    idx: usize,
    section_header: elf::SectionHeader64<Endianness>,
    data: Vec<u8>,
}

#[derive(Debug)]
pub struct ModifiedSegment {
    idx: usize,
    program_header: elf::ProgramHeader64<Endianness>,
    sections: Vec<ModifiedSection>,
    data: Vec<u8>,
}

#[derive(Debug)]
pub struct ModifiedELF {
    header: elf::FileHeader64<Endianness>,
    segments: Vec<ModifiedSegment>,
    no_load: Vec<ModifiedSection>,
}

fn any_as_u8_slice<T: Sized>(p: &T) -> &[u8] {
    unsafe {
        ::core::slice::from_raw_parts((p as *const T) as *const u8, ::core::mem::size_of::<T>())
    }
}

impl ModifiedELF {
    pub fn new(data: &[u8]) -> Box<ModifiedELF> {
        // Parse the header.
        let hdr = elf::FileHeader64::<Endianness>::parse(data).expect("Unable to parse the data");

        let mut melf = Box::new(ModifiedELF {
            header: hdr.clone(),
            segments: Vec::new(),
            no_load: Vec::new(),
        });

        // Parse the segments.
        let segs = hdr
            .program_headers(Endianness::Little, data)
            .expect("Unable to parse segments");

        for (idx, seg) in segs.iter().enumerate() {
            let seg_data = seg
                .data(Endianness::Little, data)
                .expect("Unable to get segment data");
            melf.segments.push(ModifiedSegment {
                idx,
                program_header: seg.clone(),
                sections: Vec::new(),
                data: seg_data.to_vec(),
            });
        }

        // Attribute sections.
        let secs = hdr
            .section_headers(Endianness::Little, data)
            .expect("Unable to parse sections");

        for (idx, sec) in secs.iter().enumerate() {
            // Find the right segment.
            let mut found = false;

            let name = {
                String::from_utf8(
                    sec.name(
                        Endianness::Little,
                        hdr.section_strings(Endianness::Little, data, secs)
                            .expect("ouf"),
                    )
                    .expect("ouf2")
                    .to_vec(),
                )
                .expect("ouf4")
            };

            for seg in &mut melf.segments {
                if seg.contains(sec.sh_addr.get(Endianness::Little)) {
                    found = true;
                    let sec_data = sec
                        .data(Endianness::Little, data)
                        .expect("Unable to read section's data");
                    seg.sections.push(ModifiedSection {
                        idx,
                        section_header: sec.clone(),
                        data: sec_data.to_vec(),
                    });
                    log::debug!("Attributing section {}", name);
                    break;
                }
            }
            if !found && (sec.sh_flags.get(Endianness::Little) & elf::SHF_ALLOC as u64 == 0) {
                let sec_data = sec
                    .data(Endianness::Little, data)
                    .expect("Unable to access data")
                    .to_vec();
                melf.no_load.push(ModifiedSection {
                    idx,
                    section_header: sec.clone(),
                    data: sec_data,
                });
                log::debug!("No load section {}", name);
            } else if !found {
                panic!("Unable to find a segment for an alloc section");
            }
        }
        // Return the elf.
        melf
    }

    /// Dump this object into the provided vector.
    pub fn dump(&mut self, out: &mut object::write::elf::Writer) {
        log::info!("The computed size is {}", self.len());
        out.write(any_as_u8_slice(&self.header));
        for seg in &self.segments {
            out.write(any_as_u8_slice(&seg.program_header));
        }
        for seg in &self.segments {
            for sec in &seg.sections {
                out.write(&sec.data);
            }
        }
        for sec in &self.no_load {
            out.write(&sec.data);
        }
        for seg in &self.segments {
            for sec in &seg.sections {
                out.write(any_as_u8_slice(&sec.section_header));
            }
        }
        for sec in &self.no_load {
            out.write(any_as_u8_slice(&sec.section_header));
        }
    }

    pub fn pad_bytes(content: usize, align: usize) -> usize {
        if content % align == 0 {
            return content;
        }
        return content + (align - (content % align));
    }

    /// Compute the length required in bytes.
    pub fn len(&mut self) -> usize {
        let mut total: usize = 0;
        // Header size.
        /*total += std::mem::size_of::<elf::FileHeader64<Endianness>>();
        log::debug!("Size after header {}", total);
        log::debug!(
            "Program table {:} Section table {:?}",
            self.header.e_phoff(Endianness::Little),
            self.header.e_shoff(Endianness::Little)
        );

        // Program headers size.
        total += std::mem::size_of::<elf::ProgramHeader64<Endianness>>() * self.segments.len();
        log::debug!("Size after program headers {}", total);*/

        // File content size and section headers.
        self.segments.sort_by(|a, b| {
            a.program_header
                .p_offset(Endianness::Little)
                .cmp(&b.program_header.p_offset(Endianness::Little))
        });
        for seg in &self.segments {
            total = Self::pad_bytes(
                total,
                seg.program_header.p_align(Endianness::Little) as usize,
            );
            if seg.program_header.p_offset(Endianness::Little) as usize != total {
                log::error!(
                    "[seg {}] Something went wrong, we should be at {}, but got {}",
                    seg.idx,
                    seg.program_header.p_offset(Endianness::Little),
                    total
                );
            }
            total += seg.program_header.p_filesz(Endianness::Little) as usize;
        }
        // No load section headers.
        total += std::mem::size_of::<elf::SectionHeader64<Endianness>>() * self.no_load.len();
        // Sections with no segments.
        for sec in &self.no_load {
            total += sec.data.len();
        }

        // Now add all the section headers.
        for seg in &self.segments {
            total += seg.sections.len() * std::mem::size_of::<elf::SectionHeader64<Endianness>>();
        }
        total
    }
}

impl ModifiedSegment {
    pub fn contains(&self, start: u64) -> bool {
        let vaddr = self.program_header.p_vaddr.get(Endianness::Little);
        let end = vaddr + self.program_header.p_memsz.get(Endianness::Little);
        let within = vaddr <= start && end > start;
        if self.program_header.p_type.get(Endianness::Little) == elf::PT_LOAD {
            return within;
        }
        return false;
    }
}
