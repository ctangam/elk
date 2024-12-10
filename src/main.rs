use core::str;
use std::{env, error::Error, fs, mem::transmute, ptr::copy_nonoverlapping};

use mmap::{MapOption, MemoryMap};
use region::{protect, Protection};

fn main() -> Result<(), Box<dyn Error>> {
    let input_path = env::args().nth(1).expect("usage: elk FILE");
    let input = fs::read(&input_path)?;

    println!("Analyzing {:?}...", input_path);

    let file = match delf::File::parse_or_print_error(&input[..]) {
        Some(f) => f,
        None => std::process::exit(1),
    };
    println!("{:#?}", file);

    let rela_entries = file.read_rela_entries().unwrap_or_else(|e| {
        println!("Could not read relocations: {:?}", e);
        Default::default()
    });
    println!("Found {} rela entries", rela_entries.len());
    for entry in rela_entries.iter() {
        println!("{:?}", entry);
    }

    if let Some(dynseg) = file.segment_of_type(delf::SegmentType::Dynamic) {
        if let delf::SegmentContents::Dynamic(ref dyntab) = dynseg.contents {
            println!("Dynamic table entries:");
            for e in dyntab {
                println!("{:?}", e);
                match e.tag {
                    delf::DynamicTag::Needed | delf::DynamicTag::RPath => {
                        println!(" => {:?}", file.get_string(e.addr)?);
                    }
                    _ => {}
                }
            }
        }
    }

    let base = 0x400000_usize;

    println!("Loading with base address @ 0x{:x}", base);
    let non_empty_load_segments = file
        .program_headers
        .iter()
        .filter(|ph| ph.r#type == delf::SegmentType::Load)
        // ignore zero-length segments
        .filter(|ph| ph.mem_range().end > ph.mem_range().start);

    let mut mappings = Vec::new();
    for ph in non_empty_load_segments {
        println!("Mapping {:?} - {:?}", ph.mem_range(), ph.flags);
        let mem_range = ph.mem_range();
        let len: usize = (mem_range.end - mem_range.start).into();

        let start: usize = mem_range.start.0 as usize + base;
        let aligned_start: usize = align_lo(start);
        let padding = start - aligned_start;
        let len = len + padding;

        let addr: *mut u8 = unsafe { transmute(aligned_start) };
        if padding > 0 {
            println!("(With 0x{:x} bytes of padding at the start)", padding);
        }

        let map = MemoryMap::new(len, &[MapOption::MapWritable, MapOption::MapAddr(addr)])?;
        unsafe {
            copy_nonoverlapping(ph.data.as_ptr(), addr.add(padding), len);
        }

        let mut num_relocs = 0;
        for reloc in &rela_entries {
            if mem_range.contains(&reloc.offset) {
                unsafe {
                    let real_segment_start = addr.add(padding);
                    let offset_into_segment = reloc.offset - mem_range.start;
                    let reloc_addr = real_segment_start.add(offset_into_segment.into());

                    match reloc.r#type {
                        delf::RelType::Known(t) => {
                            num_relocs += 1;
                            match t {
                                delf::KnownRelType::Relative => {
                                    // this assumes `reloc_addr` is 8-byte aligned. if this isn't
                                    // the case, we would crash, and so would the target executable.
                                    let reloc_addr: *mut u64 = transmute(reloc_addr);
                                    let reloc_value = reloc.addend + delf::Addr(base as u64);
                                    std::ptr::write_unaligned(reloc_addr, reloc_value.0);
                                }
                                t => {
                                    panic!("Unsupported relocation type {:?}", t);
                                }
                            }
                        }
                        delf::RelType::Unknown(_) => {}
                    }
                }
            }
        }
        if num_relocs > 0 {
            println!("(Applied {} relocations)", num_relocs);
        }

        let mut protection = Protection::NONE;
        for flag in ph.flags.iter() {
            protection |= match flag {
                delf::SegmentFlag::Read => Protection::READ,
                delf::SegmentFlag::Write => Protection::WRITE,
                delf::SegmentFlag::Execute => Protection::EXECUTE,
            }
        }
        unsafe {
            protect(addr, len, protection)?;
        }
        mappings.push(map);
    }

    println!("Jumping to entry point @ {:?}...", file.entry_point);
    unsafe {
        jmp(transmute(file.entry_point.0 as usize + base));
    }

    Ok(())
}

fn pause(reason: &str) -> Result<(), Box<dyn Error>> {
    println!("Press Enter to {}...", reason);
    {
        let mut s = String::new();
        std::io::stdin().read_line(&mut s)?;
    }
    Ok(())
}

/**
 * Truncates a usize value to the left-adjacent (low) 4KiB boundary.
 */
fn align_lo(x: usize) -> usize {
    x & !0xFFF
}

fn ndisasm(code: &[u8], origin: delf::Addr) -> Result<(), Box<dyn Error>> {
    use std::{
        io::Write,
        process::{Command, Stdio},
    };

    let mut child = Command::new("ndisasm")
        .arg("-b")
        .arg("64")
        .arg("-o")
        .arg(format!("{}", origin.0))
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    child.stdin.as_mut().unwrap().write_all(code)?;
    let output = child.wait_with_output()?;
    println!("{}", String::from_utf8_lossy(&output.stdout));

    Ok(())
}

unsafe fn jmp(addr: *const u8) {
    let fn_ptr: fn() = std::mem::transmute(addr);
    fn_ptr();
}
