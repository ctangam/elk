#![feature(asm)]

use core::str;
use std::error::Error;

mod name;
mod process;
mod procfs;

use argh::FromArgs;

#[derive(FromArgs, PartialEq, Debug)]
/// Top-level command
struct Args {
    #[argh(subcommand)]
    nested: SubCommand,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand)]
enum SubCommand {
    Autosym(AutosymArgs),
    Run(RunArgs),
    Dig(DigArgs),
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "dig")]
/// Shows information about an address in a memory's address space
struct DigArgs {
    #[argh(option)]
    /// the PID of the process whose memory space to examine
    pid: u32,
    #[argh(option)]
    /// the address to look for
    addr: u64,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "autosym")]
/// Given a PID, spit out GDB commands to load all .so files
/// mapped in memory.
struct AutosymArgs {
    #[argh(positional)]
    /// the PID of the process to examine
    pid: u32,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "run")]
/// Load and run an ELF executable
struct RunArgs {
    #[argh(positional)]
    /// the absolute path of an executable file to load and run
    exec_path: String,

    #[argh(positional)]
    /// arguments for the executable file
    args: Vec<String>,
}

fn main() {
    if let Err(e) = do_main() {
        eprintln!("Fatal error: {}", e);
    }
}

type AnyError = Box<dyn Error>;

fn do_main() -> Result<(), Box<dyn Error>> {
    let args: Args = argh::from_env();
    match args.nested {
        SubCommand::Run(args) => cmd_run(args),
        SubCommand::Autosym(args) => cmd_autosym(args),
        SubCommand::Dig(args) => cmd_dig(args),
    }
}

use thiserror::*;

#[derive(Error, Debug)]
enum WithMappingsError {
    #[error("parsing failed: {0}")]
    Parse(String),
}

// We're doing this in both `autosym` and `dig`, so it makes
// sense to have a helper for it.
// "Mapping<'a>" is annoying to manipulate, so we can't really
// return it, but we *can* take a closure that operates on it!
fn with_mappings<F, T>(pid: u32, f: F) -> Result<T, AnyError>
where
    F: Fn(&Vec<procfs::Mapping<'_>>) -> Result<T, Box<dyn Error>>,
{
    let maps = std::fs::read_to_string(format!("/proc/{}/maps", pid))?;
    match procfs::mappings(&maps) {
        Ok((_, maps)) => f(&maps),
        Err(e) => {
            // parsing errors borrow the input, so we wouldn't be able
            // to return it. to prevent that, format it early.
            Err(Box::new(WithMappingsError::Parse(format!("{:?}", e))))
        }
    }
}

// Does the same as previously, just refactored to use `with_mappings`:
fn cmd_autosym(args: AutosymArgs) -> Result<(), Box<dyn Error>> {
    fn analyze(mapping: &procfs::Mapping) -> Result<(), AnyError> {
        if mapping.deleted {
            // skip deleted mappings
            return Ok(());
        }

        let path = match mapping.source {
            procfs::Source::File(path) => path,
            _ => return Ok(()),
        };

        let contents = std::fs::read(path)?;
        let file = match delf::File::parse_or_print_error(&contents) {
            Some(x) => x,
            _ => return Ok(()),
        };

        let section = match file
            .section_headers
            .iter()
            .find(|sh| file.shstrtab_entry(sh.name) == b".text")
        {
            Some(section) => section,
            _ => return Ok(()),
        };

        let textaddress = mapping.addr_range.start - mapping.offset + section.offset;
        println!("add-symbol-file {:?} 0x{:?}", path, textaddress);

        Ok(())
    }

    with_mappings(args.pid, |mappings| {
        for mapping in mappings.iter().filter(|m| m.perms.x && m.source.is_file()) {
            analyze(mapping)?;
        }
        Ok(())
    })
}

struct Size(pub delf::Addr);
use std::fmt;
impl fmt::Debug for Size {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const KIB: u64 = 1024;
        const MIB: u64 = 1024 * KIB;

        let x = (self.0).0;
        #[allow(overlapping_range_endpoints)]
        #[allow(clippy::clippy::match_overlapping_arm)]
        match x {
            0..=KIB => write!(f, "{} B", x),
            KIB..=MIB => write!(f, "{} KiB", x / KIB),
            _ => write!(f, "{} MiB", x / MIB),
        }
    }
}

fn cmd_dig(args: DigArgs) -> Result<(), Box<dyn Error>> {
    let addr = delf::Addr(args.addr);

    with_mappings(args.pid, |mappings| {
        if let Some(mapping) = mappings.iter().find(|m| m.addr_range.contains(&addr)) {
            println!("Mapped {:?} from {:?}", mapping.perms, mapping.source);
            println!(
                "(Map range: {:?}, {:?} total)",
                mapping.addr_range,
                Size(mapping.addr_range.end - mapping.addr_range.start)
            );

            // we've used this pattern a bunch of times already, but in case you don't
            // see the point: this avoids deep indentation. If we didn't use that, we'd
            // soon find ourselves several levels deep into `if let` statements, whereas
            // really, if we get a `None` or an `Err`, we just want to bail out early
            // and gracefully.
            let path = match mapping.source {
                procfs::Source::File(path) => path,
                // if it's not a file mapping, bail out
                _ => return Ok(()),
            };

            let contents = std::fs::read(path)?;
            let file = match delf::File::parse_or_print_error(&contents) {
                Some(x) => x,
                // if we couldn't parse the file, a message was printed,
                // and we can bail out
                _ => return Ok(()),
            };

            let offset = addr + mapping.offset - mapping.addr_range.start;

            // Segments (loader view, `delf::ProgramHeader` type) determine what parts
            // of the ELF file get mapped where, so we try to determine which
            // segment this mapping corresponds to.
            let segment = match file
                .program_headers
                .iter()
                .find(|ph| ph.file_range().contains(&offset))
            {
                Some(s) => s,
                None => return Ok(()),
            };

            // This is the main thing I wanted `elk dig` to do - display
            // the virtual address *for this ELF object*, so that it matches
            // up with the output from `objdump` and `readelf`
            let vaddr = offset + segment.vaddr - segment.offset;
            println!("Object virtual address: {:?}", vaddr);

            // But we can go a bit further: we can find to which section
            // this corresponds, and show *where* in this section the
            // dug address was.
            let section = match file
                .section_headers
                .iter()
                .find(|sh| sh.mem_range().contains(&vaddr))
            {
                Some(s) => s,
                None => return Ok(()),
            };

            let name = file.shstrtab_entry(section.name);
            let sect_offset = vaddr - section.addr;
            println!(
                "At section {:?} + {} (0x{:x})",
                String::from_utf8_lossy(name),
                sect_offset.0,
                sect_offset.0
            );

            // And, even further, we can try to map it to a symbol. This is all
            // stuff GDB does in its `info addr 0xABCD` command, but isn't it
            // satisfying to re-implement it ourselves?
            match file.read_symtab_entries() {
                Ok(syms) => {
                    for sym in &syms {
                        let sym_range = sym.value..(sym.value + delf::Addr(sym.size));
                        // the first check is for zero-sized symbols, since `sym_range`
                        // ends up being a 0-sized range.
                        if sym.value == vaddr || sym_range.contains(&vaddr) {
                            let sym_offset = vaddr - sym.value;
                            let sym_name = String::from_utf8_lossy(file.strtab_entry(sym.name));
                            println!(
                                "At symbol {:?} + {} (0x{:x})",
                                sym_name, sym_offset.0, sym_offset.0
                            );
                        }
                    }
                }
                Err(e) => println!("Could not read syms: {:?}", e),
            }
        }
        Ok(())
    })
}

fn cmd_run(args: RunArgs) -> Result<(), Box<dyn Error>> {
    // these are the usual steps
    let mut proc = process::Process::new();
    let exec_index = proc.load_object_and_dependencies(&args.exec_path)?;
    proc.apply_relocations()?;
    proc.adjust_protections()?;

    // we'll need those to handle C-style strings (null-terminated)
    use std::ffi::CString;

    let exec = &proc.objects[exec_index];
    // the first argument is typically the path to the executable itself.
    // that's not something `argh` gives us, so let's add it ourselves
    let args = std::iter::once(CString::new(args.exec_path.as_bytes()).unwrap())
        .chain(
            args.args
                .iter()
                .map(|s| CString::new(s.as_bytes()).unwrap()),
        )
        .collect();

    let opts = process::StartOptions {
        exec,
        args,
        // on the stack, environment variables are null-terminated `K=V` strings.
        // the Rust API gives us key-value pairs, so we need to build those strings
        // ourselves
        env: std::env::vars()
            .map(|(k, v)| CString::new(format!("{}={}", k, v).as_bytes()).unwrap())
            .collect(),
        // right now we pass all *our* auxiliary vectors to the underlying process.
        // note that some of those aren't quite correct - there's a `Base` auxiliary
        // vector, for example, which is set to `elk`'s base address, not `echidna`'s!
        auxv: process::Auxv::get_known(),
    };
    proc.start(&opts);

    Ok(())
}

fn _pause(reason: &str) -> Result<(), Box<dyn Error>> {
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
fn _align_lo(x: usize) -> usize {
    x & !0xFFF
}

fn _ndisasm(code: &[u8], origin: delf::Addr) -> Result<(), Box<dyn Error>> {
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

#[allow(named_asm_labels)]
#[inline(never)]
unsafe fn jmp(entry_point: *const u8, stack_contents: *const u64, qword_count: usize) {
    std::arch::asm!(
        // allocate (qword_count * 8) bytes
        "mov {tmp}, {qword_count}",
        "sal {tmp}, 3",
        "sub rsp, {tmp}",

        "l1:",
        // start at i = (n-1)
        "sub {qword_count}, 1",
        // copy qwords to the stack
        "mov {tmp}, QWORD PTR [{stack_contents}+{qword_count}*8]",
        "mov QWORD PTR [rsp+{qword_count}*8], {tmp}",
        // loop if i isn't zero, break otherwise
        "test {qword_count}, {qword_count}",
        "jnz l1",

        "jmp {entry_point}",

        entry_point = in(reg) entry_point,
        stack_contents = in(reg) stack_contents,
        qword_count = in(reg) qword_count,
        tmp = out(reg) _,
    )
}
