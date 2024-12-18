use core::str;
use std::{env, error::Error};

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
            .find(|sh| file.get_section_name(&contents, sh.name).unwrap() == b".text")
        {
            Some(section) => section,
            _ => return Ok(()),
        };

        let textaddress = mapping.addr_range.start - mapping.offset + section.off;
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

// Here's our new command:
fn cmd_dig(args: DigArgs) -> Result<(), Box<dyn Error>> {
    let addr = delf::Addr(args.addr);

    with_mappings(args.pid, |mappings| {
        for mapping in mappings {
            if mapping.addr_range.contains(&addr) {
                println!("Found mapping: {:#?}", mapping);
                return Ok(());
            }
        }
        Ok(())
    })
}

fn cmd_run(args: RunArgs) -> Result<(), Box<dyn Error>> {
    let mut proc = process::Process::new();
    // ...except we now take `exec_path` from the `args` argument instead of
    // calling `std::env::args()` ourselves!
    let exec_index = proc.load_object_and_dependencies(args.exec_path)?;
    proc.apply_relocations()?;
    proc.adjust_protections()?;

    let exec_obj = &proc.objects[exec_index];
    let entry_point = exec_obj.file.entry_point + exec_obj.base;
    unsafe { jmp(entry_point.as_ptr()) };

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

unsafe fn jmp(addr: *const u8) {
    let fn_ptr: fn() = std::mem::transmute(addr);
    fn_ptr();
}
