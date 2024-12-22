#![no_main]
#![feature(lang_items)]
#![no_std]
#![feature(naked_functions)]
#![feature(generic_const_exprs)]
#![allow(incomplete_features)]

mod support;
use support::*;
use core::arch::naked_asm;

#[no_mangle]
#[naked]
// new: now extern "C"
pub unsafe extern "C" fn _start() {
    naked_asm!("mov rdi, rsp", "call main");
}

#[no_mangle]
pub unsafe fn main(stack_top: *const u8) {
    let argc = *(stack_top as *const u64);
    let argv = stack_top.add(8) as *const *const u8;

    use core::slice::from_raw_parts as mkslice;
    let args = mkslice(argv, argc as usize);

    println!(b"received ", argc as usize, b" arguments:");
    for &arg in args {
        let arg = mkslice(arg, strlen(arg));
        println!(b" - ", arg);
    }

    const ALLOWED_ENV_VARS: &'static [&[u8]] = &[b"USER=", b"SHELL=", b"LANG="];
    fn is_envvar_allowed(var: &[u8]) -> bool {
        for prefix in ALLOWED_ENV_VARS {
            if var.starts_with(prefix) {
                return true;
            }
        }
        false
    }

    println!(b"environment variables:");
    let mut envp = argv.add(argc as usize + 1) as *const *const u8;
    let mut filtered = 0;
    while !(*envp).is_null() {
        let var = *envp;
        let var = mkslice(var, strlen(var));

        if is_envvar_allowed(var) {
            println!(b" - ", var);
        } else {
            filtered += 1;
        }

        envp = envp.add(1);
    }
    println!(b"(+ ", filtered, b" redacted environment variables)");

    println!(b"auxiliary vectors:");
    let mut auxv = envp.add(1) as *const Auxv;

    let null_auxv = Auxv { typ: 0, val: 0 };

    while (*auxv) != null_auxv {
        println!(b" - ", (*auxv).name(), b": ", (*auxv).formatted_val());
        auxv = auxv.add(1);
    }

    exit(0);
}


#[lang = "eh_personality"]
fn eh_personailty() {}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[derive(PartialEq)]
struct Auxv {
    typ: u64,
    val: u64,
}

impl Auxv {
    fn name(&self) -> &[u8] {
        match self.typ {
            2 => b"AT_EXECFD",
            3 => b"AT_PHDR",
            4 => b"AT_PHENT",
            5 => b"AT_PHNUM",
            6 => b"AT_PAGESZ",
            7 => b"AT_BASE",
            8 => b"AT_FLAGS",
            9 => b"AT_ENTRY",
            11 => b"AT_UID",
            12 => b"AT_EUID",
            13 => b"AT_GID",
            14 => b"AT_EGID",
            15 => b"AT_PLATFORM",
            16 => b"AT_HWCAP",
            17 => b"AT_CLKTCK",
            23 => b"AT_SECURE",
            24 => b"AT_BASE_PLATFORM",
            25 => b"AT_RANDOM",
            26 => b"AT_HWCAP2",
            31 => b"AT_EXECFN",
            32 => b"AT_SYSINFO",
            33 => b"AT_SYSINFO_EHDR",
            _ => b"??",
        }
    }

    fn formatted_val(&self) -> PrintArg<'_> {
        match self.typ {
            3 | 7 | 9 | 16 | 25 | 26 | 33 => PrintArg::Hex(self.val as usize),
            31 | 15 => {
                let s = unsafe {
                    let ptr = self.val as *const u8;
                    core::slice::from_raw_parts(ptr, strlen(ptr))
                };
                PrintArg::String(s)
            }
            _ => PrintArg::Number(self.val as usize),
        }
    }
}