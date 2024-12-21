#![no_main]
#![feature(lang_items)]
#![no_std]
#![feature(naked_functions)]


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
    for &arg in args {
        write(STDOUT_FILENO, arg, strlen(arg));
    }

    exit(argc as _);
}
#[lang = "eh_personality"]
fn eh_personailty() {}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
