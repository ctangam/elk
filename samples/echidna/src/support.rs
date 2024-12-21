use core::arch::asm;

// reminder: `!` is the `never` type - this indicates
// that `exit` never returns.
pub unsafe fn exit(code: i32) -> ! {
    let syscall_number: u64 = 60;
    asm!(
        "syscall",
        in("rax") syscall_number,
        in("rdi") code,
        options(noreturn)
    )
}

pub const STDOUT_FILENO: u32 = 1;

pub unsafe fn write(fd: u32, buf: *const u8, count: usize) {
    let syscall_number: u64 = 1;
    asm!(
        "syscall",
        in("rax") syscall_number,
        in("rdi") fd,
        in("rsi") buf,
        in("rdx") count,
        // Linux syscalls don't touch the stack at all, so
        // we don't care about its alignment
        options(nostack)
    );
}

pub unsafe fn strlen(mut s: *const u8) -> usize {
    let mut count = 0;
    while *s != b'\0' {
        count += 1;
        s = s.add(1);
    }
    count
}