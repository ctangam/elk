void ftl_exit(int code) {
    __asm__ (
            " \
            mov %[code], %%edi \n\
            mov $60, %%rax \n\
            syscall"
            :
            : [code] "r" (code)
    );
}

extern int number;

extern void change_number(void);

void _start(void) {
    change_number();
    ftl_exit(number);
}