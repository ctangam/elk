import subprocess


class AutoSym(gdb.Command):
    """Load symbols for all executable files mapped in memory, through elk"""

    def __init__(self):
        super(AutoSym, self).__init__("autosym", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        pid = gdb.selected_inferior().pid
        if pid == 0:
            print("No inferior.")
            return

        cmd = ["elk", "autosym", str(pid)]
        lines = subprocess.check_output(cmd).decode("utf-8").split("\n")

        for line in lines:
            gdb.execute(line)


AutoSym()


class Dig(gdb.Command):
    """Display all the information ELK can find about a memory address for the current inferior"""

    def __init__(self):
        super(Dig, self).__init__(
            "dig", gdb.COMMAND_USER, gdb.COMPLETE_EXPRESSION)

    def invoke(self, arg, from_tty):
        if arg == "":
            print("Usage: dig ADDR")
            return

        addr = int(arg, 0)

        pid = gdb.selected_inferior().pid
        if pid == 0:
            print("No inferior.")
            return

        cmd = ["elk", "dig", "--pid", str(pid), "--addr", str(addr)]

        # note: `check_call` would print stdout directly, but this somehow
        # breaks GDB TUI, so we print every line ourselves
        lines = subprocess.check_output(cmd).decode("utf-8").split("\n")

        for line in lines:
            print(line)

Dig()