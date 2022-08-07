#!/bin/python3

from enum import Enum

""" The different printing formats """
class FormatSize(Enum):
    b    = 1
    w    = 4
    g    = 8
    

""" Guests supported by our script """
class Guests(Enum):
    RAWC = "rawc"
    LINUX = "linux"

""" Memory offsets, for the moment we have an enum.
    A better solution would have tyche dump them in a file at startup,
    so that we can read them."""
class InstanceOffsets(Enum):
    tyche = 0x18000000000
    rawc = 0x4e0000

class AddressContext(Enum):
    tyche_virt = -1 * InstanceOffsets.tyche.value
    tyche_phys = 0
    rawc_virt = InstanceOffsets.rawc.value
    rawc_phys = InstanceOffsets.rawc.value


QEMU_RAMFILE="/tmp/tyche"

class TycheGuestMemoryDump (gdb.Command):
    def __init__(self):
        super (TycheGuestMemoryDump, self).__init__("tmd", gdb.COMMAND_USER)

    """ The command expects arg =  context format start size.
        `context` is a value of AddressContext enum. 
        `format` can be b (bytes), w (word, i.e., 4 bytes), g (giant, 8 bytes).
        `start` is the start address in tyche physical memory. 
        `size` is the number of elements to print.
        Both `start` and `size` are passed as is to the linux xxd command."""
    def invoke(self, arg, from_tty):
        args = arg.split(" ")
        if len(args) != 4:
            print("Wrong number of arguments ", len(args))
            return
        (context, fmt, offset, size) = args
        
        format_size = FormatSize[fmt]
        context_real = AddressContext[context]

        """ Here we have a choice of either calling an external program to read
         the tyche ram, or doing it directly in python.
         For now, we use xxd but this might change later on.
        """
        import os
        # Convert the size into an int.
        b_size = 0
        try:
            b_size = int(size)
        except ValueError:
            print("Error: size is not an int ", size)
            return
        b_size = b_size * format_size.value
        
        start = str(int(offset, 16) + context_real.value)
        command = [
                "xxd",
                "-seek",
                start,
                "-l",
                str(b_size),
                QEMU_RAMFILE,
                ]
        os.system(" ".join(command))

""" Small gdb command to get and set the guest start address.
This command accesses the static global variable crate::debug::info::GUEST_START.
For some reason, gdb is unable to directly print it so we have to do some python
scripting in order to access its value.
This command creates a gdb global variable tyche_guest_address with the offset."""
class TycheUpdateGuestStartAddress(gdb.Command):
    def __init__(self):
        super (TycheUpdateGuestStartAddress, self).__init__("tyche_ugsa", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        infos = gdb.execute('info variables -q GUEST_START', to_string=True).split()
        address = infos[-2]
        offset = gdb.execute("x/1g "+address, to_string=True).split()[-1]
        gdb.execute("set $tyche_guest_address ="+hex(int(offset, 16)))

TycheGuestMemoryDump()
TycheUpdateGuestStartAddress()
