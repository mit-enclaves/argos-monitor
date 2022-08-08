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
    guest_phys = 0 # Use the command tyche_ugsa
    guest_rawc_virt = 0 #InstanceOffsets.rawc.value


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
        offset = gdb.execute("x/1gx "+address, to_string=True).split()[-1]
        print("The offset ", offset)
        gdb.execute("set $tyche_guest_address ="+offset)


""" Starts the remote gdb session attached to the debugger/debugger executable.
The remote gdb session executes until QEMU file-backed memory is mmaped into
the process'address space. It then blocks on gdb_block function and starts the server."""
class TycheStartServer(gdb.Command):
    def __init__(self):
        super (TycheStartServer, self).__init__("tyche_start_server", gdb.COMMAND_USER)

    """@warning there is a continue to avoid the main breakpoint.
    If you do not have one set, we should remove that."""
    def invoke(self, arg, from_tty):
        import os
        # Get the name of the binary
        name = gdb.execute("p $tyche_guest_image", to_string=True).split()[-1]
        command = [
                "nohup",
                "gdb",
                "./debugger/debugger",
                "-ex",
                '"source scripts/debug_server.py"',
                "-ex",
                '"b gdb_block"',
                "-ex",
                '"start"',
                "-ex",
                '"c"',
                "-ex",
                '"start_debug_server"',
                ">",
                "/tmp/debugger.out",
                "2>&1",
                "&"
                ]
        os.system(" ".join(command)) 

""" Receiving the entire message """
def recvall(sock):
    BUFF_SIZE = 4096 # 4 KiB
    data = b''
    while True:
        part = sock.recv(BUFF_SIZE)
        data += part
        if len(part) < BUFF_SIZE:
            # either 0 or end of data
            break
    return data.decode().strip()

""" Sends a command to the remote debugger server and waits for the response """
def execute_command(cmd):
    import sys
    import socket
    # Create a TCP/IP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = ("localhost", 5678)
    sock.connect(server_address)
    try:
        sock.sendall(cmd.encode())
        response = recvall(sock)
        print(response)
    finally:
        sock.close()
    

""" This command forwards gdb commands to the debugger server. """
class TycheClient(gdb.Command):
    def __init__(self):
        super (TycheClient, self).__init__("tyche", gdb.COMMAND_USER)

    """ The format for this command is: tyche `context` `command`.
    Moreover, we allow automatic translation of addresses surrounded by @s """
    def invoke(self, arg, from_tty):
        # Update the guest address.
        res = gdb.execute("p/x $tyche_guest_address", to_string=True)
        guest_start = int(res.split()[-1], 16)
        args = arg.split()

        # Find the context & compute the offset
        context = AddressContext[args[0]]
        offset = context.value
        if context.name.startswith("guest_"):
            offset += guest_start
        
        # Replace addresses according to context
        for i, a in enumerate(args):
            if a.startswith("@") and a.endswith("@"):
                value = a[1:-1]
                replace = "@"+value+"+"+str(offset)+"@"
                args[i] = replace

        # Now send the command to the remote server without the context
        execute_command(" ".join(args[1:])) 


TycheGuestMemoryDump()
TycheUpdateGuestStartAddress()
TycheStartServer()
TycheClient()
