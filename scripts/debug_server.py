#!/bin/python3

import sys
import gdb
import socket
from enum import Enum

""" Special commands for the server. """
class SpecialCommands(Enum):
    QUIT = 0
    STACK = 1

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

def get_offset():
    res = gdb.execute("p/x dbg_offset", to_string=True)
    return int(res.split()[-1], 16)

""" Processing the command. 
    We automatically add the offset of the mmaped region to any value enclosed in `@`, e.g., `@0xdeadbeef@`.
"""
def process_command(command):
    offset = get_offset()
    parts = command.split()
    print("the parts ", parts)
    for idx, entry in enumerate(parts):
        if entry.startswith("@") and entry.endswith("@"):
            replace = entry[1:-1]+"+"+str(offset)
            parts[idx] = replace
    command = " ".join(parts)
    output = gdb.execute(command, to_string=True)
    return output


class DebugServer(gdb.Command):
    def __init__(self):
        super (DebugServer, self).__init__("start_debug_server", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        """ Start a server listening for commands"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_address = ('localhost', 5678)
        print('starting up on %s port %s' % server_address, file=sys.stderr)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(server_address)
        sock.listen(1)
        cmds = [x.name for x in SpecialCommands]
        while True:
            # Wait for a connection
            print('waiting for a connection', file=sys.stderr)
            connection, client_address = sock.accept()
            try:
                print ('connection from', client_address, file=sys.stderr)

                # Receive the data in small chunks and retransmit it
                while True:
                    command = recvall(connection)
                    print('received "%s"' % command, file=sys.stderr)
                    
                    """ Handle special commands """
                    if command in cmds: 
                        if command == SpecialCommands.QUIT.name:
                            connection.sendall("Closing server".encode())
                            connection.close()
                            print("Quitting")
                            return
                    """ Execute other commands """
                    if command:
                        result = process_command(command)
                        connection.sendall(result.encode())
                    else:
                        """ Client quitted """
                        print('no more data from ', client_address, file=sys.stderr)
                        break
            
            finally:
                # Clean up the connection
                connection.close()

""" Loads the debugging information at the right offset """
class LoadDebugInfo(gdb.Command):
    def __init__(self):
        super (LoadDebugInfo, self).__init__("debugger_load_img", gdb.COMMAND_USER) 

    def invoke(self, arg, from_tty):
        paths = {
                    "0": "guest/rawc",
                    "1": "linux-image/images/vmlinux",
                }
        with open("/tmp/guest_info", 'r') as fd:
            lines = fd.readlines()
            path = paths[lines[0].strip()]
            offset = lines[1].strip()
            gdb.execute("set $tyche_guest_address="+offset)
            goff = int(offset, 16)
            value = goff + get_offset()
            gdb.execute("add-symbol-file "+path+" -o "+hex(value))

DebugServer()
LoadDebugInfo()
