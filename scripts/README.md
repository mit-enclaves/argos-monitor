# Collection of debugging scripts and commands

## Main Debugging Session

### GDB wrapper

**file**: `tyche-gdb`

**description**: A wrapper for gdb responsible for loading the custom debugging scripts defined in this folder.

**usage**: The script expects exactly one argument in `{linux, rawc}`.

**behaviour**: Attaches to the remote qemu gdb session, loads the `tyche-gdb.gdb` custom commands, and adds symbols for the proper guest image, i.e., either `linux` or `rawc`.

### The tyche GDB script

**file**: `tyche-gdb.gdb`

**description**: Gdb configuration to debug tyche.

**usage**: Automatically loaded by `tyche-gdb`.

**behaviour**: The script performs the following essential modifications to the debugging environment:
1. It replaces software breakpoints with hardware ones, i.e., `b` command becomes equivalent to `hb`.
2. It allows pending breakpoints by default.
3. Imports the guest symbols in the session.
4. Loads the `tyche_debug.py` script for custom commands (see below).
5. Sets a breakpoint at `tyche_hook_done`, a post guest load point, and extracts the host physical start address of guest RAM memory (`tyche_ugsa` command) before starting a remote debugging server (`tyche_start_server` command). 

**BUGS**:
1. For some reason, I cannot automatically continue after the `tyche_hook_done`.
A `cont` in the command crashes the gdb session.

### Custom GDB commands written in Python

**file**: `tyche_debug.py`

**description**: Set of custom commands available in the debugging session.
We chose to implement them as commands rather than functions to reduce the verbosity of invocation.

**behaviour**: The script defines 3 commands (and one prototype left for reference).

1. `tyche_ugsa`: Defined in the class `TycheUpdateGuestStartAddress`.
This command copies the `GUEST_START` global variable defined in tyche in the gdb variable `tyche_guest_address` for quick access.
The command is automatically called after hitting the `tyche_hook_done` breakpoint function.

2. `tyche_start_server`: Defined in the class `TycheStartServer`.
This command spawns a separate process running a gdb session attached to `debugger/debugger` and configured to let it run until the program mmaps QEMU RAM. After that, it spawns a python tcp server waiting for remote commands.
The output of the debugger is available in `/tmp/debugger.out`. 

**BUGS**:
a. Gdb does not allow setting debug variables with `-ex` or to pass strings. As a result, this command dumps an id for the guest (0 for rawc, 1 for linux as defined in `debug_server.py` enum) and the `tyche_guest_address` in the file `/tmp/guest_info` which is then read by the server. 
b. I cannot remove the breakpoint on main in the `debugger`. As a result, the command to start the server includes a continue.

3. `tyche`: Defined in the class `TycheClient`.
This command has the following format: 
```
tyche {context} {command} {args}
```
The `context` must be a valid key in the `AddressContext` map, i.e., one of `{tyche_virt, tyche_phys, guest_phys, guest_virt}`.
It is used to understand how to interpret `args` addresses wrapped in `@` symbols and automatically offset them before sending the `command` to the remote server listening on `localhost:5678`.

## Remote Debugger

### Debugging script

**file**: `debugger.gdb`

**description**: Custom debugging configuration for `debugger/debugger`.

**behaviour**: Loads the Python commands from `debug_server.py` and sets a post-initialization breakpoint on `gdb_block`, loads the guest image to have access to symbols, and starts the debug server.

**BUGS**: As mentionned above, my local gdb config apparently sets the main breakpoint after `start`, thus forcing us to spawn this gdb session with a `-ex "c"` to continue after hitting main.
Depending on your local gdb config, you might not have the same issue.

### Custom Python GDB commands

**file**: `debug_server.py`

**description**: Defines two custom python commands.

**behaviour**: The script is automatically loaded by the `debugger.gdb` configuration.
The custom commands are:

1. `debugger_load_img`: defined by the class `LoadDebugInfo`, automatically called by the `debugger.gdb` script.
Reads the `/tmp/guest_info` file, and loads the correct guest (0. rawc or 1. linux) synmbols at the offset computed as `tyche_start_address` (from `guest_info`) added to the mmap start address (`dbg_offset`).

2. `start_debug_server`: defined by the class `DebugServer`. Starts a python tcp server on `localhost:5678` waiting for commands. Any value wrapped in `@` will be offsetted by `dbg_offset`, i.e., the beginning of the mmaped QEMU RAM. We also support special command `QUIT` to stop the server.
