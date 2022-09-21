# This file is sourced when running the debugger's gdb session.

# Load the python commands
source scripts/debug_server.py

# Loads the source file for the guest and starts the python server for gdb cmds
b gdb_block
commands $bpnum
  debugger_load_img
  start_debug_server
end
