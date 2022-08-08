# This file is sourced when running the debugger's gdb session.

# Loads the source file for the guest and starts the python server for gdb cmds
b gdb_block
commands $bpnum
  debugger_load_file
  start_debug_server
end
