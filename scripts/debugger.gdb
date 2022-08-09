# This file is sourced when running the debugger's gdb session.

# Load the python commands
source scripts/debug_server.py

# Does a stack switch and a backtrace
define stack_switch_print
  set $rsp=$arg0
  set $rbp=$arg1
  bt
end

# Loads the source file for the guest and starts the python server for gdb cmds
b gdb_block
commands $bpnum
  debugger_load_img
  start_debug_server
end
