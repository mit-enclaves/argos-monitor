""" Global static rust variable that we want to capture right after instantiation.
This is done automatically by the tyche_set_convenience_vars command as we reach
the tyche_hook_done function."""
CAPTURED_VARIABLES = [
        "STAGE2_POFF",
        "STAGE2_VOFF",
        ]
