"""
Process tracing constants

Package: process_tracing
Author: Michael Witt
Mail: m.witt@htw-berlin.de
Licence: GPLv3
"""

TRACING_MODE_RUNTIME_TRACING = 0x1
TRACING_MODE_FILE_ACCESS = 0x2
TRACING_MODE_SYSCALLS = 0x4
TRACING_MODE_SYSCALL_ARGUMENTS = 0x8

TRACING_MODE_MASK = 0xFF