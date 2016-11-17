"""
Process tracing constants

Package: process_tracing
Author: Michael Witt
Mail: m.witt@htw-berlin.de
Licence: GPLv3
"""

TRACING_MODE_RUNTIME_TRACING = 0x01
TRACING_MODE_FILE_ACCESS = 0x02
TRACING_MODE_FILE_ACCESS_DETAILED =  TRACING_MODE_FILE_ACCESS | 0x04
TRACING_MODE_SYSCALLS = 0x08
TRACING_MODE_SYSCALL_ARGUMENTS = TRACING_MODE_SYSCALLS | 0x10

TRACING_MODE_MASK = 0xFF

TRACING_RECORD_MODE_MEMORY = 0x1
TRACING_RECORD_MODE_FILE = 0x2
TRACING_RECORD_MODE_CALLBACK = 0x4