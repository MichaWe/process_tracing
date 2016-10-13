"""
Process tracing event recording component

Package: process_tracing
Author: Michael Witt
Mail: m.witt@htw-berlin.de
Licence: GPLv3
"""
import time
import os
from process_tracing.tracing import Tracing


class TracingRecord(object):
    """
    Class that encapsulates all information about a traced process or thread
    """

    def __init__(self, pid, mode):
        """
        Create a new tracing record for the given process or thread id
        and use the given mode to configure logging details
        :param pid: Process or thread id the record is created for
        :param mode: Tracking mode
        """
        self.pid = pid
        self.mode = mode

        self._log = []

    def get_log(self):
        """
        Return the text log that contains basic process tracing events
        :return: list of LogRecord-Objects
        """
        return self._log

    def log(self, message):
        """
        Record the given message in the basic tracing log
        :param message: Message to record
        :return: None
        """
        self._log.append(LogRecord(message))

    def runtime_log(self, message_type, message=None):
        """
        Record the given message (of process related recording is enabled)
        :param message_type: Process action type
        :param message: Additional message
        :return: None
        """
        if self.mode & Tracing.MODE_RUNTIME_TRACING:
            self._log.append(RuntimeActionRecord(message_type, message))

    def syscall_log(self, syscall):
        """
        Record the given syscall
        :param syscall: Syscall to record
        :return: None
        """

        # Check if syscall tracing is enabled
        if self.mode & Tracing.MODE_SYSCALLS:
            # Check if this is the result of a syscall or a new issued syscall
            is_new_syscall = (syscall.result is None)
            extract_arguments = ((self.mode & Tracing.MODE_SYSCALL_ARGUMENTS) != 0)

            if is_new_syscall:
                self._log.append(SyscallRecord(syscall, extract_arguments))
            else:
                # Find the last syscall log entry
                for entry in reversed(self._log):
                    if type(entry) == SyscallRecord:
                        entry.update(syscall)
                        break

    def file_access_log(self, syscall):
        """
        Record the given syscall that is associated with file access
        :param syscall: Syscall to record
        :return: None
        """
        if self.mode & Tracing.MODE_FILE_ACCESS:
            # Check if this is the result of a syscall or a new issued syscall
            is_new_syscall = (syscall.result is None)

            if not is_new_syscall:
                self._log.append(FileAccessRecord(syscall))


class LogRecord(object):
    """
    Single entry in the the tracing record log
    """

    def __init__(self, message):
        """
        Create a record for the given message
        :param message: Message to record
        """
        self.timestamp = time.time()
        self.message = message


class RuntimeActionRecord(LogRecord):
    """
    Single entry that reflects an action of a process or thread
    """

    # Type constants
    TYPE_STARTED = 0
    TYPE_EXITED = 1
    TYPE_SIGNAL_RECEIVED = 2
    TYPE_EXEC = 3
    TYPE_SPAWN_CHILD = 4

    def __init__(self, message_type, message=None):
        """
        Create a record for the given message
        :param message_type: Type of the message that occurred
        :param message: Optional message to describe the action
        """
        super().__init__(message)
        self.type = message_type


class SyscallRecord(LogRecord):
    """
    Single entry of a captured syscall with optional arguments
    """
    def __init__(self, syscall, extract_arguments=False):
        """
        Create a new record for the given syscall
        :param syscall: Syscall structure from ptrace to extract information from
        :param extract_arguments: Specify True to extract syscall argument information
        """
        super().__init__(None)

        self.name = syscall.name
        self.id = syscall.id
        self.t_start = self.timestamp
        self.t_end = None
        self.result = None

        if extract_arguments:
            self.arguments = []
            for argument in syscall.arguments:
                self.arguments.append(SyscallArgument(argument))

    def update(self, syscall):
        """
        Update the given record with information from the given syscall structure
        :param syscall: Syscall structure from ptrace to extract information from
        :return: None
        """
        self.t_end = time.time()
        self.result = syscall.result


class SyscallArgument(object):
    """
    Reflects a single syscall argument
    """
    def __init__(self, argument):
        """
        Create a new record for the given argument
        :param argument: Argument to build the record for
        """
        self.name = argument.name
        self.type = argument.type
        self.value = argument.value
        self.text = argument.getText()


class FileAccessRecord(LogRecord):
    """
    Single entry of a captured file access syscall
    """
    def __init__(self, syscall):
        """
        Create a new record for the given syscall that accessed a file
        :param syscall: Syscall structure from ptrace to extract information from
        """
        super().__init__(None)

        self.name = syscall.name
        self.id = syscall.id
        self.result = syscall.result
        self.filename = None
        self.is_dir = False
        self.exists = False

        for argument in syscall.arguments:
            if "char *" in argument.type:
                # Get argument text and strip redundant quotes
                text = argument.getText()
                self.filename = text[text.index("'") + 1:text.rindex("'")]
                self.is_dir = os.path.isdir(self.filename)
                self.exists = os.path.exists(self.filename)
                break