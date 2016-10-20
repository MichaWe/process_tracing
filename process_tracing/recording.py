"""
Process tracing event recording component

Package: process_tracing
Author: Michael Witt
Mail: m.witt@htw-berlin.de
Licence: GPLv3
"""
import time
import os
from process_tracing.constants import *
from ptrace.syscall.socketcall_struct import sockaddr, sockaddr_un
from ptrace.syscall.socketcall import AF_FILE


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

    def runtime_log(self, message_type, message=None, signal=None, exit_code=None, child_pid=None):
        """
        Record the given message (of process related recording is enabled)
        :param message_type: Process action type
        :param message: Additional message
        :param signal: Received signal number
        :param exit_code: Exit code to associate with the log entry
        :param child_pid: Child pid to associate with the object
        :return: None
        """
        if self.mode & TRACING_MODE_RUNTIME_TRACING:
            self._log.append(RuntimeActionRecord(message_type, message, signal, exit_code, child_pid))

    def syscall_log(self, syscall):
        """
        Record the given syscall
        :param syscall: Syscall to record
        :return: None
        """

        # Check if syscall tracing is enabled
        if self.mode & TRACING_MODE_SYSCALLS:
            # Check if this is the result of a syscall or a new issued syscall
            is_new_syscall = (syscall.result is None)
            extract_arguments = ((self.mode & TRACING_MODE_SYSCALL_ARGUMENTS) != 0)

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
        if self.mode & TRACING_MODE_FILE_ACCESS:
            # Check if this is the result of a syscall or a new issued syscall
            is_new_syscall = (syscall.result is None)
            detailed = ((self.mode & TRACING_MODE_FILE_ACCESS_DETAILED) != 0)

            if not is_new_syscall:
                self._log.append(FileAccessRecord(syscall, detailed))

    def get_exit_code(self):
        """
        Search for the exit code of the given traced process or thread
        This will search the log for a RuntimeActionRecord with the RuntimeActionRecord.TYPE_EXITED type
        :return: Exit code if a matching record was found, else None
        """
        for entry in reversed(self._log):
            if type(entry) == RuntimeActionRecord and entry.type == RuntimeActionRecord.TYPE_EXITED:
                return entry.exit_code

        return None

    def get_start_time(self):
        """
        Search for the process creation record and return the timestamp
        :return: Timestamp or None if no process creation record is found
        """
        for entry in self._log:
            if type(entry) == RuntimeActionRecord and entry.type == RuntimeActionRecord.TYPE_STARTED:
                return entry.timestamp

        return None

    def get_result_stats(self):
        """
        Search for the exit code, exit signal and exit time of the given traced process or thread
        :return: Tuple with (Exit time, Exit Code, Termination Signal) or None is no record was found
        """
        for entry in reversed(self._log):
            if type(entry) == RuntimeActionRecord and entry.type == RuntimeActionRecord.TYPE_EXITED:
                return entry.timestamp, entry.exit_code, entry.signal

        return None

    exit_code = property(get_exit_code)


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

    def __repr__(self):
        return '[{}] LOG: {}'.format(self.timestamp, self.message)


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

    def __init__(self, message_type, message=None, signal=None, exit_code=None, child_pid=None):
        """
        Create a record for the given message
        :param message_type: Type of the message that occurred
        :param message: Optional message to describe the action
        :param signal: Received signal number
        :param exit_code: Exit code to associate with the log entry
        :param child_pid: Child pid to associate with the object

        """
        super().__init__(message)
        self.type = message_type

        self.signal = signal
        self.exit_code = exit_code

        if child_pid:
            self.child_pid = child_pid

    def __repr__(self):
        message = "Unknown type"
        if self.type == RuntimeActionRecord.TYPE_STARTED:
            message = "Process started"
        elif self.type == RuntimeActionRecord.TYPE_EXITED:
            message = "Process terminated: {}".format(self.message)
        elif self.type == RuntimeActionRecord.TYPE_SIGNAL_RECEIVED:
            message = "Process received signal {}".format(self.message)
        elif self.type == RuntimeActionRecord.TYPE_EXEC:
            message = "Process executed action with execve"
        elif self.type == RuntimeActionRecord.TYPE_SPAWN_CHILD:
            message = "Process spawned a child process"

        return '[{}] Process Event: {}'.format(self.timestamp, message)


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
        self.id = syscall.syscall
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

    def __repr__(self):
        return '[{}] Syscall: {} result: {}'.format(self.timestamp, self.name, self.result)


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
    def __init__(self, syscall, detailed):
        """
        Create a new record for the given syscall that accessed a file
        :param syscall: Syscall structure from ptrace to extract information from
        :param detailed: Specify True if additional file access data should be recorded
        """
        super().__init__(None)

        self.name = syscall.name
        self.id = syscall.syscall
        self.result = syscall.result
        self.filename = None
        self.is_dir = None
        self.exists = None

        for argument in syscall.arguments:
            if "char *" in argument.type:
                text, _ = syscall.process.readCString(argument.value, 1000)
                if text:
                    self.filename = text.decode('utf-8')
                    break

            elif "sockaddr *" in argument.type:
                s = syscall.process.readStruct(argument.value, sockaddr)
                if s.family == AF_FILE:
                    v = syscall.process.readStruct(argument.value, sockaddr_un)
                    self.filename = v.sun_path.decode('utf-8')
                    break

        if self.filename and detailed:
            self.is_dir = os.path.isdir(self.filename)
            self.exists = os.path.exists(self.filename)

    def __repr__(self):
        return '[{}] File access to {} by syscall {}, result: {} (exits: {}, is_dir: {})'.format(
            self.timestamp, self.filename, self.name, self.result, self.exists, self.is_dir)
