"""
Process tracing event recording component

Package: process_tracing
Author: Michael Witt
Mail: m.witt@htw-berlin.de
Licence: GPLv3
"""
import time
import os
import csv
from process_tracing.constants import *
from ptrace.syscall.socketcall_struct import sockaddr, sockaddr_un
from ptrace.syscall.socketcall import AF_FILE
from ptrace.error import PtraceError
from multiprocessing import Lock


class TracingRecord(object):
    """
    Class that encapsulates all information about a traced process or thread
    """

    _file_locks = {}
    _file_locks_access_lock = Lock()

    def __init__(self, pid, mode, recording_mode=TRACING_RECORD_MODE_MEMORY, log_filename=None, log_callback=None):
        """
        Create a new tracing record for the given process or thread id
        and use the given mode to configure logging details
        :param pid: Process or thread id the record is created for
        :param mode: Tracing mode
        :param recording_mode: Mask to configure how recorded events should be saved
        :param log_filename: If the recording_mode contains TRACING_RECORD_MODE_FILE you must specify a filename
                             where you want to write the log data to - writing to the file will be thread save
        :param log_callback: If the recording_mode contains TRACING_RECORD_MODE_CALLBACK you must specify a function to
                             invoke for every log entry
        """
        self.pid = pid
        self.mode = mode
        self.recording_mode = recording_mode
        self.log_filename = log_filename
        self.log_callback = log_callback

        if self.recording_mode & TRACING_RECORD_MODE_FILE and not self.log_filename:
            raise AttributeError("File recording requested but no log file specified")

        if self.recording_mode & TRACING_RECORD_MODE_CALLBACK and not self.log_callback:
            raise AttributeError("Callback invocation recording requested but no callback method specified")

        if self.recording_mode & TRACING_RECORD_MODE_FILE and self.log_filename:
            TracingRecord._file_locks_access_lock.acquire()
            if self.log_filename not in TracingRecord._file_locks.keys():
                file = open(self.log_filename, 'w', newline='\n')
                writer = csv.writer(file, delimiter=';', quotechar='"', quoting=csv.QUOTE_ALL)
                TracingRecord._file_locks[self.log_filename] = (Lock(), writer, file)
            TracingRecord._file_locks_access_lock.release()

        self._log = []
        self._syscall_cache = []

        self._exit_code = None
        self._start_time = None
        self._end_time = None
        self._signal = None

    def _save_log_message(self, record):
        """
        Save the given log record - this will handle the recording mode according to the user preferences
        :param record: Record to persist
        :return: None
        """
        if self.recording_mode & TRACING_RECORD_MODE_MEMORY:
            self._log.append(record)

        if self.recording_mode & TRACING_RECORD_MODE_FILE:
            # Aquire file lock
            lock, writer, file = TracingRecord._file_locks[self.log_filename]
            lock.acquire()
            writer.writerow([self.pid] + record.get_log_message_items())
            lock.release()

        if self.recording_mode & TRACING_RECORD_MODE_CALLBACK:
            self.log_callback(self, record)

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
        self._save_log_message(LogRecord(message))

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
            record = RuntimeActionRecord(message_type, message, signal, exit_code, child_pid)
            self._save_log_message(record)

            if message_type == RuntimeActionRecord.TYPE_EXITED:
                self._exit_code = exit_code
                self._signal = signal
                self._end_time = record.timestamp
            elif message_type == RuntimeActionRecord.TYPE_STARTED:
                self._start_time = record.timestamp

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
            extract_arguments = ((self.mode & TRACING_MODE_SYSCALL_ARGUMENTS) == TRACING_MODE_SYSCALL_ARGUMENTS)

            if is_new_syscall:
                self._syscall_cache.append(SyscallRecord(syscall, extract_arguments))
            else:
                # Find the last syscall log entry
                for index in range(-1, -(len(self._syscall_cache) + 1), -1):
                    entry = self._syscall_cache[index]
                    if entry.name == syscall.name:
                        entry.update(syscall)
                        self._save_log_message(entry)
                        self._syscall_cache.pop(index)
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
            detailed = ((self.mode & TRACING_MODE_FILE_ACCESS_DETAILED) == TRACING_MODE_FILE_ACCESS_DETAILED)

            if not is_new_syscall:
                self._save_log_message(FileAccessRecord(syscall, detailed))

    def get_exit_code(self):
        """
        Search for the exit code of the given traced process or thread
        This will search the log for a RuntimeActionRecord with the RuntimeActionRecord.TYPE_EXITED type
        :return: Exit code if a matching record was found, else None
        """
        return self._exit_code

    def get_start_time(self):
        """
        Search for the process creation record and return the timestamp
        :return: Timestamp or None if no process creation record is found
        """
        return self._start_time

    def get_result_stats(self):
        """
        Search for the exit code, exit signal and exit time of the given traced process or thread
        :return: Tuple with (Exit time, Exit Code, Termination Signal) or None is no record was found
        """
        return self._end_time, self._exit_code, self._signal

    exit_code = property(get_exit_code)

    @staticmethod
    def flush():
        """
        Close all open file handles and flush the log file dictionary
        All existing TracingRecord instances will no longer be able to write log files after invoking this method
        :return: None
        """
        TracingRecord._file_locks_access_lock.acquire()
        for filename in  TracingRecord._file_locks.keys():
            lock, writer, file = TracingRecord._file_locks[filename]
            lock.acquire()
            file.close()
            lock.release()

        TracingRecord._file_locks = {}
        TracingRecord._file_locks_access_lock.release()


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

    def get_log_message_items(self):
        """
        Return all fields in a list that should be written to CSV log file
        :return: List of items to save
        """
        return ["log", self.timestamp, self.message]

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
        else:
            self.child_pid = None

    def get_log_message_items(self):
        return ["run", self.timestamp, RuntimeActionRecord._get_type_name(self.type), self.message, self.exit_code,
                self.signal, self.child_pid]

    @staticmethod
    def _get_type_name(type):
        """
        Return the human readable type name
        :param type: Type identifier number
        :return: String identifying the type
        """
        if type == RuntimeActionRecord.TYPE_STARTED:
            return "start"
        elif type == RuntimeActionRecord.TYPE_EXITED:
            return "exit"
        elif type == RuntimeActionRecord.TYPE_SIGNAL_RECEIVED:
            return "signal"
        elif type == RuntimeActionRecord.TYPE_EXEC:
            return "execve"
        elif type == RuntimeActionRecord.TYPE_SPAWN_CHILD:
            return "spawn"
        else:
            return "unknown"

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
        else:
            self.arguments = None

    def get_log_message_items(self):
        items = ["syscall", self.timestamp, self.name, self.id, self.t_start, self.t_end, self.result]
        if self.arguments:
            for item in self.arguments:
                items += item.get_log_message_items()

        return items

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
        try:
            self.text = argument.getText()
        except PtraceError as pte:
            self.text = ""

    def get_log_message_items(self):
        return [self.name, self.type, self.text]


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
            try:
                if "char *" in argument.type:
                    text, _ = syscall.process.readCString(argument.value, 1024)
                    if text:
                        self.filename = text.decode('utf-8')
                        break

                elif "sockaddr *" in argument.type:
                    s = syscall.process.readStruct(argument.value, sockaddr)
                    if s.family == AF_FILE:
                        v = syscall.process.readStruct(argument.value, sockaddr_un)
                        self.filename = v.sun_path.decode('utf-8')
                        break
            except PtraceError:
                # argument reading may fail
                pass

        if self.filename and detailed:
            self.is_dir = os.path.isdir(self.filename)
            self.exists = os.path.exists(self.filename)

    def get_log_message_items(self):
        return ["file", self.timestamp, self.filename, self.name, self.result, self.is_dir, self.exists]

    def __repr__(self):
        return '[{}] File access to {} by syscall {}, result: {} (exits: {}, is_dir: {})'.format(
            self.timestamp, self.filename, self.name, self.result, self.exists, self.is_dir)
