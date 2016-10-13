"""
Process tracing component

Package: process_tracing
Author: Michael Witt
Mail: m.witt@htw-berlin.de
Licence: GPLv3
"""
import psutil
import signal
import posix
from threading import Thread
from process_tracing.recording import TracingRecord, RuntimeActionRecord
from process_tracing.constants import *

from ptrace.debugger import PtraceDebugger, ProcessEvent, NewProcessEvent, ProcessExit, ProcessSignal, ProcessExecution
from ptrace.func_call import FunctionCallOptions


class Tracing:
    """

    """
    def __init__(self, process, stop=False):
        """
        Create a new tracing instance
        This will bind to the given process and enable process observation
        using the capabilities of ptrace
        :param process: psutil.Process instance or pid of the process to trace
        :param stop: Specify true to send SIGSTOP to the process to temporary halt it
        """
        if type(process) == int:
            self.process = psutil.Process(process)
        elif type(process) == psutil.Process:
            self.process = process
        else:
            raise AttributeError("The specified process needs to be a valid PID or psutil.Process instance")

        if stop:
            posix.kill(self.process.pid, signal.SIGSTOP)

        # Initialize debugger and debugger options
        self._debugger_threads = None
        self._debugger_options = FunctionCallOptions(replace_socketcall=False)

        # Recorded process data
        self._process_records = None

        # Filters that may be used to trace only a subset of caught syscalls
        # If this parameters are valid iterables traced syscalls will be checked if they
        # are in the given filter list. If not they won't get recorded
        self.syscall_filter = None
        self.file_access_filter = ["open", "stat", "lstat", "fstat", "access", "connect"]

        self.syscall_filter_exclude = None
        self.file_access_filter_exclude = None

        # We start in Process runtime tracing mode only
        self._mode = TRACING_MODE_RUNTIME_TRACING
        self._running = False

    def get_logs(self):
        """
        Return the tracing records for all processed and threads that has been traced
        :return: Dictionary with process/thread-id as key and TracingRecord-instances as key
        """
        return self._process_records

    def set_running(self, state):
        """
        Set the state of the tracer
        :param state: Specify true to start the tracing process or False to stop tracing
        :return: True if the action could be executed, else False
        """
        if state:
            self.start()
        else:
            self.stop()

    def is_running(self):
        """
        Return the current running state
        :return: True if the tracer is listening to a process, else False
        """
        return self._running and self.process.is_running()

    def start(self):
        """
        Start the process tracing
        :return: True if a new tracing action was executed or False if tracing is already running
        """
        if self.is_running():
            return False

        self._debugger_threads = {}
        self._process_records = {}

        # Spawn the debugger thread for the start process
        if self.process.status() != psutil.STATUS_STOPPED:
            posix.kill(self.process.pid, signal.SIGSTOP)

        self._debugger_threads[self.process.pid] = self._trace_create_thread(self.process.pid)

        # Start debugger for all existing process children
        processes = [self.process] + self.process.children(recursive=True)
        for p in processes:
            # Don't double start tracing of a process
            if p.pid not in self._debugger_threads.keys():
                self._debugger_threads[p.pid] = self._trace_create_thread(p.pid)

            # Start tracing of process threads
            for t in p.threads():
                if t.id not in self._debugger_threads.keys():
                    self._debugger_threads[t.id] = self._trace_create_thread(t.id, is_thread=True)

        # Mark running
        self._running = True
        return True

    def wait(self):
        """
        Wait for tracing to complete (blocking)
        This will invoke start() if no tracing is currently running
        :return: Traced process exit code (if recorded, else True) or False on error
        """
        if not self.is_running():
            if not self.start():
                return False

        # Fetch the main thread
        t = self._debugger_threads[self.process.pid]

        # Wait for main process tracing thread to terminate
        t.join()

        # Fetch execution result
        if self.runtime_tracing:
            record = self._process_records[self.process.pid]
            return record.exit_code
        else:
            return True

    def stop(self):
        """
        Detach all debugger from the processes and threads and terminate all threads
        :return: True if an action was performed else False if no tracing is currently running
        """
        if not self.is_running():
            return False

        # terminate all pending threads

    def set_runtime_tracing(self, enabled):
        """
        Set the runtime tracing mode to the given state
        :param enabled: True if the tracer should record process start, end and subprocess/thread spawn
        :return: None
        """
        self._set_mode_option(TRACING_MODE_RUNTIME_TRACING, enabled)

    def is_runtime_tracing(self):
        """
        Returns True if the current tracer setup has TRACING_MODE_RUNTIME_TRACING enabled, else false
        :return: True or False
        """
        return self._mode & TRACING_MODE_RUNTIME_TRACING

    def set_file_access_tracing(self, enabled):
        """
        Set the file access tracing mode to the given state
        :param enabled: True if the tracer should record all syscalls that are related to filesystem actions
        :return: None
        """
        self._set_mode_option(TRACING_MODE_FILE_ACCESS, enabled)

    def is_file_access_tracing(self):
        """
        Returns True if the current tracer setup has TRACING_MODE_FILE_ACCESS enabled, else false
        :return: True or False
        """
        return self._mode & TRACING_MODE_FILE_ACCESS

    def set_syscall_tracing(self, enabled):
        """
        Set the syscall tracing mode to the given state
        :param enabled: True if the tracer should record all syscalls that occurred during execution
        :return: None
        """
        self._set_mode_option(TRACING_MODE_SYSCALLS, enabled)

    def is_syscall_tracing(self):
        """
        Returns True if the current tracer setup has TRACING_MODE_SYSCALLS enabled, else false
        :return: True or False
        """
        return self._mode & TRACING_MODE_SYSCALLS

    def set_syscall_argument_tracing(self, enabled):
        """
        Set the syscall argument tracing mode to the given state
        :param enabled: True if the tracer should record all arguments of the syscalls that occurred during execution
        :return: None
        """
        self._set_mode_option(TRACING_MODE_SYSCALL_ARGUMENTS, enabled)

    def is_syscall_argument_tracing(self):
        """
        Returns True if the current tracer setup has TRACING_MODE_SYSCALL_ARGUMENTS enabled, else false
        :return: True or False
        """
        return self._mode & TRACING_MODE_SYSCALL_ARGUMENTS

    def _set_mode_option(self, bit, enabled):
        """
        Set the enabled state of the given mode bit
        :param bit: Bit to set to the given state
        :param enabled: New state of the mode bit
        :return: None
        """
        if enabled:
            self._mode |= bit
        else:
            self._mode &= TRACING_MODE_MASK ^ bit

    def _trace_create_thread(self, pid, old_debugger=None, is_thread=False):
        """
        Create a new tracing thread
        :param pid: Process to trace
        :param old_debugger: Old debugger the process might be attached to at the moment
        :param is_thread: True if the pid is a thread else False
        :return: Thread instance
        """

        # Create tracing record
        record = self._create_tracing_record(pid)
        record.runtime_log(RuntimeActionRecord.TYPE_STARTED)

        # Create the new thread
        thread = Thread(target=self._trace_thread, args=(pid, False, is_thread, record))

        # Check if the process is attached to the debugger
        if old_debugger is not None and old_debugger.dict.get(pid):
            old_debugger.dict.get(pid).detach()
            posix.kill(pid, signal.SIGSTOP)

        # run the new thread
        thread.start()
        return thread

    def _trace_thread(self, pid, is_attached, is_thread, record):
        """
        Runner function to trace a process/thread in a new thread
        This will create a debugger, attach the process and terminate on process exit
        :param pid: Process id or thread id to trace
        :param is_attached: Specify True if there is already a debugger attached to the process
        :param is_thread: Specify True if the given pid belongs to a single thread instead of a full process
        :param record: Tracing data storage structure
        :return: None
        """

        traced_item = None
        finished = False
        record.log("Attaching debugger")
        try:
            debugger = PtraceDebugger()
            debugger.traceFork()
            debugger.traceExec()
            debugger.traceClone()

            traced_item = debugger.addProcess(pid, is_attached, is_thread=is_thread)
            record.log("PTrace debugger attached successfully")
            Tracing._trace_continue(traced_item)

        except Exception as e:
            record.log("PTrace debugger attachment failed with reason: {}".format(e))
            finished = True

        # Trace process until finished
        while not finished:
            finished = self._trace(traced_item, record)

        if traced_item:
            traced_item.detach()

        record.log("Tracee appears to have ended and thread will finish")

    def _trace(self, traced_item, record):
        """
        Trace the given process or thread for one syscall
        :param traced_item: Process or thread to trace
        :param record: Action recording object
        :return: True if the item was terminated else False
        """
        finished = False
        continue_tracing = True
        signum = 0

        try:
            # Wait for the next syscall
            event = traced_item.debugger.waitSyscall(traced_item)
            if not event:
                return False

            # Fetch the syscall state
            if self.is_syscall_tracing or self.is_file_access_tracing:
                state = traced_item.syscall_state
                syscall = state.event(self._debugger_options)

                # Trace the syscall in the process record if it is not filtered out
                if self.is_syscall_tracing and \
                        Tracing._should_record_syscall(syscall, self.syscall_filter, self.syscall_filter_exclude):
                    record.syscall_log(syscall)

                # Trace file access if the syscall is a file access syscall and not filtered out
                if self.is_file_access_tracing and \
                        Tracing._should_record_syscall(syscall, self.file_access_filter, self.file_access_filter_exclude):
                    record.file_access_log(syscall)

        except NewProcessEvent as event:
            # Trace new process and continue parent
            self._trace_new_item(event, record)
            continue_tracing = False

        except ProcessExecution as event:
            record.runtime_log(RuntimeActionRecord.TYPE_EXEC)

        except ProcessExit as event:
            # Finish process tracing
            Tracing._trace_finish(event, record)
            finished = True
            continue_tracing = False

        except ProcessSignal as event:
            record.runtime_log(RuntimeActionRecord.TYPE_SIGNAL_RECEIVED, event.signum)
            signum = event.signum

        # Continue process execution
        if continue_tracing:
            Tracing._trace_continue(traced_item, signum)

        return finished

    @staticmethod
    def _trace_continue(traced_item, signum=0):
        """
        Move the process/thread to the next execution step / syscall
        :param traced_item: Process or thread to proceed
        :param signum: Signal to emit to the traced item
        :return: None
        """
        traced_item.syscall(signum)

    @staticmethod
    def _trace_finish(event, record):
        """
        Handle process or thread completion
        Determine exit code and termination signal and return them
        :param event: ProcessExit event that was raised
        :param record: Action recording object
        :return: None
        """
        process = event.process
        record.runtime_log(RuntimeActionRecord.TYPE_EXITED, {'signal': event.signum, 'exit_code': event.exitcode})

        # Detach from tracing
        process.detach()

    def _trace_new_item(self, event, record):
        """
        Setup tracing the given new process or thread
        :param event: new process/thread event
        :param record: Action recording object
        :return: None
        """
        parent = event.process.parent
        process = event.process

        record.runtime_log(RuntimeActionRecord.TYPE_SPAWN_CHILD, process.pid)
        Tracing._trace_continue(parent)

        # Start new tracing thread for the new process
        self._trace_create_thread(process.pid, process.debugger, process.is_thread)

    def _create_tracing_record(self, pid):
        """
        Create a new tracing record for the given PID
        :param pid: Process or thread id
        :return: new tracing record or the existing one if it is already present
        """
        record = self._process_records.get(pid)
        if not record:
            record = TracingRecord(pid, self._mode)
            self._process_records[pid] = record
            record.log("Tracing record created")

        return record

    @staticmethod
    def _should_record_syscall(syscall, filter_list, filter_exclude_list):
        """
        Check if the given syscall should be recorded or not
        :param syscall: Syscall struct to check for recording
        :param filter_list: List of syscall to record only
        :param filter_exclude_list: List of syscalls to exclude explicitly
        :return: True if the syscall should be recorded - else False
        """
        if filter_list and not syscall.syscall in filter_list and not syscall.name in filter_list:
            return False

        if filter_exclude_list and (syscall.syscall in filter_list or syscall.name in filter_list):
            return False

        return True

    # Mode property accessors
    runtime_tracing = property(is_runtime_tracing, set_runtime_tracing)
    file_access_tracing = property(is_file_access_tracing, set_file_access_tracing)
    syscall_tracing = property(is_syscall_tracing, set_syscall_tracing)
    syscall_argument_tracing = property(is_syscall_argument_tracing, set_syscall_argument_tracing)
    running = property(is_running, set_running)
