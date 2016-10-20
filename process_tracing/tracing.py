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

from ptrace.debugger import PtraceDebugger, NewProcessEvent, ProcessExit, ProcessSignal, ProcessExecution
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

        # Initialize debugger
        self._debugger_threads = None

        # Recorded process data
        self._process_records = None

        # Filters that may be used to trace only a subset of caught syscalls
        # If this parameters are valid iterables traced syscalls will be checked if they
        # are in the given filter list. If not they won't get recorded
        self.syscall_filter = None
        self.file_access_filter = ["open", "stat", "lstat", "access", "connect"]

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
        return self._running

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

        self.trace_create_thread(self.process.pid)

        # Start debugger for all existing process children
        processes = [self.process] + self.process.children(recursive=True)
        for p in processes:
            # Don't double start tracing of a process
            if p.pid not in self._debugger_threads.keys():
                self.trace_create_thread(p.pid)

            # Start tracing of process threads
            for t in p.threads():
                if t.id not in self._debugger_threads.keys():
                    self.trace_create_thread(t.id, is_thread=True)

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

        # wait for all pending threads
        for pid in self._debugger_threads.keys():
            thread = self._debugger_threads[pid]
            thread.join()

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
        for pid in self._debugger_threads.keys():
            thread = self._debugger_threads[pid]
            thread.stop()
            thread.join()

    def set_runtime_tracing_enabled(self, enabled):
        """
        Set the runtime tracing mode to the given state
        :param enabled: True if the tracer should record process start, end and subprocess/thread spawn
        :return: None
        """
        self._set_mode_option(TRACING_MODE_RUNTIME_TRACING, enabled)

    def is_runtime_tracing_enabled(self):
        """
        Returns True if the current tracer setup has TRACING_MODE_RUNTIME_TRACING enabled, else false
        :return: True or False
        """
        return self._mode & TRACING_MODE_RUNTIME_TRACING

    def set_file_access_tracing_enabled(self, enabled):
        """
        Set the file access tracing mode to the given state
        :param enabled: True if the tracer should record all syscalls that are related to filesystem actions
        :return: None
        """
        self._set_mode_option(TRACING_MODE_FILE_ACCESS, enabled)

    def is_file_access_tracing_enabled(self):
        """
        Returns True if the current tracer setup has TRACING_MODE_FILE_ACCESS enabled, else false
        :return: True or False
        """
        return self._mode & TRACING_MODE_FILE_ACCESS

    def set_file_access_detailed_tracing_enabled(self, enabled):
        """
        Set the file access tracing mode to the given state
        :param enabled: True if the tracer should record all syscalls that are related to filesystem actions
        :return: None
        """
        file_access_tracing = self.is_file_access_tracing_enabled()
        self._set_mode_option(TRACING_MODE_FILE_ACCESS_DETAILED, enabled)

        if not enabled:
            self.set_file_access_tracing_enabled(file_access_tracing)

    def is_file_access_detailed_tracing_enabled(self):
        """
        Returns True if the current tracer setup has TRACING_MODE_FILE_ACCESS_DETAILED enabled, else false
        :return: True or False
        """
        return self._mode & TRACING_MODE_FILE_ACCESS_DETAILED

    def set_syscall_tracing_enabled(self, enabled):
        """
        Set the syscall tracing mode to the given state
        :param enabled: True if the tracer should record all syscalls that occurred during execution
        :return: None
        """
        self._set_mode_option(TRACING_MODE_SYSCALLS, enabled)

    def is_syscall_tracing_enabled(self):
        """
        Returns True if the current tracer setup has TRACING_MODE_SYSCALLS enabled, else false
        :return: True or False
        """
        return self._mode & TRACING_MODE_SYSCALLS

    def set_syscall_argument_tracing_enabled(self, enabled):
        """
        Set the syscall argument tracing mode to the given state
        :param enabled: True if the tracer should record all arguments of the syscalls that occurred during execution
        :return: None
        """
        syscall_tracing = self.is_syscall_tracing_enabled()
        self._set_mode_option(TRACING_MODE_SYSCALL_ARGUMENTS, enabled)

        if not enabled:
            self.set_syscall_tracing_enabled(syscall_tracing)

    def is_syscall_argument_tracing_enabled(self):
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

    def trace_create_thread(self, pid, old_debugger=None, is_thread=False):
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
        thread = TracingThread(self, pid, record, old_debugger, is_thread)

        # Save the threading instance
        self._debugger_threads[pid] = thread

        # run the new thread
        thread.start()
        return thread

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

    def should_record_syscall(self, s):
        """
        Check if the given syscall should be recorded or not
        :param s: Syscall struct to check for recording
        """
        if not self.is_syscall_tracing_enabled():
            return False

        if self.syscall_filter and s.syscall not in self.syscall_filter and s.name not in self.syscall_filter:
            return False

        if self.syscall_filter_exclude and \
                (s.syscall in self.syscall_filter_exclude or s.name in self.syscall_filter_exclude):
            return False

        return True

    def should_record_file_access(self, syscall):
        """
        Check if the given file access syscall should be recorded or not
        :param syscall: Syscall struct to check for recording
        """
        if not self.is_file_access_tracing_enabled():
            return False

        if self.file_access_filter and \
                syscall.syscall not in self.file_access_filter and \
                syscall.name not in self.file_access_filter:
            return False

        if self.file_access_filter_exclude and \
                (syscall.syscall in self.file_access_filter_exclude or syscall.name in self.file_access_filter_exclude):
            return False

        return True

    # Mode property accessors
    runtime_tracing = property(is_runtime_tracing_enabled, set_runtime_tracing_enabled)
    file_access_tracing = property(is_file_access_tracing_enabled, set_file_access_tracing_enabled)
    file_access_detailed_tracing = property(is_file_access_detailed_tracing_enabled,
                                            set_file_access_detailed_tracing_enabled)
    syscall_tracing = property(is_syscall_tracing_enabled, set_syscall_tracing_enabled)
    syscall_argument_tracing = property(is_syscall_argument_tracing_enabled, set_syscall_argument_tracing_enabled)
    running = property(is_running, set_running)


class TracingThread(Thread):
    """
    tracing thread that can be cancelled
    """
    def __init__(self, manager, pid, record, old_debugger=None, is_thread=False):
        """
        Create a new tracing thread
        :param manager: overall tracing management instance
        :param pid: Process to trace
        :param record: Action recording instance
        :param old_debugger: Old debugger the process might be attached to at the moment
        :param is_thread: True if the pid is a thread else False
        """
        super().__init__()
        self.manager = manager

        # Save tracing record
        self.record = record
        self.record.runtime_log(RuntimeActionRecord.TYPE_STARTED)
        self._debugger_options = FunctionCallOptions(replace_socketcall=False)

        self.is_thread = is_thread
        self.process = psutil.Process(pid)
        self.debugger = None
        self.traced_item = None
        self.stopped = False

        # Check if the process is attached to the debugger
        if old_debugger is not None and old_debugger.dict.get(self.process.pid):
            old_debugger.dict.get(self.process.pid).detach()
            posix.kill(self.process.pid, signal.SIGSTOP)

    def stop(self):
        """
        Mark this thread to stop tracing
        :return: None
        """
        self.stopped = True

    def run(self):
        """
        Trace the given process or thread for one syscall
        """
        finished = False
        self.record.log("Attaching debugger")
        try:
            self.debugger = PtraceDebugger()
            self.debugger.traceFork()
            self.debugger.traceExec()
            self.debugger.traceClone()

            self.traced_item = self.debugger.addProcess(self.process.pid, False, is_thread=self.is_thread)
            self.record.log("PTrace debugger attached successfully")
            TracingThread._trace_continue(self.traced_item)

        except Exception as e:
            self.record.log("PTrace debugger attachment failed with reason: {}".format(e))
            finished = True

        # Trace process until finished
        while not finished and not self.stopped:
            finished = self._trace(self.traced_item, self.record)

        if self.traced_item:
            self.traced_item.detach()
            # Keep in mind that the process maybe already gone
            try:
                if self.process.status() == psutil.STATUS_STOPPED:
                    posix.kill(self.process.pid, signal.SIGCONT)
            except psutil.NoSuchProcess:
                pass

        self.record.log("Tracee appears to have ended and thread will finish")

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
            if self.manager.is_syscall_tracing_enabled() or self.manager.is_file_access_tracing_enabled():
                state = traced_item.syscall_state
                syscall = state.event(self._debugger_options)

                # Trace the syscall in the process record if it is not filtered out
                if self.manager.should_record_syscall(syscall):
                    record.syscall_log(syscall)

                # Trace file access if the syscall is a file access syscall and not filtered out
                if self.manager.should_record_file_access(syscall):
                    record.file_access_log(syscall)

        except NewProcessEvent as event:
            # Trace new process and continue parent
            self._trace_new_item(event, record)
            continue_tracing = False

        except ProcessExecution:
            record.runtime_log(RuntimeActionRecord.TYPE_EXEC)

        except ProcessExit as event:
            # Finish process tracing
            TracingThread._trace_finish(event, record)
            finished = True
            continue_tracing = False

        except ProcessSignal as event:
            record.runtime_log(RuntimeActionRecord.TYPE_SIGNAL_RECEIVED, signal=event.signum)
            signum = event.signum

        # Continue process execution
        if continue_tracing:
            TracingThread._trace_continue(traced_item, signum)

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
        record.runtime_log(RuntimeActionRecord.TYPE_EXITED, signal=event.signum, exit_code=event.exitcode)

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

        record.runtime_log(RuntimeActionRecord.TYPE_SPAWN_CHILD, child_pid=process.pid)
        TracingThread._trace_continue(parent)

        # Start new tracing thread for the new process
        if not self.stopped:
            self.manager.trace_create_thread(process.pid, process.debugger, process.is_thread)
        else:
            TracingThread._trace_continue(process)
