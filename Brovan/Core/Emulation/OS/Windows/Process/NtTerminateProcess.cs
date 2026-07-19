using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtTerminateProcess : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            // Bitness-agnostic: GetArg64 reads the x86 stack under WOW64, and the NtCurrentProcess
            // pseudo-handle arrives as 0xFFFFFFFF on x86 / 0xFFFFFFFFFFFFFFFF on x64 (a bare
            // == ulong.MaxValue misses the WOW64 form, which is why the CRT's RtlExitUserProcess
            // path never terminated cleanly on x86). Terminating a *different* process stays
            // unimplemented, exactly as before.
            ulong ProcessHandle = Instance.WinHelper.GetArg64(0);
            ulong ExitCode = (uint)Instance.WinHelper.GetArg64(1);

            // NtTerminateProcess(NULL, code): NT semantics terminate every thread of the CURRENT
            // process EXCEPT the caller, then return to it. RtlExitUserProcess issues this first (to
            // reap background threads — GC finalizer, tiered-JIT worker, loader workers) before running
            // process-detach and self-terminating via the pseudo-handle path below. Without handling
            // NULL, GetProcessByHandle(0) fails -> STATUS_ACCESS_DENIED, the background threads survive,
            // and after managed Main returns they spin on NtDelayExecution / a parked loader event
            // forever (the emulation never cleanly ends). This is NOT a process stop: the caller continues.
            if (ProcessHandle == 0)
            {
                foreach (EmulatedThread ProcessThreads in Instance.Threads.Values)
                {
                    if (ProcessThreads == null || ProcessThreads.ThreadId == Instance.CurrentThreadId)
                        continue;

                    Instance.WinHelper.AbandonMutexesOwnedByThread(ProcessThreads.ThreadId);
                    ProcessThreads.State = EmulatedThreadState.Terminated;
                    ProcessThreads.ExitCode = (int)ExitCode;
                    Instance.WinHelper.ClearTerminationState(ProcessThreads);
                }
                return NTSTATUS.STATUS_SUCCESS;
            }

            if (Instance.WinHelper.IsCurrentProcessPseudoHandle(ProcessHandle))
                return TerminateCurrentProcess(Instance, ExitCode);

            WinProcess Process = Instance.WinHelper.GetProcessByHandle(ProcessHandle, AccessMask.ProcessTerminate);
            if (Process == null)
                return NTSTATUS.STATUS_ACCESS_DENIED;

            if (Process.PID == Instance.WinHelper.PID)
                return TerminateCurrentProcess(Instance, ExitCode);

            return Instance.WinUnimplemented;
        }

        private static NTSTATUS TerminateCurrentProcess(BinaryEmulator Instance, ulong ExitCode)
        {
            if ((Instance.Settings.Flags & LogFlags.Important) != 0)
                Instance.TriggerEventMessage($"[{(ExitCode == 0 ? '+' : '!')}] Process asked to be terminated with exit code 0x{ExitCode:X}", LogFlags.Important);

            foreach (EmulatedThread ProcessThreads in Instance.Threads.Values)
            {
                if (ProcessThreads == null)
                    continue;

                Instance.WinHelper.AbandonMutexesOwnedByThread(ProcessThreads.ThreadId);
                ProcessThreads.State = EmulatedThreadState.Terminated;
                ProcessThreads.ExitCode = (int)ExitCode;
                Instance.WinHelper.ClearTerminationState(ProcessThreads);
            }

            Instance.StopEmulation();
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
