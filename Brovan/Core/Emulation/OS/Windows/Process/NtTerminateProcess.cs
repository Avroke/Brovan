using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtTerminateProcess : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture == BinaryArchitecture.x64)
            {
                ulong ProcessHandle = Instance.WinHelper.GetArg64(0);
                ulong ExitCode = (uint)Instance.WinHelper.GetArg64(1);

                if (ProcessHandle == 0)
                {
                    uint CallingThreadId = (uint)Instance.CurrentThreadId;
                    foreach (EmulatedThread ProcessThreads in Instance.Threads.Values)
                    {
                        if (ProcessThreads == null || ProcessThreads.ThreadId == CallingThreadId)
                            continue;

                        Instance.WinHelper.AbandonMutexesOwnedByThread(ProcessThreads.ThreadId);
                        ProcessThreads.State = EmulatedThreadState.Terminated;
                        ProcessThreads.ExitCode = (int)ExitCode;
                        Instance.WinHelper.ClearTerminationState(ProcessThreads);
                    }
                    return NTSTATUS.STATUS_SUCCESS;
                }

                if (ProcessHandle == ulong.MaxValue)
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
                else
                {
                    WinProcess Process = Instance.WinHelper.GetProcessByHandle(ProcessHandle, AccessMask.ProcessTerminate);
                    if (Process == null)
                        return NTSTATUS.STATUS_ACCESS_DENIED;

                    if (Process.PID == Instance.WinHelper.PID)
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
            return Instance.WinUnimplemented;
        }
    }
}
