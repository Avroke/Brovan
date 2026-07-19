using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtSetEvent : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture == BinaryArchitecture.x64)
            {
                ulong EventHandle = Instance.WinHelper.GetArg64(0);
                ulong PreviousStatePtr = Instance.WinHelper.GetArg64(1);

                return Handle(Instance, EventHandle, PreviousStatePtr, true);
            }
            else if (Instance._binary.Architecture == BinaryArchitecture.x86)
            {
                ulong EventHandle = Instance.WinHelper.GetArg32(0);
                ulong PreviousStatePtr = Instance.WinHelper.GetArg32(1);

                return Handle(Instance, EventHandle, PreviousStatePtr, true);
            }

            return Instance.WinUnimplemented;
        }

        internal static NTSTATUS Handle(BinaryEmulator Instance, ulong EventHandle, ulong PreviousStatePtr, bool Signaled)
        {
            if (PreviousStatePtr != 0)
            {
                if (!Instance.IsRegionMapped(PreviousStatePtr, 4))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
            }

            WinEvent Ev = Instance.WinHelper.GetEventByHandle(EventHandle, (AccessMask)0x0002);
            if (Ev == null)
                return NTSTATUS.STATUS_INVALID_HANDLE;

            int Prev = Ev.Signaled ? 1 : 0;
            Ev.Signaled = Signaled;
            if (PreviousStatePtr != 0)
            {
                if (!Instance._emulator.WriteMemory(PreviousStatePtr, (uint)Prev))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
            }

            if (Signaled && Instance.WakeWorkerFactoryWaitersForObject(EventHandle))
                Instance._emulator.StopEmulation();

            // [EVT-SET] instrumentation: log a signal only when it is interesting — either it
            // transitions an auto-reset/manual event that has at least one thread parked directly
            // on this handle (the signal that *should* wake a waiter), or it is a wasted signal on
            // an already-signalled event with no waiter. Keeps the volume low vs logging every set.
            if (Signaled && (Instance.Settings.Flags & LogFlags.General) != 0)
            {
                System.Text.StringBuilder Waiters = null;
                foreach (EmulatedThread T in Instance.Threads.Values)
                {
                    if (T == null || T.State != EmulatedThreadState.Waiting || !T.WaitActive)
                        continue;
                    if (T.WaitHandles == null || !T.WaitHandles.Contains(EventHandle))
                        continue;
                    (Waiters ??= new System.Text.StringBuilder()).Append(Waiters.Length == 0 ? "" : ",").Append(T.ThreadId);
                }
                if (Waiters != null)
                    Instance.TriggerEventMessage($"[!] [EVT-SET] tid={Instance.CurrentThreadId} handle=0x{EventHandle:X} type={Ev.EventType} prev={Prev} parkedWaiters=[{Waiters}]", LogFlags.General);
            }

            return NTSTATUS.STATUS_SUCCESS;
        }
    }

    internal class NtResetEvent : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture == BinaryArchitecture.x64)
            {
                ulong EventHandle = Instance.WinHelper.GetArg64(0);
                ulong PreviousStatePtr = Instance.WinHelper.GetArg64(1);

                return NtSetEvent.Handle(Instance, EventHandle, PreviousStatePtr, false);
            }
            else if (Instance._binary.Architecture == BinaryArchitecture.x86)
            {
                ulong EventHandle = Instance.WinHelper.GetArg32(0);
                ulong PreviousStatePtr = Instance.WinHelper.GetArg32(1);

                return NtSetEvent.Handle(Instance, EventHandle, PreviousStatePtr, false);
            }

            return Instance.WinUnimplemented;
        }
    }

    internal class NtClearEvent : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture == BinaryArchitecture.x64)
            {
                ulong EventHandle = Instance.WinHelper.GetArg64(0);

                return NtSetEvent.Handle(Instance, EventHandle, 0, false);
            }
            else if (Instance._binary.Architecture == BinaryArchitecture.x86)
            {
                ulong EventHandle = Instance.WinHelper.GetArg32(0);

                return NtSetEvent.Handle(Instance, EventHandle, 0, false);
            }

            return Instance.WinUnimplemented;
        }
    }
}
