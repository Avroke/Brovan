using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtSetTimer : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture == BinaryArchitecture.x64)
            {
                ulong TimerHandle = Instance.WinHelper.GetArg64(0);
                ulong DueTimePtr = Instance.WinHelper.GetArg64(1);
                ulong TimerApcRoutine = Instance.WinHelper.GetArg64(2);
                ulong TimerContext = Instance.WinHelper.GetArg64(3);
                ulong ResumeTimer = Instance.WinHelper.GetArg64(4);
                long Period = unchecked((long)Instance.WinHelper.GetArg64(5));
                ulong PreviousStatePtr = Instance.WinHelper.GetArg64(6);

                return HandleSetTimer64(Instance, TimerHandle, DueTimePtr, TimerApcRoutine, TimerContext, ResumeTimer, Period, PreviousStatePtr);
            }

            uint SP = Instance.ReadRegister32(Registers.UC_X86_REG_ESP);

            uint TimerHandle32 = Instance.ReadMemoryUInt(SP + 4);
            uint DueTimePtr32 = Instance.ReadMemoryUInt(SP + 8);
            uint TimerApcRoutine32 = Instance.ReadMemoryUInt(SP + 12);
            uint TimerContext32 = Instance.ReadMemoryUInt(SP + 16);
            uint ResumeTimer32 = Instance.ReadMemoryUInt(SP + 20);
            long Period32 = unchecked((int)Instance.ReadMemoryUInt(SP + 24));
            uint PreviousStatePtr32 = Instance.ReadMemoryUInt(SP + 28);

            return HandleSetTimer32(Instance, TimerHandle32, DueTimePtr32, TimerApcRoutine32, TimerContext32, ResumeTimer32, Period32, PreviousStatePtr32);
        }

        private static NTSTATUS HandleSetTimer64(BinaryEmulator Instance, ulong TimerHandle, ulong DueTimePtr, ulong TimerApcRoutine, ulong TimerContext, ulong ResumeTimer, long Period, ulong PreviousStatePtr)
        {
            if (DueTimePtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(DueTimePtr, 8))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            WinTimer Timer = Instance.WinHelper.GetTimerByHandle(TimerHandle, AccessMask.TimerModifyState);
            if (Timer == null)
                return NTSTATUS.STATUS_INVALID_HANDLE;

            Instance.CanSatisfyWaitHandle(TimerHandle);
            long DueTime = unchecked((long)Instance._emulator.ReadMemoryULong(DueTimePtr));
            long DueMilliseconds = NtTimerHelpers.ConvertDueTimeToMilliseconds(Instance, DueTime);
            long PeriodMilliseconds = Period <= 0 ? 0 : Period;

            NtTimerHelpers.ArmTimer(Instance, Timer, TimerHandle, DueMilliseconds, PeriodMilliseconds, out bool WasSignaled);

            NTSTATUS PreviousStateStatus = NtTimerHelpers.WritePreviousState(Instance, PreviousStatePtr, WasSignaled);
            if (PreviousStateStatus != NTSTATUS.STATUS_SUCCESS)
                return PreviousStateStatus;

            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS HandleSetTimer32(BinaryEmulator Instance, uint TimerHandle, uint DueTimePtr, uint TimerApcRoutine, uint TimerContext, uint ResumeTimer, long Period, uint PreviousStatePtr)
        {
            if (DueTimePtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(DueTimePtr, 8))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            WinTimer Timer = Instance.WinHelper.GetTimerByHandle(TimerHandle, AccessMask.TimerModifyState);
            if (Timer == null)
                return NTSTATUS.STATUS_INVALID_HANDLE;

            Instance.CanSatisfyWaitHandle(TimerHandle);
            long DueTime = unchecked((long)Instance._emulator.ReadMemoryULong(DueTimePtr));
            long DueMilliseconds = NtTimerHelpers.ConvertDueTimeToMilliseconds(Instance, DueTime);
            long PeriodMilliseconds = Period <= 0 ? 0 : Period;

            NtTimerHelpers.ArmTimer(Instance, Timer, TimerHandle, DueMilliseconds, PeriodMilliseconds, out bool WasSignaled);

            NTSTATUS PreviousStateStatus = NtTimerHelpers.WritePreviousState(Instance, PreviousStatePtr, WasSignaled);
            if (PreviousStateStatus != NTSTATUS.STATUS_SUCCESS)
                return PreviousStateStatus;

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
