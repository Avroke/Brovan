using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserWaitMessage : IWinSyscall
    {
        private static NTSTATUS ContinueWait(BinaryEmulator Instance, EmulatedThread Thread)
        {
            WindowsThreadState State = WinEmulatedThread.GetState(Thread);

            if (Win32kHelper.TryGetMessage(Instance, 0, 0, 0, false, out _))
            {
                Instance.WinHelper.ClearWaitState(Thread);
                Instance.SetLastWinError(0);
                Instance.SetRawSyscallReturn(1);
                return NTSTATUS.STATUS_SUCCESS;
            }

            Thread.State = EmulatedThreadState.Waiting;
            State.ApcAlertable = State.WaitAlertable;
            Instance._emulator.WriteRegister(Instance.IPRegister, State.WaitResumeRIP);
            Instance._emulator.StopEmulation();
            return NTSTATUS.STATUS_PENDING;
        }

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture != BinaryArchitecture.x64)
                return Instance.WinUnimplemented;

            EmulatedThread Thread = Instance.CurrentThread;
            if (Thread == null)
                return NTSTATUS.STATUS_UNSUCCESSFUL;

            WindowsThreadState State = WinEmulatedThread.GetState(Thread);
            if (State.WaitCompleted)
            {
                NTSTATUS Completed = State.WaitStatus;
                State.WaitCompleted = false;
                State.WaitStatus = NTSTATUS.STATUS_SUCCESS;
                return Completed;
            }

            if (Thread.WaitActive)
                return ContinueWait(Instance, Thread);

            if (Win32kHelper.TryGetMessage(Instance, 0, 0, 0, false, out _))
            {
                Instance.SetLastWinError(0);
                Instance.SetRawSyscallReturn(1);
                return NTSTATUS.STATUS_SUCCESS;
            }

            Thread.WaitActive = true;
            Thread.WaitHandles = null;
            Thread.WaitAll = false;
            Thread.WaitDeadline = -1;
            State.WaitCompleted = false;
            State.WaitStatus = NTSTATUS.STATUS_PENDING;
            State.WaitResumeRIP = Instance.WinHelper.GetSyscallRip(Thread, false);
            State.WaitReturnRIP = State.WaitResumeRIP + 2;
            State.WaitAlertable = false;
            State.GetMessageWaitActive = true;
            State.GetMessageMessagePtr = 0;
            State.GetMessageHwndFilter = 0;
            State.GetMessageMinMessage = 0;
            State.GetMessageMaxMessage = 0;

            Thread.State = EmulatedThreadState.Waiting;
            State.ApcAlertable = false;
            Instance._emulator.WriteRegister(Instance.IPRegister, State.WaitResumeRIP);
            Instance._emulator.StopEmulation();

            return NTSTATUS.STATUS_PENDING;
        }
    }
}
