using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtFlushInstructionCache : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture != BinaryArchitecture.x64)
                return Instance.WinUnimplemented;

            ulong ProcessHandle = Instance.WinHelper.GetArg64(0);
            ulong BaseAddress = Instance.WinHelper.GetArg64(1);
            ulong Length = (uint)Instance.WinHelper.GetArg64(2);

            if (ProcessHandle != ulong.MaxValue && !Instance.WinHelper.ValidProcessHandle(ProcessHandle))
                return NTSTATUS.STATUS_INVALID_HANDLE;

            Instance.TriggerEventMessage($"[+] NtFlushInstructionCache: base=0x{BaseAddress:X}, length=0x{Length:X}", LogFlags.Syscall);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
