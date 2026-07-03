using static Brovan.Core.Helpers.BinaryHelpers;
namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserGetAtomName : IWinSyscall
    {
        private const int UnicodeStringMaximumLengthOffset = 0x02;
        private const int UnicodeStringBufferOffset = 0x08;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture != BinaryArchitecture.x64)
                return Instance.WinUnimplemented;

            ushort Atom = (ushort)Instance.WinHelper.GetArg64(0, true);
            ulong StringPtr = Instance.WinHelper.GetArg64(1);

            if (StringPtr == 0 || !Instance.IsRegionMapped(StringPtr, 0x10))
            {
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            ushort MaximumLengthBytes = Instance._emulator.ReadMemoryUShort(StringPtr + UnicodeStringMaximumLengthOffset);
            ulong Buffer = Instance._emulator.ReadMemoryULong(StringPtr + UnicodeStringBufferOffset);

            WinWindowClass WindowClass = Instance.WinHelper.GetWindowClass(Atom);
            string Name = WindowClass?.Name ?? string.Empty;

            if (Buffer == 0 || MaximumLengthBytes < 2 || Name.Length == 0)
            {
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            // Leave room for the null terminator
            ulong MaxChars = (ulong)(MaximumLengthBytes / 2);
            ulong Written = Win32kHelper.WriteWindowText(Instance, Name, Buffer, MaxChars, false);
            Instance.SetRawSyscallReturn(Written);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
