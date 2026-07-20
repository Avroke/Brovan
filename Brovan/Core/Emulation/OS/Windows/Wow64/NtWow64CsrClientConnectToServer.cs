using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    /// <summary>
    /// NtWow64CsrClientConnectToServer(PWSTR ObjectDirectory, ULONG ServerId, PVOID ConnectionInfo,
    ///   ULONG ConnectionInfoSize, PBOOLEAN CalledFromServer) — SSN 0x1D7, WOW64-only.
    ///
    /// The WOW64 thunk behind the 32-bit ntdll's CsrClientConnectToServer. kernel32's BaseDllInitialize
    /// (its DllMain) connects the process to the CSR (Client/Server Runtime) subsystem through this call
    /// during process init; if it fails, kernel32's DllMain returns FALSE and the loader aborts the whole
    /// process with STATUS_DLL_INIT_FAILED. On a native x64 guest the same connect is serviced over the CSR
    /// ALPC port by CsrssPortHandler — a 32-bit WOW64 process instead funnels it through this syscall, which
    /// the real WOW64 layer forwards to the 64-bit CSR. Brovan models a successful connect: the sandbox is the
    /// server, so the connection always succeeds and no callback into the guest is required.
    /// </summary>
    internal class NtWow64CsrClientConnectToServer : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong ObjectDirectory = Instance.WinHelper.GetArg64(0);
            uint ServerId = (uint)Instance.WinHelper.GetArg64(1);
            ulong ConnectionInfo = Instance.WinHelper.GetArg64(2);
            uint ConnectionInfoSize = (uint)Instance.WinHelper.GetArg64(3);
            ulong CalledFromServerPtr = Instance.WinHelper.GetArg64(4);

            if (CalledFromServerPtr != 0 && Instance.IsRegionMapped(CalledFromServerPtr, 1))
                Instance._emulator.WriteMemory(CalledFromServerPtr, (byte)0, 1);

            if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                Instance.TriggerEventMessage($"[+] NtWow64CsrClientConnectToServer: ServerId=0x{ServerId:X}, ConnInfo=0x{ConnectionInfo:X} (size {ConnectionInfoSize}) -> STATUS_SUCCESS.", LogFlags.Syscall);

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
