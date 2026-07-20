using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    /// <summary>
    /// The win32k client-connect that <c>user32.dll</c>'s <c>DllMain</c> (<c>_UserClientDllInitialize</c>)
    /// issues to attach the process to the GUI subsystem. user32 uses an <b>internal</b> syscall stub for this
    /// early-init call (before win32u is wired), so on the 19041 WOW64 build its SSN is <c>0x2000</c> — distinct
    /// from win32u's exported <c>NtUserProcessConnect</c> (SSN <c>0x10e9</c>), which is why the win32u export
    /// scan can't register it; it is bound explicitly in <c>BuildWinSyscallDictionary</c>.
    ///
    /// The call passes a <c>USERCONNECT</c> the kernel is expected to fill with the shared-info block — the GUI
    /// analog of the CSR <c>BASE_STATIC_SERVER_DATA</c> — and user32 sign-checks the return: a negative status
    /// runs user32's failure cleanup and makes <c>DllMain</c> return FALSE (<c>STATUS_DLL_INIT_FAILED</c>).
    /// Brovan is a headless sandbox with no live win32k, so it models a successful connect: it echoes the
    /// caller's requested version into <c>ulCurrentVersion</c> (so user32's version gate passes) and zero-fills
    /// the remainder of the <c>USERCONNECT</c> (a NULL <c>SHAREDINFO</c> — any later GUI call that would
    /// dereference it degrades to its own headless synthetic path). This mirrors, on the WOW64 syscall surface,
    /// what the x64 CSR <c>HandleUserSrvConnect</c> does over the ALPC port.
    ///
    /// Signature (from user32's internal stub, <c>ret 0x10</c> = 4 args):
    /// <c>(PVOID Reserved, PUSERCONNECT pUserConnect, ULONG cbUserConnect, PVOID pOut)</c>.
    /// </summary>
    internal class NtUserProcessConnect : IWinSyscall
    {
        private const uint SharedInfoBase = 0x08;
        private const uint SharedInfoPsiOffset = SharedInfoBase + 0x00;
        private const uint SharedInfoAheListOffset = SharedInfoBase + 0x08;
        private const uint SharedInfoHeEntrySizeOffset = SharedInfoBase + 0x10;
        private const uint SharedInfoDispInfoOffset = SharedInfoBase + 0x18;
        private const uint SharedInfoMinSize = SharedInfoBase + 0x28;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Reserved = Instance.WinHelper.GetArg64(0);
            ulong SharedInfoPtr = Instance.WinHelper.GetArg64(1);
            uint SharedInfoSize = (uint)Instance.WinHelper.GetArg64(2);
            ulong OutPtr = Instance.WinHelper.GetArg64(3);
            _ = Reserved;
            _ = OutPtr;

            if (SharedInfoPtr != 0 && SharedInfoSize >= SharedInfoMinSize && Instance.IsRegionMapped(SharedInfoPtr, SharedInfoSize))
            {
                Instance.WinHelper.WriteZeroMemory(SharedInfoPtr + SharedInfoBase, SharedInfoSize - SharedInfoBase);

                if (Instance.WinHelper.EnsureUserSharedInfo(out ulong ServerInfo, out ulong HandleTable, out uint EntrySize))
                {
                    Instance._emulator.WriteMemory(SharedInfoPtr + SharedInfoPsiOffset, (uint)ServerInfo, 4);
                    Instance._emulator.WriteMemory(SharedInfoPtr + SharedInfoAheListOffset, (uint)HandleTable, 4);
                    Instance._emulator.WriteMemory(SharedInfoPtr + SharedInfoHeEntrySizeOffset, EntrySize, 4);

                    ulong DisplayInfo = Instance.WinHelper.EnsureUserDesktopInfo();
                    if (DisplayInfo != 0)
                        Instance._emulator.WriteMemory(SharedInfoPtr + SharedInfoDispInfoOffset, (uint)DisplayInfo, 4);
                }
            }

            Instance.WinHelper.EnsureUserClientThreadInfo(Instance.CurrentThread, 0);

            Instance.SetRawSyscallReturn(0);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
