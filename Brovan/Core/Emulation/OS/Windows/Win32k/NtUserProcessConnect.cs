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
        // The out buffer is a USERCONNECT: an 8-byte header (ulVersion, ulCurrentVersion) followed by the
        // SHAREDINFO (siClient) at +0x08. user32's _UserClientDllInitialize copies the SHAREDINFO (from
        // buffer+0x08) wholesale into its gSharedInfo global, then reads gSharedInfo[+0x00] as psi
        // (PSERVERINFO) — the very first thing it does is `test byte [psi], 4`, so psi MUST be a valid
        // readable SERVERINFO pointer. Confirmed empirically: writing at +0x08 made user32 read it back as
        // psi, so the SHAREDINFO base is buffer+0x08.
        //
        // On the WOW64 (19041) build the shared section carries the *64-bit* SHAREDINFO layout — win32k.sys
        // is 64-bit and maps the same section into the WOW64 process, so every field is pointer-sized (8
        // bytes) even in the 32-bit view. user32's client-connect copies siClient into its globals at
        // 0x...A89F8 and then reads aheList from siClient+0x08 (global 0x...A8A00) and HeEntrySize from
        // siClient+0x10 (global 0x...A8A08) — NOT the classic 32-bit packing (aheList+0x04 / HeEntrySize+0x08).
        // Verified by disassembling user32!GetWindowThreadProcessId (`mov edx,[A8A00]` = aheList,
        // `mov ecx,[A8A08]` = HeEntrySize, `cmp byte [ecx+edx+0x18],1`) and the connect-time `rep movsd`
        // that populates those globals from siClient (dest base 0x...A89F8, +0x0C/+0x14 padding unreferenced).
        // The low 32 bits of each 8-byte field hold the (< 4 GB) guest pointer; the high dword stays 0 because
        // the SHAREDINFO region is zero-filled first. ulSharedDelta (siClient+0x20) is deliberately left 0:
        // Brovan stores user-mode guest pointers directly in the handle entries (no separate kernel mapping),
        // so user32's `userPtr = storedPtr - ulSharedDelta` fixup must be an identity.
        private const uint SharedInfoBase = 0x08;
        private const uint SharedInfoPsiOffset = SharedInfoBase + 0x00;
        private const uint SharedInfoAheListOffset = SharedInfoBase + 0x08;
        private const uint SharedInfoHeEntrySizeOffset = SharedInfoBase + 0x10;
        private const uint SharedInfoDispInfoOffset = SharedInfoBase + 0x18;
        private const uint SharedInfoMinSize = SharedInfoBase + 0x28;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            // Bitness-agnostic (GetArg64 delegates to the x86 stack in WOW64); the connect is the same shape on
            // both, only the caller differs (user32 x86 internal stub vs win32u's exported NtUserProcessConnect).
            ulong Reserved = Instance.WinHelper.GetArg64(0);
            ulong SharedInfoPtr = Instance.WinHelper.GetArg64(1);
            uint SharedInfoSize = (uint)Instance.WinHelper.GetArg64(2);
            ulong OutPtr = Instance.WinHelper.GetArg64(3);
            _ = Reserved;
            _ = OutPtr;

            if (SharedInfoPtr != 0 && SharedInfoSize >= SharedInfoMinSize && Instance.IsRegionMapped(SharedInfoPtr, SharedInfoSize))
            {
                // Build (once) the win32k SERVERINFO + handle table + display info the emulator already models for
                // the x64 CSR user-connect path, and publish their guest pointers into the SHAREDINFO. The bases
                // are 32-bit guest addresses, so they fit the 4-byte slots the WOW64 user32 reads.
                // Zero the SHAREDINFO region only, preserving the caller's USERCONNECT version header at [0..8).
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

            // Publish the per-thread client desktop info into this thread's TEB Win32ClientInfo (pDeskInfo
            // at TEB+0x820 on the WOW64 user32 build) so user32 client-side stubs that read it directly —
            // e.g. GetShellWindow — find a valid (zeroed) DESKTOPINFO instead of NULL-dereferencing it
            // before any window has been created. Without a window the DESKTOPINFO's shell-window fields
            // stay 0, so GetShellWindow returns NULL just as it would in a headless / no-shell session.
            Instance.WinHelper.EnsureUserClientThreadInfo(Instance.CurrentThread, 0);

            Instance.SetRawSyscallReturn(0); // STATUS_SUCCESS — the connect succeeded.
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
