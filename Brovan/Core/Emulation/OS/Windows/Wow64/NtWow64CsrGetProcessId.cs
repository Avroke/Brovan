namespace Brovan.Core.Emulation.OS.Windows
{
    /// <summary>
    /// WOW64 equivalent of <c>NtWow64CsrGetProcessId()</c> — returns the PID of the CSRSS process the
    /// caller is bound to. The syscall takes no arguments and returns the PID directly in EAX (not through
    /// an OUT pointer), so it's dispatched via <see cref="BinaryEmulator.SetRawSyscallReturn"/>. Brovan
    /// doesn't model a live CSRSS, so we synthesise a plausible session-0 PID (<c>0x1F4</c> = 500) that is
    /// stable, small, and — critically — <b>distinct from the caller's own PID</b>. Al-khaser's parent-
    /// process check opens this PID via <c>NtOpenProcess</c> and compares the image path against
    /// <c>explorer.exe</c>; if we return the caller's PID here, the sample opens itself, sees a mismatch,
    /// and reports the probe as BAD. Returning a distinct synthetic PID keeps that path on its
    /// "not-our-parent, moving on" branch. Also distinct from every guest PID Brovan hands out
    /// (<see cref="WinSysHelper.PID"/> starts at higher values), so the OpenProcess against 500 lands
    /// nowhere and returns INVALID_HANDLE — the natural "no CSR process visible" answer.
    /// </summary>
    internal class NtWow64CsrGetProcessId : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            const uint CsrssSyntheticPid = 500;
            if (CsrssSyntheticPid == Instance.WinHelper.PID)
            {
                Instance.SetRawSyscallReturn(CsrssSyntheticPid + 4UL);
                return NTSTATUS.STATUS_SUCCESS;
            }
            Instance.SetRawSyscallReturn(CsrssSyntheticPid);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
