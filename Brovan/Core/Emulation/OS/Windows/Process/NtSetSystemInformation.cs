using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    /// <summary>
    /// NtSetSystemInformation (SSN 0x1AA on 19041/19044). Kernel-mode / TCB-privileged surface;
    /// from a non-elevated user process real Windows returns
    /// <c>STATUS_PRIVILEGE_NOT_HELD</c> for the vast majority of classes (the callable-from-usermode
    /// carve-outs — SystemPolicyInformation, SystemTimeAdjustmentInformation with SeSystemtimePrivilege,
    /// SystemEnvironmentValueEx with SeSystemEnvironmentPrivilege — all still need TCB privilege the
    /// emulated non-elevated token doesn't have).
    ///
    /// Faithful reject beats <c>STATUS_NOT_SUPPORTED</c>: a probe that treats "call unexpectedly
    /// succeeded" as detection would flag NOT_SUPPORTED and PRIVILEGE_NOT_HELD identically, but
    /// only the latter matches what a real user token gets and won't surprise a caller that
    /// distinguishes the two.
    /// </summary>
    internal class NtSetSystemInformation : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            // Args intentionally not decoded — the answer is the same for every class from
            // an unprivileged user token; touching them would only add TOCTOU noise.
            return NTSTATUS.STATUS_PRIVILEGE_NOT_HELD;
        }
    }
}
