using System.Linq;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    /// <summary>
    /// <c>NtOpenThreadToken(THREADHANDLE, ACCESS_MASK, BOOLEAN OpenAsSelf, OUT PHANDLE)</c>. Reads args via
    /// <see cref="WinSysHelper.GetArg64"/> (bitness-aware — delegates to the x86 stack under WOW64) and
    /// writes the OUT handle at <see cref="BinaryEmulator.GuestPointerSize"/> width. The x86 branch was
    /// previously gated to <c>WinUnimplemented</c>, so every WOW64 caller got <c>STATUS_NOT_SUPPORTED</c>
    /// which kernelbase mapped to <c>ERROR_NOT_SUPPORTED</c> (50) instead of the expected
    /// <c>ERROR_NO_TOKEN</c> (0x3F0). combase's <c>CoInitializeSecurity</c> singleton-init helper reads that
    /// LastError value and only tolerates 0x3F0 ("thread has no impersonation token, fall back to process
    /// token") — a 50 aborts the whole init, leaves the singleton NULL, and later NULL-derefs during the
    /// same call (see <c>docs/AL_KHASER_EMULATION.md</c>'s Generic-Sandbox/VM frontier).
    /// </summary>
    internal class NtOpenThreadToken : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            WinSysHelper Helper = Instance.WinHelper;
            if (Helper == null)
                return NTSTATUS.STATUS_UNSUCCESSFUL;

            ulong ThreadHandle = Instance.WinHelper.GetArg64(0);
            ulong DesiredAccess = (uint)Instance.WinHelper.GetArg64(1);
            ulong OpenAsSelf = (byte)Instance.WinHelper.GetArg64(2, true);
            ulong TokenHandlePtr = Instance.WinHelper.GetArg64(3);

            if (TokenHandlePtr == 0)
                return NTSTATUS.STATUS_ACCESS_VIOLATION;
            if (!Instance.IsRegionMapped(TokenHandlePtr, (ulong)Instance.GuestPointerSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            EmulatedThread Thread;
            if (Instance.WinHelper.IsCurrentThreadPseudoHandle(ThreadHandle))
            {
                Thread = Instance.Threads.Values.FirstOrDefault(EmuThread => EmuThread.ThreadId == Instance.CurrentThreadId);
            }
            else
            {
                Thread = Helper.HandleManager.GetObjectByHandle<EmulatedThread>(ThreadHandle);
            }

            if (Thread == null)
                return NTSTATUS.STATUS_INVALID_HANDLE;

            WinToken Token = WinEmulatedThread.GetState(Thread).ImpersonationToken;

            if (Token == null)
            {
                // STATUS_NO_TOKEN is the honest "the thread simply has no impersonation token set" answer;
                // kernelbase's OpenThreadToken translates it to ERROR_NO_TOKEN (0x3F0), which callers like
                // combase treat as "fall back to the process token" — the normal case for a fresh thread.
                if (OpenAsSelf == 0)
                    return NTSTATUS.STATUS_NO_TOKEN;

                WinProcess Process = Helper.WinProcesses.FirstOrDefault(Proc => Proc.PID == Helper.PID);
                if (Process == null || Process.PrimaryToken == null)
                    return NTSTATUS.STATUS_NO_TOKEN;

                Token = new WinToken
                {
                    Type = TokenType.Impersonation,
                    SessionId = Process.PrimaryToken.SessionId,
                    IsElevated = Process.PrimaryToken.IsElevated,
                    IsRestricted = Process.PrimaryToken.IsRestricted,
                    EffectiveOnly = Process.PrimaryToken.EffectiveOnly,
                    ImpersonationLevel = SecurityImpersonationLevel.SecurityImpersonation,
                    OwningProcessId = Process.PrimaryToken.OwningProcessId,
                    OwningThreadId = (ulong)Thread.ThreadId
                };
            }

            WinHandle Handle = Helper.HandleManager.AddHandle(Token, MapDesiredTokenAccess((AccessMask)(uint)DesiredAccess) | AccessMask.TokenDuplicate);
            if (!Instance.WritePointer(TokenHandlePtr, (ulong)Handle.Handle))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            return NTSTATUS.STATUS_SUCCESS;
        }
        private static AccessMask MapDesiredTokenAccess(AccessMask DesiredAccess)
        {
            if (DesiredAccess == AccessMask.None || (DesiredAccess & AccessMask.MaximumAllowed) != 0 || (DesiredAccess & AccessMask.GenericAll) != 0)
                return AccessMask.TokenAllAccess;

            AccessMask Mapped = DesiredAccess;
            if ((Mapped & AccessMask.GenericRead) != 0)
                Mapped = (Mapped & ~AccessMask.GenericRead) | AccessMask.TokenQuery | AccessMask.ReadControl;
            if ((Mapped & AccessMask.GenericWrite) != 0)
                Mapped = (Mapped & ~AccessMask.GenericWrite) | AccessMask.TokenAdjustPrivileges | AccessMask.TokenAdjustGroups | AccessMask.TokenAdjustDefault | AccessMask.TokenAdjustSessionId | AccessMask.ReadControl;
            if ((Mapped & AccessMask.GenericExecute) != 0)
                Mapped = (Mapped & ~AccessMask.GenericExecute) | AccessMask.TokenImpersonate | AccessMask.ReadControl;

            return Mapped;
        }

    }
}
