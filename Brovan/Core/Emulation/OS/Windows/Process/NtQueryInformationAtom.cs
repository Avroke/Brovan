using System.Buffers.Binary;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    /// <summary>
    /// NtQueryInformationAtom (SSN 0x147 on 19041/19044). Backs kernel32's
    /// <c>GlobalGetAtomNameW</c> / <c>GlobalGetAtomNameA</c> (both wrap
    /// <c>RtlLookupAtomInAtomTable</c>, which issues this syscall against the global
    /// user-atom table).
    ///
    /// <code>
    /// NTSTATUS NtQueryInformationAtom(
    ///   RTL_ATOM              Atom,                    // arg0 (USHORT-in-ULONG)
    ///   ATOM_INFORMATION_CLASS InformationClass,       // arg1
    ///   PVOID                 AtomInformation,          // arg2
    ///   ULONG                 AtomInformationLength,    // arg3
    ///   PULONG                ReturnLength)             // arg4
    /// </code>
    ///
    /// Brovan doesn't emulate the process-wide atom table (would need
    /// <c>NtAddAtom</c>/<c>NtFindAtom</c>/<c>NtDeleteAtom</c> + persistent RTL_ATOM_TABLE);
    /// samples that inspect atoms via <c>GlobalGetAtomName</c> are exercising it as a
    /// probe target, not to actually round-trip a real atom. Real Windows returns
    /// <c>STATUS_INVALID_HANDLE</c> for an unregistered atom, which is exactly what
    /// al-khaser's write-watch "API calls" probe expects (invalid atom → the API leaves
    /// the OUT buffer untouched, so no page dirties). Returning that instead of
    /// <c>STATUS_NOT_SUPPORTED</c> matches real semantics and gives kernel32 the right
    /// LastError to propagate.
    /// </summary>
    internal class NtQueryInformationAtom : IWinSyscall
    {
        private const uint AtomBasicInformation = 0;
        private const uint AtomTableInformation = 1;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture != BinaryArchitecture.x64)
                return Instance.WinUnimplemented;

            uint Atom = (uint)Instance.WinHelper.GetArg64(0) & 0xFFFF;
            uint InformationClass = (uint)Instance.WinHelper.GetArg64(1);
            ulong AtomInformation = Instance.WinHelper.GetArg64(2);
            uint AtomInformationLength = (uint)Instance.WinHelper.GetArg64(3);
            ulong ReturnLengthPtr = Instance.WinHelper.GetArg64(4);

            if (ReturnLengthPtr != 0 && !Instance.IsRegionMapped(ReturnLengthPtr, 4))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (InformationClass > AtomTableInformation)
                return NTSTATUS.STATUS_INVALID_INFO_CLASS;

            if (InformationClass == AtomBasicInformation)
            {
                if (Atom < 0xC000)
                    return NTSTATUS.STATUS_INVALID_HANDLE;

                string Name = "#" + Atom.ToString(System.Globalization.CultureInfo.InvariantCulture);
                uint NameByteCount = (uint)System.Text.Encoding.Unicode.GetByteCount(Name);
                uint Required = 6 /* header */ + NameByteCount + 2 /* NUL */;

                if (ReturnLengthPtr != 0)
                    Instance._emulator.WriteMemory(ReturnLengthPtr, Required, 4);

                if (AtomInformationLength < Required)
                    return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

                if (AtomInformation == 0 || !Instance.IsRegionMapped(AtomInformation, Required))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                System.Span<byte> Buffer = Instance.WinHelper.Shared.GetSpan(Required);
                Buffer.Slice(0, (int)Required).Clear();
                BinaryPrimitives.WriteUInt16LittleEndian(Buffer.Slice(0, 2), 1);                    // UsageCount = 1
                BinaryPrimitives.WriteUInt16LittleEndian(Buffer.Slice(2, 2), 0);                    // Flags
                BinaryPrimitives.WriteUInt16LittleEndian(Buffer.Slice(4, 2), (ushort)NameByteCount);
                System.Text.Encoding.Unicode.GetBytes(Name, Buffer.Slice(6));

                if (!Instance.WriteMemory(AtomInformation, Buffer.Slice(0, (int)Required)))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                return NTSTATUS.STATUS_SUCCESS;
            }

            const uint HeaderSize = 8;
            if (ReturnLengthPtr != 0)
                Instance._emulator.WriteMemory(ReturnLengthPtr, HeaderSize, 4);

            if (AtomInformationLength < HeaderSize)
                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

            if (AtomInformation == 0 || !Instance.IsRegionMapped(AtomInformation, HeaderSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (!Instance._emulator.WriteMemory(AtomInformation, 0UL, 8))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
