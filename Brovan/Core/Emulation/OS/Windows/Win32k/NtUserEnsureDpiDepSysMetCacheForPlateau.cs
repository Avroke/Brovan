using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserEnsureDpiDepSysMetCacheForPlateau : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture != BinaryArchitecture.x64)
                return Instance.WinUnimplemented;

            uint Dpi = unchecked((uint)Instance.WinHelper.GetArg64(0, true));

            int PlateauIndex = Win32kHelper.GetDpiCacheIndex(Dpi);
            if (PlateauIndex < 0 || !Instance.WinHelper.EnsureUserSharedInfo(out ulong ServerInfo, out _, out _) || ServerInfo == 0)
            {
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            for (int Slot = 0; Slot < Win32kHelper.DpiDepSysMetCacheSlotsPerPlateau; Slot++)
            {
                int SmIndex = Win32kHelper.DpiDepSysMetCacheSlotToSmIndex[Slot];
                int Value = Win32kHelper.ComputeDpiDependentMetric(SmIndex, Dpi);

                int GlobalSlot = Slot + Win32kHelper.DpiDepSysMetCacheSlotsPerPlateau * PlateauIndex;
                ulong Address = ServerInfo + Win32kHelper.DpiDepSysMetCacheOffset + (ulong)(GlobalSlot * 4);
                Instance._emulator.WriteMemory(Address, unchecked((uint)Value), 4);
            }

            Instance.SetRawSyscallReturn(1);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
