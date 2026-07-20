using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserCallTwoParam : IWinSyscall
    {
        private const ulong RoutineGetCursorPos = 0x7F;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Param1 = Instance.WinHelper.GetArg64(0);
            ulong Code = Instance.WinHelper.GetArg64(2);

            if (Code != RoutineGetCursorPos)
                return Instance.WinUnimplemented;

            if (Param1 == 0 || !Instance.IsRegionMapped(Param1, 8))
            {
                Instance.SetRawSyscallReturn(0); // FALSE
                return NTSTATUS.STATUS_SUCCESS;
            }

            long Now = Instance.EmulatedTickCount64;
            (int ScreenWidth, int ScreenHeight) = Instance.WinHelper.ScreenResolution();
            long X = TriangleWave(Now, 9000, ScreenWidth / 10, ScreenWidth * 9L / 10);
            long Y = TriangleWave(Now, 7000, ScreenHeight / 10, ScreenHeight * 9L / 10);

            Instance._emulator.WriteMemory(Param1 + 0x00, (uint)X, 4);
            Instance._emulator.WriteMemory(Param1 + 0x04, (uint)Y, 4);

            Instance.SetRawSyscallReturn(1); // TRUE
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static long TriangleWave(long Time, long Period, long Low, long High)
        {
            long Span = High - Low;
            long Half = Period / 2;
            long Phase = ((Time % Period) + Period) % Period;
            long Position = Phase < Half ? Phase : Period - Phase;
            return Low + (Position * Span) / Half;
        }
    }
}
