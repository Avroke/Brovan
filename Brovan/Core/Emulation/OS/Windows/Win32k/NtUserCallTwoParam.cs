using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    // win32u!NtUserCallTwoParam(Param1, Param2, Code) — a win32k multiplexer whose
    // Code selects the operation. On this OS build user32!GetCursorPos and
    // GetPhysicalCursorPos both tail-call it as NtUserCallTwoParam(lpPoint, 1, 0x7F),
    // so Code 0x7F writes the screen-space cursor POINT and returns TRUE.
    //
    // Left unimplemented, the syscall returned STATUS_NOT_SUPPORTED, GetCursorPos
    // failed, and the caller's POINT stayed (0,0). A sample that samples the cursor
    // twice across a Sleep and compares (al-khaser's "mouse movement" human-presence
    // probe) then saw an unmoving cursor and deduced a sandbox. The position here is a
    // smooth, deterministic function of the guest virtual clock, so any nonzero Sleep
    // between two reads yields a different point — realistic human movement, never
    // fabricated jitter (rule #4). Bounded well inside the 1920x1080 primary monitor.
    //
    // Every other Code preserves the prior behaviour (STATUS_NOT_SUPPORTED via
    // WinUnimplemented) so registering this handler regresses nothing.
    internal class NtUserCallTwoParam : IWinSyscall
    {
        // TWOPARAM_ROUTINE code carried by GetCursorPos / GetPhysicalCursorPos on this
        // OS build (derived from the bundled user32 stub, an OS ABI constant).
        private const ulong RoutineGetCursorPos = 0x7F;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture != BinaryArchitecture.x64)
                return Instance.WinUnimplemented;

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
            // Screen bounds come from the shared SSOT (default 1920x1080, opt-in dynamic/host
            // via BROVAN_SCREEN_RESOLUTION) so the cursor stays coherent with the reported
            // monitor / device-caps metrics.
            (int ScreenWidth, int ScreenHeight) = Instance.WinHelper.ScreenResolution();
            // Lissajous over two coprime-ish periods so the path never sits still and
            // never trivially repeats. X sweeps ~0.34 px/ms, Y ~0.25 px/ms — human pace.
            long X = TriangleWave(Now, 9000, ScreenWidth / 10, ScreenWidth * 9L / 10);
            long Y = TriangleWave(Now, 7000, ScreenHeight / 10, ScreenHeight * 9L / 10);

            Instance._emulator.WriteMemory(Param1 + 0x00, (uint)X, 4);
            Instance._emulator.WriteMemory(Param1 + 0x04, (uint)Y, 4);

            Instance.SetRawSyscallReturn(1); // TRUE
            return NTSTATUS.STATUS_SUCCESS;
        }

        // Ping-pongs lo..hi..lo over Period ms — smooth, bounded, never teleports.
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
