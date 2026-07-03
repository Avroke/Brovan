using System.Text;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiHfontCreate : IWinSyscall
    {
        private const int LogFontSize = 92;
        private const int LogFontFaceNameOffset = 28;
        private const int LogFontFaceNameChars = 32;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture != BinaryArchitecture.x64)
                return Instance.WinUnimplemented;

            ulong LogFontPtr = Instance.WinHelper.GetArg64(0);
            Instance.WinHelper.GetArg64(1, true);
            Instance.WinHelper.GetArg64(2, true);
            Instance.WinHelper.GetArg64(3, true);
            Instance.WinHelper.GetArg64(4);

            Win32kFont Font = new Win32kFont
            {
                Height = -16,
                Weight = 400,
                PitchAndFamily = 0x01,
                FaceName = "MS Shell Dlg 2",
            };

            if (LogFontPtr != 0 && Instance.IsRegionMapped(LogFontPtr, LogFontSize))
            {
                Font.Height = unchecked((int)Instance._emulator.ReadMemoryUInt(LogFontPtr + 0x00));
                Font.Width = unchecked((int)Instance._emulator.ReadMemoryUInt(LogFontPtr + 0x04));
                Font.Weight = unchecked((int)Instance._emulator.ReadMemoryUInt(LogFontPtr + 0x10));

                Span<byte> Flags = stackalloc byte[8];
                Instance._emulator.ReadMemory(LogFontPtr + 0x14, Flags, 8);
                Font.Italic = Flags[0];
                Font.Underline = Flags[1];
                Font.StrikeOut = Flags[2];
                Font.CharSet = Flags[3];
                Font.PitchAndFamily = Flags[7];

                string FaceName = Instance._emulator.ReadMemoryString(LogFontPtr + LogFontFaceNameOffset, LogFontFaceNameChars * 2, Encoding.Unicode);
                if (!string.IsNullOrEmpty(FaceName))
                    Font.FaceName = FaceName;
            }

            ulong FontHandle = Win32kHelper.CreateFont(Instance, Font);
            Instance.SetRawSyscallReturn(FontHandle);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
