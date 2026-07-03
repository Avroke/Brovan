using System.Buffers.Binary;
using System.Text;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiExtGetObjectW : IWinSyscall
    {
        private const int LogPenSize = 16;
        private const int LogBrushSize = 16;
        private const int LogFontSize = 92;
        private const int LogFontFaceNameOffset = 0x1C;
        private const int LogFontFaceNameChars = 32;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture != BinaryArchitecture.x64)
                return Instance.WinUnimplemented;

            ulong GdiObject = Instance.WinHelper.GetArg64(0);
            int BufferSize = unchecked((int)Instance.WinHelper.GetArg64(1, true));
            ulong BufferPtr = Instance.WinHelper.GetArg64(2);

            byte Type = Instance.WinHelper.GetGdiHandleType(GdiObject);

            int Required;
            switch (Type)
            {
                case Win32kHelper.PenHandleType:
                    Required = LogPenSize;
                    break;
                case Win32kHelper.BrushHandleType:
                    Required = LogBrushSize;
                    break;
                case Win32kHelper.FontHandleType:
                    Required = LogFontSize;
                    break;
                default:
                    Instance.SetRawSyscallReturn(0);
                    return NTSTATUS.STATUS_SUCCESS;
            }

            if (BufferPtr == 0)
            {
                Instance.SetRawSyscallReturn((ulong)Required);
                return NTSTATUS.STATUS_SUCCESS;
            }

            if (BufferSize < Required || !Instance.IsRegionMapped(BufferPtr, (ulong)Required))
            {
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            bool Ok = Type switch
            {
                Win32kHelper.PenHandleType => WritePen(Instance, GdiObject, BufferPtr),
                Win32kHelper.BrushHandleType => WriteBrush(Instance, GdiObject, BufferPtr),
                Win32kHelper.FontHandleType => WriteFont(Instance, GdiObject, BufferPtr),
                _ => false
            };

            Instance.SetRawSyscallReturn(Ok ? (ulong)Required : 0);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static bool WritePen(BinaryEmulator Instance, ulong Handle, ulong BufferPtr)
        {
            Win32kPenBrush PenBrush = Win32kHelper.ResolvePenBrush(Instance, Handle, true);

            Span<byte> Buffer = stackalloc byte[LogPenSize];
            Buffer.Clear();
            BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x00, 4), 0u); // PS_SOLID
            BinaryPrimitives.WriteInt32LittleEndian(Buffer.Slice(0x04, 4), PenBrush.PenWidth); // lopnWidth.x
            BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x0C, 4), PenBrush.ColorRef);

            return Instance.WriteMemory(BufferPtr, Buffer);
        }

        private static bool WriteBrush(BinaryEmulator Instance, ulong Handle, ulong BufferPtr)
        {
            Win32kPenBrush PenBrush = Win32kHelper.ResolvePenBrush(Instance, Handle, false);

            Span<byte> Buffer = stackalloc byte[LogBrushSize];
            Buffer.Clear();
            BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x00, 4), 0u); // BS_SOLID
            BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x04, 4), PenBrush.ColorRef);

            return Instance.WriteMemory(BufferPtr, Buffer);
        }

        private static bool WriteFont(BinaryEmulator Instance, ulong Handle, ulong BufferPtr)
        {
            if (!Win32kHelper.TryGetFont(Instance, Handle, out Win32kFont Font))
            {
                Font = new Win32kFont
                {
                    Height = -16,
                    Weight = 400,
                    PitchAndFamily = 0x01,
                    FaceName = "MS Shell Dlg 2",
                };
            }

            Span<byte> Buffer = stackalloc byte[LogFontSize];
            Buffer.Clear();
            BinaryPrimitives.WriteInt32LittleEndian(Buffer.Slice(0x00, 4), Font.Height);
            BinaryPrimitives.WriteInt32LittleEndian(Buffer.Slice(0x04, 4), Font.Width);
            BinaryPrimitives.WriteInt32LittleEndian(Buffer.Slice(0x10, 4), Font.Weight);
            Buffer[0x14] = Font.Italic;
            Buffer[0x15] = Font.Underline;
            Buffer[0x16] = Font.StrikeOut;
            Buffer[0x17] = Font.CharSet;
            Buffer[0x1B] = Font.PitchAndFamily;

            string FaceName = Font.FaceName ?? string.Empty;
            if (FaceName.Length > LogFontFaceNameChars - 1)
                FaceName = FaceName.Substring(0, LogFontFaceNameChars - 1);
            Encoding.Unicode.GetBytes(FaceName, Buffer.Slice(LogFontFaceNameOffset, FaceName.Length * 2));

            return Instance.WriteMemory(BufferPtr, Buffer);
        }
    }
}
