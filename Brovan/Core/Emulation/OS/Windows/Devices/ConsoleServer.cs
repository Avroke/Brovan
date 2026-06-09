using System.Runtime.InteropServices;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class ConsoleServer : IWinDevice
    {
        public string DeviceName => "\\Device\\ConDrv";

        private const uint IoctlConDrvReadIo = 0x00500004;
        private const uint IoctlConDrvCompleteIo = 0x0050000B;
        private const uint IoctlConDrvReadInput = 0x0050000F;
        private const uint IoctlConDrvWriteOutput = 0x00500013;
        private const uint IoctlConDrvIssueUserIo = 0x00500016;
        private const uint IoctlConDrvSetServerInformation = 0x0050001F;
        private const uint IoctlConDrvGetServerPid = 0x00500023;
        private const uint IoctlConDrvGetDisplayMode = 0x00500027;
        private const uint IoctlConDrvSetDisplayMode = 0x0050002B;

        [StructLayout(LayoutKind.Explicit, Size = 0x30)]
        private struct ConsoleApiMsgHeader
        {
            [FieldOffset(0x28)] public uint ApiNumber;
            [FieldOffset(0x2C)] public uint ApiDescriptorSize;
        }

        private static readonly int ApiMsgHeaderSize = Marshal.SizeOf<ConsoleApiMsgHeader>();

        private const uint ApiGetConsoleMode = 0x01000008;
        private const uint ApiSetConsoleMode = 0x01000009;
        private const uint ApiGetNumberOfInputEvents = 0x01000003;
        private const uint ApiGetConsoleInput = 0x01000004;
        private const uint ApiReadConsole = 0x01000005;
        private const uint ApiWriteConsole = 0x01000006;
        private const uint ApiGetConsoleLangId = 0x01000017;

        private const uint ApiFillConsoleOutput = 0x02000000;
        private const uint ApiGetConsoleScreenBufferInfo = 0x02000007;
        private const uint ApiSetCursorPosition = 0x0200000A;
        private const uint ApiSetConsoleWindowInfo = 0x0200000C;
        private const uint ApiSetScreenBufferSize = 0x0200000B;
        private const uint ApiSetConsoleActiveScreenBuffer = 0x02000017;
        private const uint ApiGetLargestConsoleWindowSize = 0x02000003;
        private const uint ApiGetConsoleCursorInfo = 0x02000004;
        private const uint ApiSetConsoleCursorInfo = 0x02000005;
        private const uint ApiSetConsoleTextAttribute = 0x0200000F;
        private const uint ApiScrollConsoleScreenBuffer = 0x02000010;
        private const uint ApiReadConsoleOutput = 0x02000015;
        private const uint ApiWriteConsoleOutput = 0x02000016;
        private const uint ApiGetConsoleTitle = 0x02000018;
        private const uint ApiSetConsoleTitle = 0x02000019;

        private const ushort DefaultBufferWidth = 120;
        private const ushort DefaultBufferHeight = 30;
        private const ushort DefaultAttributes = 0x0007;
        private const uint DefaultConsoleMode = 0x0003;

        public NTSTATUS Create(BinaryEmulator Instance, string DevicePath, byte[] EaBuffer, out string InternalPath, out WinDeviceDelegate Handler)
        {
            InternalPath = DevicePath;
            Handler = Handle;
            return NTSTATUS.STATUS_SUCCESS;
        }

        public static NTSTATUS Handle(uint IOCTL, ref DeviceData Data, BinaryEmulator Instance)
        {
            switch (IOCTL)
            {
                case IoctlConDrvIssueUserIo:
                    return HandleIssueUserIo(ref Data, Instance);

                case IoctlConDrvGetServerPid:
                    if (Data.OutputBuffer != null && Data.OutputBuffer.Length >= 4)
                    {
                        WriteUInt32(Data.OutputBuffer, 0, Instance.WinHelper.PID);
                        Data.Information = 4;
                    }
                    return NTSTATUS.STATUS_SUCCESS;

                case IoctlConDrvGetDisplayMode:
                    if (Data.OutputBuffer != null && Data.OutputBuffer.Length >= 4)
                    {
                        WriteUInt32(Data.OutputBuffer, 0, 0);
                        Data.Information = 4;
                    }
                    return NTSTATUS.STATUS_SUCCESS;

                case IoctlConDrvReadIo:
                case IoctlConDrvCompleteIo:
                case IoctlConDrvReadInput:
                case IoctlConDrvWriteOutput:
                case IoctlConDrvSetServerInformation:
                case IoctlConDrvSetDisplayMode:
                    if (Data.OutputBuffer != null && Data.OutputBuffer.Length > 0)
                        Array.Clear(Data.OutputBuffer, 0, Data.OutputBuffer.Length);
                    return NTSTATUS.STATUS_SUCCESS;

                default:
                    if (Data.OutputBuffer != null && Data.OutputBuffer.Length > 0)
                        Array.Clear(Data.OutputBuffer, 0, Data.OutputBuffer.Length);
                    return NTSTATUS.STATUS_SUCCESS;
            }
        }

        private static NTSTATUS HandleIssueUserIo(ref DeviceData Data, BinaryEmulator Instance)
        {
            if (Data.InputBuffer == null || Data.InputBuffer.Length < ApiMsgHeaderSize)
                return NTSTATUS.STATUS_SUCCESS;

            byte[] HeaderBytes = new byte[ApiMsgHeaderSize];
            Buffer.BlockCopy(Data.InputBuffer, 0, HeaderBytes, 0, ApiMsgHeaderSize);
            if (!StructSerializer.ParseStruct(Instance, HeaderBytes, out ConsoleApiMsgHeader Header))
                return NTSTATUS.STATUS_SUCCESS;
            uint ApiNumber = Header.ApiNumber;

            if (Data.OutputBuffer == null || Data.OutputBuffer.Length < ApiMsgHeaderSize)
            {
                if (Data.OutputBuffer != null && Data.OutputBuffer.Length > 0)
                    Array.Clear(Data.OutputBuffer, 0, Data.OutputBuffer.Length);
                return NTSTATUS.STATUS_SUCCESS;
            }

            Array.Clear(Data.OutputBuffer, 0, Data.OutputBuffer.Length);
            int Available = Data.OutputBuffer.Length - ApiMsgHeaderSize;

            switch (ApiNumber)
            {
                case ApiGetConsoleScreenBufferInfo:
                    WriteScreenBufferInfo(Data.OutputBuffer, ApiMsgHeaderSize, Available);
                    Data.Information = (ulong)Data.OutputBuffer.Length;
                    return NTSTATUS.STATUS_SUCCESS;

                case ApiGetLargestConsoleWindowSize:
                    if (Available >= 4)
                    {
                        WriteCoord(Data.OutputBuffer, ApiMsgHeaderSize + 0, DefaultBufferWidth, DefaultBufferHeight);
                        Data.Information = (ulong)Data.OutputBuffer.Length;
                    }
                    return NTSTATUS.STATUS_SUCCESS;

                case ApiGetConsoleCursorInfo:
                    if (Available >= 8)
                    {
                        WriteUInt32(Data.OutputBuffer, ApiMsgHeaderSize + 0, 25);
                        WriteUInt32(Data.OutputBuffer, ApiMsgHeaderSize + 4, 1);
                        Data.Information = (ulong)Data.OutputBuffer.Length;
                    }
                    return NTSTATUS.STATUS_SUCCESS;

                case ApiGetConsoleMode:
                    if (Available >= 4)
                    {
                        WriteUInt32(Data.OutputBuffer, ApiMsgHeaderSize + 0, DefaultConsoleMode);
                        Data.Information = (ulong)Data.OutputBuffer.Length;
                    }
                    return NTSTATUS.STATUS_SUCCESS;

                case ApiGetNumberOfInputEvents:
                    if (Available >= 4)
                    {
                        WriteUInt32(Data.OutputBuffer, ApiMsgHeaderSize + 0, 0);
                        Data.Information = (ulong)Data.OutputBuffer.Length;
                    }
                    return NTSTATUS.STATUS_SUCCESS;

                case ApiFillConsoleOutput:
                    if (Available >= 16 && Data.InputBuffer.Length >= ApiMsgHeaderSize + 16)
                    {
                        uint Length = ReadUInt32(Data.InputBuffer, ApiMsgHeaderSize + 12);
                        WriteUInt32(Data.OutputBuffer, ApiMsgHeaderSize + 12, Length);
                        Data.Information = (ulong)Data.OutputBuffer.Length;
                    }
                    return NTSTATUS.STATUS_SUCCESS;

                case ApiGetConsoleLangId:
                    if (Available >= 2)
                    {
                        WriteUInt16(Data.OutputBuffer, ApiMsgHeaderSize + 0, 0x0409);
                        Data.Information = (ulong)Data.OutputBuffer.Length;
                    }
                    return NTSTATUS.STATUS_SUCCESS;

                case ApiGetConsoleTitle:
                    Data.Information = (ulong)Data.OutputBuffer.Length;
                    return NTSTATUS.STATUS_SUCCESS;

                default:
                    Data.Information = (ulong)Data.OutputBuffer.Length;
                    return NTSTATUS.STATUS_SUCCESS;
            }
        }

        private static void WriteScreenBufferInfo(byte[] Buffer, int Offset, int Available)
        {
            if (Available >= 4)
                WriteCoord(Buffer, Offset + 0x00, DefaultBufferWidth, DefaultBufferHeight);
            if (Available >= 8)
                WriteCoord(Buffer, Offset + 0x04, 0, 0);
            if (Available >= 12)
                WriteCoord(Buffer, Offset + 0x08, 0, 0);
            if (Available >= 14)
                WriteUInt16(Buffer, Offset + 0x0C, DefaultAttributes);
            if (Available >= 18)
                WriteCoord(Buffer, Offset + 0x0E, DefaultBufferWidth, DefaultBufferHeight);
            if (Available >= 22)
                WriteCoord(Buffer, Offset + 0x12, DefaultBufferWidth, DefaultBufferHeight);
            if (Available >= 24)
                WriteUInt16(Buffer, Offset + 0x16, DefaultAttributes);
            if (Available >= 25)
                Buffer[Offset + 0x18] = 0;
        }

        private static void WriteCoord(byte[] Buffer, int Offset, ushort X, ushort Y)
        {
            WriteUInt16(Buffer, Offset + 0, X);
            WriteUInt16(Buffer, Offset + 2, Y);
        }

        private static void WriteUInt16(byte[] Buffer, int Offset, ushort Value)
        {
            Buffer[Offset + 0] = (byte)Value;
            Buffer[Offset + 1] = (byte)(Value >> 8);
        }

        private static void WriteUInt32(byte[] Buffer, int Offset, uint Value)
        {
            Buffer[Offset + 0] = (byte)Value;
            Buffer[Offset + 1] = (byte)(Value >> 8);
            Buffer[Offset + 2] = (byte)(Value >> 16);
            Buffer[Offset + 3] = (byte)(Value >> 24);
        }

        private static uint ReadUInt32(byte[] Buffer, int Offset)
        {
            return (uint)(Buffer[Offset + 0] | (Buffer[Offset + 1] << 8) | (Buffer[Offset + 2] << 16) | (Buffer[Offset + 3] << 24));
        }
    }
}
