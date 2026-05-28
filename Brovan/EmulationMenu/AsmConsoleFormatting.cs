using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using Brovan.Analysis;

namespace Brovan.EmulationMenu
{
    internal enum AsmTokenKind
    {
        Text,
        Whitespace,
        Separator,
        Mnemonic,
        Register,
        Immediate,
        Label,
        MemoryKeyword,
    }

    internal readonly record struct AsmToken(string Text, AsmTokenKind Kind);

    internal sealed class AsmLine
    {
        public required ulong Address { get; init; }
        public required string Mnemonic { get; init; }
        public required IReadOnlyList<AsmToken> OperandTokens { get; init; }
        public required bool Current { get; init; }
        public required bool ShowAddress { get; init; }
    }

    internal sealed class AsmTheme
    {
        public ConsoleColor CurrentPrefixColor { get; init; } = ConsoleColor.Yellow;
        public ConsoleColor NormalPrefixColor { get; init; } = ConsoleColor.DarkGray;
        public ConsoleColor CurrentAddressColor { get; init; } = ConsoleColor.White;
        public ConsoleColor NormalAddressColor { get; init; } = ConsoleColor.DarkGray;
        public ConsoleColor CurrentMnemonicColor { get; init; } = ConsoleColor.White;
        public ConsoleColor NormalMnemonicColor { get; init; } = ConsoleColor.DarkCyan;
        public ConsoleColor DefaultOperandColor { get; init; } = ConsoleColor.Gray;
        public ConsoleColor CurrentOperandColor { get; init; } = ConsoleColor.White;
        public ConsoleColor RegisterColor { get; init; } = ConsoleColor.Yellow;
        public ConsoleColor ImmediateColor { get; init; } = ConsoleColor.Magenta;
        public ConsoleColor LabelColor { get; init; } = ConsoleColor.Green;
        public ConsoleColor MemoryKeywordColor { get; init; } = ConsoleColor.DarkCyan;
        public ConsoleColor SeparatorColor { get; init; } = ConsoleColor.DarkGray;

        public static AsmTheme Default { get; } = new();
    }

    internal static class AsmConsoleFormatter
    {
        private static readonly Regex RegisterTokenRegex = new(
            @"^(?:r(?:1[0-5]|[0-9])[dwb]?|e?[abcd]x|e?[sd]i|e?[sb]p|[abcd][lh]|[sd]p|[sd]i|rip|eip|ip|cs|ds|es|fs|gs|ss|cr[0-9]+|dr[0-9]+|tr[0-9]+|xmm[0-9]+|ymm[0-9]+|zmm[0-9]+|mm[0-9]+|st[0-7])$",
            RegexOptions.IgnoreCase | RegexOptions.Compiled);

        private const string OperandSeparators = ",()[]{}+-*:<>";

        public static AsmLine FormatInstruction(X86Instruction instruction, bool current = false, bool showAddress = true)
        {
            return new AsmLine
            {
                Address = instruction.Address,
                Mnemonic = instruction.Mnemonic ?? string.Empty,
                OperandTokens = TokenizeOperand(instruction.Operand ?? string.Empty),
                Current = current,
                ShowAddress = showAddress,
            };
        }

        public static string FormatInstructionForDebugger(X86Instruction instruction)
        {
            string text = instruction.Mnemonic ?? string.Empty;
            if (!string.IsNullOrEmpty(instruction.Operand))
                text += " " + instruction.Operand;

            return $"0x{instruction.Address:X}: {text}";
        }

        private static IReadOnlyList<AsmToken> TokenizeOperand(string operand)
        {
            if (string.IsNullOrEmpty(operand))
                return Array.Empty<AsmToken>();

            List<AsmToken> tokens = new();

            for (int i = 0; i < operand.Length;)
            {
                char ch = operand[i];

                if (char.IsWhiteSpace(ch))
                {
                    int start = i;
                    while (i < operand.Length && char.IsWhiteSpace(operand[i]))
                        i++;

                    tokens.Add(new AsmToken(operand[start..i], AsmTokenKind.Whitespace));
                    continue;
                }

                if (OperandSeparators.IndexOf(ch) >= 0)
                {
                    tokens.Add(new AsmToken(ch.ToString(), AsmTokenKind.Separator));
                    i++;
                    continue;
                }

                int tokenStart = i;
                while (i < operand.Length && !char.IsWhiteSpace(operand[i]) && OperandSeparators.IndexOf(operand[i]) < 0)
                    i++;

                string token = operand[tokenStart..i];
                tokens.Add(new AsmToken(token, ClassifyToken(token)));
            }

            return tokens;
        }

        private static AsmTokenKind ClassifyToken(string token)
        {
            if (string.IsNullOrEmpty(token))
                return AsmTokenKind.Text;

            if (IsRegisterToken(token))
                return AsmTokenKind.Register;

            if (IsNumericToken(token))
                return AsmTokenKind.Immediate;

            if (IsLabelToken(token))
                return AsmTokenKind.Label;

            if (IsMemoryKeyword(token))
                return AsmTokenKind.MemoryKeyword;

            return AsmTokenKind.Text;
        }

        private static bool IsNumericToken(string token)
        {
            if (string.IsNullOrEmpty(token))
                return false;

            if (token.Length > 2 && token[0] == '0' && (token[1] == 'x' || token[1] == 'X'))
                return token.Skip(2).All(Uri.IsHexDigit);

            if (token.EndsWith("h", StringComparison.OrdinalIgnoreCase) && token.Length > 1)
                return token[..^1].All(Uri.IsHexDigit);

            return token.All(ch => char.IsDigit(ch) || ch == '-' || ch == '+');
        }

        private static bool IsRegisterToken(string token)
        {
            return !string.IsNullOrEmpty(token) && RegisterTokenRegex.IsMatch(token);
        }

        private static bool IsLabelToken(string token)
        {
            return token.StartsWith("loc_", StringComparison.OrdinalIgnoreCase)
                || token.StartsWith("sub_", StringComparison.OrdinalIgnoreCase)
                || token.StartsWith("off_", StringComparison.OrdinalIgnoreCase)
                || token.StartsWith("byte_", StringComparison.OrdinalIgnoreCase)
                || token.StartsWith("word_", StringComparison.OrdinalIgnoreCase)
                || token.StartsWith("dword_", StringComparison.OrdinalIgnoreCase)
                || token.StartsWith("qword_", StringComparison.OrdinalIgnoreCase)
                || token.StartsWith("unk_", StringComparison.OrdinalIgnoreCase)
                || token.StartsWith("arg_", StringComparison.OrdinalIgnoreCase)
                || token.StartsWith("var_", StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsMemoryKeyword(string token)
        {
            return token.Equals("ptr", StringComparison.OrdinalIgnoreCase)
                || token.Equals("byte", StringComparison.OrdinalIgnoreCase)
                || token.Equals("word", StringComparison.OrdinalIgnoreCase)
                || token.Equals("dword", StringComparison.OrdinalIgnoreCase)
                || token.Equals("qword", StringComparison.OrdinalIgnoreCase)
                || token.Equals("xmmword", StringComparison.OrdinalIgnoreCase)
                || token.Equals("ymmword", StringComparison.OrdinalIgnoreCase)
                || token.Equals("zmmword", StringComparison.OrdinalIgnoreCase)
                || token.Equals("offset", StringComparison.OrdinalIgnoreCase)
                || token.Equals("short", StringComparison.OrdinalIgnoreCase)
                || token.Equals("near", StringComparison.OrdinalIgnoreCase)
                || token.Equals("far", StringComparison.OrdinalIgnoreCase);
        }
    }

    internal static class AsmConsoleRenderer
    {
        public static void WriteInstruction(X86Instruction instruction, bool current = false, bool showAddress = true)
        {
            WriteLine(AsmConsoleFormatter.FormatInstruction(instruction, current, showAddress), AsmTheme.Default);
        }

        public static void WriteInstructions(X86Instruction[]? instructions, bool highlightFirst = true, bool showAddress = true)
        {
            if (instructions == null || instructions.Length == 0)
                return;

            for (int i = 0; i < instructions.Length; i++)
                WriteInstruction(instructions[i], highlightFirst && i == 0, showAddress);
        }

        public static void WriteLine(AsmLine line, AsmTheme? theme = null)
        {
            theme ??= AsmTheme.Default;

            if (Console.IsOutputRedirected)
            {
                Console.WriteLine(FormatPlainText(line));
                return;
            }

            Console.ForegroundColor = line.Current ? theme.CurrentPrefixColor : theme.NormalPrefixColor;
            Console.Write(line.Current ? "=> " : "   ");
            Console.ResetColor();

            if (line.ShowAddress)
            {
                Console.ForegroundColor = line.Current ? theme.CurrentAddressColor : theme.NormalAddressColor;
                Console.Write($"0x{line.Address:X16}");
                Console.ResetColor();

                Console.ForegroundColor = theme.SeparatorColor;
                Console.Write(": ");
                Console.ResetColor();
            }

            Console.ForegroundColor = line.Current ? theme.CurrentMnemonicColor : theme.NormalMnemonicColor;
            Console.Write(line.Mnemonic);
            Console.ResetColor();

            if (line.OperandTokens.Count > 0)
                Console.Write(' ');

            ConsoleColor defaultOperandColor = line.Current ? theme.CurrentOperandColor : theme.DefaultOperandColor;
            foreach (AsmToken token in line.OperandTokens)
            {
                Console.ForegroundColor = GetTokenColor(token, theme, defaultOperandColor);
                Console.Write(token.Text);
                Console.ResetColor();
            }

            Console.WriteLine();
        }

        private static string FormatPlainText(AsmLine line)
        {
            string operand = string.Concat(line.OperandTokens.Select(t => t.Text));
            string text = line.Mnemonic;

            if (!string.IsNullOrWhiteSpace(operand))
                text += " " + operand;

            if (line.ShowAddress)
                text = $"0x{line.Address:X16}: {text}";

            return line.Current ? $"=> {text}" : $"   {text}";
        }

        private static ConsoleColor GetTokenColor(AsmToken token, AsmTheme theme, ConsoleColor defaultColor)
        {
            return token.Kind switch
            {
                AsmTokenKind.Register => theme.RegisterColor,
                AsmTokenKind.Immediate => theme.ImmediateColor,
                AsmTokenKind.Label => theme.LabelColor,
                AsmTokenKind.MemoryKeyword => theme.MemoryKeywordColor,
                AsmTokenKind.Separator => theme.SeparatorColor,
                _ => defaultColor,
            };
        }
    }
}
