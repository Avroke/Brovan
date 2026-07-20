#!/usr/bin/env python3
"""Remove comments that begin with *exactly* two slashes (`//`).

The Brovan sources are C#, where `//` starts an ordinary line comment while
`///` starts an XML documentation comment and `/* … */` is a block comment.
This tool strips only the first kind: a slash run of length exactly two that
opens a comment. Doc comments (`///`, `////`, …) and block comments are left
untouched, and — crucially — `//` that appears *inside* a string, verbatim
string, interpolated string, character literal, or block comment is preserved
(so URLs like `"http://example"` and Windows paths survive intact).

Because a naive regex would happily gut `"http://…"`, the removal is done with
a small C# lexer that tracks which construct each character lives in:

    normal ─ "…" ─ @"…" (verbatim, "" escapes) ─ $"…" / $@"… ─ '…' ─ /* … */

When, and only when, a bare `//` run of length two is met in *normal* code the
rest of that physical line is dropped. Trailing whitespace left in front of the
comment is trimmed; a line that consisted solely of a comment is removed
entirely (pass ``--keep-blank-lines`` to leave an empty line behind instead).
CRLF and LF endings are both preserved.

Usage:
    remove_double_slash_comments.py [PATH ...] [options]

    PATH may be a file or a directory (directories are walked recursively for
    files matching --ext). With no PATH, defaults to the current directory.

Options:
    --ext EXT         File extension(s) to process (repeatable / comma-list).
                      Default: .cs
    -n, --dry-run     Report what would change without writing files.
    --keep-blank-lines  Leave an empty line where a whole-line comment was,
                      instead of deleting the line.
    -q, --quiet       Only print the final summary.
"""

import argparse
import os
import sys


def strip_double_slash_comments(source: str, keep_blank_lines: bool = False) -> str:
    """Return ``source`` with every exactly-two-slash line comment removed.

    A hand-rolled C# scan avoids touching `//` sequences that live inside
    string/char literals or block comments, and skips `///`+ doc comments.
    """
    out = []
    i = 0
    n = len(source)

    while i < n:
        c = source[i]

        # --- string literal:  "…"  and verbatim/interpolated variants -----------
        if c == '"' or (
            c in "@$" and i + 1 < n and (
                source[i + 1] == '"'
                # $@"…" / @$"…"
                or (source[i + 1] in "@$" and i + 2 < n and source[i + 2] == '"')
            )
        ):
            # Determine where the opening quote is and whether it is verbatim.
            prefix = ""
            j = i
            while source[j] in "@$":
                prefix += source[j]
                j += 1
            # j now points at the opening '"'.
            verbatim = "@" in prefix
            out.append(source[i:j + 1])          # copy prefix + opening quote
            j += 1
            while j < n:
                ch = source[j]
                if verbatim:
                    if ch == '"':
                        if j + 1 < n and source[j + 1] == '"':   # "" escapes a quote
                            out.append('""')
                            j += 2
                            continue
                        out.append('"')
                        j += 1
                        break
                    out.append(ch)
                    j += 1
                else:
                    if ch == '\\' and j + 1 < n:                 # \" \\ etc.
                        out.append(source[j:j + 2])
                        j += 2
                        continue
                    if ch == '"':
                        out.append('"')
                        j += 1
                        break
                    if ch == '\n':                              # unterminated; bail out
                        break
                    out.append(ch)
                    j += 1
            i = j
            continue

        # --- character literal:  '…' -------------------------------------------
        if c == "'":
            out.append(c)
            j = i + 1
            while j < n:
                ch = source[j]
                if ch == '\\' and j + 1 < n:
                    out.append(source[j:j + 2])
                    j += 2
                    continue
                out.append(ch)
                j += 1
                if ch == "'" or ch == '\n':
                    break
            i = j
            continue

        # --- block comment:  /* … */  (kept verbatim, just skipped over) --------
        if c == '/' and i + 1 < n and source[i + 1] == '*':
            end = source.find('*/', i + 2)
            end = n if end == -1 else end + 2
            out.append(source[i:end])
            i = end
            continue

        # --- line comment candidate:  a run of slashes -------------------------
        if c == '/' and i + 1 < n and source[i + 1] == '/':
            j = i
            while j < n and source[j] == '/':
                j += 1
            run = j - i
            if run != 2:
                # ///+ doc comment (or ////): keep the slashes and the line.
                out.append(source[i:j])
                i = j
                continue

            # Exactly `//`: drop from here to end of physical line.
            while out and out[-1] in " \t":       # trim whitespace before comment
                out.pop()
            line_is_blank = (not out) or out[-1] == '\n'

            eol = source.find('\n', i)
            eol = n if eol == -1 else eol
            has_cr = eol > 0 and source[eol - 1] == '\r'

            if line_is_blank and not keep_blank_lines:
                i = eol + 1 if eol < n else n     # remove the whole line + newline
            else:
                if has_cr:
                    out.append('\r')              # preserve CRLF line ending
                i = eol                           # keep the '\n' for next iteration
            continue

        # --- ordinary character -------------------------------------------------
        out.append(c)
        i += 1

    return "".join(out)


def iter_target_files(paths, extensions):
    """Yield every file under ``paths`` whose suffix is in ``extensions``."""
    for path in paths:
        if os.path.isfile(path):
            yield path
        elif os.path.isdir(path):
            for root, _dirs, files in os.walk(path):
                for name in sorted(files):
                    if os.path.splitext(name)[1] in extensions:
                        yield os.path.join(root, name)
        else:
            print(f"[!] skipping (not found): {path}", file=sys.stderr)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Remove line comments that start with exactly two slashes (//).",
    )
    parser.add_argument("paths", nargs="*", default=["."],
                        help="files or directories to process (default: .)")
    parser.add_argument("--ext", action="append", default=[],
                        help="extension(s) to process, e.g. --ext .cs (default: .cs)")
    parser.add_argument("-n", "--dry-run", action="store_true",
                        help="report changes without writing files")
    parser.add_argument("--keep-blank-lines", action="store_true",
                        help="leave an empty line where a whole-line comment was")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="only print the final summary")
    args = parser.parse_args(argv)

    # Normalise extensions ( --ext .cs,.cshtml  or repeated --ext ).
    exts = []
    for chunk in args.ext:
        for e in chunk.split(","):
            e = e.strip()
            if e:
                exts.append(e if e.startswith(".") else "." + e)
    extensions = set(exts) if exts else {".cs"}

    paths = args.paths or ["."]
    changed = 0
    scanned = 0

    for filepath in iter_target_files(paths, extensions):
        scanned += 1
        try:
            with open(filepath, "r", encoding="utf-8-sig", newline="") as fh:
                original = fh.read()
        except (OSError, UnicodeDecodeError) as exc:
            print(f"[!] skipping {filepath}: {exc}", file=sys.stderr)
            continue

        stripped = strip_double_slash_comments(original, args.keep_blank_lines)
        if stripped == original:
            continue

        changed += 1
        if args.dry_run:
            if not args.quiet:
                print(f"[dry-run] would modify {filepath}")
        else:
            with open(filepath, "w", encoding="utf-8", newline="") as fh:
                fh.write(stripped)
            if not args.quiet:
                print(f"[+] {filepath}")

    verb = "would change" if args.dry_run else "changed"
    print(f"Scanned {scanned} file(s); {verb} {changed}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
