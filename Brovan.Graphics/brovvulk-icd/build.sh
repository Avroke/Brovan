#!/bin/sh
set -e
CC="${CC:-x86_64-w64-mingw32-gcc}"
HERE="$(cd "$(dirname "$0")" && pwd)"

if ! command -v "$CC" >/dev/null 2>&1; then
    echo "error: MinGW-w64 compiler '$CC' not found on PATH. Install mingw-w64 or set CC." >&2
    exit 1
fi

if [ ! -f "$HERE/obj/generated/brovvulk_gen.c" ]; then
    echo "error: generated sources missing. Build the Brovan project first (it runs the code generator)." >&2
    exit 1
fi

mkdir -p "$HERE/bin"

"$CC" -O2 -shared \
    -o "$HERE/bin/vulkan-1.dll" \
    "$HERE/vulkan_shim.c" "$HERE/obj/generated/exports.def" \
    -I "$HERE" -I "$HERE/../vulkan-headers" \
    -static -static-libgcc -static-libstdc++ \
    -Wl,--out-implib,"$HERE/bin/libvulkan-1.a" \
    -lkernel32

REPO="$(cd "$HERE/../.." && pwd)"

deploy_one() {
    dst="$1/C/Windows/System32"
    mkdir -p "$dst"
    cp -f "$HERE/bin/vulkan-1.dll" "$dst/vulkan-1.dll"
    echo "  deployed -> $dst/vulkan-1.dll"
}

echo "Deploying vulkan-1.dll:"
deploy_one "$REPO/VirtualFS"
find "$REPO/Brovan/bin" "$REPO/Brovan.Graphics" -name Brovan.exe 2>/dev/null | while IFS= read -r exe; do
    deploy_one "$(dirname "$exe")/VirtualFS"
done
