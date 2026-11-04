#!/usr/bin/env bash
# Called with a deliberately scoped subprocess PATH; no package/network action.
set -euo pipefail
work=$(cygpath -u "$1")
jobs=${2:-4}
prefix="$work/prefix"
mkdir -p "$work/build/zlib" "$work/build/x264" "$work/build/ffmpeg" "$work/output"
export PKG_CONFIG_LIBDIR="$prefix/lib/pkgconfig"
unset PKG_CONFIG_PATH
export CC=gcc AR=ar RANLIB=ranlib PKG_CONFIG=pkgconf

cd "$work/build/zlib"
"$work/sources/zlib-1.3.2/configure" --static --prefix="$prefix"
make -j"$jobs"
make install

cd "$work/build/x264"
"$work/sources/x264/configure" --prefix="$prefix" --host=x86_64-w64-mingw32 \
    --enable-static --disable-cli --disable-opencl \
    --bit-depth=8 --chroma-format=420
make -j"$jobs"
make install-lib-static

cd "$work/build/ffmpeg"
"$work/sources/ffmpeg-8.1.1/configure" \
    --prefix="$prefix" --target-os=mingw32 --arch=x86_64 \
    --disable-autodetect --disable-network --disable-everything --disable-devices \
    --disable-doc --disable-debug --disable-shared --enable-static \
    --extra-version=flower-minimal-1 \
    --disable-programs --enable-ffmpeg --enable-ffprobe \
    --enable-gpl --enable-version3 --enable-libx264 --enable-zlib \
    --enable-protocol=file,pipe --enable-demuxer=concat,image2,mov \
    --enable-decoder=png,h264 --enable-parser=png,h264 \
    --enable-encoder=libx264,rawvideo --enable-muxer=mp4,rawvideo \
    --enable-filter=pad,format,scale,null \
    --pkg-config=pkgconf --pkg-config-flags=--static --extra-cflags="-I$prefix/include" \
    --extra-ldflags="-L$prefix/lib -static -static-libgcc"
make -j"$jobs" ffmpeg.exe ffprobe.exe
cp -n ffmpeg.exe ffprobe.exe "$work/output/"
printf '%s\n' 'encoder_build_completed'
