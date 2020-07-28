#!/bin/sh

set -e

cd $(dirname $(readlink -f $0))

armv7="armeabi-v7a armv7-linux-androideabi armv7a-linux-androideabi16-clang"
aarch64="arm64-v8a aarch64-linux-android aarch64-linux-android21-clang"
x86="x86 i686-linux-android i686-linux-android16-clang"
x86_64="x86_64 x86_64-linux-android x86_64-linux-android21-clang"

arches=( "$armv7" "$aarch64" "$x86" "$x86_64" )

for arch in "${arches[@]}"
do
    arch=($arch)
    jniLibArch=${arch[0]}
    target=${arch[1]}
    ccompiler=${arch[2]}

    jniDir="client/src/main/jniLibs/${jniLibArch}"

    rm -rf "$jniDir"

    export CC="${ccompiler}"

    echo "Building $target"

    cargo build --target ${target} --release

    mkdir -p "$jniDir"
    cp "target/$target/release/libetebase_android.so" "$jniDir"
done

./gradlew clean build
