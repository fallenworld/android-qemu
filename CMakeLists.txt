cmake_minimum_required(VERSION 3.6)
project(qemu)

set(CMAKE_CXX_STANDARD 11)

include_directories(
        qemu-2.8.0
        qemu-2.8.0/include
        qemu-2.8.0/tcg
        qemu-2.8.0/tcg/arm
        qemu-2.8.0/target-i386
        qemu-2.8.0/linux-headers
        /home/fallenworld/dev/android/build/sysroot/usr/include
        /home/fallenworld/dev/android/build/sysroot/usr/include/glib-2.0
        /home/fallenworld/dev/android/build/sysroot/usr/include/libpng12
)

set(SOURCE_FILES qemu-2.8.0/android/linker.c qemu-2.8.0/android/android.h qemu-2.8.0/android/winapi.h qemu-2.8.0/android/loader.h qemu-2.8.0/android/apicall.c)

aux_source_directory(qemu-2.8.0/linux-user SOURCE_FILES)
aux_source_directory(qemu-2.8.0 SOURCE_FILES)
aux_source_directory(qemu-2.8.0/android SOURCE_FILES)

add_executable(qemu ${SOURCE_FILES})