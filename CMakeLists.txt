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

set(SOURCE_FILES
        qemu-2.8.0/linux-user/main.c
        qemu-2.8.0/android/debug.c
        qemu-2.8.0/android/debug.h
        qemu-2.8.0/android/start.c
        qemu-2.8.0/android/start.h qemu-2.8.0/android/logMonitor.c qemu-2.8.0/android/debugConfig.h)
add_executable(qemu ${SOURCE_FILES})