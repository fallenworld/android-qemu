#!/bin/bash

#Created by fallenworld
#email:fallenworlder@gmail.com

SDK=~/dev/android/sdk
NDK=~/dev/android/ndk
ANDROID_BUILD=~/dev/android/build
export PATH=$PATH:$SDK/platform-tools:$NDK:$ANDROID_BUILD/bin

SYSROOT=$ANDROID_BUILD/sysroot
HOST=arm-linux-androideabi
CC=$HOST-gcc
CXX=$HOST-g++
CFLAGS="-march=armv7-a -mfloat-abi=softfp -mfpu=vfpv3-d16 -fPIE -pie -fPIC -Wno-missing-prototypes -Wno-strict-prototypes -Wno-old-style-definition"
CXXFLAGS="-std=c++11"
LIBDIRS="-L$ANDROID_BUILD/arm-linux-androideabi/lib"
LDFLAGS="-march=armv7-a -Wl,--fix-cortex-a8,-soname,libqemu.so $LIBDIRS -fPIE -pie -fPIC -shared"
PKG_CONFIG_PATH="$SYSROOT/usr/lib/pkgconfig"
CONFLAGS="--prefix=${SYSROOT}/usr --cross-prefix=${HOST}- --host-cc=$CC --target-list=i386-linux-user --cpu=arm --disable-system --disable-bsd-user --disable-tools --disable-zlib-test --disable-guest-agent --disable-nettle --enable-debug"
APPDIR=../DarkGalgame
JNILIBSDIR=$APPDIR/app/src/main/jniLibs/armeabi-v7a
APPNAME=org.fallenworld.darkgalgame
SOLIB=qemu-2.8.0/i386-linux-user/qemu-i386
LOGMONITOR=qemu-2.8.0/android/logMonitor
GDBSERVER=$NDK/prebuilt/android-arm/gdbserver/gdbserver
GDB_PORT=2333
PID=
GDBSERVER_PID=
SIG_END_DEBUG=SIGUSR1
CONSOLE=konsole
MONITOR_BUILD="$CC -o android/logMonitor android/logMonitor.c -Iinclude -pie"

case $1 in

install)
    cd ../DarkGalgame
    ./gradlew installDebug
;;

build|rebuild)
    #Compile qemu
    cd qemu-2.8.0
    if [ ! -s $ANDROID_BUILD/bin/arm-linux-androideabi-pkg-config ]
    then
        ln -s /usr/bin/pkg-config $ANDROID_BUILD/bin/arm-linux-androideabi-pkg-config
    fi
    if [ $1 = rebuild ]
    then
        make clean
        make distclean
        PKG_CONFIG_PATH=$PKG_CONFIG_PATH CC=$CC CXX=$CXX CFLAGS="$CFLAGS" CXXFLAGS="$CXXFLAGS" LDFLAGS="$LDFLAGS" ./configure $CONFLAGS &&
        make
    else
        make
    fi
    if [ ! $? = 0 ]
    then
        exit 1
    fi
    $MONITOR_BUILD
    #cp -fv i386-linux-user/qemu-i386 ../$JNILIBSDIR/libqemu.so
    cp -fv i386-linux-user/qemu-i386 ../debugSysRoot/data/data/$APPNAME/libqemu.so
    cd ..

    #Push dynamic lib, gdb server, log monitor
    echo "Pushing libqemu.so and logMonitor to android target:"
    adb push $SOLIB /data/local/tmp/libqemu.so
    adb push $LOGMONITOR /data/local/tmp/logMonitor
    adb shell chmod 777 /data/local/tmp/logMonitor
    if [ ! $(adb shell ls /data/local/tmp | grep gdbserver) ]
    then
        echo "Pushing gdbserver to android target:"
        adb push $GDBSERVER /data/local/tmp/gdbserver
    fi
    echo "run-as $APPNAME" > .adbShellCmd
    echo "cp -fv /data/local/tmp/libqemu.so libqemu.so" >> .adbShellCmd
    echo "cp -fv /data/local/tmp/logMonitor logMonitor" >> .adbShellCmd
    echo "cp -fv /data/local/tmp/gdbserver gdbserver" >> .adbShellCmd
    echo "chmod 777 libqemu.so" >> .adbShellCmd
    echo "chmod 777 logMonitor" >> .adbShellCmd
    echo "chmod 777 gdbserver" >> .adbShellCmd
    adb shell < .adbShellCmd
;;

clean)
    cd qemu-2.8.0
    make clean
;;

run)
    #Start APP
    adb shell am start -n $APPNAME/$APPNAME.MainActivity -a android.intent.action.MAIN -c android.intent.category.LAUNCHER

    #Get APP process ID
    PID=$(adb shell ps | grep $APPNAME | awk {'print $2'})

    #Start GDB server
    adb forward tcp:$GDB_PORT tcp:$GDB_PORT
    echo "Starting GDB server:"
    echo "run-as $APPNAME" > .adbShellCmd
    echo "./gdbserver :$GDB_PORT --attach $PID" >> .adbShellCmd
    adb shell < .adbShellCmd &
;;

stop)
    #Stop APP
    echo "Stop APP"
    PID=$(adb shell ps | grep $APPNAME | awk {'print $2'})
    echo "run-as $APPNAME" > .adbShellCmd
    echo "kill -s SIGKILL $PID" >> .adbShellCmd
    #echo "kill -s $SIG_END_DEBUG $PID" >> .adbShellCmd
    adb shell < .adbShellCmd
    adb shell am force-stop $APPNAME

    #Kill GDB server
    echo "Stop gdb server"
    GDBSERVER_PID=$(adb shell ps | grep gdbserver | awk {'print $2'})
    echo "run-as $APPNAME" > .adbShellCmd
    echo "kill -s SIGQUIT $GDBSERVER_PID" >> .adbShellCmd
    adb shell < .adbShellCmd

    #Kill log monitor
    echo "Stop log monitor"
    LOGMONITOR_PID=$(adb shell ps | grep logMonitor | awk {'print $2'})
    echo "run-as $APPNAME" > .adbShellCmd
    echo "kill -s SIGQUIT $LOGMONITOR_PID" >> .adbShellCmd
    adb shell < .adbShellCmd
;;

log)
    echo "run-as $APPNAME" > .adbShellCmd
    echo "./logMonitor" >> .adbShellCmd
    $CONSOLE --hold -e bash -c 'adb shell < .adbShellCmd' &
;;
esac


