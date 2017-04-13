#!/bin/bash

#Created by fallenworld
#email:fallenworlder@gmail.com

export SDK_PLATFORM=~/dev/android/sdk/platform-tools
export NDK=~/dev/android/sdk/ndk-bundle
export PATH=$PATH:$SDK_PLATFORM:$NDK

ANDROID_BUILD=~/dev/android/build
PATH=$ANDROID_BUILD/bin:$PATH
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
NDK_PATH=~/dev/android/sdk/ndk-bundle
APPNAME=org.fallenworld.darkgalgame
SOLIB=qemu-2.8.0/i386-linux-user/qemu-i386
GDBSERVER=$NDK_PATH/prebuilt/android-arm/gdbserver/gdbserver
GDB_PORT=2333
DEBUG_PORT=45678
PID=
GDBSERVER_PID=
SIG_END_DEBUG=SIGUSR1

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
    #cp -fv i386-linux-user/qemu-i386 ../$JNILIBSDIR/libqemu.so
    cp -fv i386-linux-user/qemu-i386 ../debugSysRoot/data/data/$APPNAME/libqemu.so
    cd ..

    #Push dynamic lib and gdbserver
    echo "Pushing libqemu.so to android target:"
    adb push $SOLIB /data/local/tmp/libqemu.so
    if [ ! $(adb shell ls /data/local/tmp | grep gdbserver) ]
    then
        echo "Pushing gdbserver to android target:"
        adb push $GDBSERVER /data/local/tmp/gdbserver
    fi
    echo "run-as $APPNAME" > .adbShellCmd
    echo "cat /data/local/tmp/libqemu.so > libqemu.so" >> .adbShellCmd
    echo "cat /data/local/tmp/gdbserver > gdbserver" >> .adbShellCmd
    echo "chmod 777 libqemu.so" >> .adbShellCmd
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
    rm -rf .adbShellCmd
;;

debug)
    adb forward tcp:$DEBUG_PORT tcp:$DEBUG_PORT
    gnome-terminal -x ./debug.py

;;
esac


