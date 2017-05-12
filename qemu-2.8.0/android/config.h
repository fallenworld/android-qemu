//
// Created by fallenworld on 17-5-9.
//

#ifndef QEMU_ANDROID_CONFIG_H
#define QEMU_ANDROID_CONFIG_H

#include <qemu/compiler.h>

#define APP_PACKAGE_NAME org.fallenworld.darkgalgame
#define ANDROID_INTERP_PREFIX "/data/data/" stringify(APP_PACKAGE_NAME) "/i386"

#endif //QEMU_ANDROID_CONFIG_H
