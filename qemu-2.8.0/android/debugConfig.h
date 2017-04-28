//
// Created by fallenworld on 17-4-22.
//

#ifndef QEMU_DEBUGCONFIG_H
#define QEMU_DEBUGCONFIG_H

#include "qemu/compiler.h"

#define LOCAL_PREFIX    /data/data
#define PACKAGE_NAME    org.fallenworld.darkgalgame
#define PATH_PREFIX     stringify(LOCAL_PREFIX) "/" stringify(PACKAGE_NAME)

#define SOCKET_PATH     "\0debug.socket"
#define GDB_WAIT_SECONDS 1

#endif //QEMU_DEBUGCONFIG_H
