//
// Created by fallenworld on 17-5-14.
//

#ifndef QEMU_ANDROID_H
#define QEMU_ANDROID_H

#include "qemu/osdep.h"
#include "linux-user/qemu.h"
#include <jni.h>
#include "config.h"
#include "debug.h"
#include "loader.h"
#include "winapi.h"

/* start.c */
int main(int argc, char** argv, char** envp);

int start();

JNIEXPORT jstring JNICALL
Java_org_fallenworld_darkgalgame_MainActivity_entry(JNIEnv *env, jobject thiz);

JNIEnv *getEnv();

#endif //QEMU_ANDROID_H
