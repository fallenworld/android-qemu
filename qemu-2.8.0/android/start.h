//
// Created by fallenworld on 17-3-28.
//

#ifndef QEMU_ANDROID_START_H
#define QEMU_ANDROID_START_H

#include <jni.h>

int start();

JNIEXPORT jstring JNICALL
Java_org_fallenworld_darkgalgame_MainActivity_entry(JNIEnv *env, jobject thiz);

JNIEnv *getEnv();

#endif //QEMU_ANDROID_START_H
