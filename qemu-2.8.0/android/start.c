//
// Created by fallenworld on 17-3-28.
//

#include <stdio.h>
#include "start.h"
#include "debug.h"

static JNIEnv *jniEnv;

JNIEXPORT jstring JNICALL
Java_org_fallenworld_darkgalgame_MainActivity_entry
        (JNIEnv *env, jobject thiz)
{
    jniEnv = env;
    initDebug();
    start();
    return (*env)->NewStringUTF(env, "JNI end");
}

JNIEnv *getEnv()
{
    return jniEnv;
}


int start()
{
    print("log test\n");
    return 0;
}







