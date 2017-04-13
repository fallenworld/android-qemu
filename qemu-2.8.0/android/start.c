//
// Created by fallenworld on 17-3-28.
//

#include <stdio.h>
#include <stdlib.h>
#include "start.h"
#include "debug.h"

static JNIEnv *jniEnv;

JNIEXPORT jstring JNICALL
Java_org_fallenworld_darkgalgame_MainActivity_entry
        (JNIEnv *env, jobject thiz)
{
    jniEnv = env;
    int ret = initDebug();
    start();
    char buffer[16];
    if (ret != 0)
    {
        sprintf(buffer, "%d\0", ret);
        return (*env)->NewStringUTF(env, buffer);
    }
    return (*env)->NewStringUTF(env, "JNI end");
}

JNIEnv *getEnv()
{
    return jniEnv;
}


int start()
{
    puts("log test\n");
    return 0;
}







