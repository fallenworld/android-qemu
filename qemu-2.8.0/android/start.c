//
// Created by fallenworld on 17-3-28.
//

#include <unistd.h>
#include "start.h"
#include "debug.h"
#include "config.h"

int runFile(int argc, char **argv, char **envp);

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

int runFile(int argc, char** argv, char** envp)
{
    main(argc, argv, envp);
}

int start()
{
    char* executable = "/data/data/org.fallenworld.darkgalgame/helloworld";
    int argc = 6;
    char* argv[] = {"qemu-i386", "-L", ANDROID_INTERP_PREFIX, "-d",
                    "in_asm,out_asm,int,guest_errors,exec,page", executable};
    runFile(argc, argv, environ);
    return 0;
}







