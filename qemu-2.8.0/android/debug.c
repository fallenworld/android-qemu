//
// Created by fallenworld on 17-3-28.
//

#include <sys/un.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include "android.h"

static int deviceDebugFd = 0;
static int hostDebugFd = 0;

int initDebug()
{
    initSocket();
    waitDebugConnect();
    initLog();
    sleep(GDB_WAIT_SECONDS);
    return 0;
}

int initSocket()
{
    //创建socket
    deviceDebugFd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (deviceDebugFd < 0)
    {
        //alert("Init debug failed : Cannot create socket");
        return 1;
    }
    //unlink(SOCKET_PATH);
    struct sockaddr_un localAddress;
    memset(&localAddress, 0, sizeof(localAddress));
    localAddress.sun_family = AF_UNIX;
    strcpy(localAddress.sun_path, SOCKET_PATH);
    if (bind(deviceDebugFd, (struct sockaddr*)&localAddress, sizeof(localAddress)) < 0)
    {
        close(deviceDebugFd);
        //alert("Init debug failed : Socket bind error");
        return errno;
    }
    if (listen(deviceDebugFd, 8) < 0)
    {
        close(deviceDebugFd);
        //alert("Init debug failed : Socket listen error");
        return 3;
    }
    return 0;
}

void waitDebugConnect()
{
    while (1)
    {
        //等待PC端连接上来
        hostDebugFd = accept(deviceDebugFd, NULL, NULL);
        if (hostDebugFd < 0)
        {
            continue;
        }
        while (1)
        {
            //等待PC端发送确认信息
            const char *info = "DEBUG CONNECT";
            char buffer[32];
            int size = read(hostDebugFd, buffer, 32);
            if (size > 0 && strcmp(info, buffer) == 0)
            {
                goto endWait;
            }
        }
    }
    endWait:
    return;
}

int initLog()
{
    //将标准输出、标准错误重定向
    if (dup2(hostDebugFd, STDOUT_FILENO) < 0 ||
        dup2(hostDebugFd, STDERR_FILENO) < 0)
    {
        //alert("Init log failed : Cannot redirect stdout or stderr");
        return 1;
    }
    return 0;
}

void print(const char* format, ...)
{
    va_list argList;
    va_start(argList, format);
    vprintf(format, argList);
    fflush(stdout);
    va_end(argList);
}

void alert(const char* message)
{
    JNIEnv *jniEnv = getEnv();
    static jclass clazz = NULL;
    static jmethodID alertMethodId = NULL;
    //获取class对象
    if (clazz == NULL)
    {
        clazz = (*jniEnv)->FindClass(jniEnv,
                                     "org/fallenworld/darkgalgame/MainActivity");
        if (clazz == NULL)
        {
            return;
        }
    }
    //获取Java方法id
    if (alertMethodId == NULL)
    {
        alertMethodId = (*jniEnv)->GetStaticMethodID(jniEnv, clazz,
                                                     "alert", "(Ljava/lang/String)V");
        if (alertMethodId == NULL)
        {
            return;
        }
    }
    //调用方法
    jstring str = (*jniEnv)->NewStringUTF(jniEnv, message);
    (*jniEnv)->CallStaticVoidMethod(jniEnv, clazz, alertMethodId, str);
}

#define PATH_PREFIX_END qemu-2.8.0
void printFileLine(const char* fullFileName, int line)
{
    char* shortFileName = strstr(fullFileName, stringify(PATH_PREFIX_END))
                          + strlen(stringify(PATH_PREFIX_END)) + 1;
    print("%s(%d) ", shortFileName, line);
}