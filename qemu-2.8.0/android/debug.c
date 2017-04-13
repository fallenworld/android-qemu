//
// Created by fallenworld on 17-3-28.
//

#include <sys/un.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <jni.h>
#include <stdio.h>
#include "debug.h"
#include "start.h"

#ifdef DEBUG_UNIX_SOCKET
#define LOCAL_PREFIX    /data/data/
#define PACKAGE_NAME    org.fallenworld.darkgalgame
#define SOCKET_FILE     gdbConnected
#define PATH_PREFIX     stringify(LOCAL_PREFIX) stringify(PACKAGE_NAME)
#define SOCKET_PATH     PATH_PREFIX "/" stringify(SOCKET_FILE)
#else
#define DEBUG_PORT 45678
#define GDB_WAIT_SECONDS 2
#endif

static int deviceDebugFd = 0;
static int hostDebugFd = 0;

int initDebug()
{
    //设置结束调试信号的处理函数
    //signal(SIG_END_DEBUG, signalEndDebug);
    //创建socket
    deviceDebugFd = socket(AF_INET, SOCK_STREAM, 0);
    if (deviceDebugFd < 0)
    {
        //alert("Init debug failed : Cannot create socket");
        return 1;
    }
    struct sockaddr_in localAddress;
    memset(&localAddress, 0, sizeof(localAddress));
    localAddress.sin_family = AF_INET;
    localAddress.sin_port = htons(DEBUG_PORT);
    localAddress.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(deviceDebugFd, (struct sockaddr*)&localAddress, sizeof(struct sockaddr_in)) < 0)
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
    //等待PC端连接上来
    for (;;)
    {
        hostDebugFd = accept(deviceDebugFd, NULL, NULL);
        if (hostDebugFd < 0)
        {
            continue;
        }
        for (;;)
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
    //将标准输出、标准错误重定向
    if (dup2(STDOUT_FILENO, hostDebugFd) > 0 &&
        dup2(STDERR_FILENO, hostDebugFd) > 0)
    {
        //alert("Init debug failed : Cannot redirect stdout or stderr");
        return 4;
    }
    sleep(GDB_WAIT_SECONDS);
    return 0;
}

void signalEndDebug(int sig)
{
    //关闭和PC端通信的socket
    if (hostDebugFd > 0)
    {
        close(hostDebugFd);
    }
    if (deviceDebugFd > 0)
    {
        close(deviceDebugFd);
    }
    exit(1);
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
