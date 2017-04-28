//
// Created by fallenworld on 17-3-28.
//

#ifndef QEMU_ANDROID_DEBUG_H
#define QEMU_ANDROID_DEBUG_H

//PC端结束调试时所的发送信号
#define SIG_END_DEBUG SIGUSR1

//初始化调试模块
int initDebug();

//初始化用于传输调试信息的socket连接
int initSocket();

//初始化log输出
int initLog();

//等待PC端的GDB连接上来
void waitDebugConnect();

//输出log
void print(const char* format, ...);

//显示对话框消息
void alert(const char* message);

#endif //QEMU_ANDROID_DEBUG_H
