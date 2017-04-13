//
// Created by fallenworld on 17-3-28.
//

#ifndef QEMU_ANDROID_DEBUG_H
#define QEMU_ANDROID_DEBUG_H

//PC端结束调试时所的发送信号
#define SIG_END_DEBUG SIGUSR1

//初始化调试模块
int initDebug();

//当PC端结束调试时所发送信号的信号处理函数
void signalEndDebug(int sig);

//显示对话框消息
void alert(const char* message);

#endif //QEMU_ANDROID_DEBUG_H
