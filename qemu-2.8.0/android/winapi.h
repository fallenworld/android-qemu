//
// Created by fallenworld on 17-5-14.
//

#ifndef QEMU_ANDROID_WINAPI_H
#define QEMU_ANDROID_WINAPI_H

#include "android.h"

/**** 动态链接库列表 ****/
#define NATIVE_MODULE_COUNT 7
#define INIT_MODULE_LIST() \
static const char* nativeModuleList[NATIVE_MODULE_COUNT] = \
        { \
                "KERNEL32.dll", \
                "VCRUNTIME140.dll", \
                "api-ms-win-crt-stdio-l1-1-0.dll", \
                "api-ms-win-crt-runtime-l1-1-0.dll", \
                "api-ms-win-crt-math-l1-1-0.dll", \
                "api-ms-win-crt-locale-l1-1-0.dll", \
                "api-ms-win-crt-heap-l1-1-0.dll" \
        };

/**** 函数的编号 ****/
/* KERNEL32 */
#define KERNEL32_BASE 0
#define KERNEL32_NUM(_num) (KERNEL32_BASE + 1)

/**** API 函数列表 ****/
#define API_COUNT 1
#define INIT_API_LIST() \
static FunctionInfo apiList[] = \
{ \
    {"GetSystemTimeAsFileTime", KERNEL32_NUM(1), GetSystemTimeAsFileTime, 1, CONVENTION_STDCALL} \
};


#endif //QEMU_ANDROID_WINAPI_H
