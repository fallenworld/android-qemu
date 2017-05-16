//
// Created by fallenworld on 17-5-14.
//

#ifndef QEMU_ANDROID_LOADER_H
#define QEMU_ANDROID_LOADER_H

#include "winnt.h"
#include "qemu/osdep.h"
#include "linux-user/qemu.h"

/* * * * peload.c * * * * */

/**
 * 将PE文件的一个段加载到内存
 * @param section 要加载的段在PE文件中的段表项
 * @param baseAddress PE文件加载到的基址
 * @param fd 要加载的文件的文件描述符
 * @return 若加载成功，则返回0；失败返回-1
 */
int map_section(IMAGE_SECTION_HEADER* section, abi_ulong baseAddress, int fd);

/**
 * 将PE文件映像映射到内存中去
 * @param filename 文件名
 * @param fd 要加载的文件的文件描述符
 * @param image_info 文件映像信息结构体的指针
 * @param headerBuffer 文件头缓冲区
 * @return 若成功，则返回0；失败返回-1
 */
int load_pe_image(const char* filename, int fd, struct image_info* info, char* headerBuffer);

/**
 * 加载一个PE文件
 * @param linux_binprm linux文件信息
 * @param image_info 文件映像信息结构体的指针
 * @return 若加载成功，则返回0；失败返回-1
 */
int load_pe_binary(struct linux_binprm *bprm, struct image_info *info);


/* * * * linker.c * * * * */

#define FUNCTION_BASE 0x80000000

//调用约定
#define CONVENTION_CDECL     0   //cdecl(一般函数的调用约定)
#define CONVENTION_STDCALL   1   //stdcall(Windows API的调用约定)

typedef void (*X86Function)(CPUArchState* env);
typedef struct FunctionInfo
{
    char* name;     //函数名
    uint num;       //函数的编号
    X86Function address;   //函数的实际地址
    int argc;       //函数的参数个数,若为可变参数函数，则argc的为可变部分之前的参数的个数
    int callingConvention; //函数的调用约定
} FunctionInfo;

/**
 * 初始化动态链接器
 */
int linkerInit();

/**
 * 判断一个模块是否是Android下实现的模块
 * @param moduleName 模块名称
 * @return 若是，返回１；否则返回０
 */
int isNativeModule(char* moduleName);

/**
 * 对一个文件进行动态链接，处理依赖的模块和导入函数
 * @param linux_binprm linux文件信息
 * @param image_info 文件映像信息结构体的指针
 * @param headerBuffer 文件头缓冲区
 * @return 若成功，返回0；否则返回-1
 */
int resolveModule(struct linux_binprm* bprm, struct image_info* info, char* headerBuffer);


/* * * * apicall.c * * * * */
#define GETARG(env, argno) (*(abi_ulong*)(exec.cpuEnv->regs[R_ESP] + sizeof(abi_ulong) * argno))

#define IS_ARM_FUNCTION(_tb_) ((_tb_)->tc_ptr == NULL)

typedef struct ExecutionState
{
    CPUArchState* cpuEnv;
    SyncClocks* syncClocks;
    TranslationBlock** lastTB;
    TranslationBlock armTB;
}ExecutionState;


int apiTableInit();
int apiCallInit(CPUArchState *env, SyncClocks* syncClocks, TranslationBlock** lastTB);
int apiCallClean();

FunctionInfo* getFunctionByName(const char* apiName);
FunctionInfo* getFunctionByNum(uint num);

int callFunction(FunctionInfo* function);

TranslationBlock* getArmTB(abi_ulong pc);
void executeArmTB(TranslationBlock* tb);

void GetSystemTimeAsFileTime(CPUArchState* env);

#endif //QEMU_LOADER_H
