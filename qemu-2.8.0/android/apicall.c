//
// Created by fallenworld on 17-5-15.
//

#include "winapi.h"

INIT_API_LIST();

static GHashTable* apiTableNameKey;
static GHashTable* apiTableNumKey;
static ExecutionState exec;

int apiTableInit()
{
    apiTableNameKey = g_hash_table_new(g_str_hash, g_str_equal);
    apiTableNumKey = g_hash_table_new(g_direct_hash, g_direct_equal);
    int i;
    for (i = 0; i < API_COUNT; ++i)
    {
        if (!g_hash_table_insert(apiTableNameKey, apiList[i].name, apiList + i)
            || !g_hash_table_insert(apiTableNumKey, (gpointer)apiList[i].num, apiList + i))
        {
            return -1;
        }
    }
    return 0;
}

int apiCallInit(CPUArchState *env, SyncClocks* syncClocks, TranslationBlock** lastTB)
{
    exec.cpuEnv = env;
    exec.syncClocks = syncClocks;
    exec.lastTB = lastTB;
    return 0;
}

int apiCallClean()
{
    g_hash_table_destroy(apiTableNameKey);
    g_hash_table_destroy(apiTableNumKey);
    return 0;
}

FunctionInfo* getFunctionByName(const char* apiName)
{
    return (FunctionInfo*)g_hash_table_lookup(apiTableNameKey, (gpointer)apiName);
}

FunctionInfo* getFunctionByNum(uint num)
{
    return (FunctionInfo*)g_hash_table_lookup(apiTableNumKey, (gpointer)num);
}

TranslationBlock* getArmTB(abi_ulong pc)
{
    exec.armTB.pc = pc;
    exec.armTB.tc_ptr = NULL;
    return &exec.armTB;
}

void executeArmTB(TranslationBlock* tb)
{
    callFunction(getFunctionByNum(tb->pc - FUNCTION_BASE));
}

int callFunction(FunctionInfo* function)
{
    //调用函数
    function->address(exec.cpuEnv);
    //函数返回栈中的地址
    abi_ulong retAddress = (*(abi_ulong*)(exec.cpuEnv->regs[R_ESP]));
    exec.cpuEnv->eip = retAddress;
    exec.cpuEnv->regs[R_ESP] += sizeof(abi_ulong);
    //stdcall调用约定需要清除栈中的参数
    if (function->callingConvention == CONVENTION_STDCALL)
    {
        exec.cpuEnv->regs[R_ESP] += sizeof(abi_ulong) * function->argc;
    }
    return 0;
}

/* API 测试 */
typedef struct _FILETIME {
    DWORD dwLowDateTime;
    DWORD dwHighDateTime;
} FILETIME, *PFILETIME;

void GetSystemTimeAsFileTime(CPUArchState* env)
{
    print("GetSystemTimeAsFileTime called\n");
    FILETIME* fileTime = (FILETIME*)(GETARG(env, 1));
    fileTime->dwHighDateTime = 0xab;
    fileTime->dwHighDateTime = 0xcd;
}