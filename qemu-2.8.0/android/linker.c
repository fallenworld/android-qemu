//
// Created by fallenworld on 17-5-13.
// PE文件的动态链接器
//

#include <glib.h>
#include "debug.h"
#include "winapi.h"

INIT_MODULE_LIST();

int linkerInit()
{
    if (apiTableInit() < 0)
    {
        printLineNum();
        print("can't init API\n");
        return -1;
    }
    return 0;
}

int isNativeModule(char* moduleName)
{
    int i;
    for (i = 0; i < NATIVE_MODULE_COUNT; ++i)
    {
        if (strcmp(moduleName, nativeModuleList[i]) == 0)
        {
            return 1;
        }
    }
    return 0;
}

int resolveModule(struct linux_binprm* bprm, struct image_info* info, char* headerBuffer)
{
    //文件被加载的基地址
    abi_ulong loadBase = info->load_addr;
    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)(headerBuffer);
    IMAGE_NT_HEADERS* ntHeader = (IMAGE_NT_HEADERS*)(headerBuffer + dosHeader->e_lfanew);
    IMAGE_OPTIONAL_HEADER* optionalHeader = &ntHeader->OptionalHeader;
    //导入表
    IMAGE_IMPORT_DESCRIPTOR* importTable = (IMAGE_IMPORT_DESCRIPTOR*)
            (optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + loadBase);
    //遍历导入表
    IMAGE_IMPORT_DESCRIPTOR* importModule;
    for (importModule = importTable;
         importModule->DUMMYUNIONNAME.Characteristics != 0;
         importModule++)
    {
        char* moduleName = (char*)(importModule->Name + loadBase);
        IMAGE_THUNK_DATA32* importAddressTable = (IMAGE_THUNK_DATA32*)
                (importModule->FirstThunk + loadBase);
        if (isNativeModule(moduleName))
        {
            /* 该动态库是在Android上用Linux函数实现的 */

            //遍历IAT，修改函数地址
            IMAGE_THUNK_DATA32* importFunction;
            for (importFunction = importAddressTable;
                 importFunction->u1.AddressOfData != 0;
                 importFunction++)
            {
                const char* functionName;
                if (IMAGE_SNAP_BY_ORDINAL32(importFunction->u1.Ordinal))
                {
                    /* 函数根据序号导入 */
                    //TODO: 序号导入时获取函数名
                    functionName = "";
                }
                else
                {
                    /* 函数根据函数名导入 */
                    IMAGE_IMPORT_BY_NAME* functionNameInfo =
                            (IMAGE_IMPORT_BY_NAME*)(importFunction->u1.AddressOfData + loadBase);
                    functionName = functionNameInfo->Name;
                }
                FunctionInfo* functionInfo = getFunctionByName(functionName);
                if (functionInfo == NULL)
                {
                    print("invalid function %s\n", functionName);
                }
                else
                {
                    //修改导入函数地址
                    //导入函数的地址会被修改为函数编号+偏移量
                    importFunction->u1.Function = FUNCTION_BASE + functionInfo->num;
                };
            }
        }
        else
        {
            /* 该动态库使用x86 windows的原生文件 */

        }
    }
    return 0;
}
