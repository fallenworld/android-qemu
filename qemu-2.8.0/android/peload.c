//
// Created by fallenworld on 17-5-11.
//

#include <sys/mman.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

#include "loader.h"
#include "debug.h"

#define HEADER_BUFFER_SIZE 4096

#define TARGET_PAGESTART(_v) ((_v) & ~(abi_ulong)(TARGET_PAGE_SIZE-1))
#define TARGET_PAGEOFFSET(_v) ((_v) & (TARGET_PAGE_SIZE-1))
#define TARGET_PAGE_ALIGN(addr) (((addr) + TARGET_PAGE_SIZE - 1) & TARGET_PAGE_MASK)

static int pe_check(IMAGE_DOS_HEADER* dosHeader)
{
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        printLineNum();
        print("not a DOS Header\n");
        return 0;
    }
    IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)((uint)dosHeader + dosHeader->e_lfanew);
    if ((ntHeaders->Signature != IMAGE_NT_SIGNATURE)
        | (ntHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_I386))
    {
        printLineNum();
        print("not a NT image or wrong architecture\n");
        return 0;
    }
    return 1;
}

static abi_ulong setup_arg_pages(struct linux_binprm *bprm,
                                 struct image_info *info,
                                 char* headerBuffer)
{
    abi_ulong size, retval, guard;
    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)(headerBuffer);
    IMAGE_NT_HEADERS* ntHeader = (IMAGE_NT_HEADERS*)(headerBuffer + dosHeader->e_lfanew);
    size = ntHeader->OptionalHeader.SizeOfStackReserve;
    guard = TARGET_PAGE_SIZE;
    if (guard < qemu_real_host_page_size)
    {
        guard = qemu_real_host_page_size;
    }
    retval = target_mmap(0, size + guard, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (retval == -1)
    {
        printLineNum();
        perror("mmap stack");
        exit(-1);
    }
    /* We reserve one extra page at the top of the stack as guard.  */
    target_mprotect(retval, guard, PROT_NONE);
    info->stack_limit = retval + guard;
    return info->stack_limit + size - sizeof(void *);
}

static abi_ulong create_pe_tables(struct linux_binprm *bprm, struct image_info *info, char* headBuffer)
{
    return bprm->p;
}

int map_section(IMAGE_SECTION_HEADER* section, abi_ulong baseAddress, int fd)
{
    long retval;
    int sectionProperty = 0;
    //段属性
    if (section->Characteristics & IMAGE_SCN_MEM_READ) sectionProperty = PROT_READ;
    if (section->Characteristics & IMAGE_SCN_MEM_EXECUTE) sectionProperty |= PROT_EXEC;
    sectionProperty |= PROT_WRITE;
    //段在内存中的一些相关地址
    //TODO:两个段的起始和结束在同一个内存页里怎么办？
    abi_ulong address = baseAddress + section->VirtualAddress;  //段的加载地址
    abi_ulong addressRawEnd = address + section->SizeOfRawData; //根据段在文件中的大小计算出的段末地址
    abi_ulong addressRealEnd = TARGET_PAGE_ALIGN(
            MAX(addressRawEnd, address + section->Misc.VirtualSize));   //段的实际末地址
    if (addressRawEnd < addressRealEnd)
    {
        sectionProperty |= PROT_WRITE;
    }
    //把段映射进内存
    if (section->PointerToRawData % TARGET_PAGE_SIZE == 0)
    {
        /* 若段在文件中的偏移量是页的整数倍，则直接进行文件映射 */
        retval = target_mmap(address, addressRealEnd - address,
                             sectionProperty, MAP_PRIVATE | MAP_FIXED, fd,
                             section->PointerToRawData);
        if (retval < 0)
        {
            printLineNum();
            print("can't map section %s : %s\n", section->Name, strerror(errno));
            return -1;
        }
    }
    else
    {
        /* 段在文件中的偏移不是页大小的整数倍，无法进行内存映射
         * 需要将文件内容读取后复制到内存 */
        //分配段所需的内存块
        retval = target_mmap(address, addressRealEnd - address,  sectionProperty | PROT_WRITE,
                             MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
        if (retval < 0)
        {
            printLineNum();
            print("can't map section %s : %s\n", section->Name, strerror(errno));
            return -1;
        }
        //读取文件内容并复制到内存
        char buffer[TARGET_PAGE_SIZE];
        retval = lseek(fd, section->PointerToRawData, SEEK_SET);
        if (retval < 0)
        {
            printLineNum();
            print("can't load section %s, seek file failed : %s\n",
                    section->Name, strerror(errno));
            return -1;
        }
        int offset = 0;
        while (offset < section->SizeOfRawData)
        {
            int size = read(fd, buffer, TARGET_PAGE_SIZE);
            if (size > 0)
            {
                memcpy_to_target(address + offset, buffer, size);
                offset += size;
            }
            else if (size < 0)
            {
                printLineNum();
                print("can't read section %s, read file failed : %s\n",
                      section->Name, strerror(errno));
                return -1;
            }
        }
    }
    //若段映射到内存后的大小比段在文件中大，则填充0到末尾
    if (addressRawEnd < addressRealEnd)
    {
        memset((void*)addressRawEnd, 0, addressRealEnd - addressRawEnd);
    }
    return 0;
}

int load_pe_image(const char* filename, int fd, struct image_info* info, char* headerBuffer)
{
    long retval;
    int i;
    abi_ulong lowAddress = (abi_ulong)-1;  //文件加载后的最低地址
    abi_ulong highAddress = 0;  //文件加载后的最高地址
    abi_ulong loadAddress;      //文件加载到内存的基址
    abi_ulong loadBias;         //文件加载后相对于预期地址的地址偏移量
    //判断是否是合法的PE文件
    if (!pe_check((IMAGE_DOS_HEADER*)(headerBuffer)))
    {
        printLineNum();
        print("%s is not a valid PE file\n", filename);
        return -1;
    }
    //PE文件的DOS头、NT头、段表
    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)(headerBuffer);
    IMAGE_NT_HEADERS* ntHeader = (IMAGE_NT_HEADERS*)(headerBuffer + dosHeader->e_lfanew);
    IMAGE_SECTION_HEADER* sectionTable = (IMAGE_SECTION_HEADER*)((uint)ntHeader + sizeof(IMAGE_NT_HEADERS));
    //获取到文件映射到内存中后的最低和最高地址
    mmap_lock();
    loadAddress = ntHeader->OptionalHeader.ImageBase;
    lowAddress = loadAddress;
    highAddress = loadAddress + ntHeader->OptionalHeader.SizeOfImage;
    //检测文件映射的虚拟地址范围是否可用
    if (ntHeader->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE)
    {
        probe_guest_base(filename, lowAddress, highAddress);
    }
    else if(1)
    {
        //TODO : 动态链接库
    }
    loadBias = loadAddress - lowAddress;    //TODO: 装载发生偏移的话
    info->load_bias = loadBias;
    info->load_addr = loadAddress;
    info->entry = ntHeader->OptionalHeader.AddressOfEntryPoint + loadAddress;
    info->start_code = (abi_ulong)-1;
    info->end_code = 0;
    info->start_data = (abi_ulong)-1;
    info->end_data = 0;
    info->brk = 0;
    //根据段表进行加载
    for (i = 0; i < ntHeader->FileHeader.NumberOfSections; ++i)
    {
        retval = map_section(sectionTable + i, loadAddress, fd);
        if (retval < 0)
        {
            printLineNum();
            print("can't load file %s, section map failed\n", filename);
            return -1;
        }
    } //end for
    //获取到程序在内存中分布的一些边界
    info->start_code = loadAddress + ntHeader->OptionalHeader.BaseOfCode;
    info->end_code = info->start_code + ntHeader->OptionalHeader.SizeOfCode;
    info->start_data = loadAddress + ntHeader->OptionalHeader.BaseOfData;
    info->end_data = info->start_data
                     + ntHeader->OptionalHeader.SizeOfInitializedData
                     + ntHeader->OptionalHeader.SizeOfUninitializedData;
    if (info->end_data == 0)
    {
        info->start_data = info->end_code;
        info->end_data = info->end_code;
    }
    info->brk = loadBias + highAddress;
    //TODO:LOAD SYMBOLS
    mmap_unlock();
    close(fd);
    return 0;
}

int load_pe_binary(struct linux_binprm *bprm, struct image_info *info)
{
    int retval;
    //读取文件第一个页，包含了文件头、段表
    char headerBuffer[HEADER_BUFFER_SIZE];
    retval = pread(bprm->fd, headerBuffer, HEADER_BUFFER_SIZE, 0);
    if (retval < 0)
    {
        printLineNum();
        perror("can't read PE file");
        return -1;
    }
    //读取文件，将文件映射进内存
    retval = load_pe_image(bprm->filename, bprm->fd, info, headerBuffer);
    //分配栈空间
    bprm->p = setup_arg_pages(bprm, info, headerBuffer);
    //将参数、环境变量复制到栈空间
    bprm->p= create_pe_tables(bprm, info, headerBuffer);
    info->start_stack = bprm->p;
    //解析所依赖的动态链接库
    retval = linkerInit();
    if (retval < 0)
    {
        printLineNum();
        print("can't init linker\n");
        return -1;
    }
    retval = resolveModule(bprm, info, headerBuffer);
    if (retval < 0)
    {
        printLineNum();
        perror("can't load dependent modules");
        return -1;
    }
    return 0;
}