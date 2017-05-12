//
// Created by fallenworld on 17-5-11.
//

#include <sys/mman.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include "qemu/osdep.h"
#include "linux-user/qemu.h"
#include "winnt.h"

#define HEADER_BUFFER_SIZE 4096

#define TARGET_PAGESTART(_v) ((_v) & ~(abi_ulong)(TARGET_PAGE_SIZE-1))
#define TARGET_PAGEOFFSET(_v) ((_v) & (TARGET_PAGE_SIZE-1))

/* Older linux kernels provide up to MAX_ARG_PAGES (default: 32) of
 * argument/environment space. Newer kernels (>2.6.33) allow more,
 * dependent on stack size, but guarantee at least 32 pages for
 * backwards compatibility.
 */
#define STACK_LOWER_LIMIT (32 * TARGET_PAGE_SIZE)

static int pe_check(IMAGE_DOS_HEADER* dosHeader)
{
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        return 0;
    }
    IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)((uint)dosHeader + dosHeader->e_lfanew);
    if ((ntHeaders->Signature != IMAGE_NT_SIGNATURE)
        | (ntHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_I386))
    {
        return 0;
    }
    return 1;
}

int create_pe_table()
{

}

int load_pe_image(const char* filename, int fd, struct image_info* info, char* headerBuffer)
{
    int retval;
    int i;
    abi_ulong lowAddress = (abi_ulong)-1;  //文件加载后的最低地址
    abi_ulong highAddress = 0;  //文件加载后的最高地址
    abi_ulong loadAddress;      //文件加载到内存的基址
    abi_ulong loadBias;         //文件加载后相对于预期地址的地址偏移量
    //判断是否是合法的PE文件
    if (!pe_check((IMAGE_DOS_HEADER*)(headerBuffer)))
    {
        const char* errorMessage = "Invalid PE image for this architecture";
        fprintf(stderr, "%s: %s\n", filename, errorMessage);
        exit(-1);
    }
    //PE文件的DOS头、NT头、段表
    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)(headerBuffer);
    IMAGE_NT_HEADERS* ntHeader = (IMAGE_NT_HEADERS*)(headerBuffer + dosHeader->e_lfanew);
    IMAGE_SECTION_HEADER* sectionTable = (IMAGE_SECTION_HEADER*)((uint)ntHeader + sizeof(IMAGE_NT_HEADERS));
    //获取到文件映射到内存中后的最低和最高地址
    for (i = 0; i < ntHeader->FileHeader.NumberOfSections; ++i)
    {
        abi_ulong address = sectionTable[i].VirtualAddress - sectionTable[i].PointerToRawData;
        if (address < lowAddress)
        {
            lowAddress = address;
        }
        address = sectionTable[i].VirtualAddress + sectionTable[i].SizeOfRawData;
        if (address > highAddress)
        {
            highAddress = address;
        }
    }
    //文件加载到内存中后的一些地址信息
    mmap_lock();
    loadAddress = lowAddress;
    loadBias = loadAddress - lowAddress; //TODO: ???.jpg
    //检测文件映射的虚拟地址范围是否可用
    if (ntHeader->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE)
    {
        probe_guest_base(filename, lowAddress, highAddress);
    }
    else if(1)
    {
        //TODO : DLL
    }
    info->load_bias = loadBias;
    info->load_addr = loadAddress;
    info->entry = ntHeader->OptionalHeader.AddressOfEntryPoint + loadBias;
    info->start_code = (abi_ulong)-1;
    info->end_code = 0;
    info->start_data = (abi_ulong)-1;
    info->end_data = 0;
    info->brk = 0;
    //根据段表进行加载
    for (i = 0; i < ntHeader->FileHeader.NumberOfSections; ++i)
    {
        IMAGE_SECTION_HEADER *loadSection = sectionTable + i;
        int sectionProperty = 0;
        //段属性
        if (loadSection->Characteristics & IMAGE_SCN_MEM_READ) sectionProperty = PROT_READ;
        if (loadSection->Characteristics & IMAGE_SCN_MEM_WRITE) sectionProperty |= PROT_WRITE;
        if (loadSection->Characteristics & IMAGE_SCN_MEM_EXECUTE) sectionProperty |= PROT_EXEC;
        //段在内存中的一些相关地址
        abi_ulong address = loadBias + loadSection->VirtualAddress; //段的加载地址
        abi_ulong addressPageStart = TARGET_PAGESTART(address);     //段加载基址的页起始地址
        abi_ulong addressPageOffset = TARGET_PAGEOFFSET(address);   //段基址相对于页起始地址的偏移量
        abi_ulong addressRawEnd = address + loadSection->SizeOfRawData;     //根据段在文件中的大小计算出的段末地址
        abi_ulong addressRealEnd = address + loadSection->Misc.VirtualSize;   //段的实际末地址
        //把段映射进内存
        retval = target_mmap(addressPageStart, loadSection->SizeOfRawData + addressPageOffset,
                             sectionProperty, MAP_PRIVATE | MAP_FIXED, fd,
                             loadSection->PointerToRawData - addressPageOffset);
        if (retval < 0) {
            fprintf(stderr, "%s: %s\n", filename, strerror(errno));
            exit(-1);
        }
        //若为bss段，则需要映射一段0进去
        if (addressRawEnd < addressRealEnd) {
            zero_bss(addressRawEnd, addressRealEnd, sectionProperty);
        }
        //获取到程序在内存中分布的一些边界
        if (sectionProperty & PROT_EXEC) {
            if (address < info->start_code) {
                info->start_code = address;
            }
            if (addressRawEnd > info->end_code) {
                info->end_code = addressRawEnd;
            }
        }
        if (sectionProperty & PROT_WRITE) {
            if (address < info->start_data) {
                info->start_data = address;
            }
            if (addressRawEnd > info->end_data) {
                info->end_data = addressRawEnd;
            }
            if (addressRealEnd > info->brk) {
                info->brk = addressRealEnd;
            }
        }
    } //end for
    if (info->end_data == 0)
    {
        info->start_data = info->end_code;
        info->end_data = info->end_code;
        info->brk = info->end_code;
    }
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
    char headerBufferCopy[HEADER_BUFFER_SIZE];
    retval = read(bprm->fd, headerBuffer, HEADER_BUFFER_SIZE);
    if (retval < 0)
    {
        perror("Cannot read PE file");
        exit(-1);
    }
    memcpy(headerBufferCopy, headerBuffer, HEADER_BUFFER_SIZE);
    //读取文件，将文件映射进内存
    load_pe_image(bprm->filename, bprm->fd, info, headerBuffer);
    //分配栈空间
    bprm->p = setup_arg_pages(bprm, info);

}