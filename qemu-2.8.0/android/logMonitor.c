//
// Created by fallenworld on 17-4-22.
//

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <stdio.h>
#include "debug.h"

int main()
{
    puts("**** Log monitor started ****");
    fflush(stdout);
    //创建unix域的tcp socket
    int logFd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (logFd < 0)
    {
        return 1;
    }
    struct sockaddr_un unixAddress;
    memset(&unixAddress, 0, sizeof(unixAddress));
    unixAddress.sun_family = AF_UNIX;
    strcpy(unixAddress.sun_path, SOCKET_PATH);
    while (connect(logFd, (struct sockaddr*)(&unixAddress), sizeof(unixAddress)) < 0)
    {
        usleep(250 * 1000);
    }
    //发送DEBUG CONNECT消息
    char buffer[1024];
    strcpy(buffer, "DEBUG CONNECT");
    write(logFd, buffer, strlen(buffer) + 1);
    //开始读取app发送过来的log并输出
    while (1)
    {
        int size = read(logFd, buffer, 512);
        if (size > 0)
        {
            write(STDOUT_FILENO, buffer, (size_t)size);
        }
        else
        {
            goto endLog;
        }
    }
    endLog:
    puts("**** Log monitor end ****");
    close(logFd);
    return 0;
}