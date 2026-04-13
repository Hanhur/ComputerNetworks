/* На этой странице содержится клиентская лрограмма, запрашивающая файл у серверной программы, расположенной на следующей странице. 
Сервер в ответ на запрос высылает файл.*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")

#define SERVER_PORT 8080
#define BUF_SIZE 4096

int main(int argc, char **argv)
{
    int c, s, bytes;
    char buf[BUF_SIZE];
    struct hostent *h;
    struct sockaddr_in channel;
    WSADATA wsaData;

    if (argc != 3) 
    {
        printf("To run, enter: client server_name file_name\n");
        exit(-1);
    }

    // Winsock initialization
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    {
        printf("Winsock initialization failed\n");
        exit(-1);
    }

    h = gethostbyname(argv[1]);
    if (!h) 
    {
        printf("gethostbyname failed to find %s\n", argv[1]); 
        WSACleanup();
        exit(-1);
    }

    s = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s < 0) 
    {
        printf("Socket call failed\n"); 
        WSACleanup();
        exit(-1);
    }

    memset(&channel, 0, sizeof(channel));
    channel.sin_family = AF_INET;
    memcpy(&channel.sin_addr.s_addr, h->h_addr, h->h_length);
    channel.sin_port = htons(SERVER_PORT);
    
    c = connect(s, (struct sockaddr *)&channel, sizeof(channel));
    if (c < 0) 
    {
        printf("Connection failed\n"); 
        closesocket(s);
        WSACleanup();
        exit(-1);
    }
    
    /* Send the file name */
    send(s, argv[2], strlen(argv[2]) + 1, 0);

    while(1)
    {
        bytes = recv(s, buf, BUF_SIZE, 0);
        if(bytes <= 0)
            break;
        fwrite(buf, 1, bytes, stdout);
    }
    
    closesocket(s);
    WSACleanup();
    return 0;
}