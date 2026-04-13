// /* Windows Winsock2 client version - using gethostbyname */
// #include <stdio.h>
// #include <stdlib.h>
// #include <string.h>
// #include <winsock2.h>
// #include <windows.h>

// #pragma comment(lib, "ws2_32.lib")

// #define SERVER_PORT 8080
// #define BUF_SIZE 4096

// int main(int argc, char **argv)
// {
//     int bytes;
//     char buf[BUF_SIZE];
//     SOCKET s;
//     struct hostent *h;
//     struct sockaddr_in channel;
    
//     if (argc != 3) 
//     {
//         printf("Usage: client server_name filename\n");
//         exit(-1);
//     }
    
//     // Initialize Winsock
//     WSADATA wsaData;
//     if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
//         printf("WSAStartup failed\n");
//         exit(-1);
//     }
    
//     // Get host by name
//     h = gethostbyname(argv[1]);
//     if (!h) 
//     {
//         printf("gethostbyname failed to find %s\n", argv[1]);
//         WSACleanup();
//         exit(-1);
//     }
    
//     // Create socket
//     s = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
//     if (s == INVALID_SOCKET) 
//     {
//         printf("socket creation failed\n");
//         WSACleanup();
//         exit(-1);
//     }
    
//     // Setup channel
//     memset(&channel, 0, sizeof(channel));
//     channel.sin_family = AF_INET;
//     memcpy(&channel.sin_addr.s_addr, h->h_addr, h->h_length);
//     channel.sin_port = htons(SERVER_PORT);
    
//     // Connect
//     if (connect(s, (struct sockaddr *)&channel, sizeof(channel)) == SOCKET_ERROR) 
//     {
//         printf("connection failed\n");
//         closesocket(s);
//         WSACleanup();
//         exit(-1);
//     }
    
//     // Send filename
//     send(s, argv[2], (int)strlen(argv[2]) + 1, 0);
    
//     // Receive and display file content
//     while (1)
//     {
//         bytes = recv(s, buf, BUF_SIZE, 0);
//         if (bytes <= 0)
//             break;
//         fwrite(buf, 1, bytes, stdout);
//     }
    
//     closesocket(s);
//     WSACleanup();
//     return 0;
// }
// ===============================================================================
/* Windows simple client */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>

#pragma comment(lib, "ws2_32.lib")

#define SERVER_PORT 8080
#define BUF_SIZE 4096

int main(int argc, char **argv)
{
    WSADATA wsaData;
    SOCKET sock;
    struct sockaddr_in server;
    char buf[BUF_SIZE];
    int bytes;
    
    if (argc != 3) {
        printf("Usage: client.exe <server_ip> <filename>\n");
        printf("Example: client.exe 127.0.0.1 test.txt\n");
        return 1;
    }
    
    // Initialize Winsock
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    
    // Create socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        printf("Socket creation failed\n");
        WSACleanup();
        return 1;
    }
    
    // Setup server address
    server.sin_family = AF_INET;
    server.sin_port = htons(SERVER_PORT);
    server.sin_addr.s_addr = inet_addr(argv[1]);
    
    // Connect to server
    if (connect(sock, (struct sockaddr*)&server, sizeof(server)) == SOCKET_ERROR) {
        printf("Connection failed\n");
        closesocket(sock);
        WSACleanup();
        return 1;
    }
    
    // Send filename
    send(sock, argv[2], strlen(argv[2]) + 1, 0);
    
    // Receive and print file content
    while ((bytes = recv(sock, buf, BUF_SIZE, 0)) > 0) {
        fwrite(buf, 1, bytes, stdout);
    }
    
    closesocket(sock);
    WSACleanup();
    return 0;
}