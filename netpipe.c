
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#ifdef _WIN32
#include <WinSock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#else
#include <sys/types.h>
#include <unistd.h>
#include <sys/time.h>
#endif




#ifndef INVALID_SOCKET
#define INVALID_SOCKET				-1
#endif
#ifndef SOCKET_ERROR
#define SOCKET_ERROR				-1
#endif
#ifndef _WIN32
#define closesocket(a)				close(a)
#endif


typedef struct _CHANNEL_DATA {
	int SourceSocket;
	int DestSocket;
	struct timeval Timeout;
} CHANNEL_DATA, *PCHANNEL_DATA;

typedef enum _ECommEndType {
	cetConnect,
	cetAccept,
} ECommEndType, *PECommEndType;

typedef struct _CHANNEL_END {
	ECommEndType Type;
	char *Address;
	char *Service;
	int EndSocket;
} CHANNEL_END, *PCHANNEL_END;

static char *_sourceAddress = "0.0.0.0";
static char *_sourceService = "1337";
static char *_targetAddress = "jadro-windows.cz";
static char *_targetService = "22222";
static ECommEndType _sourceMode = cetAccept;
static ECommEndType _targetMode = cetConnect;
static uint32_t _timeout = 1;


static void _ProcessChannel(const CHANNEL_DATA *Data)
{
	int ret = 0;
	int len = 0;
	fd_set fds;
	char dataBuffer[1024];

	do {
		len = 0;
		fds.fd_count = 2;
		FD_ZERO(&fds);
		FD_SET(Data->SourceSocket, &fds);
		FD_SET(Data->DestSocket, &fds);
		ret = select(0, &fds, NULL, NULL, &Data->Timeout);
		if (ret > 0) {
			if (FD_ISSET(Data->SourceSocket, &fds)) {
				len = recv(Data->SourceSocket, dataBuffer, sizeof(dataBuffer), 0);
				if (len > 0)
					len = send(Data->DestSocket, dataBuffer, len, 0);
			}

			if (FD_ISSET(Data->DestSocket, &fds)) {
				len = recv(Data->DestSocket, dataBuffer, sizeof(dataBuffer), 0);
				if (len > 0)
					len = send(Data->SourceSocket, dataBuffer, len, 0);
			}
		} else if (ret == SOCKET_ERROR && errno == EINTR) {
			ret = 0;
			len = 1;
		}
	} while (len > 0 && ret >= 0);

	shutdown(Data->DestSocket, SD_BOTH);
	closesocket(Data->DestSocket);
	shutdown(Data->SourceSocket, SD_BOTH);
	closesocket(Data->SourceSocket);
	free(Data);

	return;
}


#ifdef _WIN32

static DWORD WINAPI _ChannelThreadWrapper(PVOID Parameter)
{
	_ProcessChannel((PCHANNEL_DATA)Parameter);

	return 0;
}


#endif


static int _PrepareChannelEnd(PCHANNEL_END End)
{
	int ret = 0;
	int sock = INVALID_SOCKET;
	struct addrinfo hints;
	struct addrinfo *addrs;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	char acceptAddr[64];
	int acceptAddrLen = sizeof(acceptAddr);

	ret = getaddrinfo(End->Address, End->Service, &hints, &addrs);
	if (ret == 0 && addrs->ai_family != AF_INET && addrs->ai_family != AF_INET6)
		ret = -1;
	
	if (ret == 0) {
		sock = socket(addrs->ai_family, SOCK_STREAM, IPPROTO_TCP);
		if (sock != INVALID_SOCKET) {
			switch (End->Type) {
				case cetAccept:
					ret = bind(sock, addrs->ai_addr, addrs->ai_addrlen);
					if (ret == 0)
						ret = listen(sock, 0);

					if (ret == 0) {
						End->EndSocket = accept(sock, (struct sockaddr *)&acceptAddr, &acceptAddrLen);
						if (End->EndSocket == INVALID_SOCKET)
							ret = -1;
					}
					break;
				case cetConnect:
					ret = connect(sock, addrs->ai_addr, addrs->ai_addrlen);
					if (ret == 0) {
						End->EndSocket = sock;
						sock = INVALID_SOCKET;
					}
					break;
			}

			if (sock != INVALID_SOCKET)
				closesocket(sock);
		}

		freeaddrinfo(addrs);
	}

	return ret;
}



int main(int argc, char *argv[])
{
	int ret = 0;
	char *mode = NULL;

	if (argc < 2) {
		fprintf(stderr, "Usage: netpipe <mode> [options]\n");
		return -1;
	}

	mode = argv[1];
	if (strcmp(mode, "ac") == 0) {
		_sourceMode = cetAccept;
		_targetMode = cetConnect;
	} else if (strcmp(mode, "cc") == 0) {
		_sourceMode = cetConnect;
		_targetMode = cetConnect;
	} else if (strcmp(mode, "aa") == 0) {
		_sourceMode = cetAccept;
		_targetMode = cetAccept;
	} else if (strcmp(mode, "ca") == 0) {
		_sourceMode = cetConnect;
		_targetMode = cetAccept;
	} else {
		fprintf(stderr, "Unknown operating mode \"%s\"\n", mode);
		return -2;
	}

	char **arg = argv + 2;
	argc -= 2;
	while (ret == 0 && argc > 0) {
		if (strcmp(*arg, "--source-host") == 0) {
			--argc;
			++arg;
			if (argc > 0)
				_sourceAddress = *arg;
			else ret = -3;
		} else if (strcmp(*arg, "--source-port") == 0) {
			--argc;
			++arg;
			if (argc > 0)
				_sourceService = *arg;
			else ret = -3;
		} else if (strcmp(*arg, "--target-host") == 0) {
			--argc;
			++arg;
			if (argc > 0)
				_targetAddress = *arg;
			else ret = -3;
		} else if (strcmp(*arg, "--target-port") == 0) {
			--argc;
			++arg;
			if (argc > 0)
				_targetService = *arg;
			else ret = -3;
		} else ret = -4;

		--argc;
		++arg;
	}

	switch (ret) {
		case -3:
			fprintf(stderr, "Missing argument for command-line option \"%s\"\n", *(arg - 1));
			return ret;
			break;
		case -4:
			fprintf(stderr, "Unknown command-line option \"%s\"\n", *(arg - 1));
			return ret;
			break;
		default:
			break;
	}

#ifdef _WIN32
	WSADATA wsaData;

	ret = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (ret != NO_ERROR) {
		fprintf(stderr, "WSAStartup: %i\n", ret);
		return ret;
	}

#endif
	while (1) {
		CHANNEL_END source;
		CHANNEL_END dest;

		source.Type = _sourceMode;
		source.Address = _sourceAddress;
		source.Service = _sourceService;
		ret = _PrepareChannelEnd(&source);
		if (ret == 0) {
			dest.Type = _targetMode;
			dest.Address = _targetAddress;
			dest.Service = _targetService;
			ret = _PrepareChannelEnd(&dest);
			if (ret == 0) {
				PCHANNEL_DATA d = NULL;

				d = (PCHANNEL_DATA)malloc(sizeof(CHANNEL_DATA));
				if (d != NULL) {
					d->Timeout.tv_sec = 5;
					d->Timeout.tv_usec = 0;
					d->SourceSocket = source.EndSocket;
					d->DestSocket = dest.EndSocket;
#ifdef _WIN32
					DWORD threadId = 0;
					HANDLE threadHandle = NULL;

					threadHandle = CreateThread(NULL, 0, _ChannelThreadWrapper, d, 0, &threadId);
					if (threadHandle != NULL) {
						CloseHandle(threadHandle);

					} else ret = GetLastError();
#else
					ret = forck();
					if (ret > 0) {
						closesocket(d->DestSocket);
						closesocket(d->SourceSocket);
						free(d);
						ret = 0;
					} else if (ret == 0) {
						_ProcessChannel(d);
						return 0;
					}
#endif
					if (ret != 0)
						free(d);
				} else ret = ENOMEM;

				if (ret != 0)
					closesocket(dest.EndSocket);
			}

			if (ret != 0)
				closesocket(source.EndSocket);
		}

#ifdef _WIN32
		Sleep(_timeout * 1000);
#else
		sleep(_timeout);
#endif
	}


#ifdef _WIN32
	WSACleanup();
#endif

	return ret;
}