
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#ifdef _WIN32
#include <WinSock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#else
#include <stdarg.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netdb.h>
#endif




#ifndef _WIN32
#define closesocket(a)				close(a)
#define SD_RECEIVE				SHUT_RD
#define SD_SEND					SHUT_WR
#define SD_BOTH					SHUT_RDWR
#define SOCKET_ERROR				-1
#define INVALID_SOCKET				-1
#define SOCKET						int
#else
typedef size_t ssize_t;
#endif


typedef struct _CHANNEL_DATA {
	SOCKET SourceSocket;
	SOCKET DestSocket;
	char *SourceAddress;
	char *DestAddress;
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
	char *AcceptAddress;
	SOCKET EndSocket;
} CHANNEL_END, *PCHANNEL_END;

#define LOG_FLAG_ERROR			1
#define LOG_FLAG_WARNING		2
#define LOG_FLAG_INFO			4
#define LOG_FLAG_PACKET			8
#define LOG_FLAG_PACKET_DATA	0x10

static char *_sourceAddress = NULL;
static char *_sourceService = NULL;
static char *_targetAddress = NULL;
static char *_targetService = NULL;
static ECommEndType _sourceMode = cetAccept;
static ECommEndType _targetMode = cetConnect;
static uint32_t _timeout = 1;
static uint32_t _loggingFlags = (LOG_FLAG_ERROR | LOG_FLAG_WARNING);
static int _keepAlive = 0;
static int _addressFamily = AF_UNSPEC;


static void _LogMsg(uint32_t Level, const char *Format, ...)
{
	va_list vs;
	char msg[4096];

	if (_loggingFlags & Level) {
		memset(msg, 0, sizeof(msg));
		va_start(vs, Format);
		vsnprintf(msg, sizeof(msg), Format, vs);
		fputs(msg, stderr);
		va_end(vs);
	}

	return;
}


#ifdef _WIN32

#define Log(aLevel, aFormat, ...)	\
	_LogMsg(aLevel, "[%u]: " aFormat "\n", GetCurrentThreadId(), __VA_ARGS__)

#define LogError(aFormat, ...)	 \
	Log(LOG_FLAG_ERROR, aFormat, __VA_ARGS__)

#define LogWarning(aFormat, ...)	 \
	Log(LOG_FLAG_WARNING, aFormat, __VA_ARGS__)

#define LogInfo(aFormat, ...)	 \
	Log(LOG_FLAG_INFO, aFormat, __VA_ARGS__)

#define LogPacket(aFormat, ...)	 \
	Log(LOG_FLAG_PACKET, aFormat, __VA_ARGS__)

#else

#define Log(aLevel, aFormat, ...)	\
	_LogMsg(aLevel, "[%u]: " aFormat "\n", getpid(), __VA_ARGS__)

#define LogError(aFormat, ...)	 \
	Log(LOG_FLAG_ERROR, aFormat, __VA_ARGS__)

#define LogWarning(aFormat, ...)	 \
	Log(LOG_FLAG_WARNING, aFormat, __VA_ARGS__)

#define LogInfo(aFormat, ...)	 \
	Log(LOG_FLAG_INFO, aFormat, __VA_ARGS__)

#define LogPacket(aFormat, ...)	 \
	Log(LOG_FLAG_PACKET, aFormat, __VA_ARGS__)

#endif

static void _ProcessChannel(PCHANNEL_DATA Data)
{
	int ret = 0;
	ssize_t len = 0;
	fd_set fds;
	char dataBuffer[1024];

	LogInfo("Starting to process the connection (%s <--> %s)", Data->SourceAddress, Data->DestAddress);
	do {
		len = 0;
		FD_ZERO(&fds);
		FD_SET(Data->SourceSocket, &fds);
		FD_SET(Data->DestSocket, &fds);
		ret = select(0, &fds, NULL, NULL, NULL);
		if (ret > 0) {
			if (FD_ISSET(Data->SourceSocket, &fds)) {
				len = recv(Data->SourceSocket, dataBuffer, sizeof(dataBuffer), 0);
				if (len > 0) {
					LogPacket("<<< %u bytes received", len);
					len = send(Data->DestSocket, dataBuffer, (size_t)len, 0);
					if (len >= 0)
						LogPacket(">>> %u bytes sent", len);
				}

				if (len == -1)
					ret = -1;
			}

			if (FD_ISSET(Data->DestSocket, &fds)) {
				len = recv(Data->DestSocket, dataBuffer, sizeof(dataBuffer), 0);
				if (len > 0) {
					LogPacket(">>> %u bytes received", len);
					len = send(Data->SourceSocket, dataBuffer, (size_t)len, 0);
					if (len >= 0)
						LogPacket("<<< %u bytes sent", len);
				}

				if (len == -1)
					ret = -1;
			}
		} else if (ret == SOCKET_ERROR && errno == EINTR) {
			ret = 0;
			len = 1;
		}
	} while (len > 0 && ret >= 0);

	if (len == -1 || ret == SOCKET_ERROR)
		LogError("Error %u", errno);
	else LogInfo("Closing");

	shutdown(Data->DestSocket, SD_BOTH);
	closesocket(Data->DestSocket);
	shutdown(Data->SourceSocket, SD_BOTH);
	closesocket(Data->SourceSocket);
	free(Data->SourceAddress);
	free(Data->DestAddress);
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



char *sockaddrstr(const struct sockaddr *Addr)
{
	size_t len = 0;
	char *ret = NULL;
	const struct sockaddr_in *in4 = NULL;
	const struct sockaddr_in6 *in6 = NULL;
	const unsigned char *bytes = NULL;
	const unsigned short *words = NULL;

	len = 128;
	ret = (char *)malloc(len);
	if (ret == NULL)
		return ret;

	memset(ret, 0, len);
	switch (Addr->sa_family) {
		case AF_INET:
			in4 = (struct sockaddr_in *)Addr;
			bytes = (unsigned char *)&in4->sin_addr;
			snprintf(ret, len, "%u.%u.%u.%u:%u", bytes[0], bytes[1], bytes[2], bytes[3], ntohs(in4->sin_port));
			break;
		case AF_INET6:
			in6 = (struct sockaddr_in6 *)Addr;
			words = (unsigned short *)&in6->sin6_addr;
			snprintf(ret, len, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x:%.2x:%.2x:%u", words[0], words[1], words[2], words[3], words[4], words[5], words[6], words[7], ntohs(in6->sin6_port));
			break;
		default:
			free(ret);
			ret = NULL;
			break;
	}

	return ret;
}


static int _PrepareChannelEnd(PCHANNEL_END End)
{
	int ret = 0;
	SOCKET sock = INVALID_SOCKET;
	struct addrinfo hints;
	struct addrinfo *addrs;
	struct sockaddr_storage acceptAddr;
	int acceptAddrLen = sizeof(acceptAddr);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = _addressFamily;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	LogInfo("Looking for %s:%s", End->Address, End->Service);
	ret = getaddrinfo(End->Address, End->Service, &hints, &addrs);
	if (ret == 0 && addrs->ai_family != AF_INET && addrs->ai_family != AF_INET6)
		ret = -1;
	
	if (ret == 0) {
		LogInfo("Creating a socket");
		sock = socket(addrs->ai_family, SOCK_STREAM, IPPROTO_TCP);
		if (sock != INVALID_SOCKET) {
			switch (End->Type) {
				case cetAccept:
					LogInfo("Binding the socket");
					ret = bind(sock, addrs->ai_addr, (int)addrs->ai_addrlen);
					if (ret == 0) {
						LogInfo("Listening");
						ret = listen(sock, 0);
						if (ret == -1)
							LogError("Error %u", errno);
					} else LogError("Error %u", errno);

					if (ret == 0) {
						LogInfo("Accepting");
						End->EndSocket = accept(sock, (struct sockaddr *)&acceptAddr, &acceptAddrLen);
						if (End->EndSocket != INVALID_SOCKET) {
							End->AcceptAddress = sockaddrstr((struct sockaddr *)&acceptAddr);
							if (End->AcceptAddress != NULL)
								LogInfo("Accepted a connection from %s", End->AcceptAddress);
							
							if (End->AcceptAddress == NULL) {
								LogError("Out of memory");
								closesocket(End->EndSocket);
							}
						}

						if (End->EndSocket == INVALID_SOCKET)
							ret = -1;
					}
					break;
				case cetConnect:
					End->AcceptAddress = sockaddrstr(addrs->ai_addr);
					if (End->AcceptAddress != NULL) {
						LogInfo("Connesting to %s (%s)", End->Address, End->AcceptAddress);
						ret = connect(sock, addrs->ai_addr, (int)addrs->ai_addrlen);
						if (ret == 0) {
							End->EndSocket = sock;
							sock = INVALID_SOCKET;
						}

						if (ret == -1)
							free(End->AcceptAddress);
					} else LogError("Out of memory");
					break;
			}

			if (sock != INVALID_SOCKET)
				closesocket(sock);
		} else LogError("Error %u", errno);

		freeaddrinfo(addrs);
	}

	if (ret == 0 && _keepAlive) {
		ret = setsockopt(End->EndSocket, SOL_SOCKET, SO_KEEPALIVE, (char *)&_keepAlive, sizeof(_keepAlive));
		if (ret == SOCKET_ERROR) {
			free(End->AcceptAddress);
			closesocket(End->EndSocket);
		}
	}

	return ret;
}

#define arg_advance(aArgc, aArg)	\
	{ --aArgc; ++aArg;  }



typedef enum _EOptionType {
	otUnknown,
	otSourceHost,
	otSourcePort,
	otTargetHost,
	otTargetPort,
	otIPv4Only,
	otIPv6Only,
	otLogError,
	otLogWarning,
	otLogInfo,
	otLogPacket,
	otLogPacketData,
} EOptionType, *PEOptionType;

typedef struct _COMMAND_LINE_OPTION{
	EOptionType Type;
	int Specified;
	size_t ArgumentCount;
	size_t NameCount;
	char *Names[2];
} COMMAND_LINE_OPTION, *PCOMMAND_LINE_OPTION;

static COMMAND_LINE_OPTION _cmdOptions[] = {
	{otSourceHost, 0, 1, 2, {"-h", "--source-host"}},
	{otSourcePort, 0, 1, 2, {"-p", "--source-port"}},
	{otTargetHost, 0, 1, 2, {"-H", "--target-host"}},
	{otTargetPort, 0, 1, 2, {"-P", "--target-port"}},
	{otIPv4Only, 0, 0, 1, {"-4"}},
	{otIPv6Only, 0, 0, 1, {"-6"}},
	{otLogError, 0, 0, 1, {"--log-error"}},
	{otLogWarning, 0, 0, 1, {"--log-warning"}},
	{otLogInfo, 0, 0, 1, {"--log-info"}},
	{otLogPacket, 0, 0, 1, {"--log-packet"}},
	{otLogPacketData, 0, 0, 1, {"--log-packet-data"}},
	{otUnknown, 0, 0, 0},
};

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
		int found = 0;
		PCOMMAND_LINE_OPTION cmdOption = _cmdOptions;

		for (size_t i = 0; i < sizeof(_cmdOptions) / sizeof(_cmdOptions) - 1; ++i) {
			for (size_t j = 0; j < cmdOption->NameCount; ++j) {
				found = (strcmp(*arg, cmdOption->Names[j]) == 0);
				if (found) {
					++cmdOption->Specified;
					if (argc < cmdOption->ArgumentCount) {
						ret = -1;
						LogError("Not enough arguments for the %s option", *arg);
						break;
					}

					if (cmdOption->Specified > 1)
						LogWarning("The %s has been specified for %uth time, the last specification is used", *arg);;
				
					arg_advance(argc, arg);
					break;
				}
			}

			if (found)
				break;

			++cmdOption;
		}

		switch (cmdOption->Type) {
			case otUnknown:
				ret = -1;
				LogError("Unknown option %s", *arg);
				break;
			case otSourceHost:
				_sourceAddress = *arg;
				break;
			case otSourcePort:
				_sourceService = *arg;
				break;
			case otTargetHost:
				_targetAddress = *arg;
				break;
			case otTargetPort:
				_targetService = *arg;
				break;
			case otIPv4Only:
				_addressFamily = AF_INET;
				break;
			case otIPv6Only:
				_addressFamily = AF_INET6;
				break;
			case otLogError:
				_loggingFlags |= LOG_FLAG_ERROR;
				break;
			case otLogWarning:
				_loggingFlags |= LOG_FLAG_WARNING;
				break;
			case otLogInfo:
				_loggingFlags |= LOG_FLAG_INFO;
				break;
			case otLogPacket:
				_loggingFlags |= LOG_FLAG_PACKET;
				break;
			case otLogPacketData:
				_loggingFlags |= LOG_FLAG_PACKET_DATA;
				break;
		}

		if (ret == 0 && cmdOption->ArgumentCount > 0) {
			for (size_t i = 0; i < cmdOption->ArgumentCount; ++i)
				arg_advance(argc, arg);
		}
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

	if (_sourceAddress == NULL) {
		fprintf(stderr, "Source host not specified\n");
		return -1;
	}

	if (_sourceService == NULL) {
		fprintf(stderr, "Source port not specified\n");
		return -1;
	}

	if (_targetAddress == NULL) {
		fprintf(stderr, "Target host not specified\n");
		return -1;
	}

	if (_targetService == NULL) {
		fprintf(stderr, "Target port not specified\n");
		return -1;
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

		memset(&source, 0, sizeof(source));
		source.Type = _sourceMode;
		source.Address = _sourceAddress;
		source.Service = _sourceService;
		ret = _PrepareChannelEnd(&source);
		if (ret == 0) {
			memset(&dest, 0, sizeof(dest));
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
					d->SourceAddress = source.AcceptAddress;
					d->DestAddress = dest.AcceptAddress;
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
					ret = fork();
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
