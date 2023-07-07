
#include "compat-header.h"
#include "auth.h"
#include "logging.h"
#include "utils.h"
#include "netpipe.h"


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
	int AddressFamily;
	SOCKET EndSocket;
	SOCKET ListenSocket;
	char *Password;
} CHANNEL_END, *PCHANNEL_END;


static char *_sourceAddress = NULL;
static char *_sourceService = NULL;
static char *_targetAddress = NULL;
static char *_targetService = NULL;
static ECommEndType _sourceMode = cetAccept;
static ECommEndType _targetMode = cetConnect;
static uint32_t _timeout = 1;
static int _keepAlive = 0;
static int _sourceAddressFamily = AF_UNSPEC;
static int _destAddressFamily = AF_UNSPEC;
static int _oneConnection = 0;
static char *_sourcePassword = NULL;
static char *_targetPassword = NULL;
static int _help = 0;
static int _version = 0;
static char *_logFile = NULL;
static volatile int _terminated = 0;
static char *_sourceSuppliedDomain = NULL;
static int _sourceReceiveDomain = 0;
static char *_targetSendDomain = NULL;



static int _StreamData(SOCKET Source, SOCKET Dest, uint32_t Flags)
{
	int ret = 0;
	ssize_t len = 0;
	char dataBuffer[4096];

	do {
		len = recv(Source, dataBuffer, sizeof(dataBuffer), 0);
		if (len > 0) {
			LogPacket("<<< %zu bytes received", len);
			len = send(Dest, dataBuffer, len, 0);
			if (len >= 0)
				LogPacket(">>> %zu bytes sent", len);
		}

		if (len == -1)
			ret = -1;
	} while (len > 0 &&  Flags & POLLHUP);

	return ret;
}


static void _ProcessChannel(PCHANNEL_DATA Data)
{
	int ret = 0;
#ifndef _WIN32
	struct pollfd fds[2];
#else
	pollfd fds[2];
#endif

	memset(fds, 0, sizeof(fds));
	fds[0].fd = Data->SourceSocket;
	fds[0].events = POLLIN;
	fds[1].fd = Data->DestSocket;
	fds[1].events = POLLIN;
	LogInfo("Starting to process the connection (%s <--> %s)", Data->SourceAddress, Data->DestAddress);
	do {
		fds[0].revents = 0;
		fds[1].revents = 0;
		ret = poll(fds, sizeof(fds) / sizeof(fds[0]), 1000);
		if (ret > 0) {
			if ((fds[0].revents & POLLERR) ||
				(fds[1].revents & POLLERR)) {
				for (size_t i = 0; i < sizeof(fds) / sizeof(fds[0]); ++i) {
					if (fds[i].revents & POLLERR) {
						int err = 0;
						socklen_t errLen = sizeof(err);

						getsockopt(fds[i].fd, SOL_SOCKET, SO_ERROR, (void*)&err, &errLen);
						LogError("Error occurred during channel processing on socket #%zu: %i", i, err);
					}
				}

				break;
			}

			if (fds[0].revents & POLLIN)
				ret = _StreamData(Data->SourceSocket, Data->DestSocket, fds[0].revents);

			if (fds[1].revents & POLLIN)
				ret = _StreamData(Data->DestSocket, Data->SourceSocket, fds[1].revents);

			if ((fds[0].revents & POLLHUP) ||
				(fds[1].revents & POLLHUP)) {
				LogInfo("Connection closed");
				break;
			}
		} else if (ret == SOCKET_ERROR && errno == EINTR)
			ret = 0;
	} while (!_terminated && ret >= 0);

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


static int _recv_fixed(SOCKET Socket, void *Buffer, size_t Length, int Flags)
{
	int ret = 0;

	if ((size_t)recv(Socket, Buffer, Length, Flags) != Length) {
		ret = errno;
		if (ret == 0)
			ret = EINTR;
	}

	return ret;
}


static int _PrepareChannelEnd(PCHANNEL_END End, int KeepListening, int ReceiveDomain, int SendDomain)
{
	int ret = 0;
	int af = AF_UNSPEC;
	SOCKET sock = INVALID_SOCKET;
	struct addrinfo hints;
	struct addrinfo *addrs;
	struct sockaddr_storage acceptAddr;
	int acceptAddrLen = sizeof(acceptAddr);
	struct sockaddr *genAddr = NULL;
	socklen_t genAddrLen = 0;
#ifndef _WIN32
	struct sockaddr_un *unixAddress = NULL;

	if (End->AddressFamily != AF_UNIX) {
#endif
		memset(&hints, 0, sizeof(hints));
		hints.ai_family = End->AddressFamily;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = 0;
		if (ReceiveDomain || _sourceSuppliedDomain == NULL) {
			LogInfo("Looking for %s:%s", End->Address, End->Service);
			ret = getaddrinfo(End->Address, End->Service, &hints, &addrs);
		} else {
			char *service = _sourceSuppliedDomain + strlen(_sourceSuppliedDomain);

			LogInfo("Looking for %s", _sourceSuppliedDomain);
			while (service != _sourceSuppliedDomain && *service != ':')
				--service;

			if (*service == ':') {
				*service = '\0';
				++service;
			} else service = NULL;

			ret = getaddrinfo(_sourceSuppliedDomain, service, &hints, &addrs);
			if (service != NULL) {
				--service;
				*service = ':';
			}
		}

		if (ret == 0) {
			af = addrs->ai_family;
			if (af == AF_UNSPEC)
				af = End->AddressFamily;

			genAddr = addrs->ai_addr;
			genAddrLen = (socklen_t)addrs->ai_addrlen;
		} else LogError("getaddrinfo: %i", ret);

#ifndef _WIN32
	} else {
		af = AF_UNIX;
		unixAddress = (struct sockaddr_un *)malloc(sizeof(struct sockaddr_un));
		if (unixAddress != NULL) {
			memset(unixAddress, 0, sizeof(struct sockaddr_un));
			unixAddress->sun_family = AF_UNIX;
			memcpy(unixAddress->sun_path, End->Address, strlen(End->Address));
			genAddr = (struct sockaddr *)unixAddress;
			genAddrLen = SUN_LEN(unixAddress);
		} else ret = ENOMEM;
	}
#endif

	if (ret == 0) {
		LogInfo("Creating a socket");
		sock = socket(af, SOCK_STREAM, 0);
		if (sock != INVALID_SOCKET) {
			switch (End->Type) {
				case cetAccept:
					if (End->ListenSocket == INVALID_SOCKET) {
#ifndef _WIN32
						int reuse = 1;

						LogInfo("Allowing to reuse the socket address...");
						ret = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char *)&reuse, sizeof(reuse));
						if (ret == SOCKET_ERROR) {
							LogError("Error %u", errno);
							ret = 0;
						}

						if (ret == 0) {
							LogInfo("Allowing to reuse the socket port...");
							ret = setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, (char *)&reuse, sizeof(reuse));
							if (ret == SOCKET_ERROR) {
								LogError("Error %u", errno);
								ret = 0;
							}
						}
#endif
						if (ret == 0) {
							LogInfo("Binding the socket");
							ret = bind(sock, genAddr, genAddrLen);
							if (ret == 0) {
								LogInfo("Listening");
								ret = listen(sock, SOMAXCONN);
								if (ret == -1)
									LogError("Error %u", errno);
							} else LogError("Error %u", errno);
						}
					}

					if (ret == 0) {
#ifndef _WIN32
						struct pollfd fds;
#else
						pollfd fds;
#endif
						LogInfo("Accepting");
						memset(&fds, 0, sizeof(fds));
						fds.fd = End->ListenSocket != INVALID_SOCKET ? End->ListenSocket : sock;
						fds.events = POLLIN;
						do {
							fds.revents = 0;
							ret = poll(&fds, 1, 1000);
							if (ret > 0) {
								if (fds.revents & POLLERR) {
									ret = -1;
									break;
								}

								if (fds.revents & POLLIN) {
									End->EndSocket = accept(fds.fd, (struct sockaddr *)&acceptAddr, &acceptAddrLen);
									if (End->EndSocket != INVALID_SOCKET) {
										End->AcceptAddress = sockaddrstr((struct sockaddr *)&acceptAddr);
										if (End->AcceptAddress != NULL) {
											ret = 0;
											LogInfo("Accepted a connection from %s", End->AcceptAddress);
											if (KeepListening && End->ListenSocket == INVALID_SOCKET) {
												End->ListenSocket = sock;
												sock = INVALID_SOCKET;
											}
										} else ret = ENOMEM;

										if (End->AcceptAddress == NULL) {
											LogError("Out of memory");
											closesocket(End->EndSocket);
											End->EndSocket = INVALID_SOCKET;
										}
									} else ret = errno;

									if (ret == 0)
										break;
								}

								if (fds.revents & POLLHUP)
									break;
							} else if (ret == SOCKET_ERROR && errno == EINTR)
								ret = 0;
						} while (!_terminated && ret == 0);

						if (End->EndSocket == INVALID_SOCKET)
							ret = -1;
					}
					break;
				case cetConnect:
					End->AcceptAddress = sockaddrstr(genAddr);
					if (End->AcceptAddress != NULL) {
						LogInfo("Connesting to %s (%s)", End->Address, End->AcceptAddress);
						if (genAddr != NULL) {
							ret = connect(sock, genAddr, genAddrLen);
							if (ret == 0) {
								End->EndSocket = sock;
								sock = INVALID_SOCKET;
							}
						} else ret = EINVAL;
					} else {
						ret = ENOMEM;
						LogError("Out of memory");
					}
					break;
			}

			if (sock != INVALID_SOCKET)
				closesocket(sock);
		} else ret = errno;

#ifndef _WIN32
		if (End->AddressFamily == AF_UNIX)
			free(unixAddress);
		else
#endif
			freeaddrinfo(addrs);
	}

	if (ret == 0 && _keepAlive) {
		ret = UtilsSetKeepAlive(End->EndSocket, _keepAlive);
		if (ret != 0)
			LogWarning("UtilsSetKeepAlive: %u", ret);

		ret = 0;
	}

	if (ret == 0) {
		ret = UtilsSetTimeouts(End->EndSocket, 5000);
		if (ret != 0)
			LogError("UtilsSetTimeouts: %u", ret);
	}

	if (ret == 0 && End->Password != NULL) {
		int success = 0;

		ret = AuthSocket(End->EndSocket, End->Password, &success);
		if (ret == 0 && !success)
			ret = -1;
	}

	if (ret == 0 && ReceiveDomain) {
		uint32_t domainLen = 0;
		char *domain = NULL;

		LogInfo("Receiving domain");
		ret = _recv_fixed(End->EndSocket, (char *)&domainLen, sizeof(domainLen), 0);
		if (ret != 0)
			LogError("Unable to get source domain length: %u", ret);

		if (ret == 0) {
			LogInfo("The domain len has %u characters", domainLen);
			domain = (char *)malloc(domainLen + 1);
			if (domain == NULL) {
				ret = ENOMEM;
				LogError("Unable to allocate space for the domain");
			}

			if (ret == 0) {
				domain[domainLen] = '\0';
				ret = _recv_fixed(End->EndSocket, domain, domainLen, 0);
				if (ret != 0)
					LogError("Failed to receive domain name: %u", ret);

				if (ret == 0) {
					LogInfo("Received domain %s", domain);
					if (_sourceSuppliedDomain != NULL)
						free(_sourceSuppliedDomain);

					_sourceSuppliedDomain = domain;
				}

				if (ret != 0)
					free(domain);
			}
		}
	}

	if (ret == 0 && SendDomain) {
		uint32_t domainLen = 0;

		domainLen = (uint32_t)strlen(_targetSendDomain);
		LogInfo("Sending domain %s (%u)", _targetSendDomain, domainLen);
		if (send(End->EndSocket, (char *)&domainLen, sizeof(domainLen), 0) != sizeof(domainLen)) {
			ret = errno;
			LogError("Failed to send domain length: %u", ret);
		}

		if (ret == 0 &&
			send(End->EndSocket, _targetSendDomain, domainLen, 0) != domainLen) {
			ret = errno;
			LogError("Failed to send domain: %u", ret);
		}
	}

	if (ret != 0) {
		if (End->AcceptAddress != NULL) {
			free(End->AcceptAddress);
			End->AcceptAddress = NULL;
		}

		if (End->EndSocket != INVALID_SOCKET &&
			End->EndSocket) {
			closesocket(End->EndSocket);
			End->EndSocket = INVALID_SOCKET;
		}
	}

	return ret;
}

#define arg_advance(aArgc, aArg)	\
	{ --aArgc; ++aArg;  }

COMMAND_LINE_OPTION _cmdOptions[] = {
	{ otSourceHost,      0, 1, 2, {"-d", "--source-host"},       "string",  "Domain/address of the source end" },
	{ otSourcePort,      0, 1, 2, {"-p", "--source-port"},       "integer", "Source port" },
	{ otTargetHost,      0, 1, 2, {"-D", "--target-host"},       "string",  "Domain/address of the target end" },
	{ otTargetPort,      0, 1, 2, {"-P", "--target-port"},       "integer", "Target port" },
	{ otIPv4Only,        0, 0, 2, {"-4", "--ipv4-only"},         NULL,      "Use only IPv4" },
	{ otIPv6Only,        0, 0, 2, {"-6", "--ipv6-only"},         NULL,      "Use only IPv6" },
	{ otLogError,        0, 0, 1, {      "--log-error"},         NULL,      "Log error messages" },
	{ otLogWarning,      0, 0, 1, {      "--log-warning"},       NULL,      "Log warnings" },
	{ otLogInfo,         0, 0, 1, {      "--log-info"},          NULL,      "Log information-level messages" },
	{ otLogPacket,       0, 0, 1, {      "--log-packet"},        NULL,      "Log lengths of sent and received data" },
	{ otLogPacketData,   0, 0, 1, {      "--log-packet-data"},   NULL,      "Log data of the transmitted packets" },
	{ otOneConnection,   0, 0, 2, {"-1", "--single-connection"}, NULL,      "Allow at most one connection established between the source and the target at any moment" },
	{ otKeepAlive,       0, 0, 2, {"-k", "--keep-alive"},        NULL,      "Use the keep-alive feature of the TCP protocol" },
	{ otHelp,            0, 0, 2, {"-h", "--help"},              NULL,      "Show this help" },
	{ otAuthSource,      0, 1, 2, {"-a", "--auth-source"},       "string",  "Use a password to authenticate the source connection (another netpipe instance with the same password must be running at the other end)"},
	{ otAuthTarget,      0, 1, 2, {"-A", "--auth-target"},       "string",  "Use a password to authenticate the target connection (another netpipe instance with the same password must be running at the other end)"},
	{ otLogFile,         0, 1, 2, {"-l", "--log-file"},          "string",  "Log netpipe output to a given file"},
	{ otVersion,         0, 0, 2, {"-v", "--version"},           NULL,      "Show version information" },
	{ otReceiveDomain,   0, 0, 2, {"-r", "--receive-domain"},    NULL,      "Expect a domain before first data of the source connection. A netpipe instance with the -S option specified must be running on the other end"},
	{ otSendDomain,      0, 1, 2, {"-S", "--send-domain"},       "string",  "Instruct the netpipe on the other end of the target connection to forward the data to a given domain"},
#ifndef _WIN32
	{ otUnixSource,      0, 0, 2, {"-u", "--unix-source"},       NULL,      "The source is an Unix domain socket" },
	{ otUnixDest,        0, 0, 2, {"-U", "--unix-dest"},         NULL,      "The dest is an Unix domain socket" },
#endif
	{ otUnknown,         0, 0, 0},
};


void usage(void)
{
	fprintf(stderr, "Usage: netpipe <mode> [options]\n");
	fprintf(stderr, "Supported modes:\n");
	fprintf(stderr, "  aa - accept connection from both source and destination\n");
	fprintf(stderr, "  ac - accept connection from the source, make connection to the target\n");
	fprintf(stderr, "  ca - make connection to the source, accept connection from the target\n");
	fprintf(stderr, "  cc - connect to both source and target\n");
	fprintf(stderr, "The connection to the target is established only after the source connection\n");
	fprintf(stderr, "Options:\n");
	for (const COMMAND_LINE_OPTION *c = _cmdOptions; c->Type != otUnknown; c++) {
		fprintf(stderr, "  %s", c->Names[0]);
		for (int i = 1 ; i < c->NameCount; i++)
			fprintf(stderr, ", %s", c->Names[i]);

		if (c->ArgumentType != NULL)
			fprintf(stderr, " <%s>", c->ArgumentType);

		if (c->Description)
			fprintf(stderr, " - %s", c->Description);

		fputc('\n', stderr);
	}

	return;
}


void NetPipeTerminate(void)
{
	_terminated = 1;

	return;
}


int NetPipeMain(int argc, char *argv[])
{
	int ret = 0;
	char *mode = NULL;

	if (argc < 2) {
		usage();
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

		for (size_t i = 0; i < sizeof(_cmdOptions) / sizeof(_cmdOptions[0]) - 1; ++i) {
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
				_sourceAddressFamily = AF_INET;
				_destAddressFamily = AF_INET;
				break;
			case otIPv6Only:
				_sourceAddressFamily = AF_INET6;
				_destAddressFamily = AF_INET6;
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
			case otOneConnection:
				_oneConnection = 1;
				break;
			case otHelp:
				_help = 1;
				break;
			case otVersion:
				_version = 1;
				break;
			case otKeepAlive:
				_keepAlive = 1;
				break;
			case otAuthSource:
				_sourcePassword = *arg;
				break;
			case otAuthTarget:
				_targetPassword = *arg;
				break;
			case otLogFile:
				_logFile = *arg;
				break;
			case otReceiveDomain:
				_sourceReceiveDomain = 1;
				break;
			case otSendDomain:
				_targetSendDomain = *arg;
				break;
#ifndef _WIN32
			case otUnixSource:
				_sourceAddressFamily = AF_UNIX;
				break;
			case otUnixDest:
				_destAddressFamily = AF_UNIX;
				break;
#endif
		}

		if (ret == 0 && cmdOption->ArgumentCount > 0) {
			for (int i = 0; i < cmdOption->ArgumentCount; ++i)
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

	if (_help) {
		usage();
		return 0;
	}

	if (_version) {
		fprintf(stderr, "NetPipe v1.0\n");
		return 0;
	}

	if (_logFile != NULL) {
		ret = LogSetFile(_logFile);
		if (ret != 0) {
			fprintf(stderr, "Failed to change log file: %u\n", ret);
			return ret;
		}
	}

	if (_sourceAddress == NULL) {
		fprintf(stderr, "Source host not specified\n");
		return -1;
	}

	if (_sourceAddressFamily != AF_UNIX && _sourceService == NULL) {
		fprintf(stderr, "Source port not specified\n");
		return -1;
	}

	if (_targetAddress == NULL) {
		fprintf(stderr, "Target host not specified\n");
		return -1;
	}

	if (_destAddressFamily != AF_UNIX && _targetService == NULL) {
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
	CHANNEL_END source;
	CHANNEL_END dest;

	memset(&source, 0, sizeof(source));
	source.ListenSocket = INVALID_SOCKET;
	memset(&dest, 0, sizeof(dest));
	dest.ListenSocket = INVALID_SOCKET;
	while (!_terminated) {
		source.Type = _sourceMode;
		source.AddressFamily = _sourceAddressFamily;
		source.Address = _sourceAddress;
		source.Service = _sourceService;
		source.EndSocket = INVALID_SOCKET;
		source.Password = _sourcePassword;
		ret = _PrepareChannelEnd(&source, !_oneConnection, _sourceReceiveDomain, 0);		
		if (ret == 0) {
			dest.Type = _targetMode;
			dest.AddressFamily = _destAddressFamily;
			dest.Address = _targetAddress;
			dest.Service = _targetService;
			dest.EndSocket = INVALID_SOCKET;
			dest.Password = _targetPassword;
			ret = _PrepareChannelEnd(&dest, 0, 0, _targetSendDomain != NULL);
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
						if (_oneConnection)
							WaitForSingleObject(threadHandle, INFINITE);

						CloseHandle(threadHandle);
					} else ret = GetLastError();
#else
					ret = fork();
					if (ret > 0) {
						closesocket(d->DestSocket);
						closesocket(d->SourceSocket);
						free(d);
						if (_oneConnection)
							waitpid(ret, &ret, 0);
						
						ret = 0;
					} else if (ret == 0) {
						_ProcessChannel(d);
						return 0;
					}
#endif
					if (ret != 0)
						free(d);
				} else ret = ENOMEM;

				if (dest.ListenSocket != INVALID_SOCKET) {
					closesocket(dest.ListenSocket);
					dest.ListenSocket = INVALID_SOCKET;
				}

				if (ret != 0)
					closesocket(dest.EndSocket);
			} else LogError("Failed to prepare the target channel: %u", ret);

			if (ret != 0)
				closesocket(source.EndSocket);
		} else LogError("Failed to prepare the source channel: %u", ret);

		sleep(_timeout);
	}


#ifdef _WIN32
	WSACleanup();
#endif

	return ret;
}
