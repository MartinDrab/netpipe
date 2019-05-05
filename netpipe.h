
#ifndef __NETPIPE_H__
#define __NETPIPE_H__


#include "compat-header.h"

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
	otOneConnection,
	otKeepAlive,
	otHelp,
	otVersion,
	otLogPacketData,
	otAuthSource,
	otAuthTarget,
#ifndef _WIN32
	otUnixSource,
	otUnixDest,
#endif
} EOptionType, *PEOptionType;

typedef struct _COMMAND_LINE_OPTION {
	EOptionType Type;
	int Specified;
	int ArgumentCount;
	size_t NameCount;
	char *Names[2];
} COMMAND_LINE_OPTION, *PCOMMAND_LINE_OPTION;

#ifdef _WIN32
extern COMMAND_LINE_OPTION _cmdOptions[18];
#endif


int NetPipeMain(int argc, char *argv[]);



#endif
