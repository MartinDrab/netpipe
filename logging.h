
#ifndef __NETPIPE_LOGGING_H__
#define __NETPIPE_LOGGING_H__




#define LOG_FLAG_ERROR			1
#define LOG_FLAG_WARNING		2
#define LOG_FLAG_INFO			4
#define LOG_FLAG_PACKET			8
#define LOG_FLAG_PACKET_DATA	0x10



#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>



extern uint32_t _loggingFlags;


#ifdef _WIN32

#define Log(aLevel, aFormat, ...)	\
	LogMsg(aLevel, "[%u]: " aFormat "\n", GetCurrentThreadId(), __VA_ARGS__)

#else

#define Log(aLevel, aFormat, ...)	\
	LogMsg(aLevel, "[%u]: " aFormat "\n", getpid(), __VA_ARGS__)

#endif

#define LogError(aFormat, ...)	 \
	Log(LOG_FLAG_ERROR, aFormat, __VA_ARGS__ + 0)

#define LogWarning(aFormat, ...)	 \
	Log(LOG_FLAG_WARNING, aFormat, __VA_ARGS__ + 0)

#define LogInfo(aFormat, ...)	 \
	Log(LOG_FLAG_INFO, aFormat, __VA_ARGS__ + 0)

#define LogPacket(aFormat, ...)	 \
	Log(LOG_FLAG_PACKET, aFormat, __VA_ARGS__ + 0)


void LogMsg(uint32_t Level, const char *Format, ...);



#endif
