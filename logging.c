
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <sys/types.h>
#include "logging.h"



uint32_t _loggingFlags = (LOG_FLAG_ERROR | LOG_FLAG_WARNING);



void LogMsg(uint32_t Level, const char *Format, ...)
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
