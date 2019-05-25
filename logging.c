
#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <sys/types.h>
#include "logging.h"



uint32_t _loggingFlags = (LOG_FLAG_ERROR | LOG_FLAG_WARNING);
static FILE *_logStream = NULL;



void LogMsg(uint32_t Level, const char *Format, ...)
{
	va_list vs;
	char msg[4096];

	if (_loggingFlags & Level) {
		if (_logStream == NULL)
			_logStream = stderr;

		memset(msg, 0, sizeof(msg));
		va_start(vs, Format);
		vsnprintf(msg, sizeof(msg), Format, vs);
		fputs(msg, _logStream);
		va_end(vs);
	}

	return;
}


int LogSetFile(const char *FileName)
{
	int ret = 0;

	_logStream = fopen(FileName, "wb");
	if (_logStream == NULL)
		ret = errno;

	return ret;
}
