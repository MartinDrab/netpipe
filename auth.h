
#ifndef __NETPIPE_AUTH_H__
#define __NETPIPE_AUTH_H__


#include <stdint.h>
#include "compat-header.h"



void AuthKeyGen(const char *Password, unsigned char *Salt, unsigned int SaltLen, uint32_t IterationCount, unsigned char Key[16]);
int AuthSocket(SOCKET Socket, const char *Password, int *Success);


#endif
