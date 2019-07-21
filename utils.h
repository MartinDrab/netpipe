
#ifndef __NETPIPE_UTILS_H__
#define __NETPIPE_UTILS_H__


#include "compat-header.h"



int UtilsSetTimeouts(SOCKET Socket, uint32_t Miliseconds);
int UtilsSetKeepAlive(SOCKET Socket, int KeepAlive);



#endif
