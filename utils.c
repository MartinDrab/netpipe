
#include "compat-header.h"
#include "utils.h"




int UtilsSetTimeouts(SOCKET Socket, uint32_t Miliseconds)
{
	int ret = 0;
#ifdef _WIN32
	uint32_t timeout;
#else
	struct timeval timeout;
#endif

	memset(&timeout, 0, sizeof(timeout));
#ifdef _WIN32
	timeout = Miliseconds;
#else
	timeout.tv_sec = Miliseconds / 1000;
	timeout.tv_usec = (Miliseconds * 1000) % 1000000;
#endif
	ret = setsockopt(Socket, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));
	if (ret != 0) {
		ret = errno;
		goto Exit;
	}

	ret = setsockopt(Socket, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout));
	if (ret != 0) {
		ret = errno;
		goto Exit;
	}

Exit:
	return ret;
}


int UtilsSetKeepAlive(SOCKET Socket, int KeepAlive)
{
	int ret = 0;

	ret = setsockopt(Socket, SOL_SOCKET, SO_KEEPALIVE, (char *)&KeepAlive, sizeof(KeepAlive));

	return ret;
}
