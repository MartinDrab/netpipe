
#include "compat-header.h"
#include "netpipe.h"


/************************************************************************/
/*                      GLOBAL VARIABLES                                */
/************************************************************************/

static SERVICE_STATUS _statusRecord;
static SERVICE_STATUS_HANDLE _statusHandle = NULL;
static HANDLE _exitEventHandle = NULL;


static DWORD WINAPI _NetpipeServiceHandlerEx(DWORD dwControl, DWORD dwEventType, LPVOID lpEventData, LPVOID lpContext
)
{
	DWORD ret = NO_ERROR;

	switch (dwControl) {
		case SERVICE_CONTROL_STOP:
			_statusRecord.dwCurrentState = SERVICE_STOP_PENDING;
			SetServiceStatus(_statusHandle, &_statusRecord);
			SetEvent(_exitEventHandle);
			break;
		default:
			break;
	}

	return ret;
}


void WINAPI ServiceMain(DWORD argc, LPWSTR *argv)
{
	memset(&_statusRecord, 0, sizeof(_statusRecord));
	_statusHandle = RegisterServiceCtrlHandlerExW(L"Netpipe", _NetpipeServiceHandlerEx, NULL);
	if (_statusHandle != NULL) {
		_statusRecord.dwCurrentState = SERVICE_START_PENDING;
		_statusRecord.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
		SetServiceStatus(_statusHandle, &_statusRecord);
		_exitEventHandle = CreateEventW(NULL, TRUE, FALSE, NULL);
		if (_exitEventHandle != NULL) {
			_statusRecord.dwCurrentState = SERVICE_RUNNING;
			_statusRecord.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SESSIONCHANGE;
			SetServiceStatus(_statusHandle, &_statusRecord);
			NetPipeMain(0, NULL);
			WaitForSingleObject(_exitEventHandle, INFINITE);
			_statusRecord.dwCurrentState = SERVICE_STOPPED;
			SetServiceStatus(_statusHandle, &_statusRecord);
			CloseHandle(_exitEventHandle);
		}

		if (_statusHandle != NULL) {
			_statusRecord.dwCurrentState = SERVICE_STOPPED;
			SetServiceStatus(_statusHandle, &_statusRecord);
		}
	}

	return;
}


int main(int argc, char *argv[])
{
	int ret = 0;
	SERVICE_TABLE_ENTRYW svcTable[2];

	memset(svcTable, 0, sizeof(svcTable));
	svcTable[0].lpServiceName = L"Netpipe";
	svcTable[0].lpServiceProc = ServiceMain;
	if (!StartServiceCtrlDispatcherW(svcTable))
		ret = GetLastError();

	return ret;
}
