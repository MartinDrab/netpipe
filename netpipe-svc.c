
#include "compat-header.h"
#include "netpipe.h"


/************************************************************************/
/*                      GLOBAL VARIABLES                                */
/************************************************************************/

static SERVICE_STATUS _statusRecord;
static SERVICE_STATUS_HANDLE _statusHandle = NULL;
static HANDLE _exitEventHandle = NULL;
static BOOL _testRun = FALSE;
static int _argc = 0;
static char **_argv = NULL;


static DWORD _ReportError(const char *Text, DWORD Code)
{
	fprintf(stderr, "%s: %u\n", Text, Code);

	return Code;
}


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
	DWORD dwError = 0;
	int argCount = 0;
	char **args = NULL;

	if (!_testRun) {
		memset(&_statusRecord, 0, sizeof(_statusRecord));
		_statusHandle = RegisterServiceCtrlHandlerExW(L"Netpipe", _NetpipeServiceHandlerEx, NULL);
		if (_statusHandle != NULL) {
			_statusRecord.dwCurrentState = SERVICE_START_PENDING;
			_statusRecord.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
			if (SetServiceStatus(_statusHandle, &_statusRecord)) {
				_exitEventHandle = CreateEventW(NULL, TRUE, FALSE, NULL);
				if (_exitEventHandle == NULL) {
					_statusRecord.dwCurrentState = SERVICE_STOPPED;
					SetServiceStatus(_statusHandle, &_statusRecord);
				}
			}

			if (_exitEventHandle == NULL)
				_statusHandle = NULL;
		}
	}

	if (_testRun || _statusHandle != NULL) {
		argCount = _argc;
		args = _argv;
		if (dwError == ERROR_SUCCESS) {
			if (!_testRun) {
				_statusRecord.dwCurrentState = SERVICE_RUNNING;
				_statusRecord.dwControlsAccepted = SERVICE_ACCEPT_STOP;
				SetServiceStatus(_statusHandle, &_statusRecord);
			}
			
			NetPipeMain(argCount, args);			
			if (!_testRun) {
				WaitForSingleObject(_exitEventHandle, INFINITE);
				_statusRecord.dwCurrentState = SERVICE_STOPPED;
				SetServiceStatus(_statusHandle, &_statusRecord);
				CloseHandle(_exitEventHandle);
			}
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

	switch (argc) {
		case 2: {
			SC_HANDLE hScm = NULL;
			SC_HANDLE hService = NULL;

			if (_stricmp(argv[1], "/install") == 0) {
				DWORD moduleNameLen = 0;
				wchar_t moduleName[MAX_PATH];
				
				memset(moduleName, 0, sizeof(moduleName));
				moduleNameLen = GetModuleFileNameW(NULL, moduleName, MAX_PATH);
				if (moduleNameLen > 0) {
					hScm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CREATE_SERVICE | SC_MANAGER_CONNECT);
					if (hScm != NULL) {
						hService = CreateServiceW(hScm, L"NetPipe", L"Network to Network Pipe Service", SERVICE_ALL_ACCESS,  SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, moduleName, NULL, NULL, NULL, NULL, NULL);
						if (hService != NULL)
							CloseServiceHandle(hService);
						
						if (hService == NULL && GetLastError() != ERROR_SERVICE_EXISTS)
							_ReportError("CreateService", GetLastError());
						
						CloseServiceHandle(hScm);
					} else _ReportError("OpenSCManager", GetLastError());
				} else _ReportError("GetModuleFileName", GetLastError());
			} else if (_stricmp(argv[1], "/uninstall") == 0) {
				hScm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
				if (hScm != NULL) {
					hService = OpenServiceW(hScm, L"NetPipe", DELETE);
					if (hService != NULL) {
						if (!DeleteService(hService))
							ret = _ReportError("DeleteService", GetLastError());

						CloseServiceHandle(hService);
					} else ret = _ReportError("OpenService", GetLastError());

					CloseServiceHandle(hScm);
				} else ret = _ReportError("OpenSCManager", GetLastError());
			} else if (_stricmp(argv[1], "/test") == 0) {
				_testRun = TRUE;
				ServiceMain(0, NULL);
			}
		default: {
			SERVICE_TABLE_ENTRYW svcTable[2];

			_argc = argc;
			_argv = argv;
			memset(svcTable, 0, sizeof(svcTable));
			svcTable[0].lpServiceName = L"Netpipe";
			svcTable[0].lpServiceProc = ServiceMain;
			if (!StartServiceCtrlDispatcherW(svcTable))
				ret = GetLastError();
		} break;
		} break;
	}

	return ret;
}
