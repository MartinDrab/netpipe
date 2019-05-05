
#include "compat-header.h"
#include "netpipe.h"


/************************************************************************/
/*                      GLOBAL VARIABLES                                */
/************************************************************************/

static SERVICE_STATUS _statusRecord;
static SERVICE_STATUS_HANDLE _statusHandle = NULL;
static HANDLE _exitEventHandle = NULL;


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


static DWORD _LoadSettings(int *argc, char ***argv)
{
	DWORD index = 0;
	int tmpArgc = 0;
	char **tmpArgv = NULL;
	HKEY hParamsKey = NULL;
	DWORD ret = ERROR_GEN_FAILURE;
	const int maxArgs = sizeof(_cmdOptions) / sizeof(_cmdOptions[0]);

	tmpArgv = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (2*maxArgs + 1)*sizeof(char *));
	if (tmpArgv != NULL) {
		tmpArgv[0] = "netpipe.exe";
		tmpArgc = 1;
		ret = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\Netpipe\\Parameters", 0, KEY_QUERY_VALUE, &hParamsKey);
		if (ret == ERROR_SUCCESS) {
			do {
				BOOL argFound = FALSE;
				char valueName[MAX_PATH];
				char valueData[MAX_PATH + 1];
				DWORD cbValueName = sizeof(valueName);
				DWORD cbValueData = MAX_PATH;
				PCOMMAND_LINE_OPTION cmdOpt = NULL;
				size_t nameLen = 0;

				memset(valueName, 0, sizeof(valueName));
				memset(valueData, 0, sizeof(valueData));
				ret = RegEnumValueA(hParamsKey, index - 1, valueName, &cbValueName, NULL, NULL, valueData, &cbValueData);
				if (ret == ERROR_SUCCESS) {
					cmdOpt = _cmdOptions;
					for (size_t i = 0; i < maxArgs; ++i) {
						for (size_t j = 0; j < cmdOpt->NameCount; ++j) {
							nameLen = strlen(cmdOpt->Names[j]);
							if (nameLen > 2 &&
								!cmdOpt->Specified &&
								cmdOpt->Names[j][0] == '-' &&
								cmdOpt->Names[j][1] == '-') {
								tmpArgv[tmpArgc] = cmdOpt->Names[j];
								++tmpArgc;
								if (cmdOpt->ArgumentCount == 1) {
									tmpArgv[tmpArgc] = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbValueData + sizeof(char));
									if (tmpArgv[tmpArgc] != NULL) {
										memcpy(tmpArgv[tmpArgc], valueData, cbValueData);
										tmpArgv[tmpArgc][cbValueData] = '\0';
										++tmpArgc;
									} else ret = GetLastError();
								}
							
								argFound = TRUE;
								break;
							}
						}

						++cmdOpt;
						if (argFound)
							break;
					}
				}

				++index;
			} while (ret == ERROR_SUCCESS && tmpArgc < 2*maxArgs + 1);

			if (ret == ERROR_NO_MORE_ITEMS)
				ret = ERROR_SUCCESS;
			RegCloseKey(hParamsKey);
		}
		
		if (ret != ERROR_SUCCESS) {
			while (tmpArgc > 0) {
				--tmpArgc;
				if (tmpArgv[tmpArgc] != NULL)
					HeapFree(GetProcessHeap(), 0, tmpArgv[tmpArgc]);
			}
			
			HeapFree(GetProcessHeap(), 0, tmpArgv);
		}
	} else ret = GetLastError();

	return ret;
}


void WINAPI ServiceMain(DWORD argc, LPWSTR *argv)
{
	DWORD dwError = 0;
	int argCount = 0;
	char **args = NULL;

	memset(&_statusRecord, 0, sizeof(_statusRecord));
	_statusHandle = RegisterServiceCtrlHandlerExW(L"Netpipe", _NetpipeServiceHandlerEx, NULL);
	if (_statusHandle != NULL) {
		_statusRecord.dwCurrentState = SERVICE_START_PENDING;
		_statusRecord.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
		SetServiceStatus(_statusHandle, &_statusRecord);
		dwError = _LoadSettings(&argCount, &args);
		if (dwError == ERROR_SUCCESS) {
			_exitEventHandle = CreateEventW(NULL, TRUE, FALSE, NULL);
			if (_exitEventHandle != NULL) {
				_statusRecord.dwCurrentState = SERVICE_RUNNING;
				_statusRecord.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SESSIONCHANGE;
				SetServiceStatus(_statusHandle, &_statusRecord);
				NetPipeMain(argCount, args);
				WaitForSingleObject(_exitEventHandle, INFINITE);
				_statusRecord.dwCurrentState = SERVICE_STOPPED;
				SetServiceStatus(_statusHandle, &_statusRecord);
				CloseHandle(_exitEventHandle);
			}
		
			for (int i = 1; i < argCount; ++i) {
				if (args[i] != NULL)
					HeapFree(GetProcessHeap(), 0, args[i]);

				HeapFree(GetProcessHeap(), 0, args);
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
		case 1: {
			SERVICE_TABLE_ENTRYW svcTable[2];

			memset(svcTable, 0, sizeof(svcTable));
			svcTable[0].lpServiceName = L"Netpipe";
			svcTable[0].lpServiceProc = ServiceMain;
			if (!StartServiceCtrlDispatcherW(svcTable))
				ret = GetLastError();
		} break;
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
						hService = CreateServiceW(hScm, L"NetPipe", L"Network to Network Pipe Service", SERVICE_ALL_ACCESS, SERVICE_WIN32 | SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, moduleName, NULL, NULL, NULL, NULL, NULL);
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
			}
		} break;
	}

	return ret;
}
