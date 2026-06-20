/*
 * hook_mirage.c — SAGE-generated hook implementations.
 * Auto-regenerated; do not edit by hand.
 */
#include <tlhelp32.h>
#include <slpublic.h>
#include "hooking.h"
#include "log.h"
#include "config.h"
#include "misc.h"

static const wchar_t *mirage_sandbox_helper_exenames[] = {
	L"VBoxService.exe",
	L"VBoxTray.exe",
	L"vmtoolsd.exe",
	L"vmwaretray.exe",
	L"vmwareuser.exe",
	L"vmacthlp.exe",
	L"capemon.exe",
	L"agent.exe"
};

static BOOL mirage_wnetenum_contains_ci(LPCSTR str, LPCSTR substr)
{
	if (!str)
		return FALSE;

	return stristr((char *)str, substr) ? TRUE : FALSE;
}

static BOOL mirage_process32first_is_sandbox_helper(LPCWSTR exeFileName)
{
	ULONG i;

	if (!exeFileName)
		return FALSE;

	for (i = 0; i < sizeof(mirage_sandbox_helper_exenames) / sizeof(mirage_sandbox_helper_exenames[0]); i++) {
		if (!wcsicmp(exeFileName, mirage_sandbox_helper_exenames[i]))
			return TRUE;
	}

	return FALSE;
}

static BOOL mirage_toolhelp_is_sandbox_helper_pid(DWORD pid)
{
	HANDLE snap;
	PROCESSENTRY32W entry;
	BOOL ismatch;

	snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snap == INVALID_HANDLE_VALUE)
		return FALSE;

	ismatch = FALSE;
	entry.dwSize = sizeof(PROCESSENTRY32W);

	if (Process32FirstW(snap, &entry)) {
		do {
			if (entry.th32ProcessID == pid) {
				ismatch = mirage_process32first_is_sandbox_helper(entry.szExeFile);
				break;
			}
		} while (Process32NextW(snap, &entry));
	}

	CloseHandle(snap);
	return ismatch;
}

        HOOKDEF(BOOL, WINAPI, GetSystemFirmwareTable, DWORD FirmwareTableProviderSignature, DWORD FirmwareTableID, PVOID pFirmwareTableBuffer, DWORD BufferSize)
        {
            BOOL ret;
	lasterror_t lasterror;

	ret = Old_GetSystemFirmwareTable(FirmwareTableProviderSignature, FirmwareTableID, pFirmwareTableBuffer, BufferSize);

	if (!g_config.no_stealth && ret && pFirmwareTableBuffer && BufferSize &&
		FirmwareTableProviderSignature == 'ACPI') {
		get_lasterrors(&lasterror);
		replace_ci_string_in_buf((PCHAR)pFirmwareTableBuffer, BufferSize, "VirtualBox", "Gigabyte__");
		replace_ci_string_in_buf((PCHAR)pFirmwareTableBuffer, BufferSize, "BOCHS", "Award");
		replace_ci_string_in_buf((PCHAR)pFirmwareTableBuffer, BufferSize, "BXPC", "ASUS");
		set_lasterrors(&lasterror);
	}

	return ret;
        }

        HOOKDEF(BOOL, WINAPI, EnumSystemFirmwareTables, DWORD FirmwareTableProviderSignature, PVOID pFirmwareTableEnumBuffer, DWORD BufferSize)
        {
            static const char *vm_strings[] = {
		"VirtualBox", "BOCHS", "BXPC", "VBOX", "QEMU", "VMware"
	};
	BOOL ret;
	lasterror_t lasterror;
	PDWORD ids;
	BYTE tablebuf[512];
	ULONG count;
	ULONG kept;
	ULONG i;
	ULONG j;
	BOOL tableret;
	BOOL hasvmstring;

	ret = Old_EnumSystemFirmwareTables(FirmwareTableProviderSignature, pFirmwareTableEnumBuffer, BufferSize);

	if (!g_config.no_stealth && ret && pFirmwareTableEnumBuffer && BufferSize &&
		FirmwareTableProviderSignature == 'ACPI') {
		get_lasterrors(&lasterror);

		ids = (PDWORD)pFirmwareTableEnumBuffer;
		count = BufferSize / sizeof(DWORD);
		kept = 0;

		for (i = 0; i < count; i++) {
			hasvmstring = FALSE;
			tableret = Old_GetSystemFirmwareTable(FirmwareTableProviderSignature, ids[i], tablebuf, sizeof(tablebuf));
			if (tableret) {
				for (j = 0; j < sizeof(vm_strings) / sizeof(vm_strings[0]); j++) {
					if (is_bytes_in_buf((PCHAR)tablebuf, sizeof(tablebuf), (PCHAR)vm_strings[j], (ULONG)strlen(vm_strings[j]), sizeof(tablebuf))) {
						hasvmstring = TRUE;
						break;
					}
				}
			}

			if (!hasvmstring)
				ids[kept++] = ids[i];
		}

		for (i = kept; i < count; i++)
			ids[i] = 0;

		set_lasterrors(&lasterror);
	}

	return ret;
        }

        HOOKDEF(char *, WINAPI, fgets, char *s, int size, void *stream)
        {
            char *ret;
	lasterror_t lasterror;
	static const char fake_line[] = "OneDrive\n";

	ret = Old_fgets(s, size, stream);

	if (!g_config.no_stealth && ret && s && size > (int)sizeof(fake_line)) {
		get_lasterrors(&lasterror);
		strcpy_s(s, size, fake_line);
		set_lasterrors(&lasterror);
	}

	return ret;
        }

        HOOKDEF(BOOL, WINAPI, PathFileExistsA, LPCSTR pszPath)
        {
            static const char *known_paths[] = {
		"C:\\Program Files\\7-Zip",
		"C:\\Program Files\\WinRAR",
		"C:\\Program Files\\WinZip"
	};
	BOOL ret;
	lasterror_t lasterror;
	ULONG i;
	BOOL ismatch;

	ret = Old_PathFileExistsA(pszPath);

	if (!g_config.no_stealth && pszPath) {
		ismatch = FALSE;
		for (i = 0; i < sizeof(known_paths) / sizeof(known_paths[0]); i++) {
			if (!_strnicmp(pszPath, known_paths[i], strlen(known_paths[i]))) {
				ismatch = TRUE;
				break;
			}
		}

		if (ismatch) {
			get_lasterrors(&lasterror);
			ret = TRUE;
			set_lasterrors(&lasterror);
		}
	}

	return ret;
        }

        HOOKDEF(HRESULT, WINAPI, WMI_Get, IWbemClassObject *this, LPCWSTR wszName, long lFlags, VARIANT *pVal, CIMTYPE *pType, long *plFlavor)
        {
            static const wchar_t *vm_substrings[] = {
		L"VMWare", L"Xen", L"innotek GmbH", L"QEMU"
	};
	static const wchar_t fake_manufacturer[] = L"Dell Inc.";
	HRESULT ret;
	lasterror_t lasterror;
	BSTR newval;
	ULONG i;
	BOOL ismatch;

	ret = Old_WMI_Get(this, wszName, lFlags, pVal, pType, plFlavor);

	if (!g_config.no_stealth && SUCCEEDED(ret) && wszName && pVal &&
		!wcsicmp(wszName, L"Manufacturer") && pVal->vt == VT_BSTR && pVal->bstrVal) {
		ismatch = FALSE;
		for (i = 0; i < sizeof(vm_substrings) / sizeof(vm_substrings[0]); i++) {
			if (wcsstr(pVal->bstrVal, vm_substrings[i])) {
				ismatch = TRUE;
				break;
			}
		}

		if (ismatch) {
			newval = SysAllocString(fake_manufacturer);
			if (newval) {
				get_lasterrors(&lasterror);
				SysFreeString(pVal->bstrVal);
				pVal->bstrVal = newval;
				set_lasterrors(&lasterror);
			}
		}
	}

	return ret;
        }

        HOOKDEF(VOID, WINAPI, GetSystemInfo, LPSYSTEM_INFO lpSystemInfo)
        {
            lasterror_t lasterror;

	Old_GetSystemInfo(lpSystemInfo);

	if (!g_config.no_stealth && lpSystemInfo && lpSystemInfo->dwNumberOfProcessors < 2) {
		get_lasterrors(&lasterror);
		lpSystemInfo->dwNumberOfProcessors = 4;
		set_lasterrors(&lasterror);
	}
        }

        HOOKDEF(BOOL, WINAPI, IsProcessorFeaturePresent, DWORD Feature)
        {
            BOOL ret;
	lasterror_t lasterror;

	ret = Old_IsProcessorFeaturePresent(Feature);

	if (!g_config.no_stealth && Feature == PF_VIRT_FIRMWARE_ENABLED && ret) {
		get_lasterrors(&lasterror);
		ret = FALSE;
		set_lasterrors(&lasterror);
	}

	return ret;
        }

        HOOKDEF(BOOL, WINAPI, GlobalMemoryStatusEx, LPMEMORYSTATUSEX lpBuffer)
        {
            BOOL ret;
	lasterror_t lasterror;

	ret = Old_GlobalMemoryStatusEx(lpBuffer);

	if (!g_config.no_stealth && ret && lpBuffer && lpBuffer->ullTotalPhys <= 8589934592ull) {
		get_lasterrors(&lasterror);
		lpBuffer->ullTotalPhys = 17179869184ull;
		set_lasterrors(&lasterror);
	}

	return ret;
        }

        HOOKDEF(BOOL, WINAPI, GetPwrCapabilities, SYSTEM_POWER_CAPABILITIES *PowerCaps)
        {
            BOOL ret;
	lasterror_t lasterror;

	ret = Old_GetPwrCapabilities(PowerCaps);

	if (!g_config.no_stealth && ret && PowerCaps && !PowerCaps->SystemS1) {
		get_lasterrors(&lasterror);
		PowerCaps->SystemS1 = 1;
		set_lasterrors(&lasterror);
	}

	return ret;
        }

        HOOKDEF(BOOL, WINAPI, EnumPrintersA, DWORD Flags, LPSTR Name, DWORD Level, LPBYTE pPrinterEnum, DWORD cbBuf, LPDWORD pcbNeeded, LPDWORD pcReturned)
        {
            BOOL ret;
	lasterror_t lasterror;

	ret = Old_EnumPrintersA(Flags, Name, Level, pPrinterEnum, cbBuf, pcbNeeded, pcReturned);

	if (!g_config.no_stealth && ret && pcReturned && *pcReturned != 0) {
		get_lasterrors(&lasterror);
		*pcReturned = 0;
		set_lasterrors(&lasterror);
	}

	return ret;
        }

        HOOKDEF(HANDLE, WINAPI, CreateFileA, LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
        {
            static const char *history_suffixes[] = {
		"\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadline\\ConsoleHost_history.txt",
		"\\AppData\\Local\\Microsoft\\Windows\\cmd.exe\\history.txt"
	};
	HANDLE ret;
	lasterror_t lasterror;
	BOOL ismatch;
	size_t pathlen;
	size_t suffixlen;
	ULONG i;

	ret = Old_CreateFileA(lpFileName, dwDesiredAccess, dwShareMode,
		lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes,
		hTemplateFile);

	if (!g_config.no_stealth && ret == INVALID_HANDLE_VALUE && lpFileName) {
		ismatch = FALSE;
		pathlen = strlen(lpFileName);

		for (i = 0; i < sizeof(history_suffixes) / sizeof(history_suffixes[0]); i++) {
			suffixlen = strlen(history_suffixes[i]);
			if (pathlen >= suffixlen &&
				!_stricmp(lpFileName + (pathlen - suffixlen), history_suffixes[i])) {
				ismatch = TRUE;
				break;
			}
		}

		if (ismatch) {
			get_lasterrors(&lasterror);
			ret = (HANDLE)0x1;
			set_lasterrors(&lasterror);
		}
	}

	return ret;
        }

        HOOKDEF(DWORD, WINAPI, GetTickCount, void)
        {
            DWORD ret;
	lasterror_t lasterror;

	ret = Old_GetTickCount();

	if (!g_config.no_stealth && ret < 720000) {
		get_lasterrors(&lasterror);
		ret = 7200000;
		set_lasterrors(&lasterror);
	}

	return ret;
        }

        HOOKDEF(ULONGLONG, WINAPI, GetTickCount64, void)
        {
            ULONGLONG ret;
	lasterror_t lasterror;

	ret = Old_GetTickCount64();

	if (!g_config.no_stealth && ret < 720000) {
		get_lasterrors(&lasterror);
		ret = 7200000;
		set_lasterrors(&lasterror);
	}

	return ret;
        }

        HOOKDEF(HANDLE, WINAPI, FindFirstFileA, LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData)
        {
            static const char taskbar_marker[] = "Microsoft\\Internet Explorer\\Quick Launch\\User Pinned\\TaskBar";
	static const char fake_filename[] = "Google Chrome.lnk";
	HANDLE ret;
	lasterror_t lasterror;
	BOOL ismatch;
	size_t pathlen;
	size_t markerlen;
	size_t i;

	ret = Old_FindFirstFileA(lpFileName, lpFindFileData);

	if (!g_config.no_stealth && ret == INVALID_HANDLE_VALUE && lpFileName) {
		ismatch = FALSE;
		pathlen = strlen(lpFileName);
		markerlen = strlen(taskbar_marker);

		for (i = 0; i + markerlen <= pathlen; i++) {
			if (!_strnicmp(lpFileName + i, taskbar_marker, markerlen)) {
				ismatch = TRUE;
				break;
			}
		}

		if (ismatch) {
			get_lasterrors(&lasterror);

			if (lpFindFileData) {
				memset(lpFindFileData, 0, sizeof(WIN32_FIND_DATAA));
				lpFindFileData->dwFileAttributes = FILE_ATTRIBUTE_ARCHIVE;
				strcpy_s(lpFindFileData->cFileName, sizeof(lpFindFileData->cFileName), fake_filename);
			}
			ret = (HANDLE)0x1;

			set_lasterrors(&lasterror);
		}
	}

	return ret;
        }

        HOOKDEF(BOOL, WINAPI, FindNextFileA, HANDLE hFindFile, LPWIN32_FIND_DATAA lpFindFileData)
        {
            static const char *fake_filenames[] = {
		"Mozilla Firefox.lnk",
		"Microsoft Edge.lnk",
		"VLC media player.lnk"
	};
	static unsigned int pinned_counter = 0;
	BOOL ret;
	lasterror_t lasterror;

	ret = Old_FindNextFileA(hFindFile, lpFindFileData);

	if (!g_config.no_stealth && !ret && hFindFile != 0 && hFindFile != INVALID_HANDLE_VALUE) {
		get_lasterrors(&lasterror);

		if (pinned_counter < sizeof(fake_filenames) / sizeof(fake_filenames[0])) {
			if (lpFindFileData) {
				memset(lpFindFileData, 0, sizeof(WIN32_FIND_DATAA));
				lpFindFileData->dwFileAttributes = FILE_ATTRIBUTE_ARCHIVE;
				strcpy_s(lpFindFileData->cFileName, sizeof(lpFindFileData->cFileName), fake_filenames[pinned_counter]);
			}
			pinned_counter++;
			ret = TRUE;
		} else {
			pinned_counter = 0;
		}

		set_lasterrors(&lasterror);
	}

	return ret;
        }

        HOOKDEF(LONG, WINAPI, RegOpenKeyExA, HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult)
        {
            static const char *sandbox_keys[] = {
		"SOFTWARE\\Oracle\\VirtualBox Guest Additions",
		"SYSTEM\\ControlSet001\\Services\\VBoxGuest",
		"SYSTEM\\ControlSet001\\Services\\VBoxMouse",
		"SYSTEM\\ControlSet001\\Services\\VBoxService",
		"SYSTEM\\ControlSet001\\Services\\VBoxSF",
		"SOFTWARE\\VMware, Inc.\\VMware Tools",
		"SYSTEM\\ControlSet001\\Services\\vmci",
		"SOFTWARE\\Sandboxie"
	};
	LONG ret;
	lasterror_t lasterror;
	ULONG i;
	BOOL ismatch;
	HKEY leftover;

	ret = Old_RegOpenKeyExA(hKey, lpSubKey, ulOptions, samDesired, phkResult);

	if (!g_config.no_stealth && ret == ERROR_SUCCESS && lpSubKey && phkResult) {
		ismatch = FALSE;
		for (i = 0; i < sizeof(sandbox_keys) / sizeof(sandbox_keys[0]); i++) {
			if (!_stricmp(lpSubKey, sandbox_keys[i])) {
				ismatch = TRUE;
				break;
			}
		}

		if (ismatch) {
			get_lasterrors(&lasterror);

			leftover = *phkResult;
			RegCloseKey(leftover);
			*phkResult = NULL;
			ret = 2;

			set_lasterrors(&lasterror);
		}
	}

	return ret;
        }

        HOOKDEF(DWORD, WINAPI, WNetEnumResource, HANDLE hEnum, LPDWORD lpcCount, LPNETRESOURCE lpBuffer, LPDWORD lpBufferSize)
        {
            DWORD ret;
	lasterror_t lasterror;
	DWORD count;
	DWORD kept;
	DWORD i;
	LPSTR remotename;
	BOOL ismatch;

	ret = Old_WNetEnumResource(hEnum, lpcCount, lpBuffer, lpBufferSize);

	if (!g_config.no_stealth && ret == NO_ERROR && lpBuffer && lpcCount && *lpcCount) {
		get_lasterrors(&lasterror);

		count = *lpcCount;
		kept = 0;

		for (i = 0; i < count; i++) {
			remotename = lpBuffer[i].lpRemoteName;
			ismatch = mirage_wnetenum_contains_ci(remotename, "VIRTUALBOX") ||
				mirage_wnetenum_contains_ci(remotename, "VBOXSVR");

			if (!ismatch)
				lpBuffer[kept++] = lpBuffer[i];
		}

		if (kept != count) {
			for (i = kept; i < count; i++)
				memset(&lpBuffer[i], 0, sizeof(NETRESOURCE));

			*lpcCount = kept;

			if (kept == 0)
				ret = ERROR_NO_MORE_ITEMS;
		}

		set_lasterrors(&lasterror);
	}

	return ret;
        }

        HOOKDEF(HANDLE, WINAPI, CreateToolhelp32Snapshot, DWORD dwFlags, DWORD th32ProcessID)
        {
            HANDLE ret;
	lasterror_t lasterror;

	ret = Old_CreateToolhelp32Snapshot(dwFlags, th32ProcessID);

	if (!g_config.no_stealth && ret != INVALID_HANDLE_VALUE && th32ProcessID &&
		mirage_toolhelp_is_sandbox_helper_pid(th32ProcessID)) {
		get_lasterrors(&lasterror);

		CloseHandle(ret);
		ret = INVALID_HANDLE_VALUE;

		set_lasterrors(&lasterror);
	}

	return ret;
        }

        HOOKDEF(BOOL, WINAPI, Process32FirstW, HANDLE hSnapshot, void* lppe)
        {
            BOOL ret;
	lasterror_t lasterror;
	typedef struct _MIRAGE_PROCESSENTRY32W {
		DWORD dwSize;
		DWORD cntUsage;
		DWORD th32ProcessID;
		ULONG_PTR th32DefaultHeapID;
		DWORD th32ModuleID;
		DWORD cntThreads;
		DWORD th32ParentProcessID;
		LONG pcPriClassBase;
		DWORD dwFlags;
		WCHAR szExeFile[260];
	} MIRAGE_PROCESSENTRY32W, *PMIRAGE_PROCESSENTRY32W;
	PMIRAGE_PROCESSENTRY32W entry = (PMIRAGE_PROCESSENTRY32W)lppe;

	ret = Old_Process32FirstW(hSnapshot, lppe);

	if (!g_config.no_stealth && ret && lppe) {
		get_lasterrors(&lasterror);

		while (ret && mirage_process32first_is_sandbox_helper(entry->szExeFile))
			ret = Process32NextW(hSnapshot, lppe);

		set_lasterrors(&lasterror);
	}

	return ret;
        }

        HOOKDEF(BOOL, WINAPI, Process32NextW, HANDLE hSnapshot, void *lppe)
        {
            BOOL ret;
	lasterror_t lasterror;
	typedef struct _MIRAGE_PROCESSENTRY32W {
		DWORD dwSize;
		DWORD cntUsage;
		DWORD th32ProcessID;
		ULONG_PTR th32DefaultHeapID;
		DWORD th32ModuleID;
		DWORD cntThreads;
		DWORD th32ParentProcessID;
		LONG pcPriClassBase;
		DWORD dwFlags;
		WCHAR szExeFile[260];
	} MIRAGE_PROCESSENTRY32W, *PMIRAGE_PROCESSENTRY32W;
	PMIRAGE_PROCESSENTRY32W pe = (PMIRAGE_PROCESSENTRY32W)lppe;

	ret = Old_Process32NextW(hSnapshot, lppe);

	if (!g_config.no_stealth && ret && pe) {
		get_lasterrors(&lasterror);

		while (ret && mirage_process32first_is_sandbox_helper(pe->szExeFile))
			ret = Old_Process32NextW(hSnapshot, lppe);

		set_lasterrors(&lasterror);
	}

	return ret;
        }

        HOOKDEF(DWORD, WINAPI, WNetEnumResourceW, HANDLE hEnum, LPDWORD lpcCount, LPVOID lpBuffer, LPDWORD lpBufferSize)
        {
            DWORD ret;
	lasterror_t lasterror;
	LPNETRESOURCEW entries;
	DWORD count;
	DWORD kept;
	DWORD i;

	ret = Old_WNetEnumResourceW(hEnum, lpcCount, lpBuffer, lpBufferSize);

	if (!g_config.no_stealth && ret == NO_ERROR && lpBuffer && lpcCount && *lpcCount) {
		get_lasterrors(&lasterror);

		entries = (LPNETRESOURCEW)lpBuffer;
		count = *lpcCount;
		kept = 0;

		for (i = 0; i < count; i++) {
			if (!entries[i].lpProvider || wcsicmp(entries[i].lpProvider, L"VirtualBox Shared Folders"))
				entries[kept++] = entries[i];
		}

		if (kept != count) {
			for (i = kept; i < count; i++)
				memset(&entries[i], 0, sizeof(NETRESOURCEW));

			*lpcCount = kept;

			if (kept == 0)
				ret = ERROR_NO_MORE_ITEMS;
		}

		set_lasterrors(&lasterror);
	}

	return ret;
        }

        HOOKDEF(HRESULT, WINAPI, SLIsGenuineLocal, const SLID* AppId, SL_GENUINE_STATE* GenuineState, PVOID Reserved)
        {
            HRESULT ret;
	lasterror_t lasterror;

	ret = Old_SLIsGenuineLocal(AppId, GenuineState, Reserved);

	if (!g_config.no_stealth && GenuineState) {
		get_lasterrors(&lasterror);

		*GenuineState = SL_GEN_STATE_IS_GENUINE;
		ret = S_OK;

		set_lasterrors(&lasterror);
	}

	return ret;
        }