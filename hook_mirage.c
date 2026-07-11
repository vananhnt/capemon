/*
 * hook_mirage.c — SAGE-generated hook implementations.
 * Auto-regenerated; do not edit by hand.
 */
#include "hooking.h"
#include <tlhelp32.h>
#include <slpublic.h>
#include "log.h"
#include "config.h"
#include "misc.h"
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

        HOOKDEF(ULONGLONG, WINAPI, GetTickCount64, void)
        {
            static ULONGLONG g_real_base = 0;
            static ULONGLONG g_forged_base = 0;
            ULONGLONG ret;
	lasterror_t lasterror;

	ret = Old_GetTickCount64();

	if (!g_config.no_stealth) {
		get_lasterrors(&lasterror);

		if (g_real_base == 0) {
			g_real_base = ret;
			g_forged_base = (ret < 600000) ? 600000 : ret;
		}

		ret = g_forged_base + (ret - g_real_base);

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

        static BOOL mirage_wnetenum_contains_ci(LPSTR remotename, LPCSTR needle)
        {
            if (!remotename)
		return FALSE;

	return stristr(remotename, needle) != NULL;
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

        static BOOL mirage_process32first_is_sandbox_helper(LPCWSTR szExeFile)
        {
            static const wchar_t *sandbox_helper_names[] = {
		L"vboxservice.exe", L"vboxtray.exe", L"vmtoolsd.exe",
		L"vmwaretray.exe", L"vmwareuser.exe", L"vboxcontrol.exe",
		L"prl_cc.exe", L"prl_tools.exe"
	};
	ULONG i;

	if (!szExeFile)
		return FALSE;

	for (i = 0; i < sizeof(sandbox_helper_names) / sizeof(sandbox_helper_names[0]); i++) {
		if (!wcsicmp(szExeFile, sandbox_helper_names[i]))
			return TRUE;
	}

	return FALSE;
        }

        static BOOL mirage_toolhelp_is_sandbox_helper_pid(DWORD pid)
        {
            HANDLE snap;
	PROCESSENTRY32W entry;
	BOOL found;

	found = FALSE;

	snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snap == INVALID_HANDLE_VALUE)
		return FALSE;

	entry.dwSize = sizeof(PROCESSENTRY32W);

	if (Process32FirstW(snap, &entry)) {
		do {
			if (entry.th32ProcessID == pid) {
				found = mirage_process32first_is_sandbox_helper(entry.szExeFile);
				break;
			}
		} while (Process32NextW(snap, &entry));
	}

	CloseHandle(snap);
	return found;
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