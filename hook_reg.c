/*
Cuckoo Sandbox - Automated Malware Analysis
Copyright (C) 2010-2015 Cuckoo Sandbox Developers, Optiv, Inc. (brad.spengler@optiv.com)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include "ntapi.h"
#include "hooking.h"
#include "misc.h"
#include "log.h"
#include "config.h"
#include "CAPE\CAPE.h"

HOOKDEF(LONG, WINAPI, RegOpenKeyExA,
	__in		HKEY hKey,
	__in_opt	LPCTSTR lpSubKey,
	__reserved  DWORD ulOptions,
	__in		REGSAM samDesired,
	__out	   PHKEY phkResult
) {
	HKEY saved_hkey = phkResult ? *phkResult : INVALID_HANDLE_VALUE;
	LONG ret = Old_RegOpenKeyExA(hKey, lpSubKey, ulOptions, samDesired,
		phkResult);

	// fake the absence of some keys
	if (!g_config.no_stealth && (ret == ERROR_SUCCESS || ret == ERROR_ACCESS_DENIED)) {
		unsigned int allocsize = sizeof(KEY_NAME_INFORMATION) + MAX_KEY_BUFLEN;
		PKEY_NAME_INFORMATION keybuf = malloc(allocsize);
		wchar_t *keypath = get_full_key_pathA(hKey, lpSubKey, keybuf, allocsize);
		int i;

		wchar_t *hidden_keys[] = {
			L"HKEY_LOCAL_MACHINE\\HARDWARE\\ACPI\\DSDT\\VBOX__",
			L"HKEY_LOCAL_MACHINE\\HARDWARE\\ACPI\\DSDT\\VBOX__\\VBOXBIOS",
			L"HKEY_LOCAL_MACHINE\\HARDWARE\\ACPI\\FADT\\VBOX__",
			L"HKEY_LOCAL_MACHINE\\HARDWARE\\ACPI\\FADT\\VBOX__\\VBOXFACP",
			L"HKEY_LOCAL_MACHINE\\HARDWARE\\ACPI\\RSDT\\VBOX__",
			L"HKEY_LOCAL_MACHINE\\HARDWARE\\ACPI\\RSDT\\VBOX__\\VBOXRSDT"
		};

		for (i = 0; i < _countof(hidden_keys); ++i) {
			if (!wcsicmp(keypath, hidden_keys[i])) {
				lasterror_t errors;
				// clean up state to avoid leaking information
				if (ret == ERROR_SUCCESS && phkResult) {
					RegCloseKey(*phkResult);
					*phkResult = saved_hkey;
				}
				ret = errors.Win32Error = ERROR_FILE_NOT_FOUND;
				errors.NtstatusError = STATUS_OBJECT_NAME_NOT_FOUND;
				errors.Eflags = 0;
				set_lasterrors(&errors);
				break;
			}
		}

		// fake some values
		if (lpSubKey && !g_config.no_stealth)
			perform_ascii_registry_fakery(keypath, (LPVOID)lpSubKey, (ULONG)strlen(lpSubKey));
		free(keybuf);
	}

	LOQ_zero("registry", "psPe", "Registry", hKey, "SubKey", lpSubKey, "Handle", phkResult,
		"FullName", hKey, lpSubKey);
	return ret;
}

HOOKDEF(LONG, WINAPI, RegOpenKeyExW,
	__in		HKEY hKey,
	__in_opt	LPWSTR lpSubKey,
	__reserved  DWORD ulOptions,
	__in		REGSAM samDesired,
	__out	   PHKEY phkResult
)
{
/* WOW64 view-selector access-mask bits; guarded in case the winreg
	   headers visible in this TU predate them. */
#ifndef KEY_WOW64_64KEY
#define KEY_WOW64_64KEY 0x0100
#endif
#ifndef KEY_WOW64_32KEY
#define KEY_WOW64_32KEY 0x0200
#endif
	LONG ret;
	lasterror_t lasterror;
	HKEY forged;
	const wchar_t *p;
	int targets_uninstall;

	ret = Old_RegOpenKeyExW(hKey, lpSubKey, ulOptions, samDesired, phkResult);

	/* Samples enumerate installed software by opening
	 * HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall in BOTH WOW64
	 * registry views — once with KEY_WOW64_64KEY and once with
	 * KEY_WOW64_32KEY — so a 32-bit sample sees the native 64-bit hive and a
	 * 64-bit sample sees the WOW6432Node hive; gatherInfo() aborts early if
	 * either RegOpenKeyExW fails, never reaching the subkey-count decision.
	 * On a freshly-imaged analysis VM one of the two view opens can fail
	 * (a stripped/absent WOW6432Node Uninstall hive, or a restrictive
	 * samDesired the bare guest cannot satisfy), so the paired open fails and
	 * the sample takes its sandbox-detected branch before the companion
	 * RegEnumKeyExW forge can inflate the subkey tally. The transparent answer
	 * is to make both WOW64-view opens of the Uninstall key succeed: when the
	 * real open of that exact key in a WOW64 view fails, retry the open of the
	 * same Uninstall subkey in the default view with KEY_READ to obtain a
	 * genuine, closeable HKEY whose NtQueryKey path still ends in
	 * CurrentVersion\Uninstall (so the RegEnumKeyExW hook recognises it), hand
	 * it back through phkResult, and return ERROR_SUCCESS. gatherInfo() then
	 * proceeds past both opens to the forged subkey count. Only Uninstall-key
	 * opens carrying a WOW64 selector are touched; every other open, and any
	 * genuine success, passes straight through untouched. lasterror is
	 * preserved around the forged response. */
	if (!g_config.no_stealth && ret != ERROR_SUCCESS && phkResult != NULL &&
			lpSubKey != NULL &&
			(samDesired & (KEY_WOW64_64KEY | KEY_WOW64_32KEY)) != 0) {
		targets_uninstall = 0;
		for (p = lpSubKey; *p != L'\0'; p++) {
			if (_wcsnicmp(p,
					L"Microsoft\\Windows\\CurrentVersion\\Uninstall",
					42) == 0) {
				targets_uninstall = 1;
				break;
			}
		}

		if (targets_uninstall) {
			get_lasterrors(&lasterror);

			/* Prefer the requested WOW64 view first, dropping only the
			   access mask down to KEY_READ in case the original failure
			   was a too-restrictive samDesired the bare guest could not
			   grant; if that view is genuinely absent (e.g. a stripped
			   WOW6432Node Uninstall hive), fall back to the default view
			   so we still return a genuine, closeable Uninstall handle
			   whose NtQueryKey path ends in CurrentVersion\Uninstall. */
			forged = NULL;
			if (Old_RegOpenKeyExW(hKey, lpSubKey, ulOptions,
					KEY_READ | (samDesired &
						(KEY_WOW64_64KEY | KEY_WOW64_32KEY)),
					&forged) == ERROR_SUCCESS ||
					Old_RegOpenKeyExW(hKey, lpSubKey, ulOptions,
						KEY_READ, &forged) == ERROR_SUCCESS) {
				*phkResult = forged;
				ret = ERROR_SUCCESS;
				lasterror.Win32Error = ERROR_SUCCESS;
			}

			set_lasterrors(&lasterror);
		}
	}

	LOQ_zero("registry", "pu", "Handle", hKey, "SubKey",
		lpSubKey != NULL ? lpSubKey : L"");

	return ret;
}

HOOKDEF(LONG, WINAPI, RegCreateKeyExA,
	__in		HKEY hKey,
	__in		LPCTSTR lpSubKey,
	__reserved  DWORD Reserved,
	__in_opt	LPTSTR lpClass,
	__in		DWORD dwOptions,
	__in		REGSAM samDesired,
	__in_opt	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	__out	   PHKEY phkResult,
	__out_opt   LPDWORD lpdwDisposition
) {
	LONG ret;
	ENSURE_DWORD(lpdwDisposition);
	ret = Old_RegCreateKeyExA(hKey, lpSubKey, Reserved, lpClass,
		dwOptions, samDesired, lpSecurityAttributes, phkResult,
		lpdwDisposition);

	// fake the absence of some keys
	if (!g_config.no_stealth && ret == ERROR_SUCCESS && *lpdwDisposition == REG_OPENED_EXISTING_KEY) {
		unsigned int allocsize = sizeof(KEY_NAME_INFORMATION) + MAX_KEY_BUFLEN;
		PKEY_NAME_INFORMATION keybuf = malloc(allocsize);
		wchar_t *keypath = get_full_key_pathA(hKey, lpSubKey, keybuf, allocsize);
		int i;

		wchar_t *hidden_keys[] = {
			L"HKEY_LOCAL_MACHINE\\HARDWARE\\ACPI\\DSDT\\VBOX__",
			L"HKEY_LOCAL_MACHINE\\HARDWARE\\ACPI\\DSDT\\VBOX__\\VBOXBIOS",
			L"HKEY_LOCAL_MACHINE\\HARDWARE\\ACPI\\FADT\\VBOX__",
			L"HKEY_LOCAL_MACHINE\\HARDWARE\\ACPI\\FADT\\VBOX__\\VBOXFACP",
			L"HKEY_LOCAL_MACHINE\\HARDWARE\\ACPI\\RSDT\\VBOX__",
			L"HKEY_LOCAL_MACHINE\\HARDWARE\\ACPI\\RSDT\\VBOX__\\VBOXRSDT"
		};

		for (i = 0; i < _countof(hidden_keys); ++i) {
			if (!wcsicmp(keypath, hidden_keys[i])) {
				*lpdwDisposition = REG_CREATED_NEW_KEY;
				break;
			}
		}
		free(keybuf);
	}

	LOQ_zero("registry", "psshPeI", "Registry", hKey, "SubKey", lpSubKey, "Class", lpClass,
		"Access", samDesired, "Handle", phkResult, "FullName", hKey, lpSubKey,
		"Disposition", lpdwDisposition);
	return ret;
}

HOOKDEF(LONG, WINAPI, RegCreateKeyExW,
	__in		HKEY hKey,
	__in		LPWSTR lpSubKey,
	__reserved  DWORD Reserved,
	__in_opt	LPWSTR lpClass,
	__in		DWORD dwOptions,
	__in		REGSAM samDesired,
	__in_opt	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	__out	   PHKEY phkResult,
	__out_opt   LPDWORD lpdwDisposition
)
{
LONG ret;

	/* Diagnostic-only fallback: a real transparency countermeasure for this
	 * API failed to compile even after a repair attempt, so this hook simply
	 * forwards to the original function and returns its result completely
	 * unmodified. It logs the real arguments and return value for analysis
	 * visibility but alters no output buffers, arguments or the disposition. */
	ret = Old_RegCreateKeyExW(hKey, lpSubKey, Reserved, lpClass, dwOptions, samDesired, lpSecurityAttributes, phkResult, lpdwDisposition);

	LOQ_zero("registry", "puiiP", "Handle", hKey, "SubKey", lpSubKey,
		"Access", (int)samDesired, "Disposition",
		lpdwDisposition != NULL ? (int)*lpdwDisposition : 0, "Key", phkResult);

	return ret;
}

HOOKDEF(LONG, WINAPI, RegDeleteKeyA,
	__in  HKEY hKey,
	__in  LPCTSTR lpSubKey
) {
	LONG ret = Old_RegDeleteKeyA(hKey, lpSubKey);
	LOQ_zero("registry", "pse", "Handle", hKey, "SubKey", lpSubKey,
		"FullName", hKey, lpSubKey);
	return ret;
}

HOOKDEF(LONG, WINAPI, RegDeleteKeyW,
	__in  HKEY hKey,
	__in  LPWSTR lpSubKey
) {
	LONG ret = Old_RegDeleteKeyW(hKey, lpSubKey);
	LOQ_zero("registry", "puE", "Handle", hKey, "SubKey", lpSubKey,
		"FullName", hKey, lpSubKey);
	return ret;
}

HOOKDEF(LSTATUS, WINAPI, RegDeleteKeyExW,
	_In_ HKEY    hKey,
	_In_ LPCWSTR lpSubKey,
	_In_ REGSAM  samDesired,
	__reserved DWORD   Reserved
) {
	LSTATUS ret = Old_RegDeleteKeyExW(hKey, lpSubKey, samDesired, Reserved);
	LOQ_zero("registry", "puhE", "Handle", hKey, "SubKey", lpSubKey, "Access", samDesired, "FullName", hKey, lpSubKey);
	return ret;
}

HOOKDEF(LSTATUS, WINAPI, RegDeleteKeyExA,
	_In_ HKEY   hKey,
	_In_ LPCSTR lpSubKey,
	_In_ REGSAM samDesired,
	__reserved DWORD  Reserved
) {
	LSTATUS ret = Old_RegDeleteKeyExA(hKey, lpSubKey, samDesired, Reserved);
	LOQ_zero("registry", "puhE", "Handle", hKey, "SubKey", lpSubKey, "Access", samDesired, "FullName", hKey, lpSubKey);
	return ret;
}

HOOKDEF(LONG, WINAPI, RegEnumKeyW,
	__in   HKEY hKey,
	__in   DWORD dwIndex,
	__out  LPWSTR lpName,
	__in   DWORD cchName
) {
	LONG ret = Old_RegEnumKeyW(hKey, dwIndex, lpName, cchName);

	// fake the absence of some keys
	if (!g_config.no_stealth && ret == ERROR_SUCCESS) {
		unsigned int allocsize = sizeof(KEY_NAME_INFORMATION) + MAX_KEY_BUFLEN;
		PKEY_NAME_INFORMATION keybuf = malloc(allocsize);
		wchar_t *keypath = get_full_key_pathW(hKey, NULL, keybuf, allocsize);
		int i, j;

		wchar_t *parent_keys[] = {
			L"HKEY_LOCAL_MACHINE\\HARDWARE\\ACPI\\DSDT",
			L"HKEY_LOCAL_MACHINE\\HARDWARE\\ACPI\\FADT",
			L"HKEY_LOCAL_MACHINE\\HARDWARE\\ACPI\\RSDT"
			L"HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Enum\\IDE"
		};

		wchar_t *replace_subkeys[] = {
			L"VBOX__", L"DELL__",
			L"VMware_", L"Dell_",
			L"VMWar_", L"Dell_",
		};

		for (i = 0, j = 0; i < _countof(parent_keys); i += 1, j += 2) {
			if (!wcsicmp(keypath, parent_keys[i]) && !wcsicmp(lpName, replace_subkeys[j])) {
				wcscpy_s(lpName, sizeof(lpName), replace_subkeys[j + 1]);
				break;
			}
		}
		free(keybuf);
	}

	LOQ_zero("registry", "piuE", "Handle", hKey, "Index", dwIndex, "Name", ret ? L"" : lpName,
		"FullName", hKey, ret ? L"" : lpName);

	return ret;
}

HOOKDEF(LONG, WINAPI, RegEnumKeyExA,
	__in		 HKEY hKey,
	__in		 DWORD dwIndex,
	__out		LPTSTR lpName,
	__inout	  LPDWORD lpcName,
	__reserved   LPDWORD lpReserved,
	__inout	  LPTSTR lpClass,
	__inout_opt  LPDWORD lpcClass,
	__out_opt	PFILETIME lpftLastWriteTime
) {
	LONG ret = Old_RegEnumKeyExA(hKey, dwIndex, lpName, lpcName, lpReserved,
		lpClass, lpcClass, lpftLastWriteTime);

	// fake the absence of some keys
	if (!g_config.no_stealth && ret == ERROR_SUCCESS) {
		unsigned int allocsize = sizeof(KEY_NAME_INFORMATION) + MAX_KEY_BUFLEN;
		PKEY_NAME_INFORMATION keybuf = malloc(allocsize);
		wchar_t *keypath = get_full_key_pathA(hKey, NULL, keybuf, allocsize);
		int i, j;

		wchar_t *parent_keys[] = {
			L"HKEY_LOCAL_MACHINE\\HARDWARE\\ACPI\\DSDT",
			L"HKEY_LOCAL_MACHINE\\HARDWARE\\ACPI\\FADT",
			L"HKEY_LOCAL_MACHINE\\HARDWARE\\ACPI\\RSDT"
			L"HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Enum\\IDE"
		};

		char *replace_subkeys[] = {
			"VBOX__", "DELL__",
			"VMware_", "Dell_",
			"VMWar_", "Dell_",
		};

		for (i = 0, j = 0; i < _countof(parent_keys); i += 1, j += 2) {
			if (!wcsicmp(keypath, parent_keys[i]) && !stricmp(lpName, replace_subkeys[j])) {
				strcpy_s(lpName, sizeof(lpName), replace_subkeys[j + 1]);
				break;
			}
		}

		// fake some values
		if (lpName && !g_config.no_stealth)
			perform_ascii_registry_fakery(keypath, lpName, (ULONG)strlen(lpName));
		free(keybuf);
	}

	LOQ_zero("registry", "pisse", "Handle", hKey, "Index", dwIndex, "Name", ret ? "" : lpName,
		"Class", ret ? "" : lpClass, "FullName", hKey, ret ? "" : lpName);
	return ret;
}

HOOKDEF(LONG, WINAPI, RegEnumKeyExW,
	__in		 HKEY hKey,
	__in		 DWORD dwIndex,
	__out		LPWSTR lpName,
	__inout	  LPDWORD lpcName,
	__reserved   LPDWORD lpReserved,
	__inout	  LPWSTR lpClass,
	__inout_opt  LPDWORD lpcClass,
	__out_opt	PFILETIME lpftLastWriteTime
)
{
LONG ret;
	lasterror_t lasterror;
	typedef LONG (WINAPI *NtQueryKey_t)(HANDLE, ULONG, PVOID, ULONG, PULONG);
	NtQueryKey_t pNtQueryKey;
	HMODULE ntdll;
	BYTE keybuf[1024];
	ULONG reslen, namelen, namechars, i;
	const wchar_t *name;
	const wchar_t suffix[] = L"CurrentVersion\\Uninstall";
	unsigned int suffixlen = (unsigned int)(sizeof(suffix) / sizeof(wchar_t) - 1);
	int is_uninstall;
	wchar_t fake[16];
	wchar_t ca, cb;
	unsigned int num;
	FILETIME nowft;
	ULARGE_INTEGER stamp;

	ret = Old_RegEnumKeyExW(hKey, dwIndex, lpName, lpcName, lpReserved,
		lpClass, lpcClass, lpftLastWriteTime);

	/* The sample counts the subkeys of
	 * HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall (in both WOW64
	 * views) by walking dwIndex until ERROR_NO_MORE_ITEMS, and treats a tally
	 * below 100 as "nobody ever installed anything on this box" => sandbox. A
	 * freshly imaged analysis guest genuinely has only a few dozen Uninstall
	 * subkeys, so forwarding the real answer (the previous diagnostic body)
	 * always loses the check. Transparent response: once the real enumeration
	 * is exhausted, keep the walk alive with synthesised, plausibly named
	 * uninstall entries until the index reaches 128, so the loop counts 128
	 * installed applications before it finally sees ERROR_NO_MORE_ITEMS. Every
	 * out parameter the caller may read is filled consistently - the name
	 * buffer, *lpcName (characters excluding the terminator), an empty class
	 * (these keys carry none) and a staggered last-write time - and
	 * ERROR_MORE_DATA is returned honestly when the caller's buffer is too
	 * small. Only handles whose NtQueryKey path ends in
	 * CurrentVersion\Uninstall are touched (which covers the native and the
	 * WOW6432Node view alike), so every other registry enumeration in the
	 * process is unaffected, and lasterror is preserved and normalised around
	 * the forged path so a following GetLastError() cannot expose it. */
	if (!g_config.no_stealth && ret == ERROR_NO_MORE_ITEMS && dwIndex < 128 &&
			lpName != NULL && lpcName != NULL) {
		get_lasterrors(&lasterror);

		is_uninstall = 0;
		ntdll = GetModuleHandleA("ntdll.dll");
		if (ntdll != NULL) {
			pNtQueryKey = (NtQueryKey_t)GetProcAddress(ntdll, "NtQueryKey");
			if (pNtQueryKey != NULL) {
				reslen = 0;
				/* 3 == KeyNameInformation: ULONG NameLength followed by the
				   full \REGISTRY\... path, not NUL terminated */
				if (pNtQueryKey((HANDLE)hKey, 3, keybuf, (ULONG)sizeof(keybuf),
						&reslen) >= 0 && reslen > sizeof(ULONG)) {
					namelen = *(ULONG *)keybuf;
					name = (const wchar_t *)(keybuf + sizeof(ULONG));
					namechars = namelen / (ULONG)sizeof(wchar_t);
					if (namechars >= suffixlen && namechars <=
							(ULONG)((sizeof(keybuf) - sizeof(ULONG)) / sizeof(wchar_t))) {
						is_uninstall = 1;
						for (i = 0; i < suffixlen; i++) {
							ca = name[namechars - suffixlen + i];
							cb = suffix[i];
							if (ca >= L'A' && ca <= L'Z')
								ca = (wchar_t)(ca + 32);
							if (cb >= L'A' && cb <= L'Z')
								cb = (wchar_t)(cb + 32);
							if (ca != cb) {
								is_uninstall = 0;
								break;
							}
						}
					}
				}
			}
		}

		if (is_uninstall) {
			/* deterministic, plausible update-package style subkey name:
			   "KB" followed by seven digits, unique per index */
			num = 4030000 + (unsigned int)dwIndex * 137;
			fake[0] = L'K';
			fake[1] = L'B';
			for (i = 0; i < 7; i++) {
				fake[2 + 6 - i] = (wchar_t)(L'0' + (num % 10));
				num /= 10;
			}
			fake[9] = L'\0';

			if (*lpcName < 10) {
				ret = ERROR_MORE_DATA;
				lasterror.Win32Error = ERROR_MORE_DATA;
			}
			else {
				for (i = 0; i < 10; i++)
					lpName[i] = fake[i];
				*lpcName = 9;

				if (lpClass != NULL && lpcClass != NULL && *lpcClass > 0)
					lpClass[0] = L'\0';
				if (lpcClass != NULL)
					*lpcClass = 0;

				if (lpftLastWriteTime != NULL) {
					GetSystemTimeAsFileTime(&nowft);
					stamp.LowPart = nowft.dwLowDateTime;
					stamp.HighPart = nowft.dwHighDateTime;
					/* stagger the fabricated installs one day apart, into the past */
					stamp.QuadPart -= (ULONGLONG)(dwIndex + 1) * 864000000000ULL;
					lpftLastWriteTime->dwLowDateTime = stamp.LowPart;
					lpftLastWriteTime->dwHighDateTime = stamp.HighPart;
				}

				ret = ERROR_SUCCESS;
				lasterror.Win32Error = ERROR_SUCCESS;
			}
		}

		set_lasterrors(&lasterror);
	}

	LOQ_zero("registry", "piu", "Handle", hKey, "Index", dwIndex, "Name",
		(ret == ERROR_SUCCESS && lpName != NULL) ? lpName : L"");

	return ret;
}

HOOKDEF(LONG, WINAPI, RegEnumValueA,
	__in		 HKEY hKey,
	__in		 DWORD dwIndex,
	__out		LPTSTR lpValueName,
	__inout	  LPDWORD lpcchValueName,
	__reserved   LPDWORD lpReserved,
	__out_opt	LPDWORD lpType,
	__out_opt	LPBYTE lpData,
	__inout_opt  LPDWORD lpcbData
) {
	LONG ret;
	ENSURE_DWORD(lpType);
	ret = Old_RegEnumValueA(hKey, dwIndex, lpValueName, lpcchValueName,
		lpReserved, lpType, lpData, lpcbData);
	if (ret == ERROR_SUCCESS && lpType != NULL && lpData != NULL &&
			lpcbData != NULL) {
		LOQ_zero("registry", "pisre", "Handle", hKey, "Index", dwIndex,
			"ValueName", lpValueName, "Data", *lpType, *lpcbData, lpData,
			"FullName", hKey, lpValueName);
	}
	else {
		LOQ_zero("registry", "pisIIe", "Handle", hKey, "Index", dwIndex,
			"ValueName", ret == ERROR_SUCCESS ? lpValueName : "", "Type", lpType, "DataLength", lpcbData,
			"FullName", hKey, ret == ERROR_SUCCESS ? lpValueName : "");
	}
	return ret;
}

HOOKDEF(LONG, WINAPI, RegEnumValueW,
	__in		 HKEY hKey,
	__in		 DWORD dwIndex,
	__out		LPWSTR lpValueName,
	__inout	  LPDWORD lpcchValueName,
	__reserved   LPDWORD lpReserved,
	__out_opt	LPDWORD lpType,
	__out_opt	LPBYTE lpData,
	__inout_opt  LPDWORD lpcbData
)
{
/* NtQueryKey(KeyNameInformation) fills this fixed layout with the
	   full registry path of the queried handle. Defined locally (with a
	   guard) so this hook compiles even if the ntapi headers visible in
	   this TU don't expose it; NameLength is a byte count and Name is NOT
	   NUL-terminated. */
#ifndef __MIRAGE_KEY_NAME_INFORMATION_DEFINED
#define __MIRAGE_KEY_NAME_INFORMATION_DEFINED
	typedef struct _MIRAGE_KEY_NAME_INFORMATION {
		ULONG NameLength;
		WCHAR Name[1];
	} MIRAGE_KEY_NAME_INFORMATION;
#endif
	/* Rotating pool of plausible FeatureUsage\\AppSwitched value entries.
	   Real AppSwitched values are keyed by an application identifier — an
	   AUMID or a full executable path — with a REG_DWORD switch-count
	   payload, so each synthetic entry reads as an app a real user has
	   alt-tabbed to. */
	static const wchar_t *mirage_appswitched_values[] = {
		L"Microsoft.Windows.Explorer",
		L"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
		L"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
		L"C:\\Program Files\\Mozilla Firefox\\firefox.exe",
		L"C:\\Windows\\System32\\notepad.exe",
		L"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
		L"C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE",
		L"C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE",
		L"C:\\Program Files\\Windows Media Player\\wmplayer.exe",
		L"C:\\Program Files (x86)\\Adobe\\Acrobat Reader DC\\Reader\\AcroRd32.exe",
		L"C:\\Program Files\\Spotify\\Spotify.exe",
		L"C:\\Program Files\\VideoLAN\\VLC\\vlc.exe",
		L"Microsoft.WindowsCalculator_8wekyb3d8bbwe!App",
		L"Microsoft.WindowsTerminal_8wekyb3d8bbwe!App",
		L"C:\\Windows\\explorer.exe",
		L"C:\\Windows\\System32\\cmd.exe",
		L"C:\\Windows\\System32\\mmc.exe",
		L"C:\\Program Files\\Git\\git-bash.exe",
		L"C:\\Program Files\\Microsoft VS Code\\Code.exe",
		L"C:\\Program Files\\7-Zip\\7zFM.exe",
		L"C:\\Program Files\\PowerShell\\7\\pwsh.exe",
		L"C:\\Program Files (x86)\\Steam\\steam.exe",
		L"C:\\Program Files\\Slack\\slack.exe",
		L"C:\\Program Files\\Zoom\\bin\\Zoom.exe",
	};
	/* Opaque shell ITEMIDLIST used as the REG_BINARY payload of synthetic
	   ComDlg32 MRU entries: a My-Computer CLSID item, a "C:\\" drive item and
	   the two-byte list terminator — the same shape as the real PidlMRU blobs
	   this key already holds, so a parser that walks cb fields sees a
	   well-formed pidl rather than filler. */
	static const unsigned char mirage_mru_pidl[] = {
		0x14, 0x00, 0x1f, 0x50, 0xe0, 0x4f, 0xd0, 0x20,
		0xea, 0x3a, 0x69, 0x10, 0xa2, 0xd8, 0x08, 0x00,
		0x2b, 0x30, 0x30, 0x9d,
		0x19, 0x00, 0x2f, 0x43, 0x3a, 0x5c, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00,
		0x00, 0x00
	};
	/* Drive the enumerable value count past the sample's "< 20" threshold:
	   ensure at least 24 entries yield ERROR_SUCCESS before
	   ERROR_NO_MORE_ITEMS. 24 == the task's forced value. */
	static const DWORD MIRAGE_MIN_ENTRIES = 24;
	LONG ret;
	lasterror_t lasterror;
	HMODULE hNtdll;
	LONG (WINAPI *pNtQueryKey)(HANDLE, int, PVOID, ULONG, PULONG);
	unsigned char keyname_buf[1024];
	unsigned char pidl_buf[64];
	wchar_t namebuf[16];
	wchar_t digits[12];
	ULONG keyname_len;
	MIRAGE_KEY_NAME_INFORMATION *keyname;
	const wchar_t *name_w;
	const wchar_t *p;
	const wchar_t *value;
	DWORD listex[32];
	DWORD value_chars;
	DWORD usage;
	DWORD pool_total;
	DWORD pidl_len;
	DWORD slot;
	DWORD n;
	int key_kind;
	int t;
	int i;

	ENSURE_DWORD(lpType);
	ret = Old_RegEnumValueW(hKey, dwIndex, lpValueName, lpcchValueName,
		lpReserved, lpType, lpData, lpcbData);

	/* Two families of "has a human used this desktop?" registry probes reach
	 * this API, and both are answered here:
	 *
	 *   key_kind 1 — HKCU\\...\\Explorer\\FeatureUsage\\AppSwitched: one value per
	 *     application the user alt-tab/taskbar-switched to. A sample counts the
	 *     ERROR_SUCCESS iterations and treats "< 20" as a freshly-imaged VM.
	 *   key_kind 2 — HKCU\\...\\Explorer\\ComDlg32\\{OpenSavePidlMRU,
	 *     LastVisitedPidlMRU,...} and the sibling RecentDocs / RunMRU /
	 *     TypedPaths MRU keys: numbered values holding shell pidls plus an
	 *     MRUListEx index list. The previous revision of this hook only knew
	 *     about AppSwitched, so the OpenSavePidlMRU enumeration ran dry after
	 *     three real values and the sample concluded "few MRU entries".
	 *
	 * The enumerated handle is classified by resolving its registry path with
	 * NtQueryKey(KeyNameInformation) so unrelated keys are never padded. When
	 * the real enumeration has run dry (ERROR_NO_MORE_ITEMS) and the caller is
	 * still inside the first MIRAGE_MIN_ENTRIES slots, one more plausible entry
	 * is synthesised: an app path/AUMID + REG_DWORD switch count for kind 1, or
	 * a numbered value + REG_BINARY pidl for kind 2. For kind 2 the MRUListEx
	 * value is additionally rewritten as it is enumerated so its index list
	 * agrees with the forged entry count — a sample that counts entries and a
	 * sample that parses MRUListEx then see the same, lived-in number instead of
	 * contradicting each other. Real values and every other key pass through
	 * untouched; lasterror is preserved around each forged path. */
	key_kind = 0;
	if (!g_config.no_stealth) {
		hNtdll = GetModuleHandleA("ntdll.dll");
		if (hNtdll != NULL) {
			pNtQueryKey = (LONG (WINAPI *)(HANDLE, int, PVOID, ULONG, PULONG))
				GetProcAddress(hNtdll, "NtQueryKey");
			if (pNtQueryKey != NULL) {
				keyname_len = 0;
				/* KeyNameInformation == 3; leave room for a NUL */
				if (pNtQueryKey(hKey, 3, keyname_buf,
						(ULONG)(sizeof(keyname_buf) - sizeof(wchar_t)),
						&keyname_len) == 0 &&
						keyname_len >= sizeof(ULONG)) {
					keyname = (MIRAGE_KEY_NAME_INFORMATION *)keyname_buf;
					if (keyname->NameLength <=
							sizeof(keyname_buf) - sizeof(ULONG) - sizeof(wchar_t)) {
						*(wchar_t *)((unsigned char *)keyname->Name +
							keyname->NameLength) = L'\0';
						name_w = keyname->Name;
						for (p = name_w; *p != L'\0'; p++) {
							if (_wcsnicmp(p, L"FeatureUsage\\AppSwitched", 24) == 0) {
								key_kind = 1;
								break;
							}
							if (_wcsnicmp(p, L"ComDlg32\\", 9) == 0 ||
									_wcsnicmp(p, L"RecentDocs", 10) == 0 ||
									_wcsnicmp(p, L"RunMRU", 6) == 0 ||
									_wcsnicmp(p, L"TypedPaths", 10) == 0) {
								key_kind = 2;
								break;
							}
						}
					}
				}
			}
		}
	}

	/* Keep MRUListEx consistent with the padded entry count: most-recent-first
	   indices 23..0 followed by the 0xFFFFFFFF terminator. */
	if (key_kind == 2 && ret == ERROR_SUCCESS && lpValueName != NULL &&
			lpData != NULL && lpcbData != NULL &&
			_wcsnicmp(lpValueName, L"MRUListEx", 10) == 0 &&
			*lpcbData >= (MIRAGE_MIN_ENTRIES + 1) * sizeof(DWORD)) {
		get_lasterrors(&lasterror);
		for (i = 0; i < (int)MIRAGE_MIN_ENTRIES; i++)
			listex[i] = MIRAGE_MIN_ENTRIES - 1 - (DWORD)i;
		listex[MIRAGE_MIN_ENTRIES] = 0xFFFFFFFF;
		memcpy(lpData, listex, (MIRAGE_MIN_ENTRIES + 1) * sizeof(DWORD));
		*lpcbData = (DWORD)((MIRAGE_MIN_ENTRIES + 1) * sizeof(DWORD));
		if (lpType != NULL)
			*lpType = REG_BINARY;
		set_lasterrors(&lasterror);
	}

	if (key_kind != 0 && ret == ERROR_NO_MORE_ITEMS &&
			lpValueName != NULL && lpcchValueName != NULL) {
		value = NULL;
		usage = 0;
		slot = 0;

		if (key_kind == 1) {
			if (dwIndex < MIRAGE_MIN_ENTRIES) {
				pool_total = (DWORD)(sizeof(mirage_appswitched_values) /
					sizeof(mirage_appswitched_values[0]));
				value = mirage_appswitched_values[dwIndex % pool_total];
				/* plausible, index-varying switch count */
				usage = 5 + dwIndex * 2;
			}
		} else {
			/* One enumeration slot in a ComDlg32 MRU key is taken by
			   MRUListEx, so the numbered value at enumeration index i is
			   conventionally named i-1; continuing that numbering keeps the
			   synthetic names from colliding with the real ones. */
			slot = (dwIndex >= 1) ? (dwIndex - 1) : 0;
			if (slot < MIRAGE_MIN_ENTRIES) {
				n = slot;
				t = 0;
				if (n == 0)
					digits[t++] = L'0';
				while (n != 0) {
					digits[t++] = (wchar_t)(L'0' + (n % 10));
					n /= 10;
				}
				i = 0;
				while (t > 0)
					namebuf[i++] = digits[--t];
				namebuf[i] = L'\0';
				value = namebuf;
			}
		}

		if (value != NULL) {
			get_lasterrors(&lasterror);
			value_chars = (DWORD)wcslen(value);

			if (*lpcchValueName > value_chars) {
				/* room for the name plus its terminating NUL */
				memcpy(lpValueName, value,
					((size_t)value_chars + 1) * sizeof(wchar_t));
				*lpcchValueName = value_chars;

				if (key_kind == 1) {
					if (lpType != NULL)
						*lpType = REG_DWORD;
					if (lpData != NULL && lpcbData != NULL) {
						if (*lpcbData >= sizeof(DWORD)) {
							memcpy(lpData, &usage, sizeof(DWORD));
							*lpcbData = sizeof(DWORD);
							ret = ERROR_SUCCESS;
						} else {
							/* caller's data buffer too small: report the
							   required size, matching RegEnumValue */
							*lpcbData = sizeof(DWORD);
							ret = ERROR_MORE_DATA;
						}
					} else {
						if (lpcbData != NULL)
							*lpcbData = sizeof(DWORD);
						ret = ERROR_SUCCESS;
					}
				} else {
					pidl_len = (DWORD)sizeof(mirage_mru_pidl);
					if (lpType != NULL)
						*lpType = REG_BINARY;
					if (lpData != NULL && lpcbData != NULL) {
						if (*lpcbData >= pidl_len) {
							memcpy(pidl_buf, mirage_mru_pidl, pidl_len);
							/* vary the opaque tail so no two synthetic
							   pidls are byte-identical */
							pidl_buf[pidl_len - 3] =
								(unsigned char)(0x30 + (slot % 10));
							memcpy(lpData, pidl_buf, pidl_len);
							*lpcbData = pidl_len;
							ret = ERROR_SUCCESS;
						} else {
							*lpcbData = pidl_len;
							ret = ERROR_MORE_DATA;
						}
					} else {
						if (lpcbData != NULL)
							*lpcbData = pidl_len;
						ret = ERROR_SUCCESS;
					}
				}
			} else {
				/* caller's name buffer too small: report the required
				   character count so the caller can retry */
				*lpcchValueName = value_chars;
				ret = ERROR_MORE_DATA;
			}

			set_lasterrors(&lasterror);
		}
	}

	if (ret == ERROR_SUCCESS && lpType != NULL && lpData != NULL &&
			lpcbData != NULL) {
		LOQ_zero("registry", "piuRE", "Handle", hKey, "Index", dwIndex,
			"ValueName", lpValueName, "Data", *lpType, *lpcbData, lpData,
			"FullName", hKey, lpValueName);
	}
	else {
		LOQ_zero("registry", "piuIIE", "Handle", hKey, "Index", dwIndex,
			"ValueName", ret == ERROR_SUCCESS ? lpValueName : L"", "Type", lpType, "DataLength", lpcbData,
			"FullName", hKey, ret == ERROR_SUCCESS ? lpValueName : L"");
	}
	return ret;
}

HOOKDEF(LONG, WINAPI, RegSetValueExA,
	__in		HKEY hKey,
	__in_opt	LPCTSTR lpValueName,
	__reserved  DWORD Reserved,
	__in		DWORD dwType,
	__in		const BYTE *lpData,
	__in		DWORD cbData
) {
	LONG ret = Old_RegSetValueExA(hKey, lpValueName, Reserved, dwType, lpData,
		cbData);
	if (ret == ERROR_SUCCESS) {
		if (g_config.regdump && cbData > REGISTRY_VALUE_SIZE_MIN) {
			CapeMetaData->DumpType = REGDUMP;
			DumpMemory((PVOID)lpData, cbData);
			DebugOutput("RegSetValueExA hook: Dumped registry value %s.\n", lpValueName);
		}
		LOQ_zero("registry", "psiriv", "Handle", hKey, "ValueName", lpValueName, "Type", dwType,
			"Buffer", dwType, cbData, lpData, "BufferLength", cbData,
			"FullName", hKey, lpValueName);
	}
	else {
		LOQ_zero("registry", "psiv", "Handle", hKey, "ValueName", lpValueName, "Type", dwType,
			"FullName", hKey, lpValueName);
	}
	return ret;
}

HOOKDEF(LONG, WINAPI, RegSetValueExW,
	__in		HKEY hKey,
	__in_opt	LPWSTR lpValueName,
	__reserved  DWORD Reserved,
	__in		DWORD dwType,
	__in		const BYTE *lpData,
	__in		DWORD cbData
) {
	LONG ret = Old_RegSetValueExW(hKey, lpValueName, Reserved, dwType, lpData,
		cbData);
	if (ret == ERROR_SUCCESS) {
		if (g_config.regdump && cbData > REGISTRY_VALUE_SIZE_MIN) {
			CapeMetaData->DumpType = REGDUMP;
			DumpMemory((PVOID)lpData, cbData);
			DebugOutput("RegSetValueExW hook: Dumped registry value %s.\n", lpValueName);
		}
		LOQ_zero("registry", "puiRiV", "Handle", hKey, "ValueName", lpValueName, "Type", dwType,
			"Buffer", dwType, cbData, lpData, "BufferLength", cbData,
			"FullName", hKey, lpValueName);
	}
	else {
		LOQ_zero("registry", "puiV", "Handle", hKey, "ValueName", lpValueName, "Type", dwType,
			"FullName", hKey, lpValueName);
	}
	return ret;
}

HOOKDEF(LONG, WINAPI, RegQueryValueExA,
	__in		 HKEY hKey,
	__in_opt	 LPCTSTR lpValueName,
	__reserved   LPDWORD lpReserved,
	__out_opt	LPDWORD lpType,
	__out_opt	LPBYTE lpData,
	__inout_opt  LPDWORD lpcbData
) {
	LONG ret;
	ENSURE_DWORD(lpType);
	ret = Old_RegQueryValueExA(hKey, lpValueName, lpReserved, lpType,
		lpData, lpcbData);
	if (ret == ERROR_SUCCESS && lpType != NULL && lpData != NULL && lpcbData != NULL) {
		unsigned int allocsize = sizeof(KEY_NAME_INFORMATION) + MAX_KEY_BUFLEN;
		PKEY_NAME_INFORMATION keybuf = malloc(allocsize);
		wchar_t *keypath = get_full_keyvalue_pathA(hKey, lpValueName, keybuf, allocsize);

		// fake some values
		if (lpData && !g_config.no_stealth)
			perform_ascii_registry_fakery(keypath, lpData, *lpcbData);

		LOQ_zero("registry", "psru", "Handle", hKey, "ValueName", lpValueName,
			"Data", *lpType, *lpcbData, lpData,
			"FullName", keypath);
		free(keybuf);
	}
	else if (ret == ERROR_MORE_DATA) {
		LOQ_zero("registry", "psPIv", "Handle", hKey, "ValueName", lpValueName,
			"Type", lpType, "DataLength", lpcbData,
			"FullName", hKey, lpValueName);
	}
	else {
		LOQ_zero("registry", "psv", "Handle", hKey, "ValueName", lpValueName,
			"FullName", hKey, lpValueName);
	}
	return ret;
}

HOOKDEF(LONG, WINAPI, RegQueryValueExW,
	__in		 HKEY hKey,
	__in_opt	 LPWSTR lpValueName,
	__reserved   LPDWORD lpReserved,
	__out_opt	LPDWORD lpType,
	__out_opt	LPBYTE lpData,
	__inout_opt  LPDWORD lpcbData
)
{
LONG ret;
	lasterror_t lasterror;
	/* User-application whitelist the sample matches DisplayName strings
	   against (case-insensitive substring, needs >= 2 hits). "Slack" is the
	   forced/lead value; rotating across subkeys yields distinct matches. */
	static const wchar_t *whitelist[] = {
		L"Slack",
		L"Discord",
		L"Notion",
		L"Docker",
		L"Visual Studio",
	};
	static unsigned int rotation;
	/* Physical-OEM model string forged for the BIOS SystemProductName read.
	   A real desktop reports a concrete product model; a VM reports a
	   virtualization keyword ("VMware Virtual Platform", "VirtualBox",
	   "KVM", "QEMU", "Standard PC", "Xen", "Parallels", ...) that the
	   sample's LIKE '%virtual%'/... substring scan flags. "OptiPlex 7090"
	   is a genuine Dell OEM model containing none of those keywords. */
	static const wchar_t forced_value[] = L"OptiPlex 7090";
	/* First-run persistence marker the sample reads to decide isFirstRun:
	   HKCU\Software\RdpServersHistoryChecker\FirstRunCompleted, a REG_DWORD
	   whose value == 0 (or an absent value) means "first run". Forcing a
	   non-zero DWORD (1) makes isFirstRun evaluate false. */
	static const DWORD MIRAGE_FIRSTRUN_FORCED_VALUE = 1;
	const wchar_t *forged;
	DWORD needed;
	DWORD forced;
	ENSURE_DWORD(lpType);
	ret = Old_RegQueryValueExW(hKey, lpValueName, lpReserved, lpType,
		lpData, lpcbData);

	/* Samples enumerate the subkeys of
	 * ...\Microsoft\Windows\CurrentVersion\Uninstall and read each subkey's
	 * "DisplayName" value via RegQueryValueExW, lowercasing it and testing it
	 * (appLower.find(keywordLower) != npos) against a whitelist of common user
	 * applications (Slack, Discord, Notion, Docker, Visual Studio); fewer than
	 * two whitelist hits reads as a bare analysis VM with no real user software
	 * installed and the sample takes its sandbox-detected branch. A
	 * freshly-imaged guest's Uninstall hive holds only OS/driver entries, so the
	 * real DisplayName strings rarely match and the count stays below two.
	 * RegQueryValueExW hands us only an HKEY, not the key path, so the
	 * "DisplayName" value name is the discriminator here: whenever a DisplayName
	 * string value is queried, answer with the next whitelisted application name
	 * (starting with "Slack", then "Discord", ... rotating per successful read).
	 * Because each enumerated Uninstall subkey issues its own DisplayName query,
	 * consecutive subkeys report distinct whitelisted apps and the sample sees
	 * >= 2 matches, classifying the host as a genuine user environment.
	 * RegQueryValueExW is a two-pass API (lpData == NULL sizes the value, then
	 * the caller retries with a buffer): report the forged string's size on the
	 * sizing pass and only advance the rotation once the value is actually
	 * delivered. */
	if (!g_config.no_stealth && lpValueName != NULL &&
			_wcsicmp(lpValueName, L"DisplayName") == 0 && lpcbData != NULL) {
		get_lasterrors(&lasterror);

		forged = whitelist[rotation % (sizeof(whitelist) / sizeof(whitelist[0]))];
		needed = (DWORD)((lstrlenW(forged) + 1) * sizeof(wchar_t));

		if (lpData == NULL) {
			/* sizing pass: report the room the forged REG_SZ needs so the
			   caller comes back with a large enough buffer */
			*lpcbData = needed;
			if (lpType != NULL)
				*lpType = REG_SZ;
			ret = ERROR_SUCCESS;
		} else if (*lpcbData >= needed) {
			memcpy(lpData, forged, needed);
			*lpcbData = needed;
			if (lpType != NULL)
				*lpType = REG_SZ;
			rotation++;
			ret = ERROR_SUCCESS;
		} else {
			/* caller's buffer is too small; report the required size and let
			   it retry, matching RegQueryValueExW's ERROR_MORE_DATA contract */
			*lpcbData = needed;
			ret = ERROR_MORE_DATA;
		}

		set_lasterrors(&lasterror);
	}

	/* Samples read HKLM\HARDWARE\DESCRIPTION\System\BIOS!SystemProductName
	 * and treat the value as a sandbox tell: a virtualization keyword in the
	 * string (LIKE '%virtual%','%virtualbox%','%vmware%','%kvm%','%qemu%',
	 * '%hyper-v%','%hyperv%','%xen%','%parallels%'), or an empty/failed read,
	 * classifies the host as a VM and steers the sample down its
	 * sandbox-detected branch. A freshly-imaged guest's BIOS product name
	 * carries exactly such a keyword (or the key is absent), so the real read
	 * fails the check. When the queried value is SystemProductName, overwrite
	 * the returned data with a REG_SZ physical-OEM model ("OptiPlex 7090")
	 * that contains none of the virtualization keywords and is never empty,
	 * and set *lpcbData to the string's byte length so the substring scan sees
	 * genuine OEM hardware and the sample follows its real-user-environment
	 * path. RegQueryValueExW is a two-call API (a NULL lpData sizing call
	 * followed by the real read, and an undersized buffer reports
	 * ERROR_MORE_DATA), so honor each phase: size queries report the needed
	 * length, adequate buffers receive the forged string, and undersized
	 * buffers get ERROR_MORE_DATA with the required size. lasterror is
	 * preserved around the forged response. */
	if (!g_config.no_stealth && lpValueName != NULL &&
			_wcsicmp(lpValueName, L"SystemProductName") == 0 &&
			lpcbData != NULL) {
		get_lasterrors(&lasterror);

		needed = (DWORD)sizeof(forced_value);

		if (lpType != NULL)
			*lpType = REG_SZ;

		if (lpData == NULL) {
			/* sizing pass: report the byte length the forged value needs */
			*lpcbData = needed;
			ret = ERROR_SUCCESS;
		} else if (*lpcbData >= needed) {
			memcpy(lpData, forced_value, needed);
			*lpcbData = needed;
			ret = ERROR_SUCCESS;
		} else {
			/* caller's buffer is too small; report the required size so it
			   retries with a large enough buffer */
			*lpcbData = needed;
			ret = ERROR_MORE_DATA;
		}

		set_lasterrors(&lasterror);
	}

	/* Samples gate their behaviour on a first-run persistence marker under
	 * HKCU\Software\RdpServersHistoryChecker\FirstRunCompleted: they read the
	 * FirstRunCompleted REG_DWORD via RegQueryValueExW and set isFirstRun from
	 * whether the value is present and non-zero — a missing value (the query
	 * fails with ERROR_FILE_NOT_FOUND) or a value of 0 leaves isFirstRun true.
	 * On a freshly-imaged analysis VM the marker was never written, and the
	 * sandbox discards it across disposable snapshots, so every detonation
	 * reads the value as absent/zero, isFirstRun stays true, and the sample
	 * runs its "first execution" evasion/setup path instead of the genuine
	 * returning-user task routine. The transparent answer is to make the marker
	 * read as already set: when the queried value name is FirstRunCompleted,
	 * report a successful REG_DWORD read whose data is 1 (non-zero) so
	 * isFirstRun evaluates false and the sample follows its normal
	 * returning-user path. RegQueryValueExW is a two-pass API — a NULL lpData
	 * queries the required size — so honor both phases: report REG_DWORD and a
	 * 4-byte size on the sizing pass, and write the forged DWORD only when the
	 * caller's buffer is large enough (otherwise ERROR_MORE_DATA with the
	 * required size). Any other value name passes straight through untouched.
	 * lasterror is preserved around the forged response. */
	if (!g_config.no_stealth && lpValueName != NULL &&
			_wcsicmp(lpValueName, L"FirstRunCompleted") == 0) {
		get_lasterrors(&lasterror);

		forced = MIRAGE_FIRSTRUN_FORCED_VALUE;

		if (lpType != NULL)
			*lpType = REG_DWORD;

		if (lpData == NULL) {
			/* sizing pass: report the type and required byte count */
			if (lpcbData != NULL)
				*lpcbData = sizeof(DWORD);
			ret = ERROR_SUCCESS;
			lasterror.Win32Error = ERROR_SUCCESS;
		} else if (lpcbData != NULL && *lpcbData >= sizeof(DWORD)) {
			memcpy(lpData, &forced, sizeof(DWORD));
			*lpcbData = sizeof(DWORD);
			ret = ERROR_SUCCESS;
			lasterror.Win32Error = ERROR_SUCCESS;
		} else if (lpcbData != NULL) {
			/* caller's data buffer too small: report the required size,
			   matching RegQueryValueExW's ERROR_MORE_DATA behaviour */
			*lpcbData = sizeof(DWORD);
			ret = ERROR_MORE_DATA;
			lasterror.Win32Error = ERROR_MORE_DATA;
		}

		set_lasterrors(&lasterror);
	}

	if (ret == ERROR_SUCCESS && lpType != NULL && lpData != NULL &&
			lpcbData != NULL) {
		unsigned int allocsize = sizeof(KEY_NAME_INFORMATION) + ((16384 + 256) * sizeof(wchar_t));
		PKEY_NAME_INFORMATION keybuf = malloc(allocsize);
		wchar_t *keypath = get_full_keyvalue_pathW(hKey, lpValueName, keybuf, allocsize);

		// fake some values
		if (lpData && !g_config.no_stealth)
			perform_unicode_registry_fakery(keypath, lpData, *lpcbData);

		LOQ_zero("registry", "puRu", "Handle", hKey, "ValueName", lpValueName,
			"Data", *lpType, *lpcbData, lpData,
			"FullName", keypath);
		free(keybuf);
	}
	else if (ret == ERROR_MORE_DATA) {
		LOQ_zero("registry", "puPIV", "Handle", hKey, "ValueName", lpValueName,
			"Type", lpType, "DataLength", lpcbData,
			"FullName", hKey, lpValueName);
	}
	else {
		LOQ_zero("registry", "puV", "Handle", hKey, "ValueName", lpValueName,
			"FullName", hKey, lpValueName);
	}
	return ret;
}

HOOKDEF(LONG, WINAPI, RegDeleteValueA,
	__in	  HKEY hKey,
	__in_opt  LPCTSTR lpValueName
) {
	LONG ret = Old_RegDeleteValueA(hKey, lpValueName);
	LOQ_zero("registry", "psv", "Handle", hKey, "ValueName", lpValueName,
		"FullName", hKey, lpValueName);
	return ret;
}

HOOKDEF(LONG, WINAPI, RegDeleteValueW,
	__in	  HKEY hKey,
	__in_opt  LPWSTR lpValueName
) {
	LONG ret = Old_RegDeleteValueW(hKey, lpValueName);
	LOQ_zero("registry", "puV", "Handle", hKey, "ValueName", lpValueName,
		"FullName", hKey, lpValueName);
	return ret;
}

HOOKDEF(LONG, WINAPI, RegQueryInfoKeyA,
	_In_		 HKEY hKey,
	_Out_opt_	LPTSTR lpClass,
	_Inout_opt_  LPDWORD lpcClass,
	_Reserved_   LPDWORD lpReserved,
	_Out_opt_	LPDWORD lpcSubKeys,
	_Out_opt_	LPDWORD lpcMaxSubKeyLen,
	_Out_opt_	LPDWORD lpcMaxClassLen,
	_Out_opt_	LPDWORD lpcValues,
	_Out_opt_	LPDWORD lpcMaxValueNameLen,
	_Out_opt_	LPDWORD lpcMaxValueLen,
	_Out_opt_	LPDWORD lpcbSecurityDescriptor,
	_Out_opt_	PFILETIME lpftLastWriteTime
) {
	LONG ret = Old_RegQueryInfoKeyA(hKey, lpClass, lpcClass, lpReserved,
		lpcSubKeys, lpcMaxSubKeyLen, lpcMaxClassLen, lpcValues,
		lpcMaxValueNameLen, lpcMaxValueLen, lpcbSecurityDescriptor,
		lpftLastWriteTime);
	LOQ_zero("registry", "pS6I", "KeyHandle", hKey, "Class", lpcClass ? *lpcClass : 0, lpClass,
		"SubKeyCount", lpcSubKeys, "MaxSubKeyLength", lpcMaxSubKeyLen,
		"MaxClassLength", lpcMaxClassLen, "ValueCount", lpcValues,
		"MaxValueNameLength", lpcMaxValueNameLen,
		"MaxValueLength", lpcMaxValueLen);
	return ret;
}

HOOKDEF(LONG, WINAPI, RegQueryInfoKeyW,
	_In_		 HKEY hKey,
	_Out_opt_	LPWSTR lpClass,
	_Inout_opt_  LPDWORD lpcClass,
	_Reserved_   LPDWORD lpReserved,
	_Out_opt_	LPDWORD lpcSubKeys,
	_Out_opt_	LPDWORD lpcMaxSubKeyLen,
	_Out_opt_	LPDWORD lpcMaxClassLen,
	_Out_opt_	LPDWORD lpcValues,
	_Out_opt_	LPDWORD lpcMaxValueNameLen,
	_Out_opt_	LPDWORD lpcMaxValueLen,
	_Out_opt_	LPDWORD lpcbSecurityDescriptor,
	_Out_opt_	PFILETIME lpftLastWriteTime
)
{
/* KEY_NAME_INFORMATION as returned by NtQueryKey(KeyNameInformation):
	   a byte-length-prefixed wide key path. Declared locally, and NtQueryKey
	   resolved dynamically from ntdll, so this hook does not depend on which
	   ntapi.h revision exposes the registry key info classes or the NtQueryKey
	   prototype. */
	typedef struct {
		ULONG NameLength;
		WCHAR Name[1];
	} mirage_key_name_information_t;
	typedef LONG (WINAPI *mirage_ntquerykey_t)(HANDLE, int, PVOID, ULONG, PULONG);
	/* KEY_NAME_INFORMATION slot in KEY_INFORMATION_CLASS */
	enum { MIRAGE_KEY_NAME_INFORMATION = 3 };

	/* Forced MuiCache value count, comfortably above the sample's < 50
	   floor so muiCacheValueCount fails the "< 50" test. */
	static const DWORD MIRAGE_MUICACHE_FORCED_VALUES = 64;

	LONG ret;
	lasterror_t lasterror;
	HMODULE hNtdll;
	mirage_ntquerykey_t pNtQueryKey;
	mirage_key_name_information_t *key_name;
	unsigned char name_buf[1024];
	ULONG result_len;
	int is_recentdocs;
	int is_muicache;
	const wchar_t *p;

	ret = Old_RegQueryInfoKeyW(hKey, lpClass, lpcClass, lpReserved,
		lpcSubKeys, lpcMaxSubKeyLen, lpcMaxClassLen, lpcValues,
		lpcMaxValueNameLen, lpcMaxValueLen, lpcbSecurityDescriptor,
		lpftLastWriteTime);

	/* Samples enumerate HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\
	 * RecentDocs and read its value count via RegQueryInfoKeyW's lpcValues
	 * out-parameter, treating cValues <= 20 as a freshly-imaged analysis VM
	 * whose most-recently-used document history was never populated by genuine
	 * user activity, taking their sandbox-detected branch. A bare guest's
	 * RecentDocs key holds only a handful of values (or none), so the real count
	 * falls at or below the threshold. Similarly, samples read the number of
	 * values under the per-user MuiCache key (HKCU\Software\Classes\Local
	 * Settings\Software\Microsoft\Windows\Shell\MuiCache) as muiCacheValueCount:
	 * MuiCache records one value per application whose friendly name the shell
	 * has ever resolved, so an aged, genuinely-used desktop accumulates dozens of
	 * entries while a freshly-imaged VM has only a handful, and the checker treats
	 * muiCacheValueCount < 50 as a sandbox. That value-count test is the second
	 * half of a compound isSandbox condition (the first half being a first-run
	 * persistence marker, neutralized by the companion RegOpenKeyExW hook), so
	 * defeating it independently collapses the conjunction. RegQueryInfoKeyW hands
	 * us only an HKEY, not the key path, so resolve the handle's full registry
	 * path via NtQueryKey(KeyNameInformation) and only forge when that path names
	 * one of these keys. The MuiCache match is against the trailing "Shell\MuiCache"
	 * component (case-insensitive) so it matches the UsrClass.dat-backed native
	 * path (\REGISTRY\USER\<SID>_Classes\...\Shell\MuiCache) regardless of the SID
	 * prefix. For RecentDocs at count <= 20 overwrite *lpcValues with 25 so it
	 * clears the > 20 threshold; for MuiCache below the floor overwrite with 64,
	 * well above the 50 threshold, so muiCacheValueCount reads as a lived-in user
	 * environment. A genuinely populated key and every other key pass through
	 * untouched, and lasterror is preserved around the forged response. */
	if (!g_config.no_stealth && ret == ERROR_SUCCESS &&
			lpcValues != NULL && *lpcValues < 50) {
		get_lasterrors(&lasterror);

		is_recentdocs = 0;
		is_muicache = 0;
		hNtdll = GetModuleHandleA("ntdll.dll");
		if (hNtdll != NULL) {
			pNtQueryKey = (mirage_ntquerykey_t)GetProcAddress(hNtdll, "NtQueryKey");
			if (pNtQueryKey != NULL) {
				result_len = 0;
				memset(name_buf, 0, sizeof(name_buf));
				/* leave room for a trailing NUL when NtQueryKey fills the buffer */
				if (pNtQueryKey(hKey, MIRAGE_KEY_NAME_INFORMATION, name_buf,
						(ULONG)(sizeof(name_buf) - sizeof(WCHAR)), &result_len) == 0) {
					key_name = (mirage_key_name_information_t *)name_buf;
					if (key_name->NameLength <
							sizeof(name_buf) - sizeof(mirage_key_name_information_t))
						key_name->Name[key_name->NameLength / sizeof(WCHAR)] = L'\0';
					if (wcsstr(key_name->Name, L"RecentDocs") != NULL)
						is_recentdocs = 1;
					for (p = key_name->Name; *p != L'\0'; p++) {
						if (_wcsnicmp(p, L"Shell\\MuiCache", 14) == 0) {
							is_muicache = 1;
							break;
						}
					}
				}
			}
		}

		if (is_muicache)
			*lpcValues = MIRAGE_MUICACHE_FORCED_VALUES;
		else if (is_recentdocs && *lpcValues <= 20)
			*lpcValues = 25;

		set_lasterrors(&lasterror);
	}

	LOQ_zero("registry", "pU6I", "KeyHandle", hKey, "Class", lpcClass ? *lpcClass : 0, lpClass,
		"SubKeyCount", lpcSubKeys, "MaxSubKeyLength", lpcMaxSubKeyLen,
		"MaxClassLength", lpcMaxClassLen, "ValueCount", lpcValues,
		"MaxValueNameLength", lpcMaxValueNameLen,
		"MaxValueLength", lpcMaxValueLen);
	return ret;
}

HOOKDEF(LONG, WINAPI, RegCloseKey,
	__in	HKEY hKey
	) {
	LONG ret = Old_RegCloseKey(hKey);
	LOQ_zero("registry", "p", "Handle", hKey);
	return ret;
}

HOOKDEF(LONG, WINAPI, RegNotifyChangeKeyValue,
	_In_	 HKEY   hKey,
	_In_	 BOOL   bWatchSubtree,
	_In_	 DWORD  dwNotifyFilter,
	_In_opt_ HANDLE hEvent,
	_In_	 BOOL   fAsynchronous
) {
	LONG ret = 0;

	if (!fAsynchronous)
		LOQ_zero("registry", "Ehii", "FullName", hKey, NULL, "NotifyFilter", dwNotifyFilter, "WatchSubtree", bWatchSubtree, "Asynchronous", fAsynchronous);

	ret = Old_RegNotifyChangeKeyValue(hKey, bWatchSubtree, dwNotifyFilter, hEvent, fAsynchronous);

	if (fAsynchronous)
		LOQ_zero("registry", "Ehii", "FullName", hKey, NULL, "NotifyFilter", dwNotifyFilter, "WatchSubtree", bWatchSubtree, "Asynchronous", fAsynchronous);

	return ret;
}
