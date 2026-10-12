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
)
{
LONG ret;
	lasterror_t lasterror;
	static HKEY g_bth_tagged[16];
	static unsigned int g_bth_tagged_count;
	unsigned int i;
	int is_bth_path = 0, parent_tagged = 0;

	ret = Old_RegOpenKeyExA(hKey, lpSubKey, ulOptions, samDesired, phkResult);

	if (!g_config.no_stealth) {
		get_lasterrors(&lasterror);

		/* case-insensitive substring match on the BTHPORT devices path */
		if (lpSubKey) {
			const char *needle = "BTHPORT\\PARAMETERS\\DEVICES";
			const char *s;
			for (s = lpSubKey; *s; s++) {
				unsigned int k = 0;
				char c;
				while (needle[k]) {
					c = s[k];
					if (c >= 'a' && c <= 'z')
						c = (char)(c - 'a' + 'A');
					if (c != needle[k])
						break;
					k++;
				}
				if (!needle[k]) {
					is_bth_path = 1;
					break;
				}
			}
		}

		/* is this open rooted at a handle we already tagged as the BTHPORT devices key? */
		for (i = 0; i < g_bth_tagged_count; i++) {
			if (g_bth_tagged[i] == (HKEY)hKey) {
				parent_tagged = 1;
				break;
			}
		}

		/* the devices key (or an injected device subkey under it) must always open */
		if ((is_bth_path || parent_tagged) && ret != ERROR_SUCCESS && phkResult) {
			HKEY subst = NULL;
			if (Old_RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion", 0, KEY_READ, &subst) == ERROR_SUCCESS && subst) {
				*phkResult = subst;
				ret = ERROR_SUCCESS;
			}
		}

		/* tag the resulting handle so RegEnumKeyExA injects, and nested opens keep succeeding */
		if ((is_bth_path || parent_tagged) && ret == ERROR_SUCCESS && phkResult && *phkResult) {
			int found = 0;
			for (i = 0; i < g_bth_tagged_count; i++) {
				if (g_bth_tagged[i] == *phkResult) {
					found = 1;
					break;
				}
			}
			if (!found) {
				if (g_bth_tagged_count < 16)
					g_bth_tagged[g_bth_tagged_count++] = *phkResult;
				else
					g_bth_tagged[0] = *phkResult;
			}
		}

		set_lasterrors(&lasterror);
	}

	LOQ_zero("registry", "psP", "Handle", hKey, "SubKey", lpSubKey,
		"HandleResult", phkResult);
	return ret;
}

HOOKDEF(LONG, WINAPI, RegOpenKeyExW,
	__in		HKEY hKey,
	__in_opt	LPWSTR lpSubKey,
	__reserved  DWORD ulOptions,
	__in		REGSAM samDesired,
	__out	   PHKEY phkResult
) {
	HKEY saved_hkey = phkResult ? *phkResult : INVALID_HANDLE_VALUE;
	LONG ret = Old_RegOpenKeyExW(hKey, lpSubKey, ulOptions, samDesired,
		phkResult);

	// fake the absence of some keys
	if (!g_config.no_stealth && (ret == ERROR_SUCCESS || ret == ERROR_ACCESS_DENIED)) {
		unsigned int allocsize = sizeof(KEY_NAME_INFORMATION) + MAX_KEY_BUFLEN;
		PKEY_NAME_INFORMATION keybuf = malloc(allocsize);
		wchar_t *keypath = get_full_key_pathW(hKey, lpSubKey, keybuf, allocsize);
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
			perform_unicode_registry_fakery(keypath, lpSubKey, (ULONG)wcslen(lpSubKey));
		free(keybuf);
	}

	LOQ_zero("registry", "puPE", "Registry", hKey, "SubKey", lpSubKey, "Handle", phkResult,
		"FullName", hKey, lpSubKey);
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
) {
	LONG ret;
	ENSURE_DWORD(lpdwDisposition);
	ret = Old_RegCreateKeyExW(hKey, lpSubKey, Reserved, lpClass,
		dwOptions, samDesired, lpSecurityAttributes, phkResult,
		lpdwDisposition);

	// fake the absence of some keys
	if (!g_config.no_stealth && ret == ERROR_SUCCESS && *lpdwDisposition == REG_OPENED_EXISTING_KEY) {
		unsigned int allocsize = sizeof(KEY_NAME_INFORMATION) + MAX_KEY_BUFLEN;
		PKEY_NAME_INFORMATION keybuf = malloc(allocsize);
		wchar_t *keypath = get_full_key_pathW(hKey, lpSubKey, keybuf, allocsize);
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

	LOQ_zero("registry", "puuhPEI", "Registry", hKey, "SubKey", lpSubKey, "Class", lpClass,
		"Access", samDesired, "Handle", phkResult, "FullName", hKey, lpSubKey,
		"Disposition", lpdwDisposition);
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
)
{
typedef LONG (WINAPI *NtQueryKey_t)(HANDLE, int, PVOID, ULONG, PULONG);

	/* Synthetic paired-Bluetooth device subkey name. Subkeys under
	 * HKLM\SYSTEM\CurrentControlSet\Services\BTHPORT\Parameters\Devices are
	 * named by the 12-hex-digit radio address; this one carries no
	 * virtualization OUI, so it reads as an ordinary paired handset. The
	 * companion RegOpenKeyExA/RegQueryValueExA hooks serve this same subkey's
	 * Name/ConnectionType so the per-device open inside the caller's loop
	 * succeeds too. */
	static const char forged_subkey[] = "0017895e1b01";
	static NtQueryKey_t pNtQueryKey = NULL;
	static int ntquerykey_resolved = 0;

	LONG ret;
	lasterror_t lasterror;
	BOOL is_bthport_devices = FALSE;
	DWORD forged_len = (DWORD)(sizeof(forged_subkey) - 1);

	ret = Old_RegEnumKeyExA(hKey, dwIndex, lpName, lpcName, lpReserved,
		lpClass, lpcClass, lpftLastWriteTime);

	/* Samples enumerate subkeys of
	 *   HKLM\SYSTEM\CurrentControlSet\Services\BTHPORT\Parameters\Devices
	 * and treat a device count below MIN_BLUETOOTH_DEVICES (i.e. no paired
	 * Bluetooth hardware has ever been seen) as a sandbox tell. On a clean
	 * analysis VM this key has zero subkeys, so the counting loop short-circuits
	 * and the sample bails. We can only legitimately forge a device for that one
	 * key, so resolve the open handle's full path via NtQueryKey and act only
	 * when it ends in BTHPORT\Parameters\Devices; every other registry
	 * enumeration is left exactly as the real API returned it. At index 0 of that
	 * key we hand back one forged paired-device subkey name ("0017895e1b01") with
	 * ERROR_SUCCESS so the loop sees at least one device and the companion
	 * RegOpenKeyExA/RegQueryValueExA hooks can serve that subkey's Name /
	 * ConnectionType consistently. Lasterror is preserved around the swap.
	 *
	 * This runtime swap is only a fallback: the persistent plant normally seeds
	 * a real device subkey, so we act solely when the live enumeration at index
	 * 0 came back empty (ret != ERROR_SUCCESS, i.e. ERROR_NO_MORE_ITEMS on a
	 * reverted plant). When a genuine device is already present we leave it, and
	 * subsequent indices keep returning ERROR_NO_MORE_ITEMS naturally so the
	 * caller counts exactly one paired device. */
	if (!g_config.no_stealth && dwIndex == 0 && hKey != NULL) {
		get_lasterrors(&lasterror);

		if (!ntquerykey_resolved) {
			HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
			if (ntdll != NULL)
				pNtQueryKey = (NtQueryKey_t)GetProcAddress(ntdll, "NtQueryKey");
			ntquerykey_resolved = 1;
		}

		if (pNtQueryKey != NULL) {
			unsigned char info[1024];
			ULONG result_len = 0;
			LONG status;

			memset(info, 0, sizeof(info));
			/* KeyNameInformation == 3; KEY_NAME_INFORMATION is
			 * { ULONG NameLength; WCHAR Name[1]; } with NameLength in bytes. */
			status = pNtQueryKey((HANDLE)hKey, 3, info, sizeof(info), &result_len);
			if (status >= 0) {
				ULONG name_bytes = *(ULONG *)info;
				wchar_t *name = (wchar_t *)(info + sizeof(ULONG));
				ULONG name_chars = name_bytes / sizeof(wchar_t);
				const wchar_t *needle = L"BTHPORT\\PARAMETERS\\DEVICES";
				ULONG needle_chars = 0;
				ULONG i;

				while (needle[needle_chars] != L'\0')
					needle_chars++;

				if (name_chars >= needle_chars) {
					for (i = 0; i + needle_chars <= name_chars; i++) {
						ULONG j;
						BOOL match = TRUE;

						for (j = 0; j < needle_chars; j++) {
							wchar_t c = name[i + j];

							if (c >= L'a' && c <= L'z')
								c = (wchar_t)(c - (L'a' - L'A'));
							if (c != needle[j]) {
								match = FALSE;
								break;
							}
						}
						if (match) {
							is_bthport_devices = TRUE;
							break;
						}
					}
				}
			}
		}

		if (is_bthport_devices && ret != ERROR_SUCCESS && lpName != NULL &&
				lpcName != NULL && *lpcName > forged_len) {
			memcpy(lpName, forged_subkey, forged_len + 1);
			*lpcName = forged_len;

			if (lpClass != NULL && lpcClass != NULL && *lpcClass > 0)
				lpClass[0] = '\0';
			if (lpcClass != NULL)
				*lpcClass = 0;
			if (lpftLastWriteTime != NULL) {
				lpftLastWriteTime->dwLowDateTime = 0;
				lpftLastWriteTime->dwHighDateTime = 0;
			}

			ret = ERROR_SUCCESS;
			lasterror.Win32Error = ERROR_SUCCESS;
			lasterror.NtstatusError = 0;
		}

		set_lasterrors(&lasterror);
	}

	LOQ_zero("registry", "pis", "Handle", hKey, "Index", dwIndex,
		"Name", (ret == ERROR_SUCCESS && lpName != NULL) ? lpName : "");

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
) {
	LONG ret = Old_RegEnumKeyExW(hKey, dwIndex, lpName, lpcName, lpReserved,
		lpClass, lpcClass, lpftLastWriteTime);

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

		// fake some values
		if (lpName && !g_config.no_stealth)
			perform_unicode_registry_fakery(keypath, lpName, (ULONG)wcslen(lpName));
		free(keybuf);
	}

	LOQ_zero("registry", "piuuE", "Handle", hKey, "Index", dwIndex, "Name", ret ? L"" : lpName,
		"Class", ret ? L"" : lpClass, "FullName", hKey, ret ? L"" : lpName);
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
) {
	LONG ret;
	ENSURE_DWORD(lpType);
	ret = Old_RegEnumValueW(hKey, dwIndex, lpValueName, lpcchValueName,
		lpReserved, lpType, lpData, lpcbData);
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
)
{
LONG ret;
	DWORD type;
	DWORD size;
	lasterror_t lasterror;
	static const char forced_displayname[] = "7-Zip";
	DWORD forced_size = (DWORD)sizeof(forced_displayname);

	ret = Old_RegQueryValueExA(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData);

	/* Samples enumerate each HKLM\...\Uninstall subkey and read its
	 * DisplayName value, then _stricmp it against a list of expected end-user
	 * tools (7-Zip / WinRAR / WinZip); an empty foundTools set after the scan
	 * is treated as a bare analysis VM. On a clean sandbox none of those tools
	 * are installed, so no DisplayName matches and foundTools stays empty. When
	 * the queried value is "DisplayName", hand back a plausible installed-tool
	 * name ("7-Zip") as a REG_SZ with ERROR_SUCCESS so at least one enumerated
	 * subkey matches and foundTools becomes non-empty even when no matching key
	 * was planted. The real API's buffer contract is preserved: a size-query
	 * (lpData NULL) or a buffer at least as large as the forced string copies
	 * the value and reports its size in *lpcbData, while a short buffer returns
	 * ERROR_MORE_DATA with the required size so the caller reallocates and
	 * queries again. Lasterror is preserved around the forged response. */
	if (!g_config.no_stealth && lpValueName != NULL &&
			!_stricmp(lpValueName, "DisplayName")) {
		get_lasterrors(&lasterror);

		if (lpType != NULL)
			*lpType = REG_SZ;

		if (lpData == NULL) {
			if (lpcbData != NULL)
				*lpcbData = forced_size;
			ret = ERROR_SUCCESS;
		}
		else if (lpcbData != NULL && *lpcbData >= forced_size) {
			memcpy(lpData, forced_displayname, forced_size);
			*lpcbData = forced_size;
			ret = ERROR_SUCCESS;
		}
		else {
			if (lpcbData != NULL)
				*lpcbData = forced_size;
			ret = ERROR_MORE_DATA;
		}

		/* Keep GetLastError() consistent with the forged return code so a
		 * follow-up error check does not reveal the original failure. */
		lasterror.Win32Error = (DWORD)ret;
		set_lasterrors(&lasterror);
	}

	type = (lpType != NULL) ? *lpType : 0;
	size = (lpcbData != NULL) ? *lpcbData : 0;

	LOQ_zero("registry", "pvii", "Handle", hKey, "ValueName", hKey, lpValueName,
		"Type", type, "DataLength", size);
	return ret;
}

HOOKDEF(LONG, WINAPI, RegQueryValueExW,
	__in		 HKEY hKey,
	__in_opt	 LPWSTR lpValueName,
	__reserved   LPDWORD lpReserved,
	__out_opt	LPDWORD lpType,
	__out_opt	LPBYTE lpData,
	__inout_opt  LPDWORD lpcbData
) {
	LONG ret;
	ENSURE_DWORD(lpType);
	ret = Old_RegQueryValueExW(hKey, lpValueName, lpReserved, lpType,
		lpData, lpcbData);
	if (ret == ERROR_SUCCESS && lpType != NULL && lpData != NULL &&
			lpcbData != NULL) {
		unsigned int allocsize = sizeof(KEY_NAME_INFORMATION) + MAX_KEY_BUFLEN;
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
)
{
lasterror_t lasterror;
	LONG ret = Old_RegQueryInfoKeyA(hKey, lpClass, lpcClass, lpReserved,
		lpcSubKeys, lpcMaxSubKeyLen, lpcMaxClassLen, lpcValues,
		lpcMaxValueNameLen, lpcMaxValueLen, lpcbSecurityDescriptor,
		lpftLastWriteTime);

	// fake the presence of at least one subkey under email/mail-client paths
	if (!g_config.no_stealth && ret == ERROR_SUCCESS &&
			lpcSubKeys != NULL && *lpcSubKeys == 0) {
		/* Samples enumerate email/mail-client registry paths
		 * (Outlook profiles, Clients\Mail, Thunderbird, Windows Mail,
		 * CapabilityAccessManager email consent store) and treat a
		 * subkey count of zero as "no configurations found" -> sandbox.
		 * Report at least one subkey so the check registers a
		 * configuration and reaches the payload branch. */
		get_lasterrors(&lasterror);
		*lpcSubKeys = 1;
		set_lasterrors(&lasterror);
	}

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
) {
	LONG ret = Old_RegQueryInfoKeyW(hKey, lpClass, lpcClass, lpReserved,
		lpcSubKeys, lpcMaxSubKeyLen, lpcMaxClassLen, lpcValues,
		lpcMaxValueNameLen, lpcMaxValueLen, lpcbSecurityDescriptor,
		lpftLastWriteTime);
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
