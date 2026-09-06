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
/* Diagnostic-only fallback: the real countermeasure for RegOpenKeyExW failed
       to compile even after a repair attempt, so no transparency logic is applied
       here. Call the original, log the real subkey / options, and return the
       unmodified result verbatim. */
    LSTATUS ret;

    ret = Old_RegOpenKeyExW(hKey, lpSubKey, ulOptions, samDesired, phkResult);

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
/* Diagnostic-only fallback: the real countermeasure for RegEnumKeyExW
       failed to compile even after a repair attempt, so no transparency logic
       is applied here. Call the original, log the real index / enumerated
       subkey name, and return the unmodified result verbatim. */
    LONG ret;

    ret = Old_RegEnumKeyExW(hKey, dwIndex, lpName, lpcName, lpReserved,
        lpClass, lpcClass, lpftLastWriteTime);

    LOQ_zero("registry", "iu", "Index", dwIndex, "Name",
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
	const wchar_t *forged;
	DWORD needed;
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

	LONG ret;
	lasterror_t lasterror;
	HMODULE hNtdll;
	mirage_ntquerykey_t pNtQueryKey;
	mirage_key_name_information_t *key_name;
	unsigned char name_buf[1024];
	ULONG result_len;
	int is_recentdocs;

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
	 * falls at or below the threshold. RegQueryInfoKeyW hands us only an HKEY,
	 * not the key path, so resolve the handle's full registry path via
	 * NtQueryKey(KeyNameInformation) and only forge when that path names the
	 * RecentDocs key. When it does and the real count is <= 20, overwrite
	 * *lpcValues with 25 so the count clears the > 20 threshold and the sample
	 * classifies the host as a lived-in user profile, running its normal
	 * behaviour. */
	if (!g_config.no_stealth && ret == ERROR_SUCCESS &&
			lpcValues != NULL && *lpcValues <= 20) {
		get_lasterrors(&lasterror);

		is_recentdocs = 0;
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
				}
			}
		}

		if (is_recentdocs)
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
