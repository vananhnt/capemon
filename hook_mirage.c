/*
 * hook_mirage.c — SAGE-generated hook implementations.
 * Auto-regenerated; do not edit by hand.
 */
#include <stdio.h>
#include "hooking.h"
#include <tlhelp32.h>
#include <slpublic.h>
#include "log.h"
#include "config.h"

static BOOL MirageStrContainsI(LPCSTR haystack, const char *needle)
{
	size_t needle_len;
	const char *p;

	if (!haystack || !needle)
		return FALSE;

	needle_len = strlen(needle);

	for (p = haystack; *p; p++) {
		if (!_strnicmp(p, needle, needle_len))
			return TRUE;
	}

	return FALSE;
}

/* Well-known install directories for the compression tools
 * (7-Zip/WinRAR/WinZip) that samples probe for under both Program Files and
 * Program Files (x86); a plain substring match covers either root. */
static BOOL MirageIsCompressionToolPath(LPCSTR pszPath)
{
	static const char *needles[] = {
		"\\7-Zip\\",
		"\\WinRAR\\",
		"\\WinZip\\",
	};
	size_t i;

	if (!pszPath)
		return FALSE;

	for (i = 0; i < sizeof(needles) / sizeof(needles[0]); i++) {
		if (MirageStrContainsI(pszPath, needles[i]))
			return TRUE;
	}

	return FALSE;
}

/* Virtual/software printer names that don't count as evidence of a real,
 * physical printer for the "physicalPrinters" evasion check. */
static BOOL MirageIsExcludedPrinterName(LPCSTR pName)
{
	static const char *excluded[] = {
		"Microsoft Print to PDF",
		"Microsoft XPS Document Writer",
		"Fax",
		"OneNote",
	};
	size_t i;

	if (!pName)
		return TRUE;

	for (i = 0; i < sizeof(excluded) / sizeof(excluded[0]); i++) {
		if (MirageStrContainsI(pName, excluded[i]))
			return TRUE;
	}

	return FALSE;
}

        HOOKDEF(BOOL, WINAPI, PathFileExistsA, LPCSTR pszPath)
        {
            BOOL ret;
	lasterror_t lasterror;

	ret = Old_PathFileExistsA(pszPath);

	/* Samples inventory installed compression tools (7-Zip/WinRAR/WinZip) by
	 * checking for their well-known install directories under both
	 * Program Files and Program Files (x86); treat any such VM lacking one
	 * of these as a sandbox tell and force the check to observe the tool as
	 * present regardless of the VM's actual install state. */
	if (!g_config.no_stealth && !ret && MirageIsCompressionToolPath(pszPath)) {
		get_lasterrors(&lasterror);
		ret = TRUE;
		set_lasterrors(&lasterror);
	}

	return ret;
        }

        HOOKDEF(void, WINAPI, GetNativeSystemInfo, LPSYSTEM_INFO lpSystemInfo)
        {
            lasterror_t lasterror;

	Old_GetNativeSystemInfo(lpSystemInfo);

	if (!g_config.no_stealth) {
		if (lpSystemInfo && lpSystemInfo->dwNumberOfProcessors <= 1) {
			get_lasterrors(&lasterror);
			lpSystemInfo->dwNumberOfProcessors = 4;
			lpSystemInfo->dwActiveProcessorMask = 0xf;
			set_lasterrors(&lasterror);
		}
	}

	return;
        }

        HOOKDEF(BOOL, WINAPI, IsProcessorFeaturePresent, DWORD ProcessorFeature)
        {
            BOOL ret;
	lasterror_t lasterror;

	ret = Old_IsProcessorFeaturePresent(ProcessorFeature);

	if (!g_config.no_stealth) {
		if (ProcessorFeature == PF_VIRT_FIRMWARE_ENABLED && ret != FALSE) {
			get_lasterrors(&lasterror);
			ret = FALSE;
			set_lasterrors(&lasterror);
		}
	}

	return ret;
        }

        HOOKDEF(BOOL, WINAPI, EnumPrintersA, DWORD Flags, LPSTR Name, DWORD Level, LPBYTE pPrinterEnum, DWORD cbBuf, LPDWORD pcbNeeded, LPDWORD pcReturned)
        {
            BOOL ret;
	lasterror_t lasterror;
	PRINTER_INFO_1A *entries;
	DWORD i;
	BOOLEAN has_physical;
	DWORD struct_size;
	DWORD fake_name_len;
	DWORD fake_strings_size;
	DWORD extra_needed;
	DWORD free_space;
	char *string_region_start;
	DWORD string_region_len;
	char *new_struct_slot;
	char *new_strings_slot;

	ret = Old_EnumPrintersA(Flags, Name, Level, pPrinterEnum, cbBuf, pcbNeeded, pcReturned);

	/* Only PRINTER_INFO_1A (Level 1) enumerations of local/connected printers
	 * are what the "physicalPrinters" evasion check walks; leave every other
	 * level/flags combination untouched. */
	if (!g_config.no_stealth && ret && Level == 1 && pPrinterEnum && pcReturned && pcbNeeded &&
			(Flags & (PRINTER_ENUM_LOCAL | PRINTER_ENUM_CONNECTIONS))) {
		entries = (PRINTER_INFO_1A *)pPrinterEnum;
		has_physical = FALSE;

		for (i = 0; i < *pcReturned; i++) {
			if (!MirageIsExcludedPrinterName(entries[i].pName)) {
				has_physical = TRUE;
				break;
			}
		}

		if (!has_physical) {
			struct_size = sizeof(PRINTER_INFO_1A);
			fake_name_len = (DWORD)strlen("HP LaserJet 1020") + 1;
			fake_strings_size = fake_name_len * 3; /* pDescription, pName, pComment */
			extra_needed = struct_size + fake_strings_size;
			free_space = (cbBuf > *pcbNeeded) ? (cbBuf - *pcbNeeded) : 0;

			/* Only inject when the caller's buffer already has enough spare
			 * room; if there isn't, leave the real (all-virtual) result alone
			 * rather than risk writing past cbBuf. */
			if (free_space >= extra_needed) {
				string_region_start = (char *)pPrinterEnum + (*pcReturned) * struct_size;
				string_region_len = *pcbNeeded - (*pcReturned) * struct_size;

				get_lasterrors(&lasterror);

				/* The struct array and its string pool are laid out
				 * contiguously by the real API: array first, then the
				 * variable-length strings each entry points into. To append
				 * one more struct slot at the end of the array, shift the
				 * whole string pool right by one struct's width and repoint
				 * the existing entries' string pointers to follow it. */
				memmove(string_region_start + struct_size, string_region_start, string_region_len);

				for (i = 0; i < *pcReturned; i++) {
					if (entries[i].pDescription)
						entries[i].pDescription += struct_size;
					if (entries[i].pName)
						entries[i].pName += struct_size;
					if (entries[i].pComment)
						entries[i].pComment += struct_size;
				}

				new_struct_slot = string_region_start;
				new_strings_slot = string_region_start + struct_size + string_region_len;

				memcpy(new_strings_slot, "HP LaserJet 1020", fake_name_len);
				memcpy(new_strings_slot + fake_name_len, "HP LaserJet 1020", fake_name_len);
				memcpy(new_strings_slot + fake_name_len * 2, "HP LaserJet 1020", fake_name_len);

				((PRINTER_INFO_1A *)new_struct_slot)->Flags = 0;
				((PRINTER_INFO_1A *)new_struct_slot)->pDescription = new_strings_slot;
				((PRINTER_INFO_1A *)new_struct_slot)->pName = new_strings_slot + fake_name_len;
				((PRINTER_INFO_1A *)new_struct_slot)->pComment = new_strings_slot + fake_name_len * 2;

				*pcReturned += 1;
				*pcbNeeded += extra_needed;

				set_lasterrors(&lasterror);
			}
		}
	}

	return ret;
        }

        HOOKDEF(HANDLE, WINAPI, FindFirstFileA, LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData)
        {
            HANDLE ret;
lasterror_t lasterror;
char dir_path[MAX_PATH];
char temp_path[MAX_PATH];
HANDLE dir_handle;
FILETIME now;
const char *suffix;
const char *p;
size_t suffix_len;
BOOL matched;
const char *last_sep;
size_t dir_len;

ret = Old_FindFirstFileA(lpFileName, lpFindFileData);

/* nonDefaultApps.size(), derived by walking
 * Quick Launch\User Pinned\TaskBar\*.lnk, is expected to be non-empty on a
 * real user's machine. This is a defense-in-depth fallback for when the
 * pre-created .lnk files (channel_6) don't survive a VM snapshot reset:
 * if this very first enumeration call already comes up empty (directory
 * missing entirely, or present but containing no matching files), hand
 * back one synthesized third-party shortcut instead of letting the
 * sample see an empty enumeration from the start. */
if (!g_config.no_stealth && ret == INVALID_HANDLE_VALUE && lpFileName) {
	suffix = "\\Quick Launch\\User Pinned\\TaskBar";
	suffix_len = strlen(suffix);
	matched = FALSE;

	for (p = lpFileName; *p; p++) {
		if (!_strnicmp(p, suffix, suffix_len)) {
			matched = TRUE;
			break;
		}
	}

	if (matched) {
		dir_path[0] = '\0';

		last_sep = strrchr(lpFileName, '\\');
		if (last_sep) {
			dir_len = (size_t)(last_sep - lpFileName) + 1;
			if (dir_len >= sizeof(dir_path))
				dir_len = sizeof(dir_path) - 1;
			memcpy(dir_path, lpFileName, dir_len);
			dir_path[dir_len] = '\0';
		}

		dir_handle = INVALID_HANDLE_VALUE;

		if (dir_path[0] != '\0')
			dir_handle = CreateFileA(dir_path, FILE_LIST_DIRECTORY,
				FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
				OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);

		if (dir_handle == INVALID_HANDLE_VALUE) {
			/* The Quick Launch directory itself doesn't exist on this VM --
			 * fall back to any real, always-present directory purely so the
			 * handle we hand back is genuine and safe for the sample to pass
			 * to FindNextFileA/FindClose afterwards. */
			if (GetTempPathA(sizeof(temp_path), temp_path))
				dir_handle = CreateFileA(temp_path, FILE_LIST_DIRECTORY,
					FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
					OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
		}

		if (dir_handle != INVALID_HANDLE_VALUE && lpFindFileData) {
			get_lasterrors(&lasterror);

			GetSystemTimeAsFileTime(&now);

			memset(lpFindFileData, 0, sizeof(*lpFindFileData));
			lpFindFileData->dwFileAttributes = FILE_ATTRIBUTE_ARCHIVE;
			lpFindFileData->ftCreationTime = now;
			lpFindFileData->ftLastAccessTime = now;
			lpFindFileData->ftLastWriteTime = now;
			memcpy(lpFindFileData->cFileName, "Google Chrome.lnk", sizeof("Google Chrome.lnk"));

			ret = dir_handle;
			lasterror.Win32Error = ERROR_SUCCESS;

			set_lasterrors(&lasterror);
		}
	}
}

return ret;
        }

        HOOKDEF(BOOL, WINAPI, FindNextFileA, HANDLE hFindFile, LPWIN32_FIND_DATAA lpFindFileData)
        {
            BOOL ret;
	lasterror_t lasterror;
	FILETIME now;
	static struct {
		HANDLE handle;
		unsigned int nondefault_seen;
	} mirage_fnf_table[32];
	int i, slot;

	ret = Old_FindNextFileA(hFindFile, lpFindFileData);

	/* Only step in once the real enumeration on this handle has run out
	 * (ret == FALSE, i.e. ERROR_NO_MORE_FILES). Track per-handle progress
	 * locally: the first call for a given handle assumes the FindFirstFileA
	 * hook already surfaced one non-default entry (Google Chrome.lnk), so
	 * it starts the count at 1 and tops it up to 2 with one more
	 * synthesized non-default shortcut before letting the enumeration end
	 * naturally (ret stays FALSE) on every call after that. */
	if (!g_config.no_stealth && !ret && lpFindFileData) {
		slot = -1;

		for (i = 0; i < 32; i++) {
			if (mirage_fnf_table[i].handle == hFindFile) {
				slot = i;
				break;
			}
			if (slot < 0 && mirage_fnf_table[i].handle == NULL)
				slot = i;
		}

		if (slot >= 0 && mirage_fnf_table[slot].handle == NULL) {
			mirage_fnf_table[slot].handle = hFindFile;
			mirage_fnf_table[slot].nondefault_seen = 1;
		}

		if (slot >= 0 && mirage_fnf_table[slot].nondefault_seen < 2) {
			get_lasterrors(&lasterror);

			GetSystemTimeAsFileTime(&now);

			memset(lpFindFileData, 0, sizeof(*lpFindFileData));
			lpFindFileData->dwFileAttributes = FILE_ATTRIBUTE_ARCHIVE;
			lpFindFileData->ftCreationTime = now;
			lpFindFileData->ftLastAccessTime = now;
			lpFindFileData->ftLastWriteTime = now;
			memcpy(lpFindFileData->cFileName, "Mozilla Firefox.lnk", sizeof("Mozilla Firefox.lnk"));

			mirage_fnf_table[slot].nondefault_seen++;

			ret = TRUE;
			lasterror.Win32Error = ERROR_SUCCESS;

			set_lasterrors(&lasterror);
		}
	}

	return ret;
        }

        HOOKDEF(HRESULT, WINAPI, SLIsGenuineLocal, const SLID* pAppId, SL_GENUINE_STATE* pGenuineState, PVOID pvReserved)
        {
            HRESULT ret;
	lasterror_t lasterror;

	ret = Old_SLIsGenuineLocal(pAppId, pGenuineState, pvReserved);

	/* hResult != S_OK or GenuineState != SL_GEN_STATE_IS_GENUINE are both
	 * evasive tells here (a non-S_OK return also aborts gatherInfo before the
	 * GenuineState comparison is even reached), so force both unconditionally
	 * rather than only patching up whichever one tripped. */
	if (!g_config.no_stealth) {
		get_lasterrors(&lasterror);
		if (pGenuineState)
			*pGenuineState = SL_GEN_STATE_IS_GENUINE;
		ret = S_OK;
		set_lasterrors(&lasterror);
	}

	return ret;
        }