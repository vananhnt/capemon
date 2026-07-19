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
        HOOKDEF(BOOL, WINAPI, PathFileExistsA, LPCSTR pszPath)
        {
            BOOL ret;
	lasterror_t lasterror;

	ret = Old_PathFileExistsA(pszPath);

	if (!g_config.no_stealth && pszPath != NULL &&
			(strstr(pszPath, "7-Zip") != NULL ||
			 strstr(pszPath, "WinRAR") != NULL ||
			 strstr(pszPath, "WinZip") != NULL)) {
		get_lasterrors(&lasterror);

		ret = TRUE;

		set_lasterrors(&lasterror);
	}

	return ret;
        }

        HOOKDEF(VOID, WINAPI, GetNativeSystemInfo, LPSYSTEM_INFO lpSystemInfo)
        {
            lasterror_t lasterror;

	Old_GetNativeSystemInfo(lpSystemInfo);

	if (!g_config.no_stealth && lpSystemInfo != NULL &&
			lpSystemInfo->dwNumberOfProcessors <= 1) {
		get_lasterrors(&lasterror);

		lpSystemInfo->dwNumberOfProcessors = 4;

		set_lasterrors(&lasterror);
	}

	return;
        }

        HOOKDEF(BOOL, WINAPI, EnumPrintersA, DWORD Flags, LPSTR Name, DWORD Level, LPBYTE pPrinterEnum, DWORD cbBuf, LPDWORD pcbNeeded, LPDWORD pcReturned)
        {
            typedef struct {
		DWORD Flags;
		LPSTR pDescription;
		LPSTR pName;
		LPSTR pComment;
	} mirage_printer_info_1a_t;

	BOOL ret;
	lasterror_t lasterror;
	static const char fake_name[] = "HP LaserJet 1020";
	DWORD entry_size;
	DWORD array_bytes;
	DWORD string_bytes;
	DWORD new_total;
	mirage_printer_info_1a_t *info;
	unsigned int i;

	ret = Old_EnumPrintersA(Flags, Name, Level, pPrinterEnum, cbBuf, pcbNeeded, pcReturned);

	if (!g_config.no_stealth && Level == 1 && pcbNeeded != NULL && pcReturned != NULL) {
		entry_size = sizeof(mirage_printer_info_1a_t) + sizeof(fake_name);
		get_lasterrors(&lasterror);

		if (!ret && lasterror.Win32Error == ERROR_INSUFFICIENT_BUFFER) {
			/* make room for a synthetic physical-printer entry on the caller's follow-up call */
			*pcbNeeded += entry_size;
		} else if (ret && pPrinterEnum != NULL) {
			info = (mirage_printer_info_1a_t *)pPrinterEnum;
			array_bytes = sizeof(mirage_printer_info_1a_t) * (*pcReturned);
			string_bytes = *pcbNeeded - array_bytes;
			new_total = *pcbNeeded + entry_size;

			if (cbBuf >= new_total) {
				/* shift the existing string data forward to open a new struct slot
				   right after the current array, and re-base the entries' pointers */
				memmove(pPrinterEnum + array_bytes + sizeof(mirage_printer_info_1a_t),
					pPrinterEnum + array_bytes, string_bytes);

				for (i = 0; i < *pcReturned; i++) {
					if (info[i].pDescription)
						info[i].pDescription += sizeof(mirage_printer_info_1a_t);
					if (info[i].pName)
						info[i].pName += sizeof(mirage_printer_info_1a_t);
					if (info[i].pComment)
						info[i].pComment += sizeof(mirage_printer_info_1a_t);
				}

				memcpy(pPrinterEnum + new_total - sizeof(fake_name), fake_name, sizeof(fake_name));

				info[*pcReturned].Flags = 0;
				info[*pcReturned].pDescription = (LPSTR)(pPrinterEnum + new_total - sizeof(fake_name));
				info[*pcReturned].pName = (LPSTR)(pPrinterEnum + new_total - sizeof(fake_name));
				info[*pcReturned].pComment = (LPSTR)(pPrinterEnum + new_total - sizeof(fake_name));

				*pcReturned += 1;
				*pcbNeeded = new_total;
			} else {
				/* not enough slack in this buffer; ask for more room next time */
				*pcbNeeded = new_total;
			}
		}

		set_lasterrors(&lasterror);
	}

	return ret;
        }

        HOOKDEF(BOOL, WINAPI, FindNextFileA, HANDLE hFindFile, LPWIN32_FIND_DATAA lpFindFileData)
        {
            static const char *g_mirage_taskbar_fake_names[] = {
		"Mozilla Firefox.lnk",
		"Adobe Acrobat Reader DC.lnk",
	};
	static unsigned int fake_enum_count;
	BOOL ret;
	lasterror_t lasterror;
	unsigned int fake_total;

	ret = Old_FindNextFileA(hFindFile, lpFindFileData);

	fake_total = sizeof(g_mirage_taskbar_fake_names) / sizeof(g_mirage_taskbar_fake_names[0]);

	if (!g_config.no_stealth && !ret && lpFindFileData != NULL &&
			hFindFile == (HANDLE)0x00000001) {
		/* Continuation of the Quick Launch\User Pinned\TaskBar *.lnk
		 * enumeration started by the FindFirstFileA hook (which emits
		 * "Google Chrome.lnk" on the sentinel handle 0x00000001).
		 * Samples count the non-default pinned shortcuts and treat
		 * nonDefaultApps.size() < 2 as a sandbox. Synthesize a second
		 * and third non-default shortcut so nonDefaultApps.size() >=
		 * minPinnedAppsThreshold even without real files on disk, then
		 * report FALSE/ERROR_NO_MORE_FILES to end the loop cleanly. */
		get_lasterrors(&lasterror);

		if (fake_enum_count < fake_total) {
			memset(lpFindFileData, 0, sizeof(WIN32_FIND_DATAA));
			lpFindFileData->dwFileAttributes = FILE_ATTRIBUTE_ARCHIVE;
			lstrcpyA(lpFindFileData->cFileName, g_mirage_taskbar_fake_names[fake_enum_count]);
			lpFindFileData->nFileSizeLow = 2210;

			fake_enum_count++;
			ret = TRUE;
		} else {
			/* fake entries exhausted; end the enumeration cleanly */
			ret = FALSE;
			lasterror.Win32Error = ERROR_NO_MORE_FILES;
		}

		set_lasterrors(&lasterror);
	}

	return ret;
        }

        HOOKDEF(HRESULT, WINAPI, SLIsGenuineLocal, const SLID* pAppId, SL_GENUINE_STATE* pGenuineState, PVOID pvReserved)
        {
            HRESULT ret;
	lasterror_t lasterror;

	ret = Old_SLIsGenuineLocal(pAppId, pGenuineState, pvReserved);

	if (!g_config.no_stealth) {
		get_lasterrors(&lasterror);

		if (pGenuineState)
			*pGenuineState = SL_GEN_STATE_IS_GENUINE;
		ret = S_OK;

		set_lasterrors(&lasterror);
	}

	return ret;
        }