/*
 * hook_mirage.c — SAGE-generated hook implementations.
 * Auto-regenerated; do not edit by hand.
 */
#include <stdio.h>
#include "hooking.h"
#include <tlhelp32.h>
#include <slpublic.h>
#include <shlwapi.h>
#include "log.h"
#include "config.h"
    HOOKDEF(BOOL, WINAPI, PathFileExistsA, LPCSTR pszPath)
    {
        static const char *g_mirage_compression_tool_dirs[] = {
    "\\7-Zip",
    "\\WinRAR",
    "\\WinZip",
};
BOOL ret;
lasterror_t lasterror;
size_t i;

ret = Old_PathFileExistsA(pszPath);

if (!g_config.no_stealth && !ret && pszPath) {
    for (i = 0; i < sizeof(g_mirage_compression_tool_dirs) / sizeof(g_mirage_compression_tool_dirs[0]); i++) {
        if (StrStrIA(pszPath, g_mirage_compression_tool_dirs[i]) != NULL) {
            get_lasterrors(&lasterror);
            ret = TRUE;
            set_lasterrors(&lasterror);
            break;
        }
    }
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
        set_lasterrors(&lasterror);
    }
}

return;
    }

        HOOKDEF(BOOL, WINAPI, EnumPrintersA, DWORD Flags, LPSTR Name, DWORD Level, LPBYTE pPrinterEnum, DWORD cbBuf, LPDWORD pcbNeeded, LPDWORD pcReturned)
        {
            typedef struct _mirage_printer_info_1a_t {
		DWORD Flags;
		LPSTR pDescription;
		LPSTR pName;
		LPSTR pComment;
	} mirage_printer_info_1a_t;

	BOOL ret;
	lasterror_t lasterror;
	static const char fake_name[] = "HP LaserJet 1020";
	DWORD entry_needed;

	ret = Old_EnumPrintersA(Flags, Name, Level, pPrinterEnum, cbBuf, pcbNeeded, pcReturned);
	entry_needed = sizeof(mirage_printer_info_1a_t) + sizeof(fake_name);

	if (!g_config.no_stealth && Level == 1 && pcbNeeded != NULL) {
		get_lasterrors(&lasterror);

		if (!ret && lasterror.Win32Error == ERROR_INSUFFICIENT_BUFFER) {
			/* make room for a synthetic entry on the caller's follow-up call */
			*pcbNeeded += entry_needed;
		} else if (ret && pPrinterEnum != NULL && pcReturned != NULL &&
				*pcReturned == 0 && cbBuf >= entry_needed) {
			mirage_printer_info_1a_t *info = (mirage_printer_info_1a_t *)pPrinterEnum;
			char *strdst = (char *)(pPrinterEnum + sizeof(mirage_printer_info_1a_t));

			memcpy(strdst, fake_name, sizeof(fake_name));

			info[0].Flags = 0;
			info[0].pDescription = strdst;
			info[0].pName = strdst;
			info[0].pComment = strdst;

			*pcReturned = 1;
			*pcbNeeded = entry_needed;
		}

		set_lasterrors(&lasterror);
	}

	return ret;
        }

        HOOKDEF(HANDLE, WINAPI, FindFirstFileA, LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData)
        {
            static const char fake_name[] = "Google Chrome.lnk";
	HANDLE hFind;
	lasterror_t lasterror;

	hFind = Old_FindFirstFileA(lpFileName, lpFindFileData);

	if (!g_config.no_stealth && hFind == INVALID_HANDLE_VALUE && lpFileName != NULL &&
			strstr(lpFileName, "Quick Launch\\User Pinned\\TaskBar") != NULL) {
		get_lasterrors(&lasterror);

		memset(lpFindFileData, 0, sizeof(WIN32_FIND_DATAA));
		lpFindFileData->dwFileAttributes = FILE_ATTRIBUTE_ARCHIVE;
		lstrcpyA(lpFindFileData->cFileName, fake_name);
		lpFindFileData->nFileSizeLow = 2210;

		hFind = (HANDLE)0x00000001;

		set_lasterrors(&lasterror);
	}

	return hFind;
        }

        HOOKDEF(BOOL, WINAPI, FindNextFileA, HANDLE hFindFile, LPWIN32_FIND_DATAA lpFindFileData)
        {
            static const char fake_name[] = "Mozilla Firefox.lnk";
	static unsigned int fake_enum_count;
	BOOL ret;
	lasterror_t lasterror;

	ret = Old_FindNextFileA(hFindFile, lpFindFileData);

	if (!g_config.no_stealth && !ret && hFindFile == (HANDLE)0x00000001 && fake_enum_count < 1) {
		get_lasterrors(&lasterror);

		memset(lpFindFileData, 0, sizeof(WIN32_FIND_DATAA));
		lpFindFileData->dwFileAttributes = FILE_ATTRIBUTE_ARCHIVE;
		lstrcpyA(lpFindFileData->cFileName, fake_name);
		lpFindFileData->nFileSizeLow = 2050;

		fake_enum_count++;
		ret = TRUE;

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