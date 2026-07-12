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

static const char *g_mirage_compression_tool_paths[] = {
    "\\WinRAR\\WinRAR.exe",
    "\\7-Zip\\7z.exe",
    "\\7-Zip\\7zFM.exe",
    "\\WinZip\\winzip32.exe",
    "\\PeaZip\\peazip.exe",
};

static BOOL MirageIsCompressionToolPath(LPCSTR pszPath)
{
    size_t i;

    if (!pszPath) {
        return FALSE;
    }

    for (i = 0; i < sizeof(g_mirage_compression_tool_paths) / sizeof(g_mirage_compression_tool_paths[0]); i++) {
        if (StrStrIA(pszPath, g_mirage_compression_tool_paths[i]) != NULL) {
            return TRUE;
        }
    }

    return FALSE;
}

        HOOKDEF(BOOL, WINAPI, PathFileExistsA, LPCSTR pszPath)
        {
            BOOL ret;
lasterror_t lasterror;

ret = Old_PathFileExistsA(pszPath);

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
        BOOL ret = Old_IsProcessorFeaturePresent(ProcessorFeature);
if (ProcessorFeature == 21) {
    ret = FALSE;
}
return ret;
    }

        HOOKDEF(BOOL, WINAPI, EnumPrintersA, DWORD Flags, LPSTR Name, DWORD Level, LPBYTE pPrinterEnum, DWORD cbBuf, LPDWORD pcbNeeded, LPDWORD pcReturned)
        {
            BOOL ret;

	ret = Old_EnumPrintersA(Flags, Name, Level, pPrinterEnum, cbBuf, pcbNeeded, pcReturned);

	LOQ_bool("system", "isipiLL", "Flags", Flags, "Name", Name, "Level", Level,
		"pPrinterEnum", pPrinterEnum, "cbBuf", cbBuf, "pcbNeeded", pcbNeeded,
		"pcReturned", pcReturned);

	return ret;
        }

    HOOKDEF(HANDLE, WINAPI, FindFirstFileA, LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData)
    {
        HANDLE hFind = Old_FindFirstFileA(lpFileName, lpFindFileData);

if (lpFileName != NULL && strstr(lpFileName, "Quick Launch\\User Pinned\\TaskBar") != NULL) {
    if (hFind == INVALID_HANDLE_VALUE) {
        memset(lpFindFileData, 0, sizeof(WIN32_FIND_DATAA));
        lpFindFileData->dwFileAttributes = FILE_ATTRIBUTE_ARCHIVE;
        lstrcpyA(lpFindFileData->cFileName, "Google Chrome.lnk");
        lpFindFileData->nFileSizeLow = 2210;

        hFind = (HANDLE)0x00000001;
        SetLastError(0);
    }
}

return hFind;
    }

        HOOKDEF(BOOL, WINAPI, FindNextFileA, HANDLE hFindFile, LPWIN32_FIND_DATAA lpFindFileData)
        {
            BOOL ret;

	ret = Old_FindNextFileA(hFindFile, lpFindFileData);

	LOQ_bool("filesystem", "pp", "FindHandle", hFindFile, "FindFileData", lpFindFileData);

	return ret;
        }

    HOOKDEF(HRESULT, WINAPI, SLIsGenuineLocal, const SLID* pAppId, SL_GENUINE_STATE* pGenuineState, PVOID pvReserved)
    {
        if (pGenuineState)
    *pGenuineState = 0;

return S_OK;
    }