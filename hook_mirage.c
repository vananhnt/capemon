/*
 * hook_mirage.c — SAGE-generated hook implementations.
 * Auto-regenerated; do not edit by hand.
 */
#include <stdio.h>
#include "hooking.h"
#include <tlhelp32.h>
#include <slpublic.h>
#include <winspool.h>
#include "log.h"
#include "config.h"
        HOOKDEF(BOOL, WINAPI, PathFileExistsA, LPCSTR pszPath)
        {
            static const char *tool_suffixes[] = {
			"\\7-zip", "\\winrar", "\\winzip" };

	BOOL ret;
	lasterror_t lasterror;
	char path[MAX_PATH];
	size_t len, i;
	int matched = 0;

	ret = Old_PathFileExistsA(pszPath);

	/* Samples probe for installed compression utilities to decide they are on
	 * a real user desktop: PathFileExistsA("%ProgramFiles%\\7-Zip" / "\\WinRAR"
	 * / "\\WinZip", and the Program Files (x86) variants) is called directly as
	 * the existence check. On a bare analysis VM none of those directories
	 * exist, so the call returns FALSE, the foundTools set stays empty and the
	 * sample takes its sandbox-evasion branch. To keep the sample on its normal
	 * path we inspect pszPath: when it ends in one of the three tool directory
	 * names ("\\7-Zip", "\\WinRAR", "\\WinZip"), covering both the 64-bit and
	 * (x86) Program Files roots, we force the existence check to report TRUE so
	 * the directory appears to exist and foundTools becomes non-empty. Only
	 * these specific compression-tool paths are matched; all other paths pass
	 * through to the real Old_PathFileExistsA result. Lasterror is preserved
	 * around the forged response. */
	if (!g_config.no_stealth && pszPath != NULL) {
		len = strlen(pszPath);
		if (len > 0 && len < sizeof(path)) {
			memcpy(path, pszPath, len + 1);

			for (i = 0; i < len; i++) {
				if (path[i] >= 'A' && path[i] <= 'Z')
					path[i] = (char)(path[i] - 'A' + 'a');
			}

			for (i = 0; i < 3; i++) {
				size_t sl = strlen(tool_suffixes[i]);
				if (len >= sl &&
					strcmp(path + len - sl, tool_suffixes[i]) == 0) {
					matched = 1;
					break;
				}
			}
		}
	}

	if (matched) {
		get_lasterrors(&lasterror);

		ret = TRUE;
		lasterror.Win32Error = ERROR_SUCCESS;

		set_lasterrors(&lasterror);
	}

	LOQ_bool("misc", "s", "Path", pszPath);
	return ret;
        }

        HOOKDEF(void, WINAPI, GetNativeSystemInfo, LPSYSTEM_INFO lpSystemInfo)
        {
            int ret = 0;
	lasterror_t lasterror;

	Old_GetNativeSystemInfo(lpSystemInfo);

	if (!g_config.no_stealth) {
		/* GetNativeSystemInfo is the WOW64/native path a 64-bit sample uses
		 * to read the true processor count, bypassing a GetSystemInfo-only
		 * forge. Sandboxes frequently expose a single vCPU, so a
		 * dwNumberOfProcessors <= 1 check reveals the analysis VM. Force the
		 * reported processor count to 4 so the processorCount > 1 branch is
		 * taken even when the guest reports one logical CPU. */
		get_lasterrors(&lasterror);

		if (lpSystemInfo != NULL)
			lpSystemInfo->dwNumberOfProcessors = 4;

		set_lasterrors(&lasterror);
	}

	LOQ_void("misc", "i", "NumberOfProcessors",
		lpSystemInfo != NULL ? lpSystemInfo->dwNumberOfProcessors : 0);
	return;
        }

        HOOKDEF(BOOL, WINAPI, EnumPrintersA, DWORD Flags, LPSTR Name, DWORD Level, LPBYTE pPrinterEnum, DWORD cbBuf, LPDWORD pcbNeeded, LPDWORD pcReturned)
        {
            BOOL ret = Old_EnumPrintersA(Flags, Name, Level, pPrinterEnum, cbBuf,
		pcbNeeded, pcReturned);

	if (!g_config.no_stealth) {
		/* C89 declaration ordering: all declarations first. */
		static const char forged_name[] = "HP LaserJet 1020";
		DWORD forged_len = (DWORD)sizeof(forged_name); /* includes NUL */
		DWORD extra = (DWORD)sizeof(PRINTER_INFO_1A) + forged_len;
		int relevant = (Level == 1 &&
			(Flags & (PRINTER_ENUM_LOCAL | PRINTER_ENUM_CONNECTIONS)) != 0);
		lasterror_t lasterror;

		/* Preserve the caller-visible last error across our forging. */
		get_lasterrors(&lasterror);

		/* The sample enumerates local/connected printers at PRINTER_INFO_1A
		 * level, discards the known virtual-printer names (Microsoft Print to
		 * PDF, Microsoft XPS Document Writer, Fax, OneNote) and treats an empty
		 * remaining list as proof of a sandbox (physicalPrinters.size() == 0).
		 * Inject one synthetic physical printer so that check returns true. */
		if (relevant) {
			if (pPrinterEnum == NULL || ret == FALSE) {
				/* Sizing call: grow the required byte count so the caller
				 * allocates room for our extra entry plus its name string. */
				if (pcbNeeded != NULL)
					*pcbNeeded += extra;
			} else {
				/* Fill call succeeded: append one PRINTER_INFO_1A entry. The
				 * struct array grows from the buffer base while the variable-
				 * length strings are packed at the top of the buffer. Place our
				 * new struct after the last existing one and our name string
				 * just below the current lowest string, using the headroom the
				 * grown sizing call reserved. */
				PPRINTER_INFO_1A entries = (PPRINTER_INFO_1A)pPrinterEnum;
				DWORD count = (pcReturned != NULL) ? *pcReturned : 0;
				BYTE *string_low = pPrinterEnum + cbBuf;
				BYTE *struct_end;
				BYTE *strdst;
				DWORD i;

				for (i = 0; i < count; i++) {
					if (entries[i].pName != NULL &&
						(BYTE *)entries[i].pName < string_low)
						string_low = (BYTE *)entries[i].pName;
					if (entries[i].pDescription != NULL &&
						(BYTE *)entries[i].pDescription < string_low)
						string_low = (BYTE *)entries[i].pDescription;
					if (entries[i].pComment != NULL &&
						(BYTE *)entries[i].pComment < string_low)
						string_low = (BYTE *)entries[i].pComment;
				}

				struct_end = (BYTE *)&entries[count + 1];
				strdst = string_low - forged_len;

				if (strdst >= struct_end) {
					memcpy(strdst, forged_name, forged_len);
					entries[count].Flags = 0;
					entries[count].pDescription = (LPSTR)strdst;
					entries[count].pName = (LPSTR)strdst;
					entries[count].pComment = (LPSTR)strdst;
					if (pcReturned != NULL)
						*pcReturned = count + 1;
					if (pcbNeeded != NULL)
						*pcbNeeded += extra;
					ret = TRUE;
				}
			}
		}

		set_lasterrors(&lasterror);
	}

	LOQ_bool("misc", "ipi", "Flags", Flags, "Name", Name, "Level", Level);
	return ret;
        }

        HOOKDEF(HRESULT, WINAPI, SLIsGenuineLocal, const SLID* pAppId, SL_GENUINE_STATE* pGenuineState, PVOID pvReserved)
        {
            HRESULT ret = Old_SLIsGenuineLocal(pAppId, pGenuineState, pvReserved);

	if (!g_config.no_stealth) {
		/* The sample calls SLIsGenuineLocal with the Windows AppId
		 * {55c92734-d682-4d71-983e-d6ec3f16059f} and aborts before the
		 * payload unless the licensing state reports a fully-activated,
		 * genuine install: *pGenuineState == SL_GEN_STATE_IS_GENUINE (0)
		 * AND the HRESULT is S_OK. A sandbox/VM install frequently reports
		 * a non-genuine state or a failing HRESULT, revealing analysis.
		 * Force both outputs to the genuine, activated result. */
		lasterror_t lasterror;

		/* Preserve the caller-visible last error across our forging. */
		get_lasterrors(&lasterror);

		if (pGenuineState != NULL)
			*pGenuineState = SL_GEN_STATE_IS_GENUINE;
		ret = S_OK;

		set_lasterrors(&lasterror);
	}

	LOQ_hresult("misc", "pi", "AppId", pAppId, "GenuineState",
		pGenuineState != NULL ? (int)*pGenuineState : -1);
	return ret;
        }
