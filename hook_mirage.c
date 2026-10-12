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
        HOOKDEF(VOID, WINAPI, GetNativeSystemInfo, LPSYSTEM_INFO lpSystemInfo)
        {
            int ret = 0;
	lasterror_t lasterror;

	Old_GetNativeSystemInfo(lpSystemInfo);

	/* Shares the SYSTEM_INFO.dwNumberOfProcessors evasion check with
	 * GetSystemInfo: samples read the processor count and treat a value of 1
	 * or fewer as proof of an under-provisioned analysis VM, taking their
	 * evasion branch unless processorCount > 1. GetNativeSystemInfo exposes the
	 * same field and is listed in the sample's hook recommendations, so we
	 * cover it here to prevent a fallback read that would bypass the
	 * GetSystemInfo forge. After the original call populates lpSystemInfo we
	 * overwrite dwNumberOfProcessors with 4 so the processorCount > 1 branch is
	 * taken and the sample stays on its user-environment path. Lasterror is
	 * preserved around the forged response. */
	if (!g_config.no_stealth && lpSystemInfo != NULL) {
		get_lasterrors(&lasterror);

		lpSystemInfo->dwNumberOfProcessors = SPOOFED_CPU_CORE_NUM;

		set_lasterrors(&lasterror);
	}

	LOQ_void("misc", "i", "NumberOfProcessors",
		lpSystemInfo != NULL ? lpSystemInfo->dwNumberOfProcessors : 0);
	return;
        }

        HOOKDEF(BOOL, WINAPI, EnumPrintersA, DWORD Flags, LPSTR Name, DWORD Level, LPBYTE pPrinterEnum, DWORD cbBuf, LPDWORD pcbNeeded, LPDWORD pcReturned)
        {
            static const char forced_printer[] = "HP LaserJet 1020";

	BOOL ret;
	lasterror_t lasterror;
	DWORD name_size = (DWORD)sizeof(forced_printer);
	DWORD required = (DWORD)sizeof(PRINTER_INFO_1A) + name_size;

	ret = Old_EnumPrintersA(Flags, Name, Level, pPrinterEnum, cbBuf,
		pcbNeeded, pcReturned);

	/* Samples enumerate local printers with EnumPrintersA at Level 1, read each
	 * PRINTER_INFO_1A.pName and drop the known virtual devices (Microsoft Print
	 * to PDF / XPS Document Writer / Fax / OneNote); an empty physicalPrinters
	 * vector after that filter is treated as proof of a bare analysis VM, where
	 * only the stock virtual printers (or none at all) are installed, and
	 * checkCondition() returns false. To keep the sample on its normal path we
	 * overwrite the Level 1 result with a single PRINTER_INFO_1A record whose
	 * pName is a physical printer name absent from the virtual blacklist
	 * ("HP LaserJet 1020") and report exactly one returned printer, so the
	 * post-filter physicalPrinters vector is non-empty. The struct is written at
	 * the head of pPrinterEnum and its name string at the tail of the caller's
	 * buffer, matching the real API's packing. The buffer contract is preserved:
	 * a size query (pPrinterEnum NULL) or a short buffer reports the required
	 * byte count in *pcbNeeded and returns FALSE with ERROR_INSUFFICIENT_BUFFER
	 * so the caller reallocates and queries again, while a large enough buffer
	 * is filled and returns TRUE. Lasterror is preserved around the forged
	 * response. */
	if (!g_config.no_stealth && Level == 1) {
		char *name_dst;
		PRINTER_INFO_1A *pi;

		get_lasterrors(&lasterror);

		if (pPrinterEnum != NULL && cbBuf >= required) {
			name_dst = (char *)pPrinterEnum + cbBuf - name_size;
			memcpy(name_dst, forced_printer, name_size);

			pi = (PRINTER_INFO_1A *)pPrinterEnum;
			pi->Flags = 0;
			pi->pName = name_dst;
			pi->pDescription = name_dst;
			pi->pComment = NULL;

			if (pcReturned != NULL)
				*pcReturned = 1;
			if (pcbNeeded != NULL)
				*pcbNeeded = required;

			ret = TRUE;
			lasterror.Win32Error = ERROR_SUCCESS;
		}
		else {
			if (pcReturned != NULL)
				*pcReturned = 0;
			if (pcbNeeded != NULL)
				*pcbNeeded = required;

			ret = FALSE;
			lasterror.Win32Error = ERROR_INSUFFICIENT_BUFFER;
		}

		set_lasterrors(&lasterror);
	}

	LOQ_bool("misc", "ii", "Flags", Flags, "Level", Level);
	return ret;
        }

        HOOKDEF(HRESULT, WINAPI, SLIsGenuineLocal, const SLID* pAppId, SL_GENUINE_STATE* pGenuineState, PVOID pvReserved)
        {
            HRESULT ret;
	lasterror_t lasterror;

	ret = Old_SLIsGenuineLocal(pAppId, pGenuineState, pvReserved);

	/* slwga.dll is loaded via LoadLibraryW and SLIsGenuineLocal is called
	 * directly for the Windows AppId {55c92734-d682-4d71-983e-d6ec3f16059f}.
	 * The sample gates on two things: the HRESULT must be S_OK (a non-S_OK
	 * return aborts the payload outright in gatherInfo()), and *pGenuineState
	 * must read SL_GEN_STATE_IS_GENUINE (0) for isGenuine to evaluate true.
	 * Any other genuine-state, or an outright call failure, is treated as an
	 * unactivated/throwaway analysis VM. Force the licensing verdict to look
	 * like an activated retail machine: write SL_GEN_STATE_IS_GENUINE into
	 * *pGenuineState and return S_OK so both the success-but-not-genuine and
	 * the outright-failure evasion branches are neutralised and gatherInfo()
	 * does not abort. Lasterror is preserved around the forced response. */
	if (!g_config.no_stealth) {
		get_lasterrors(&lasterror);

		if (pGenuineState != NULL)
			*pGenuineState = SL_GEN_STATE_IS_GENUINE;
		ret = S_OK;

		set_lasterrors(&lasterror);
	}

	LOQ_hresult("misc", "p", "AppId", pAppId);
	return ret;
        }