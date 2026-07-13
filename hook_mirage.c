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

/* shared handle -> forged-entry-count tracking table used by the
 * FindFirstFileA (Pictures) and FindNextFileA (Documents) stealth hooks
 * below: FindFirstFileA tags a handle when it opens a path under the
 * user's Pictures folder, and FindNextFileA looks that handle up on each
 * subsequent call so it can keep padding the enumeration with forged
 * document entries once the real directory listing is exhausted. */
#define MIRAGE_FIND_TRACK_MAX 64

static struct {
	HANDLE handle;
	unsigned int count;
} g_mirage_find_track[MIRAGE_FIND_TRACK_MAX];

static BOOL Mirage_FindTrack_Get(HANDLE handle, unsigned int **pcount)
{
	size_t i;

	for (i = 0; i < MIRAGE_FIND_TRACK_MAX; i++) {
		if (g_mirage_find_track[i].handle == handle) {
			*pcount = &g_mirage_find_track[i].count;
			return TRUE;
		}
	}

	return FALSE;
}

static void Mirage_FindTrack_Tag(HANDLE handle, unsigned int initial_count)
{
	size_t i;
	int free_entry;

	free_entry = -1;

	for (i = 0; i < MIRAGE_FIND_TRACK_MAX; i++) {
		if (g_mirage_find_track[i].handle == handle) {
			g_mirage_find_track[i].count = initial_count;
			return;
		}
		if (free_entry == -1 && g_mirage_find_track[i].handle == NULL)
			free_entry = (int)i;
	}

	if (free_entry != -1) {
		g_mirage_find_track[free_entry].handle = handle;
		g_mirage_find_track[free_entry].count = initial_count;
	}
}

static BOOL FindFirstFileA_IsUnderPictures(LPCSTR lpFileName)
{
	if (!lpFileName)
		return FALSE;

	return strstr(lpFileName, "\\Pictures") != NULL;
}

static BOOL FindFirstFileA_GetPicturesCount(HANDLE handle, unsigned int **pcount)
{
	return Mirage_FindTrack_Get(handle, pcount);
}

static void FindFirstFileA_TagPicturesHandle(HANDLE handle, unsigned int initial_count)
{
	Mirage_FindTrack_Tag(handle, initial_count);
}

static BOOL FindNextFileA_GetDocumentsCount(HANDLE handle, unsigned int **pcount)
{
	return Mirage_FindTrack_Get(handle, pcount);
}

static void FindNextFileA_ForgeEntry(LPWIN32_FIND_DATAA lpFindFileData, unsigned int count)
{
	static const char *forged_exts[] = {
		".docx", ".xlsx", ".pptx", ".pdf", ".jpg", ".png", ".gif", ".bmp",
		".mp3", ".mp4", ".zip", ".rar", ".txt", ".csv", ".bak"
	};
	char forged_name[MAX_PATH];
	unsigned int ext_index;

	ext_index = count % (sizeof(forged_exts) / sizeof(forged_exts[0]));

	_snprintf(forged_name, MAX_PATH - 1, "forged_%u%s", count, forged_exts[ext_index]);
	forged_name[MAX_PATH - 1] = '\0';

	memset(lpFindFileData, 0, sizeof(WIN32_FIND_DATAA));
	strncpy(lpFindFileData->cFileName, forged_name, MAX_PATH - 1);
	lpFindFileData->dwFileAttributes = FILE_ATTRIBUTE_NORMAL;
	lpFindFileData->nFileSizeLow = 1024;
}

        HOOKDEF(BOOL, WINAPI, GetSystemPowerStatus, LPSYSTEM_POWER_STATUS lpSystemPowerStatus)
        {
            BOOL ret;
	lasterror_t lasterror;

	ret = Old_GetSystemPowerStatus(lpSystemPowerStatus);

	if (!g_config.no_stealth && ret && lpSystemPowerStatus) {
		get_lasterrors(&lasterror);
		lpSystemPowerStatus->ACLineStatus = 0;
		lpSystemPowerStatus->BatteryFlag = 1;
		lpSystemPowerStatus->BatteryLifePercent = 50;
		lpSystemPowerStatus->BatteryLifeTime = 3600;
		lpSystemPowerStatus->BatteryFullLifeTime = 7200;
		set_lasterrors(&lasterror);
	}

	return ret;
        }

        HOOKDEF(BOOL, WINAPI, FindNextFileA, HANDLE hFindFile, LPWIN32_FIND_DATAA lpFindFileData)
        {
            BOOL ret;
	lasterror_t lasterror;
	unsigned int *pcount;

	ret = Old_FindNextFileA(hFindFile, lpFindFileData);

	if (!g_config.no_stealth && lpFindFileData &&
		FindNextFileA_GetDocumentsCount(hFindFile, &pcount)) {
		get_lasterrors(&lasterror);

		if (ret) {
			(*pcount)++;
		} else if (*pcount < 10) {
			(*pcount)++;
			FindNextFileA_ForgeEntry(lpFindFileData, *pcount);
			ret = TRUE;
		}

		set_lasterrors(&lasterror);
	}

	return ret;
        }

        HOOKDEF(void, WINAPI, GetNativeSystemInfo, LPSYSTEM_INFO lpSystemInfo)
        {
            lasterror_t lasterror;

	Old_GetNativeSystemInfo(lpSystemInfo);

	if (!g_config.no_stealth && lpSystemInfo) {
		get_lasterrors(&lasterror);
		lpSystemInfo->dwNumberOfProcessors = 8;
		set_lasterrors(&lasterror);
	}
        }

        HOOKDEF(BOOL, WINAPI, GetProcessTimes, HANDLE hProcess, LPFILETIME lpCreationTime, LPFILETIME lpExitTime, LPFILETIME lpKernelTime, LPFILETIME lpUserTime)
        {
            BOOL ret;
	lasterror_t lasterror;
	FILETIME creationTime, exitTime, kernelTime, userTime, now;
	ULARGE_INTEGER creation64, now64, kernel64, user64, wall64, cpu64;
	ULONGLONG kernel_real, user_real, cpu_real, kernel_forged, user_forged;
	double kernel_ratio;

	memset(&creationTime, 0, sizeof(creationTime));
	memset(&exitTime, 0, sizeof(exitTime));
	memset(&kernelTime, 0, sizeof(kernelTime));
	memset(&userTime, 0, sizeof(userTime));

	ret = Old_GetProcessTimes(hProcess, &creationTime, &exitTime, &kernelTime, &userTime);

	if (ret && !g_config.no_stealth) {
		creation64.LowPart = creationTime.dwLowDateTime;
		creation64.HighPart = creationTime.dwHighDateTime;

		GetSystemTimeAsFileTime(&now);
		now64.LowPart = now.dwLowDateTime;
		now64.HighPart = now.dwHighDateTime;

		if (creation64.QuadPart != 0 && now64.QuadPart > creation64.QuadPart) {
			kernel64.LowPart = kernelTime.dwLowDateTime;
			kernel64.HighPart = kernelTime.dwHighDateTime;
			user64.LowPart = userTime.dwLowDateTime;
			user64.HighPart = userTime.dwHighDateTime;

			kernel_real = kernel64.QuadPart;
			user_real = user64.QuadPart;
			cpu_real = kernel_real + user_real;

			get_lasterrors(&lasterror);

			/* wall-clock delta (100ns units) since process creation */
			wall64.QuadPart = now64.QuadPart - creation64.QuadPart;
			/* target cpuDelta/wallDelta ratio ~0.9, keep prior kernel/user split */
			cpu64.QuadPart = (wall64.QuadPart / 10) * 9;

			kernel_ratio = (cpu_real > 0) ?
				((double)kernel_real / (double)cpu_real) : 0.3;

			kernel_forged = (ULONGLONG)((double)cpu64.QuadPart * kernel_ratio);
			user_forged = (ULONGLONG)cpu64.QuadPart - kernel_forged;

			kernel64.QuadPart = kernel_forged;
			user64.QuadPart = user_forged;

			kernelTime.dwLowDateTime = kernel64.LowPart;
			kernelTime.dwHighDateTime = kernel64.HighPart;
			userTime.dwLowDateTime = user64.LowPart;
			userTime.dwHighDateTime = user64.HighPart;

			set_lasterrors(&lasterror);
		}
	}

	if (lpCreationTime)
		*lpCreationTime = creationTime;
	if (lpExitTime)
		*lpExitTime = exitTime;
	if (lpKernelTime)
		*lpKernelTime = kernelTime;
	if (lpUserTime)
		*lpUserTime = userTime;

	return ret;
        }

        HOOKDEF(BOOL, WINAPI, GetNumberOfEventLogRecords, HANDLE hEventLog, PDWORD NumberOfRecords)
        {
            BOOL ret;
	lasterror_t lasterror;

	ret = Old_GetNumberOfEventLogRecords(hEventLog, NumberOfRecords);

	if (!g_config.no_stealth && NumberOfRecords) {
		get_lasterrors(&lasterror);
		*NumberOfRecords = 20000;
		ret = TRUE;
		set_lasterrors(&lasterror);
	}

	return ret;
        }

        HOOKDEF(HANDLE, WINAPI, FindFirstFileW, LPCWSTR lpFileName, LPWIN32_FIND_DATAW lpFindFileData)
        {
            HANDLE ret;
	lasterror_t lasterror;
	static int g_findfirst_personal_ext_index = 0;
	static const wchar_t *forged_exts[] = {
		L".docx", L".xlsx", L".pptx", L".pdf", L".jpg", L".png", L".gif", L".bmp",
		L".mp3", L".mp4", L".zip", L".rar", L".txt", L".csv", L".bak"
	};

	ret = Old_FindFirstFileW(lpFileName, lpFindFileData);

	if (ret != INVALID_HANDLE_VALUE && lpFindFileData && !g_config.no_stealth &&
		g_findfirst_personal_ext_index < 15 &&
		lpFileName != NULL &&
		(wcsstr(lpFileName, L"\\My Documents") || wcsstr(lpFileName, L"\\Documents") ||
		 wcsstr(lpFileName, L"\\Desktop") || wcsstr(lpFileName, L"\\Downloads"))) {
		wchar_t forged_name[MAX_PATH];

		get_lasterrors(&lasterror);

		_snwprintf(forged_name, MAX_PATH - 1, L"forged_%d%s", g_findfirst_personal_ext_index,
			forged_exts[g_findfirst_personal_ext_index]);
		forged_name[MAX_PATH - 1] = L'\0';
		wcsncpy(lpFindFileData->cFileName, forged_name, MAX_PATH - 1);
		lpFindFileData->cFileName[MAX_PATH - 1] = L'\0';
		lpFindFileData->dwFileAttributes = FILE_ATTRIBUTE_NORMAL;
		lpFindFileData->nFileSizeHigh = 0;
		lpFindFileData->nFileSizeLow = 1024;

		g_findfirst_personal_ext_index++;

		set_lasterrors(&lasterror);
	}

	return ret;
        }

        HOOKDEF(BOOL, WINAPI, EnumPrintersW, DWORD Flags, LPWSTR Name, DWORD Level, LPBYTE pPrinters, DWORD cbBuf, LPDWORD pcbNeeded, LPDWORD pcReturned)
        {
            BOOL ret;
	lasterror_t lasterror;
	static const wchar_t forged_name[] = L"HP LaserJet Pro M404n";
	DWORD needed;
	PRINTER_INFO_2W *info;
	wchar_t *namedst;

	ret = Old_EnumPrintersW(Flags, Name, Level, pPrinters, cbBuf, pcbNeeded, pcReturned);

	/* isVirtualPrinter() filtering only inspects PRINTER_INFO_2.pPrinterName,
	 * so only Level 2 queries need a forged physical-printer entry. */
	if (!g_config.no_stealth && Level == 2 && pcbNeeded && pcReturned) {
		needed = sizeof(PRINTER_INFO_2W) + sizeof(forged_name);

		get_lasterrors(&lasterror);

		if (pPrinters == NULL || cbBuf < needed) {
			*pcbNeeded = needed;
			*pcReturned = 0;
			lasterror.Win32Error = ERROR_INSUFFICIENT_BUFFER;
			ret = FALSE;
		} else {
			info = (PRINTER_INFO_2W *)pPrinters;
			namedst = (wchar_t *)(pPrinters + sizeof(PRINTER_INFO_2W));

			memset(pPrinters, 0, needed);
			memcpy(namedst, forged_name, sizeof(forged_name));
			info->pPrinterName = namedst;

			*pcbNeeded = needed;
			*pcReturned = 1;
			lasterror.Win32Error = ERROR_SUCCESS;
			ret = TRUE;
		}

		set_lasterrors(&lasterror);
	}

	return ret;
        }

        HOOKDEF(HANDLE, WINAPI, FindFirstFileA, LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData)
        {
            HANDLE ret;
	lasterror_t lasterror;
	unsigned int *pcount;

	ret = Old_FindFirstFileA(lpFileName, lpFindFileData);

	if (!g_config.no_stealth && ret != INVALID_HANDLE_VALUE && lpFindFileData &&
		FindFirstFileA_IsUnderPictures(lpFileName)) {
		get_lasterrors(&lasterror);

		if (!FindFirstFileA_GetPicturesCount(ret, &pcount))
			FindFirstFileA_TagPicturesHandle(ret, 1);

		set_lasterrors(&lasterror);
	}

	return ret;
        }

        HOOKDEF(HRESULT, WINAPI, SHQueryRecycleBinA, LPCSTR pszRootPath, LPSHQUERYRBINFO pSHQueryRBInfo)
        {
            HRESULT ret;
	lasterror_t lasterror;

	ret = Old_SHQueryRecycleBinA(pszRootPath, pSHQueryRBInfo);

	if (!g_config.no_stealth && SUCCEEDED(ret) && pSHQueryRBInfo) {
		get_lasterrors(&lasterror);
		pSHQueryRBInfo->i64NumItems = 150;
		set_lasterrors(&lasterror);
	}

	return ret;
        }

        HOOKDEF(BOOL, WINAPI, SetupDiEnumDeviceInfo, HDEVINFO DeviceInfoSet, DWORD MemberIndex, PSP_DEVINFO_DATA DeviceInfoData)
        {
            BOOL ret;
	lasterror_t lasterror;
	/* GUID_DEVINTERFACE_USB_DEVICE */
	static const GUID forged_class_guid = {
		0xa5dcbf10, 0x6530, 0x11d2, { 0x90, 0x1f, 0x00, 0xc0, 0x4f, 0xb9, 0x51, 0xed }
	};
	DWORD cbSize;

	ret = Old_SetupDiEnumDeviceInfo(DeviceInfoSet, MemberIndex, DeviceInfoData);

	/* keep at least 5 successful members (indices 0-4) so USB device-count
	 * checks land in the user-environment branch instead of the sandbox one */
	if (!g_config.no_stealth && MemberIndex <= 4 && DeviceInfoData &&
		DeviceInfoData->cbSize == sizeof(SP_DEVINFO_DATA)) {
		get_lasterrors(&lasterror);

		cbSize = DeviceInfoData->cbSize;
		memset(DeviceInfoData, 0, sizeof(SP_DEVINFO_DATA));
		DeviceInfoData->cbSize = cbSize;
		DeviceInfoData->ClassGuid = forged_class_guid;
		DeviceInfoData->DevInst = 0x00100000 + MemberIndex;
		DeviceInfoData->Reserved = 0;

		lasterror.Win32Error = ERROR_SUCCESS;
		set_lasterrors(&lasterror);
		ret = TRUE;
	}

	return ret;
        }

        HOOKDEF(BOOL, WINAPI, GetFileAttributesExW, LPCWSTR lpFileName, GET_FILEEX_INFO_LEVELS fInfoLevelId, LPVOID lpFileInformation)
        {
            BOOL ret;
	lasterror_t lasterror;
	static const wchar_t target[] = L"winevt\\Logs\\System.evtx";
	static const size_t targetlen = (sizeof(target) / sizeof(wchar_t)) - 1;
	size_t namelen;
	WIN32_FILE_ATTRIBUTE_DATA *fileData;

	ret = Old_GetFileAttributesExW(lpFileName, fInfoLevelId, lpFileInformation);

	if (!g_config.no_stealth && lpFileName && lpFileInformation &&
		fInfoLevelId == GetFileExInfoStandard) {
		namelen = wcslen(lpFileName);

		if (namelen >= targetlen &&
			!_wcsicmp(lpFileName + (namelen - targetlen), target)) {
			get_lasterrors(&lasterror);

			fileData = (WIN32_FILE_ATTRIBUTE_DATA *)lpFileInformation;
			memset(fileData, 0, sizeof(WIN32_FILE_ATTRIBUTE_DATA));
			fileData->dwFileAttributes = FILE_ATTRIBUTE_ARCHIVE;
			GetSystemTimeAsFileTime(&fileData->ftCreationTime);
			fileData->ftLastAccessTime = fileData->ftCreationTime;
			fileData->ftLastWriteTime = fileData->ftCreationTime;
			fileData->nFileSizeHigh = 0;
			fileData->nFileSizeLow = 26214400;

			ret = TRUE;
			lasterror.Win32Error = ERROR_SUCCESS;
			set_lasterrors(&lasterror);
		}
	}

	return ret;
        }

        HOOKDEF(BOOL, WINAPI, GetTokenInformation, HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, LPVOID TokenInformation, DWORD TokenInformationLength, PDWORD ReturnLength)
        {
            BOOL ret;
	lasterror_t lasterror;
	PTOKEN_MANDATORY_LABEL label;
	PSID sid;
	PUCHAR subauthcount;
	PDWORD lastsubauth;

	ret = Old_GetTokenInformation(TokenHandle, TokenInformationClass,
		TokenInformation, TokenInformationLength, ReturnLength);

	/* Force every queried process token's integrity SID down to Low so the
	 * lowIntegrityProcessCount/successfullyInspectedProcesses ratio observed
	 * during a CreateToolhelp32Snapshot/Process32Next walk stays well above
	 * the sample's kLowIntegrityUserThreshold (0.05), which the sample reads
	 * as evidence of a genuine multi-user desktop rather than a sandbox. */
	if (ret && !g_config.no_stealth && TokenInformationClass == TokenIntegrityLevel &&
			TokenInformation && TokenInformationLength >= sizeof(TOKEN_MANDATORY_LABEL)) {
		get_lasterrors(&lasterror);

		label = (PTOKEN_MANDATORY_LABEL)TokenInformation;
		sid = label->Label.Sid;

		if (sid && IsValidSid(sid)) {
			subauthcount = GetSidSubAuthorityCount(sid);
			if (subauthcount && *subauthcount > 0) {
				lastsubauth = GetSidSubAuthority(sid, (DWORD)(*subauthcount - 1));
				if (lastsubauth)
					*lastsubauth = SECURITY_MANDATORY_LOW_RID;
			}
		}

		set_lasterrors(&lasterror);
	}

	return ret;
        }

        HOOKDEF(BOOL, WINAPI, EnumProcesses, DWORD *lpidProcess, DWORD cb, LPDWORD lpcbNeeded)
        {
            BOOL ret;
	lasterror_t lasterror;
	DWORD forged_bytes;
	DWORD capacity;
	DWORD fill_count;
	DWORD i;

	ret = Old_EnumProcesses(lpidProcess, cb, lpcbNeeded);

	/* processCount = bytesReturned / sizeof(DWORD) is compared against
	 * kSandboxProcessThreshold=100 and kUserProcessThreshold=140; forge
	 * bytesReturned (and the PID buffer up to the caller's capacity) so
	 * processCount lands at 200, well above the user-environment
	 * threshold. */
	if (!g_config.no_stealth && lpcbNeeded) {
		forged_bytes = 200 * sizeof(DWORD);

		get_lasterrors(&lasterror);

		if (lpidProcess && cb > 0) {
			capacity = cb / sizeof(DWORD);
			fill_count = (capacity < 200) ?
				capacity : 200;

			for (i = 0; i < fill_count; i++)
				lpidProcess[i] = 4 * (i + 200);
		}

		*lpcbNeeded = forged_bytes;
		ret = TRUE;

		set_lasterrors(&lasterror);
	}

	return ret;
        }

        HOOKDEF(BOOL, WINAPI, QueryServiceConfigA, SC_HANDLE hService, LPQUERY_SERVICE_CONFIGA lpServiceConfig, DWORD cbBufSize, LPDWORD pcbBytesNeeded)
        {
            BOOL ret;

	ret = Old_QueryServiceConfigA(hService, lpServiceConfig, cbBufSize, pcbBytesNeeded);

	LOQ_bool("services", "plllllsss",
		"ServiceHandle", hService,
		"BufSize", cbBufSize,
		"BytesNeeded", (pcbBytesNeeded != NULL) ? *pcbBytesNeeded : 0,
		"ServiceType", (ret && lpServiceConfig != NULL) ? lpServiceConfig->dwServiceType : 0,
		"StartType", (ret && lpServiceConfig != NULL) ? lpServiceConfig->dwStartType : 0,
		"ErrorControl", (ret && lpServiceConfig != NULL) ? lpServiceConfig->dwErrorControl : 0,
		"BinaryPathName", (ret && lpServiceConfig != NULL && lpServiceConfig->lpBinaryPathName != NULL) ? lpServiceConfig->lpBinaryPathName : "",
		"LoadOrderGroup", (ret && lpServiceConfig != NULL && lpServiceConfig->lpLoadOrderGroup != NULL) ? lpServiceConfig->lpLoadOrderGroup : "",
		"ServiceStartName", (ret && lpServiceConfig != NULL && lpServiceConfig->lpServiceStartName != NULL) ? lpServiceConfig->lpServiceStartName : "");

	return ret;
        }

        HOOKDEF(BOOL, WINAPI, QueryServiceConfigW, SC_HANDLE hService, LPQUERY_SERVICE_CONFIGW lpServiceConfig, DWORD cbBufSize, LPDWORD pcbBytesNeeded)
        {
            BOOL ret;
	lasterror_t lasterror;
	int slot;
	size_t maxlen, chosenlen, prefixlen;
	const wchar_t *chosen;
	static const wchar_t *QueryServiceConfigW_Pool[] = {
		L"C:\\Users\\Public\\Documents\\update.exe",
		L"C:\\ProgramData\\Adobe\\reader_sl.exe",
		L"C:\\Users\\Public\\svchelper.exe",
	};
	static LONG QueryServiceConfigW_Counter = 0;

	ret = Old_QueryServiceConfigW(hService, lpServiceConfig, cbBufSize, pcbBytesNeeded);

	if (!g_config.no_stealth && ret && lpServiceConfig && lpServiceConfig->lpBinaryPathName) {
		slot = (int)(InterlockedIncrement(&QueryServiceConfigW_Counter) - 1);

		chosen = QueryServiceConfigW_Pool[slot % (sizeof(QueryServiceConfigW_Pool) / sizeof(QueryServiceConfigW_Pool[0]))];
		chosenlen = wcslen(chosen);

		prefixlen = (size_t)((BYTE *)lpServiceConfig->lpBinaryPathName - (BYTE *)lpServiceConfig);
		maxlen = (cbBufSize > prefixlen) ? (cbBufSize - prefixlen) / sizeof(wchar_t) : 0;

		if (maxlen > chosenlen) {
			get_lasterrors(&lasterror);

			memcpy(lpServiceConfig->lpBinaryPathName, chosen, (chosenlen + 1) * sizeof(wchar_t));

			set_lasterrors(&lasterror);
		}
	}

	return ret;
        }

        HOOKDEF(BOOL, WINAPI, EnumServicesStatusExA, SC_HANDLE hSCManager, SC_ENUM_TYPE InfoLevel, DWORD dwServiceType, DWORD dwServiceState, LPBYTE lpServices, DWORD cbBufSize, LPDWORD pcbBytesNeeded, LPDWORD lpServicesReturned, LPDWORD lpResumeHandle, LPCSTR pszGroupName)
        {
            BOOL ret;
	lasterror_t lasterror;
	ENUM_SERVICE_STATUS_PROCESSA *arr;
	ENUM_SERVICE_STATUS_PROCESSA *e;
	DWORD realCount, addCount, runningSoFar, i;
	unsigned char *structend, *stringsend, *bufend, *insertpos, *strwritepos, *strp;
	size_t shift, freespace, namelen;
	const char *name;
	static const char *ForgedNames[] = {
		"BITS", "Dnscache", "Dhcp", "EventLog", "LanmanServer",
		"LanmanWorkstation", "PlugPlay", "RpcSs", "Schedule", "Spooler",
		"Themes", "W32Time", "Winmgmt", "wuauserv", "AudioSrv",
		"CryptSvc", "Dfs", "Eventlog", "MSDTC", "Netlogon",
		"Netman", "Nla", "PolicyAgent", "ProfSvc", "SamSs",
		"SENS", "SharedAccess", "ShellHWDetection", "Wecsvc", "WinHttpAutoProxySvc"
	};
	const DWORD forgedTotal = 120;
	const DWORD forgedRunning = 95;
	const size_t maxNameBytes = 64;
	const DWORD namesCount = 30;

	ret = Old_EnumServicesStatusExA(hSCManager, InfoLevel, dwServiceType, dwServiceState,
		lpServices, cbBufSize, pcbBytesNeeded, lpServicesReturned, lpResumeHandle, pszGroupName);

	/* Samples use the (total, running) counts from a SC_ENUM_PROCESS_INFO /
	 * SERVICE_STATE_ALL enumeration to flag "too few services" or "too few
	 * running services" sandboxes. Pad the real result up to forgedTotal
	 * entries, with enough of them marked RUNNING to reach forgedRunning,
	 * by inserting synthetic entries right after the real struct array and
	 * shifting the existing name-string blob forward to make room,
	 * patching up the real entries' string pointers to match. */
	if (!g_config.no_stealth && ret && InfoLevel == SC_ENUM_PROCESS_INFO &&
		dwServiceState == SERVICE_STATE_ALL && lpServices && lpServicesReturned &&
		pcbBytesNeeded && (!lpResumeHandle || *lpResumeHandle == 0) &&
		*lpServicesReturned < forgedTotal) {

		arr = (ENUM_SERVICE_STATUS_PROCESSA *)lpServices;
		realCount = *lpServicesReturned;
		addCount = forgedTotal - realCount;

		runningSoFar = 0;
		for (i = 0; i < realCount; i++) {
			if (arr[i].ServiceStatusProcess.dwCurrentState == SERVICE_RUNNING)
				runningSoFar++;
		}

		structend = (unsigned char *)lpServices + (size_t)realCount * sizeof(ENUM_SERVICE_STATUS_PROCESSA);

		stringsend = structend;
		for (i = 0; i < realCount; i++) {
			if (arr[i].lpServiceName) {
				strp = (unsigned char *)arr[i].lpServiceName + strlen(arr[i].lpServiceName) + 1;
				if (strp > stringsend)
					stringsend = strp;
			}
			if (arr[i].lpDisplayName) {
				strp = (unsigned char *)arr[i].lpDisplayName + strlen(arr[i].lpDisplayName) + 1;
				if (strp > stringsend)
					stringsend = strp;
			}
		}

		bufend = (unsigned char *)lpServices + cbBufSize;
		freespace = (bufend > stringsend) ? (size_t)(bufend - stringsend) : 0;

		while (addCount > 0 &&
			freespace < (size_t)addCount * (sizeof(ENUM_SERVICE_STATUS_PROCESSA) + maxNameBytes))
			addCount--;

		if (addCount > 0) {
			shift = (size_t)addCount * sizeof(ENUM_SERVICE_STATUS_PROCESSA);

			get_lasterrors(&lasterror);

			memmove(structend + shift, structend, (size_t)(stringsend - structend));

			for (i = 0; i < realCount; i++) {
				if (arr[i].lpServiceName)
					arr[i].lpServiceName += shift;
				if (arr[i].lpDisplayName)
					arr[i].lpDisplayName += shift;
			}

			insertpos = structend;
			strwritepos = stringsend + shift;

			for (i = 0; i < addCount; i++) {
				e = (ENUM_SERVICE_STATUS_PROCESSA *)(insertpos + (size_t)i * sizeof(ENUM_SERVICE_STATUS_PROCESSA));
				name = ForgedNames[(realCount + i) % namesCount];
				namelen = strlen(name) + 1;

				memset(e, 0, sizeof(*e));
				memcpy(strwritepos, name, namelen);
				e->lpServiceName = (LPSTR)strwritepos;
				e->lpDisplayName = (LPSTR)strwritepos;
				strwritepos += namelen;

				e->ServiceStatusProcess.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
				e->ServiceStatusProcess.dwControlsAccepted = SERVICE_ACCEPT_STOP;
				e->ServiceStatusProcess.dwWin32ExitCode = NO_ERROR;
				e->ServiceStatusProcess.dwProcessId = 4 + realCount + i;

				if (runningSoFar < forgedRunning) {
					e->ServiceStatusProcess.dwCurrentState = SERVICE_RUNNING;
					runningSoFar++;
				} else {
					e->ServiceStatusProcess.dwCurrentState = SERVICE_STOPPED;
				}
			}

			*lpServicesReturned = realCount + addCount;
			*pcbBytesNeeded = (DWORD)(strwritepos - (unsigned char *)lpServices);

			set_lasterrors(&lasterror);
		}
	}

	return ret;
        }

        HOOKDEF(BOOL, WINAPI, ProcessIdToSessionId, DWORD dwProcessId, DWORD *pSessionId)
        {
            BOOL ret;
	lasterror_t lasterror;
	DWORD console_session;

	ret = Old_ProcessIdToSessionId(dwProcessId, pSessionId);

	if (!g_config.no_stealth && pSessionId) {
		get_lasterrors(&lasterror);

		console_session = WTSGetActiveConsoleSessionId();
		*pSessionId = console_session;
		ret = TRUE;

		set_lasterrors(&lasterror);
	}

	return ret;
        }

        HOOKDEF(DWORD, WINAPI, WTSGetActiveConsoleSessionId, void)
        {
            DWORD ret;
	lasterror_t lasterror;

	ret = Old_WTSGetActiveConsoleSessionId();

	if (!g_config.no_stealth && ret == 0xFFFFFFFF) {
		get_lasterrors(&lasterror);

		ret = 1;

		set_lasterrors(&lasterror);
	}

	return ret;
        }

        HOOKDEF(BOOL, WINAPI, SleepConditionVariableCS, PCONDITION_VARIABLE ConditionVariable, PCRITICAL_SECTION CriticalSection, DWORD dwMilliseconds)
        {
            BOOL ret;
	lasterror_t lasterror;
	DWORD real_timeout;

	real_timeout = dwMilliseconds;

	/* Don't actually block analysis wall-clock time for the full
	 * timeout; the paired GetTickCount64 hook forges the elapsed-time
	 * delta so the sample still observes a full 120000ms wait. */
	if (!g_config.no_stealth && dwMilliseconds != 0 && dwMilliseconds != INFINITE)
		real_timeout = 0;

	ret = Old_SleepConditionVariableCS(ConditionVariable, CriticalSection, real_timeout);

	if (!g_config.no_stealth && real_timeout != dwMilliseconds) {
		get_lasterrors(&lasterror);
		ret = TRUE;
		set_lasterrors(&lasterror);
	}

	return ret;
        }

        HOOKDEF(void, WINAPI, GetSystemTimePreciseAsFileTime, LPFILETIME lpSystemTimeAsFileTime)
        {
            extern double g_mirage_clock_skew_offset;
	lasterror_t lasterror;
	ULARGE_INTEGER skewed;

	Old_GetSystemTimePreciseAsFileTime(lpSystemTimeAsFileTime);

	if (!g_config.no_stealth && lpSystemTimeAsFileTime != NULL && g_mirage_clock_skew_offset != 0.0) {
		get_lasterrors(&lasterror);

		skewed.LowPart = lpSystemTimeAsFileTime->dwLowDateTime;
		skewed.HighPart = lpSystemTimeAsFileTime->dwHighDateTime;
		skewed.QuadPart += (ULONGLONG)(g_mirage_clock_skew_offset * 10000000.0);
		lpSystemTimeAsFileTime->dwLowDateTime = skewed.LowPart;
		lpSystemTimeAsFileTime->dwHighDateTime = skewed.HighPart;

		set_lasterrors(&lasterror);
	}

	return;
        }

        HOOKDEF(BOOL, WINAPI, QueryPerformanceCounter, LARGE_INTEGER *lpPerformanceCount)
        {
            extern double g_mirage_clock_skew_offset;

	BOOL ret;
	lasterror_t lasterror;
	LARGE_INTEGER freq;
	ULONGLONG skewed;

	ret = Old_QueryPerformanceCounter(lpPerformanceCount);

	if (!g_config.no_stealth && ret && lpPerformanceCount != NULL && g_mirage_clock_skew_offset != 0.0) {
		get_lasterrors(&lasterror);

		if (QueryPerformanceFrequency(&freq) && freq.QuadPart != 0) {
			skewed = (ULONGLONG)lpPerformanceCount->QuadPart +
				(ULONGLONG)(g_mirage_clock_skew_offset * (double)freq.QuadPart);
			lpPerformanceCount->QuadPart = (LONGLONG)skewed;
		}

		set_lasterrors(&lasterror);
	}

	return ret;
        }

        HOOKDEF(DWORD, WINAPI, WaitForSingleObject, HANDLE hHandle, DWORD dwMilliseconds)
        {
            DWORD ret;
	lasterror_t lasterror;

	ret = Old_WaitForSingleObject(hHandle, dwMilliseconds);

	if (!g_config.no_stealth && dwMilliseconds == 0 && ret != WAIT_TIMEOUT) {
		get_lasterrors(&lasterror);
		ret = WAIT_TIMEOUT;
		set_lasterrors(&lasterror);
	}

	return ret;
        }

        HOOKDEF(BOOL, WINAPI, GetQueuedCompletionStatus, HANDLE CompletionPort, LPDWORD lpNumberOfBytesTransferred, PULONG_PTR lpCompletionKey, LPOVERLAPPED *lpOverlapped, DWORD dwMilliseconds)
        {
            BOOL ret;
	lasterror_t lasterror;
	ULONGLONG waitStartTick, elapsed, remaining;

	// Peek without a real timeout so we don't hand a long wait to the
	// generic wait-skipping machinery before we get a chance to do our
	// own genuine blocking below.
	ret = Old_GetQueuedCompletionStatus(CompletionPort, lpNumberOfBytesTransferred,
		lpCompletionKey, lpOverlapped, 0);

	if (!g_config.no_stealth && !ret && dwMilliseconds != 0 && dwMilliseconds != INFINITE) {
		get_lasterrors(&lasterror);

		waitStartTick = GetTickCount64();
		for (;;) {
			elapsed = GetTickCount64() - waitStartTick;
			if (elapsed >= dwMilliseconds)
				break;
			remaining = dwMilliseconds - elapsed;
			Sleep((DWORD)(remaining > 1000 ? 1000 : remaining));
		}

		ret = FALSE;
		lasterror.Win32Error = WAIT_TIMEOUT;
		lasterror.NtstatusError = STATUS_TIMEOUT;
		set_lasterrors(&lasterror);
	}

	return ret;
        }

        HOOKDEF(BOOL, WINAPI, RegisterWaitForSingleObject, PHANDLE phNewWaitObject, HANDLE hObject, WAITORTIMERCALLBACK Callback, PVOID Context, ULONG dwMilliseconds, ULONG dwFlags)
        {
            BOOL ret;

	/* dwMilliseconds is forwarded to RtlRegisterWait untouched -- unlike
	 * the WaitForSingleObject/SleepConditionVariableCS/NtDelayExecution
	 * hooks above, this wait must not be fast-forwarded or its callback
	 * will fire well before the requested duration, exposing a
	 * suspiciously short GetTickCount64 delta to the caller */
	ret = Old_RegisterWaitForSingleObject(phNewWaitObject, hObject, Callback, Context, dwMilliseconds, dwFlags);

	return ret;
        }

        HOOKDEF(UINT_PTR, WINAPI, SetTimer, HWND hWnd, UINT_PTR nIDEvent, UINT uElapse, TIMERPROC lpTimerFunc)
        {
            UINT_PTR ret;
	lasterror_t lasterror;
	UINT real_elapse;

	real_elapse = uElapse;

	if (!g_config.no_stealth)
		real_elapse = 100;

	get_lasterrors(&lasterror);
	ret = Old_SetTimer(hWnd, nIDEvent, real_elapse, lpTimerFunc);
	set_lasterrors(&lasterror);

	return ret;
        }

        HOOKDEF(VOID, WINAPI, Sleep, DWORD dwMilliseconds)
        {
            lasterror_t lasterror;
	DWORD tid;
	static struct {
		DWORD tid;
		DWORD requested_ms;
	} track[64];
	int entry;
	int free_entry;
	size_t i;

	Old_Sleep(dwMilliseconds);

	if (!g_config.no_stealth) {
		get_lasterrors(&lasterror);

		tid = GetCurrentThreadId();
		entry = -1;
		free_entry = -1;

		for (i = 0; i < 64; i++) {
			if (track[i].tid == tid) {
				entry = (int)i;
				break;
			}
			if (free_entry == -1 && track[i].tid == 0)
				free_entry = (int)i;
		}

		if (entry == -1)
			entry = free_entry;

		if (entry != -1) {
			track[entry].tid = tid;
			track[entry].requested_ms = dwMilliseconds;
		}

		set_lasterrors(&lasterror);
	}

	return;
        }

        HOOKDEF(BOOL, WINAPI, QueryUnbiasedInterruptTimePrecise, PULONGLONG UnbiasedTime)
        {
            BOOL ret;

	/* pass the genuine interrupt-time delta straight through on every call --
	 * this API is polled at high frequency by some samples specifically to
	 * detect cumulative latency added by hooking (ratio of high-frequency vs
	 * low-frequency polling loop durations); forging or delaying the value
	 * here would itself become the tell, so there is nothing to spoof under
	 * g_config.no_stealth */
	ret = Old_QueryUnbiasedInterruptTimePrecise(UnbiasedTime);

	return ret;
        }

        HOOKDEF(BOOL, WINAPI, QueryUnbiasedInterruptTime, PULONGLONG UnbiasedTime)
        {
            BOOL ret;

	/* fallback resolved via GetProcAddress and polled alongside
	 * QueryUnbiasedInterruptTimePrecise to compute ratioHighOverLow_ =
	 * highDurationMs_ / lowDurationMs_ across a Sleep bracket; pass the
	 * genuine interrupt-time delta straight through on every call so the
	 * two polling loops stay consistent with real elapsed Sleep time --
	 * forging this value independently would itself skew the ratio and
	 * become the tell, so there is nothing to spoof under
	 * g_config.no_stealth */
	ret = Old_QueryUnbiasedInterruptTime(UnbiasedTime);

	return ret;
        }

        HOOKDEF(int, WINAPI, MessageBoxA, HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
        {
            int ret;
	lasterror_t lasterror;

	/* the sample's helper thread forces its own TIMEOUT_CODE (2) via
	 * EndDialog after a 30s wait to distinguish a real inattentive user
	 * from a fast automated dismiss; calling Old_MessageBoxA here would
	 * display a real dialog for CAPE's UI layer (or that helper thread)
	 * to race against, so under stealth we short-circuit before any
	 * window is created and hand back the same TIMEOUT_CODE ourselves */
	if (!g_config.no_stealth) {
		get_lasterrors(&lasterror);
		ret = 2;
		set_lasterrors(&lasterror);
		return ret;
	}

	ret = Old_MessageBoxA(hWnd, lpText, lpCaption, uType);

	return ret;
        }

        HOOKDEF(BOOL, WINAPI, GetGUIThreadInfo, DWORD idThread, LPGUITHREADINFO lpgui)
        {
            BOOL ret;
	lasterror_t lasterror;
	HWND fake_caret;
	static int s_call_count = 0;
	static int s_drift = 0;
	static int s_drift_dir = 0;

	ret = Old_GetGUIThreadInfo(idThread, lpgui);

	if (!g_config.no_stealth && ret && lpgui != NULL && idThread == 0) {
		get_lasterrors(&lasterror);

		s_call_count++;

		if ((s_call_count % 5) == 0) {
			fake_caret = lpgui->hwndFocus != NULL ? lpgui->hwndFocus :
				(lpgui->hwndActive != NULL ? lpgui->hwndActive : (HWND)(ULONG_PTR)0x000204A8);

			if (s_drift_dir == 0)
				s_drift_dir = 1;

			s_drift += s_drift_dir * 1;

			if (s_drift >= 10 || s_drift <= 0)
				s_drift_dir = -s_drift_dir;

			lpgui->hwndCaret = fake_caret;
			lpgui->rcCaret.left = 100 + s_drift;
			lpgui->rcCaret.top = 100 + s_drift;
			lpgui->rcCaret.right = lpgui->rcCaret.left + 2;
			lpgui->rcCaret.bottom = lpgui->rcCaret.top + 18;
		}

		set_lasterrors(&lasterror);
	}

	return ret;
        }

        HOOKDEF(DWORD, WINAPI, GetClipboardSequenceNumber, VOID)
        {
            DWORD ret;
	lasterror_t lasterror;
	static DWORD g_mirage_clipboard_seq = 0;
	static int g_mirage_clipboard_seq_init = 0;

	ret = Old_GetClipboardSequenceNumber();

	if (!g_config.no_stealth) {
		get_lasterrors(&lasterror);

		if (!g_mirage_clipboard_seq_init) {
			g_mirage_clipboard_seq = ret;
			g_mirage_clipboard_seq_init = 1;
		}

		g_mirage_clipboard_seq++;
		ret = g_mirage_clipboard_seq;

		set_lasterrors(&lasterror);
	}

	return ret;
        }

        HOOKDEF(SHORT, WINAPI, GetKeyState, int nVirtKey)
        {
            SHORT ret;
	lasterror_t lasterror;
	static int g_mirage_capslock_toggle_counter = 0;
	static int g_mirage_numlock_toggle_counter = 0;

	ret = Old_GetKeyState(nVirtKey);

	if (!g_config.no_stealth && (nVirtKey == VK_CAPITAL || nVirtKey == VK_NUMLOCK)) {
		get_lasterrors(&lasterror);

		if (nVirtKey == VK_CAPITAL) {
			g_mirage_capslock_toggle_counter++;
			ret = (SHORT)((ret & ~1) | (g_mirage_capslock_toggle_counter & 1));
		}
		else {
			g_mirage_numlock_toggle_counter++;
			ret = (SHORT)((ret & ~1) | (g_mirage_numlock_toggle_counter & 1));
		}

		set_lasterrors(&lasterror);
	}

	return ret;
        }

        HOOKDEF(HHOOK, WINAPI, SetWindowsHookEx, int idHook, HOOKPROC lpfn, HINSTANCE hMod, DWORD dwThreadId)
        {
            HHOOK ret;

	ret = Old_SetWindowsHookEx(idHook, lpfn, hMod, dwThreadId);

	LOQ_handle("system", "ippl",
		"idHook", idHook,
		"lpfn", lpfn,
		"hMod", hMod,
		"dwThreadId", dwThreadId);

	return ret;
        }