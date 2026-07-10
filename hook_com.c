
#include "hooking.h"
#include "log.h"
#include "CAPE\CAPE.h"
#include <Wbemidl.h>

BOOL ContainsNamespace(const wchar_t* resource, const wchar_t* target) {
	/*
	* Basically case insensitive strstr except we don't care about forward/backward slashes.
	* Used for namespace checks in WbemLocator_ConnectServer
	*/
	if (!resource || !target) {
		return FALSE;
	}

	// Iterate through the resource string to find a starting match point
	for (; *resource; ++resource) {
		const wchar_t* h = resource; // Haystack pointer
		const wchar_t* n = target;   // Needle pointer

		// Attempt to match the target string from the current position
		while (*h && *n) {
			BOOL isSlashMatch = (*h == L'/' || *h == L'\\') && (*n == L'/' || *n == L'\\');
			if (isSlashMatch || (towlower(*h) == towlower(*n))) {
				h++;
				n++;
			}
			else {
				// Break on mismatch
				break;
			}
		}

		// If we reached the end of the target string, it's a successful match
		if (*n == L'\0') {
			return TRUE;
		}
	}

	return FALSE;
}

__declspec(thread) BOOL bHookViaWbemLocator;
HOOKDEF(HRESULT, WINAPI, WbemLocator_ConnectServer,
	_In_	PVOID			_this,
	_In_	const BSTR		strNetworkResource,
	_In_	const BSTR		strUser,
	_In_	const BSTR		strPassword,
	_In_	const BSTR		strLocale,
	_In_	long			lSecurityFlags,
	_In_	const BSTR		strAuthority,
	_In_	IWbemContext	*pCtx,
	_Out_	IWbemServices	**ppNamespace
) {
	HRESULT ret;
	ret = Old_WbemLocator_ConnectServer(_this, strNetworkResource, strUser, strPassword, strLocale, lSecurityFlags, strAuthority, pCtx, ppNamespace);

	if (ret == S_OK && (
		ContainsNamespace(strNetworkResource, L"ROOT\\CIMV2") ||
		ContainsNamespace(strNetworkResource, L"ROOT\\SecurityCenter2") ||
		ContainsNamespace(strNetworkResource, L"ROOT\\Microsoft\\Windows\\Defender") ||
		ContainsNamespace(strNetworkResource, L"ROOT\\subscription") ||
		ContainsNamespace(strNetworkResource, L"ROOT\\Microsoft\\Windows\\TaskScheduler")
	)) 
	{
		bHookViaWbemLocator = TRUE;
		set_com_hooks(NULL, NULL, *ppNamespace);
		bHookViaWbemLocator = FALSE;
	}

	LOQ_hresult("com", "uu", "NetworkResource", strNetworkResource, "User", strUser);
	return ret;
}

HOOKDEF(HRESULT, WINAPI, CoInitialize,
	_In_opt_ LPVOID pvReserved
) {
	HRESULT ret;
	ret = Old_CoInitialize(pvReserved);
	if (ret == S_OK) {
		set_com_hooks(NULL, NULL, NULL);
	}
	LOQ_hresult("com", "p", "Reserved", pvReserved);
	return ret;
}

HOOKDEF(HRESULT, WINAPI, CoInitializeEx,
	_In_opt_ LPVOID pvReserved,
	_In_ DWORD dwCoInit
) {
	HRESULT ret;
	ret = Old_CoInitializeEx(pvReserved, dwCoInit);
	if (ret == S_OK) {
		set_com_hooks(NULL, NULL, NULL);
	}
	LOQ_hresult("com", "ph", "Reserved", pvReserved, "CoInit", dwCoInit);
	return ret;
}

HOOKDEF(HRESULT, WINAPI, CoInitializeSecurity,
	_In_opt_ PSECURITY_DESCRIPTOR pSecDesc,
	_In_ LONG cAuthSvc,
	_In_opt_ SOLE_AUTHENTICATION_SERVICE *asAuthSvc,
	_In_opt_ void *pReserved1,
	_In_ DWORD dwAuthnLevel,
	_In_ DWORD dwImpLevel,
	_In_opt_ void *pAuthList,
	_In_ DWORD dwCapabilities,
	_In_opt_ void *pReserved3
) {
	HRESULT ret;
	ret = Old_CoInitializeSecurity(pSecDesc, cAuthSvc, asAuthSvc, pReserved1, dwAuthnLevel, dwImpLevel, pAuthList, dwCapabilities, pReserved3);
	if (ret == S_OK) {
		set_com_hooks(NULL, NULL, NULL);
	}
	LOQ_hresult("com", "pipphhphp", "SecDesc", pSecDesc, "cAuthSvc", cAuthSvc, "asAuthSvc", asAuthSvc, "Reserved1", pReserved1, "AuthnLevel", dwAuthnLevel, "ImpLevel", dwImpLevel, "AuthList", pAuthList, "Capabilities", dwCapabilities, "Reserved3", pReserved3);
	return ret;
}

HOOKDEF(HRESULT, WINAPI, CoSetProxyBlanket,
	_In_ IUnknown *pProxy,
	_In_ DWORD dwAuthnSvc,
	_In_ DWORD dwAuthzSvc,
	_In_opt_ OLECHAR *pServerPrincName,
	_In_ DWORD dwAuthnLevel,
	_In_ DWORD dwImpLevel,
	_In_opt_ RPC_AUTH_IDENTITY_HANDLE pAuthInfo,
	_In_ DWORD dwCapabilities
) {
	HRESULT ret;
	ret = Old_CoSetProxyBlanket(pProxy, dwAuthnSvc, dwAuthzSvc, pServerPrincName, dwAuthnLevel, dwImpLevel, pAuthInfo, dwCapabilities);
	if (ret == S_OK) {
		set_com_hooks(NULL, NULL, NULL);
	}
	LOQ_hresult("com", "phhuhhph", "Proxy", pProxy, "AuthnSvc", dwAuthnSvc, "AuthzSvc", dwAuthzSvc, "ServerPrincName", pServerPrincName, "AuthnLevel", dwAuthnLevel, "ImpLevel", dwImpLevel, "AuthInfo", pAuthInfo, "Capabilities", dwCapabilities);
	return ret;
}

HOOKDEF(void, WINAPI, CoTaskMemFree,
	_In_opt_ LPVOID pv
) {
	int ret = 0;
	Old_CoTaskMemFree(pv);
	// CoTaskMemFree returns void and does not create a COM object,
	// so no set_com_hooks() here. Log the freed pointer only.
	LOQ_void("com", "p", "Mem", pv);
	return;
}

HOOKDEF(void, WINAPI, CoUninitialize,
	void
) {
	int ret = 0;
	Old_CoUninitialize();
	// void return; COM is being torn down, so no set_com_hooks() here.
	LOQ_void("com", "");
	return;
}


// ---- priority-high spec hooks (auto-generated from hook_spec_priority_high.jsonl) ----

HOOKDEF(HRESULT, WINAPI, CreateBindCtx,
	DWORD reserved,
	PVOID ppbc
) {
	HRESULT ret;
	ret = Old_CreateBindCtx(reserved, ppbc);
	LOQ_hresult("com", "hp", "reserved", reserved, "ppbc", ppbc);
	return ret;
}

HOOKDEF(HRESULT, WINAPI, OleInitialize,
	PVOID pvReserved
) {
	HRESULT ret;
	ret = Old_OleInitialize(pvReserved);
	LOQ_hresult("com", "p", "pvReserved", pvReserved);
	return ret;
}

HOOKDEF(void, WINAPI, OleUninitialize,
	void
) {
	int ret = 0;
	Old_OleUninitialize();
	LOQ_void("com", "");
	return;
}

HOOKDEF(HRESULT, WINAPI, PropVariantClear,
	PVOID pvar
) {
	HRESULT ret;
	ret = Old_PropVariantClear(pvar);
	LOQ_hresult("com", "p", "pvar", pvar);
	return ret;
}

HOOKDEF(void, WINAPI, PropVariantInit,
	PVOID pvar
) {
	int ret = 0;
	Old_PropVariantInit(pvar);
	LOQ_void("com", "p", "pvar", pvar);
	return;
}

HOOKDEF(int, WINAPI, StringFromGUID2,
	PVOID rguid,
	LPCWSTR lpsz,
	int cchMax
) {
	int ret;
	ret = Old_StringFromGUID2(rguid, lpsz, cchMax);
	LOQ_nonzero("com", "pui", "rguid", rguid, "lpsz", lpsz, "cchMax", cchMax);
	return ret;
}

HOOKDEF(PVOID, WINAPI, ILCombine,
	PVOID pidl1,
	PVOID pidl2
) {
	PVOID ret;
	ret = Old_ILCombine(pidl1, pidl2);
	LOQ_nonnull("com", "pp", "pidl1", pidl1, "pidl2", pidl2);
	return ret;
}

HOOKDEF(void, WINAPI, ILFree,
	PVOID pidl
) {
	int ret = 0;
	Old_ILFree(pidl);
	LOQ_void("com", "p", "pidl", pidl);
	return;
}

HOOKDEF(HRESULT, WINAPI, SHBindToObject,
	PVOID psf,
	PVOID pidl,
	PVOID pbc,
	PVOID riid,
	PVOID ppv
) {
	HRESULT ret;
	ret = Old_SHBindToObject(psf, pidl, pbc, riid, ppv);
	LOQ_hresult("com", "ppppp", "psf", psf, "pidl", pidl, "pbc", pbc, "riid", riid, "ppv", ppv);
	return ret;
}

HOOKDEF(HRESULT, WINAPI, SHCreateItemFromIDList,
	PVOID pidl,
	PVOID riid,
	PVOID ppv
) {
	HRESULT ret;
	ret = Old_SHCreateItemFromIDList(pidl, riid, ppv);
	LOQ_hresult("com", "ppp", "pidl", pidl, "riid", riid, "ppv", ppv);
	return ret;
}

HOOKDEF(HRESULT, WINAPI, SHCreateItemFromParsingName,
	LPCWSTR pszPath,
	PVOID pbc,
	PVOID riid,
	PVOID ppv
) {
	HRESULT ret;
	ret = Old_SHCreateItemFromParsingName(pszPath, pbc, riid, ppv);
	LOQ_hresult("com", "uppp", "pszPath", pszPath, "pbc", pbc, "riid", riid, "ppv", ppv);
	return ret;
}

HOOKDEF(HRESULT, WINAPI, SHCreateItemWithParent,
	PVOID pidlParent,
	PVOID psfParent,
	PVOID pidl,
	PVOID riid,
	PVOID ppvItem
) {
	HRESULT ret;
	ret = Old_SHCreateItemWithParent(pidlParent, psfParent, pidl, riid, ppvItem);
	LOQ_hresult("com", "ppppp", "pidlParent", pidlParent, "psfParent", psfParent, "pidl", pidl, "riid", riid, "ppvItem", ppvItem);
	return ret;
}

HOOKDEF(HRESULT, WINAPI, SHGetDesktopFolder,
	PVOID ppshf
) {
	HRESULT ret;
	ret = Old_SHGetDesktopFolder(ppshf);
	LOQ_hresult("com", "p", "ppshf", ppshf);
	return ret;
}

HOOKDEF(HRESULT, WINAPI, SHGetFolderLocation,
	HWND hwnd,
	int csidl,
	HANDLE hToken,
	DWORD dwFlags,
	PVOID ppidl
) {
	HRESULT ret;
	ret = Old_SHGetFolderLocation(hwnd, csidl, hToken, dwFlags, ppidl);
	LOQ_hresult("com", "piphp", "hwnd", hwnd, "csidl", csidl, "hToken", hToken, "dwFlags", dwFlags, "ppidl", ppidl);
	return ret;
}

HOOKDEF(HRESULT, WINAPI, SHGetFolderPathA,
	HWND hwnd,
	int csidl,
	HANDLE hToken,
	DWORD dwFlags,
	LPCSTR pszPath
) {
	HRESULT ret;
	ret = Old_SHGetFolderPathA(hwnd, csidl, hToken, dwFlags, pszPath);
	LOQ_hresult("com", "piphs", "hwnd", hwnd, "csidl", csidl, "hToken", hToken, "dwFlags", dwFlags, "pszPath", pszPath);
	return ret;
}

HOOKDEF(HRESULT, WINAPI, SHGetKnownFolderIDList,
	PVOID rfid,
	DWORD dwFlags,
	HANDLE hToken,
	PVOID ppidl
) {
	HRESULT ret;
	ret = Old_SHGetKnownFolderIDList(rfid, dwFlags, hToken, ppidl);
	LOQ_hresult("com", "phpp", "rfid", rfid, "dwFlags", dwFlags, "hToken", hToken, "ppidl", ppidl);
	return ret;
}

HOOKDEF(BOOL, WINAPI, SHGetPathFromIDListA,
	PVOID pidl,
	LPCSTR pszPath
) {
	BOOL ret;
	ret = Old_SHGetPathFromIDListA(pidl, pszPath);
	LOQ_bool("com", "ps", "pidl", pidl, "pszPath", pszPath);
	return ret;
}

HOOKDEF(BOOL, WINAPI, SHGetPathFromIDListW,
	PVOID pidl,
	LPCWSTR pszPath
) {
	BOOL ret;
	ret = Old_SHGetPathFromIDListW(pidl, pszPath);
	LOQ_bool("com", "pu", "pidl", pidl, "pszPath", pszPath);
	return ret;
}

HOOKDEF(HRESULT, WINAPI, SHGetSpecialFolderLocation,
	HWND hwnd,
	int csidl,
	PVOID ppidl
) {
	HRESULT ret;
	ret = Old_SHGetSpecialFolderLocation(hwnd, csidl, ppidl);
	LOQ_hresult("com", "pip", "hwnd", hwnd, "csidl", csidl, "ppidl", ppidl);
	return ret;
}

HOOKDEF(BOOL, WINAPI, SHGetSpecialFolderPathA,
	HWND hwnd,
	LPCSTR pszPath,
	int csidl,
	BOOL fCreate
) {
	BOOL ret;
	ret = Old_SHGetSpecialFolderPathA(hwnd, pszPath, csidl, fCreate);
	LOQ_bool("com", "psii", "hwnd", hwnd, "pszPath", pszPath, "csidl", csidl, "fCreate", fCreate);
	return ret;
}

HOOKDEF(HRESULT, WINAPI, SHParseDisplayName,
	LPCWSTR pszName,
	PVOID pbc,
	PVOID ppidl,
	DWORD sfgaoIn,
	PVOID psfgaoOut
) {
	HRESULT ret;
	ret = Old_SHParseDisplayName(pszName, pbc, ppidl, sfgaoIn, psfgaoOut);
	LOQ_hresult("com", "upphp", "pszName", pszName, "pbc", pbc, "ppidl", ppidl, "sfgaoIn", sfgaoIn, "psfgaoOut", psfgaoOut);
	return ret;
}

HOOKDEF(HRESULT, WINAPI, SHQueryRecycleBin,
	LPCWSTR pszRootPath,
	PVOID pSHQueryRBInfo
) {
	HRESULT ret;
	ret = Old_SHQueryRecycleBin(pszRootPath, pSHQueryRBInfo);
	LOQ_hresult("com", "up", "pszRootPath", pszRootPath, "pSHQueryRBInfo", pSHQueryRBInfo);
	return ret;
}

HOOKDEF(HRESULT, WINAPI, SHQueryRecycleBinA,
	LPCSTR pszRootPath,
	PVOID pSHQueryRBInfo
) {
	HRESULT ret;
	ret = Old_SHQueryRecycleBinA(pszRootPath, pSHQueryRBInfo);
	LOQ_hresult("com", "sp", "pszRootPath", pszRootPath, "pSHQueryRBInfo", pSHQueryRBInfo);
	return ret;
}

HOOKDEF(HRESULT, WINAPI, SHQueryRecycleBinW,
	LPCWSTR pszRootPath,
	PVOID pSHQueryRBInfo
) {
	HRESULT ret;
	ret = Old_SHQueryRecycleBinW(pszRootPath, pSHQueryRBInfo);
	LOQ_hresult("com", "up", "pszRootPath", pszRootPath, "pSHQueryRBInfo", pSHQueryRBInfo);
	return ret;
}

HOOKDEF(HRESULT, WINAPI, StrRetToBufW,
	PVOID pstr,
	PVOID pidl,
	LPCWSTR pszBuf,
	UINT cchBuf
) {
	HRESULT ret;
	ret = Old_StrRetToBufW(pstr, pidl, pszBuf, cchBuf);
	LOQ_hresult("com", "ppuh", "pstr", pstr, "pidl", pidl, "pszBuf", pszBuf, "cchBuf", cchBuf);
	return ret;
}

HOOKDEF(HRESULT, WINAPI, SafeArrayDestroy,
	PVOID psa
) {
	HRESULT ret;
	ret = Old_SafeArrayDestroy(psa);
	LOQ_hresult("com", "p", "psa", psa);
	return ret;
}

HOOKDEF(HRESULT, WINAPI, SafeArrayGetElement,
	PVOID psa,
	PVOID rgIndices,
	PVOID pv
) {
	HRESULT ret;
	ret = Old_SafeArrayGetElement(psa, rgIndices, pv);
	LOQ_hresult("com", "ppp", "psa", psa, "rgIndices", rgIndices, "pv", pv);
	return ret;
}

HOOKDEF(HRESULT, WINAPI, SafeArrayGetLBound,
	PVOID psa,
	UINT nDim,
	PVOID plLbound
) {
	HRESULT ret;
	ret = Old_SafeArrayGetLBound(psa, nDim, plLbound);
	LOQ_hresult("com", "php", "psa", psa, "nDim", nDim, "plLbound", plLbound);
	return ret;
}

HOOKDEF(HRESULT, WINAPI, SafeArrayGetUBound,
	PVOID psa,
	UINT nDim,
	PVOID plUbound
) {
	HRESULT ret;
	ret = Old_SafeArrayGetUBound(psa, nDim, plUbound);
	LOQ_hresult("com", "php", "psa", psa, "nDim", nDim, "plUbound", plUbound);
	return ret;
}

HOOKDEF(PVOID, WINAPI, SysAllocString,
	LPCWSTR psz
) {
	PVOID ret;
	ret = Old_SysAllocString(psz);
	LOQ_nonnull("com", "u", "psz", psz);
	return ret;
}

HOOKDEF(UINT, WINAPI, SysStringLen,
	LPCWSTR bstr
) {
	UINT ret;
	ret = Old_SysStringLen(bstr);
	LOQ_nonzero("com", "u", "bstr", bstr);
	return ret;
}

HOOKDEF(HRESULT, WINAPI, VariantClear,
	PVOID pvarg
) {
	HRESULT ret;
	ret = Old_VariantClear(pvarg);
	LOQ_hresult("com", "p", "pvarg", pvarg);
	return ret;
}

HOOKDEF(void, WINAPI, VariantInit,
	PVOID pvarg
) {
	int ret = 0;
	Old_VariantInit(pvarg);
	LOQ_void("com", "p", "pvarg", pvarg);
	return;
}
