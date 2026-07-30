
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

/* ==== complete_hooks.py generated batch (all-free) ==== */

// -> hook_com.c に追加 | category="com" | winapi:COM
// REVIEW: 引数 pvReserved: 生バッファ(void*)。アドレスのみ記録。長さ引数と対にして 'b'(size_t,buf)/'S'(int,buf) 指定にすれば内容を人間可読で記録できる
HOOKDEF(HRESULT, WINAPI, CoInitialize, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_In_opt_ LPVOID pvReserved
) {
	HRESULT ret;
	ret = Old_CoInitialize(pvReserved);
	LOQ_hresult("com", "p", "VReserved", pvReserved);
	return ret;
}

// -> hook_com.c に追加 | category="com" | winapi:COM
// REVIEW: 引数 pvReserved: 生バッファ(void*)。アドレスのみ記録。長さ引数と対にして 'b'(size_t,buf)/'S'(int,buf) 指定にすれば内容を人間可読で記録できる
HOOKDEF(HRESULT, WINAPI, CoInitializeEx, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_In_opt_ LPVOID pvReserved,
	_In_ DWORD dwCoInit
) {
	HRESULT ret;
	ret = Old_CoInitializeEx(pvReserved, dwCoInit);
	LOQ_hresult("com", "pi", "VReserved", pvReserved, "CoInit", dwCoInit);
	return ret;
}

// -> hook_com.c に追加 | category="com" | winapi:COM
// REVIEW: 引数 pSecDesc: 型 PSECURITY_DESCRIPTOR は自動解釈不可(構造体等)。アドレスのみ記録。内容が重要なら該当メンバを手動でログ
// REVIEW: 引数 asAuthSvc: 型 SOLE_AUTHENTICATION_SERVICE* は自動解釈不可(構造体等)。アドレスのみ記録。内容が重要なら該当メンバを手動でログ
// REVIEW: 引数 pReserved1: 型 void* は自動解釈不可(構造体等)。アドレスのみ記録。内容が重要なら該当メンバを手動でログ
// REVIEW: 引数 pAuthList: 型 void* は自動解釈不可(構造体等)。アドレスのみ記録。内容が重要なら該当メンバを手動でログ
// REVIEW: 引数 pReserved3: 型 void* は自動解釈不可(構造体等)。アドレスのみ記録。内容が重要なら該当メンバを手動でログ
HOOKDEF(HRESULT, WINAPI, CoInitializeSecurity, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_In_opt_ PSECURITY_DESCRIPTOR pSecDesc,
	_In_ LONG cAuthSvc,
	_In_opt_ SOLE_AUTHENTICATION_SERVICE* asAuthSvc,
	_In_opt_ void* pReserved1,
	_In_ DWORD dwAuthnLevel,
	_In_ DWORD dwImpLevel,
	_In_opt_ void* pAuthList,
	_In_ DWORD dwCapabilities,
	_In_opt_ void* pReserved3
) {
	HRESULT ret;
	ret = Old_CoInitializeSecurity(pSecDesc, cAuthSvc, asAuthSvc, pReserved1, dwAuthnLevel, dwImpLevel, pAuthList, dwCapabilities, pReserved3);
	LOQ_hresult("com", "pippiipip", "SecDesc", pSecDesc, "CAuthSvc", cAuthSvc, "AsAuthSvc", asAuthSvc, "Reserved1", pReserved1, "AuthnLevel", dwAuthnLevel, "ImpLevel", dwImpLevel, "AuthList", pAuthList, "Capabilities", dwCapabilities, "Reserved3", pReserved3);
	return ret;
}

// -> hook_com.c に追加 | category="com" | winapi:COM
// REVIEW: 引数 pStm: 型 LPSTREAM は自動解釈不可(構造体等)。アドレスのみ記録。内容が重要なら該当メンバを手動でログ
// REVIEW: 引数 riid: 型 REFIID を i(int32)で仮記録。要確認
// REVIEW: 引数 pUnk: 型 LPUNKNOWN は自動解釈不可(構造体等)。アドレスのみ記録。内容が重要なら該当メンバを手動でログ
// REVIEW: 引数 pvDestContext: 生バッファ(void*)。アドレスのみ記録。長さ引数と対にして 'b'(size_t,buf)/'S'(int,buf) 指定にすれば内容を人間可読で記録できる
HOOKDEF(HRESULT, WINAPI, CoMarshalInterface, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_In_ LPSTREAM pStm,
	_In_ REFIID riid,
	_In_ LPUNKNOWN pUnk,
	_In_ DWORD dwDestContext,
	_In_opt_ LPVOID pvDestContext,
	_In_ DWORD mshlflags
) {
	HRESULT ret;
	ret = Old_CoMarshalInterface(pStm, riid, pUnk, dwDestContext, pvDestContext, mshlflags);
	LOQ_hresult("com", "pipipi", "Stm", pStm, "Riid", riid, "Unk", pUnk, "DestContext", dwDestContext, "VDestContext", pvDestContext, "Mshlflags", mshlflags);
	return ret;
}

// -> hook_com.c に追加 | category="com" | winapi:COM
// REVIEW: 引数 pStm: 型 LPSTREAM は自動解釈不可(構造体等)。アドレスのみ記録。内容が重要なら該当メンバを手動でログ
HOOKDEF(HRESULT, WINAPI, CoReleaseMarshalData, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_In_ LPSTREAM pStm
) {
	HRESULT ret;
	ret = Old_CoReleaseMarshalData(pStm);
	LOQ_hresult("com", "p", "Stm", pStm);
	return ret;
}

// -> hook_com.c に追加 | category="com" | winapi:COM
// REVIEW: 引数 pProxy: 型 IUnknown* は自動解釈不可(構造体等)。アドレスのみ記録。内容が重要なら該当メンバを手動でログ
// REVIEW: 引数 pServerPrincName: 型 OLECHAR* は自動解釈不可(構造体等)。アドレスのみ記録。内容が重要なら該当メンバを手動でログ
// REVIEW: 引数 pAuthInfo: 型 RPC_AUTH_IDENTITY_HANDLE を i(int32)で仮記録。要確認
HOOKDEF(HRESULT, WINAPI, CoSetProxyBlanket, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_In_ IUnknown* pProxy,
	_In_ DWORD dwAuthnSvc,
	_In_ DWORD dwAuthzSvc,
	_In_opt_ OLECHAR* pServerPrincName,
	_In_ DWORD dwAuthnLevel,
	_In_ DWORD dwImpLevel,
	_In_opt_ RPC_AUTH_IDENTITY_HANDLE pAuthInfo,
	_In_ DWORD dwCapabilities
) {
	HRESULT ret;
	ret = Old_CoSetProxyBlanket(pProxy, dwAuthnSvc, dwAuthzSvc, pServerPrincName, dwAuthnLevel, dwImpLevel, pAuthInfo, dwCapabilities);
	LOQ_hresult("com", "piipiiii", "Proxy", pProxy, "AuthnSvc", dwAuthnSvc, "AuthzSvc", dwAuthzSvc, "ServerPrincName", pServerPrincName, "AuthnLevel", dwAuthnLevel, "ImpLevel", dwImpLevel, "AuthInfo", pAuthInfo, "Capabilities", dwCapabilities);
	return ret;
}

// -> hook_com.c に追加 | category="com" | winapi:COM
HOOKDEF(LPVOID, WINAPI, CoTaskMemAlloc, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_In_ SIZE_T cb
) {
	LPVOID ret;
	ret = Old_CoTaskMemAlloc(cb);
	LOQ_nonnull("com", "i", "cb", cb);
	return ret;
}

// -> hook_com.c に追加 | category="com" | winapi:COM
// REVIEW: 引数 pv: 生バッファ(void*)。アドレスのみ記録。長さ引数と対にして 'b'(size_t,buf)/'S'(int,buf) 指定にすれば内容を人間可読で記録できる
HOOKDEF(void, WINAPI, CoTaskMemFree, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_In_opt_ LPVOID pv
) {
	ULONG_PTR ret = 0; (void)ret;  // void 関数: LOQ 用ダミー
	Old_CoTaskMemFree(pv);
	LOQ_void("com", "p", "V", pv);
}

// -> hook_com.c に追加 | category="com" | winapi:COM
HOOKDEF(void, WINAPI, CoUninitialize, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	void
) {
	ULONG_PTR ret = 0; (void)ret;  // void 関数: LOQ 用ダミー
	Old_CoUninitialize();
	LOQ_void("com", "");
}

// -> hook_com.c に追加 | category="com" | winapi:COM
// REVIEW: 引数 pStm: 型 LPSTREAM は自動解釈不可(構造体等)。アドレスのみ記録。内容が重要なら該当メンバを手動でログ
// REVIEW: 引数 riid: 型 REFIID を i(int32)で仮記録。要確認
// REVIEW: 引数 ppv: 生バッファ(void*)。アドレスのみ記録。長さ引数と対にして 'b'(size_t,buf)/'S'(int,buf) 指定にすれば内容を人間可読で記録できる
HOOKDEF(HRESULT, WINAPI, CoUnmarshalInterface, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_In_ LPSTREAM pStm,
	_In_ REFIID riid,
	_Out_ LPVOID* ppv
) {
	HRESULT ret;
	ret = Old_CoUnmarshalInterface(pStm, riid, ppv);
	LOQ_hresult("com", "pip", "Stm", pStm, "Riid", riid, "Pv", ppv);
	return ret;
}

// -> hook_com.c に追加 | category="com" | winapi:Device Context
HOOKDEF(HDC, WINAPI, CreateCompatibleDC, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_In_ HDC hdc
) {
	HDC ret;
	ret = Old_CreateCompatibleDC(hdc);
	LOQ_nonnull("com", "p", "Dc", hdc);
	return ret;
}

// -> hook_com.c に追加 | category="com" | winapi:Print Spooler
// REVIEW: 引数 pPrinterEnum: 生バッファ(void*)。アドレスのみ記録。長さ引数と対にして 'b'(size_t,buf)/'S'(int,buf) 指定にすれば内容を人間可読で記録できる
HOOKDEF(BOOL, WINAPI, EnumPrintersW, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_In_ DWORD Flags,
	_In_ LPWSTR Name,
	_In_ DWORD Level,
	_Out_ LPBYTE pPrinterEnum,
	_In_ DWORD cbBuf,
	_Out_ LPDWORD pcbNeeded,
	_Out_ LPDWORD pcReturned
) {
	BOOL ret;
	ret = Old_EnumPrintersW(Flags, Name, Level, pPrinterEnum, cbBuf, pcbNeeded, pcReturned);
	LOQ_bool("com", "iuipiII", "Flags", Flags, "Name", Name, "Level", Level, "PrinterEnum", pPrinterEnum, "Buf", cbBuf, "CbNeeded", pcbNeeded, "CReturned", pcReturned);
	return ret;
}

// -> hook_com.c に追加 | category="com" | winapi:COM
// REVIEW: 引数 rclsid: 型 REFIID を i(int32)で仮記録。要確認
HOOKDEF(HRESULT, WINAPI, StringFromIID, // 呼出規約は WINAPI 仮定(socket/native/CRT系は要確認)
	_In_ REFIID rclsid,
	_Out_ LPOLESTR* lplpsz
) {
	HRESULT ret;
	ret = Old_StringFromIID(rclsid, lplpsz);
	LOQ_hresult("com", "iP", "Rclsid", rclsid, "Lpsz", lplpsz);
	return ret;
}
