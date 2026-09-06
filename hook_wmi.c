#include "log.h"
#include "misc.h"
#include <Wbemidl.h>

void SpoofWmiData(const wchar_t* szClassName, const wchar_t* wszName, VARIANT* pVal) {
	if (g_config.no_stealth)
		return;

	if (!szClassName || !wszName || !pVal)
		return;

	//
	// Spoofery logic for BSTR (wchar_t *)
	//
	if (pVal->vt == VT_BSTR && pVal->bstrVal) {
		if (!_wcsicmp(pVal->bstrVal, L"Microsoft Basic Display Adapter")) {
			SysFreeString(pVal->bstrVal);
			pVal->bstrVal = SysAllocString(SPOOFED_GPU_NAME);
		}
		else if (!_wcsicmp(wszName, L"TotalPhysicalMemory")) {
			unsigned long long actualMemory = wcstoull(pVal->bstrVal, NULL, 10);
			if (actualMemory < SPOOFED_RAM) {
				SysFreeString(pVal->bstrVal);
				pVal->bstrVal = SysAllocString(WIDE_SPOOFED_RAM);
			}
		}
		else if (!_wcsicmp(wszName, L"TotalVisibleMemorySize")) {
			unsigned long long actualMemory = wcstoull(pVal->bstrVal, NULL, 10);
			// actualMemory is in Kilobytes, our spoofed values are in bytes
			if (actualMemory < (SPOOFED_RAM / 1024)) {
				SysFreeString(pVal->bstrVal);
				pVal->bstrVal = SysAllocString(WIDE_SPOOFED_RAM_IN_KB);
			}
		}
		//
		// Logic for BSTR fakery specific to an exact szClassName
		//
		else if (!_wcsicmp(szClassName, L"Win32_LogicalDisk") && !_wcsicmp(wszName, L"Size")) {
			unsigned long long lSize = wcstoull(pVal->bstrVal, NULL, 10);
			if (lSize < SPOOFED_DISK_SIZE - RECOVERY_PARTITION_SIZE) {
				SysFreeString(pVal->bstrVal);
				pVal->bstrVal = SysAllocString(WIDE_DISK_LOGICAL_SIZE);
			}
		}
		else if (!_wcsicmp(szClassName, L"Win32_PhysicalMemory") && !_wcsicmp(wszName, L"Capacity")) {
			unsigned long long actualMemory = wcstoull(pVal->bstrVal, NULL, 10);
			if (actualMemory < SPOOFED_RAM) {
				SysFreeString(pVal->bstrVal);
				pVal->bstrVal = SysAllocString(WIDE_SPOOFED_RAM);
			}
		}
	}
	//
	// Spoofery logic for I4 (Signed 32-bit integer)
	//
	else if (pVal->vt == VT_I4) {
		if (!_wcsicmp(szClassName, L"Win32_Processor") && !_wcsicmp(wszName, L"ThreadCount")) {
			if (pVal->lVal < SPOOFED_CPU_CORE_NUM)
				pVal->lVal = SPOOFED_CPU_CORE_NUM;
		}
		else if (!_wcsicmp(wszName, L"NumberOfCores")) {
			if (pVal->lVal < SPOOFED_CPU_CORE_NUM)
				pVal->lVal = SPOOFED_CPU_CORE_NUM;
		}
		else if (!_wcsicmp(wszName, L"NumberOfLogicalProcessors")) {
			if (pVal->lVal < SPOOFED_CPU_CORE_NUM)
				pVal->lVal = SPOOFED_CPU_CORE_NUM;
		}
		else if (!_wcsicmp(wszName, L"NumberOfEnabledCore")) {
			if (pVal->lVal < SPOOFED_CPU_CORE_NUM)
				pVal->lVal = SPOOFED_CPU_CORE_NUM;
		}
		else if (!_wcsicmp(wszName, L"AdapterRAM")) {
			if (SPOOFED_GPU_RAM > 0x7FFFFFFFULL) {
				// Mimic overflowing the I4 if you have >2GB of Spoofed GPU RAM
				pVal->lVal = 0x7FFFFFFF;
			}
			else {
				// Cast to LONG to avoid compiler warning if SPOOFED_GPU_RAM is >2GB
				if (pVal->lVal < (LONG)SPOOFED_GPU_RAM) {
					pVal->lVal = (LONG)SPOOFED_GPU_RAM;
				}
			}
		}
	}
	//
	// Spoofery logic for NULL
	//
	else if (pVal->vt == VT_NULL) {
		if (!_wcsicmp(wszName, L"SMBIOSBIOSVersion")) {
			pVal->vt = VT_BSTR;
			pVal->bstrVal = SysAllocString(L"1.23.1");
		}
	}
}

HOOKDEF(HRESULT, WINAPI, WMI_Get,
	_In_		PVOID	_this,
	_In_		LPCWSTR	wszName,
	_In_		LONG	lFlags,
	_Out_		VARIANT	*pVal,
	_Out_opt_	CIMTYPE	*pType,
	_Out_opt_	LONG	*plFlavor
)
{
/* flat capemon alias for IWbemClassObject::Get — the interface pointer
       is passed as the first argument (_this). This is a diagnostic-only
       fallback: the real countermeasure for WMI_Get failed to compile even
       after a repair attempt, so no transparency logic is applied here. Call
       the original, log the real property name / flags / returned VARIANT, and
       return the unmodified result. */
    HRESULT ret;

    ret = Old_WMI_Get(_this, wszName, lFlags, pVal, pType, plFlavor);

    LOQ_hresult("system", "uln", "PropertyName", wszName, "Flags", lFlags,
        "Value", pVal);

    return ret;
}

HOOKDEF(HRESULT, WINAPI, WMI_Next,
	_In_		PVOID	_this,
	_In_		LONG	lFlags,
	_Out_		BSTR	*strName,
	_Out_		VARIANT	*pVal,
	_Out_opt_	CIMTYPE	*pType,
	_Out_opt_	LONG	*plFlavor
)
{
/* Diagnostic-only fallback: this hook binds to CWbemObject::Next, i.e.
	   IWbemClassObject::Next (property enumeration — lFlags, strName, pVal,
	   pType, plFlavor), but the generated countermeasure was written against
	   IEnumWbemClassObject::Next (object enumeration — lTimeout, uCount,
	   ppOutParams, puReturned), a different interface whose parameters do not
	   exist in this signature. Applying that object-enumeration logic here would
	   misinterpret the arguments at runtime, so no transparency logic is applied:
	   call the original with the real property-enumeration arguments and return
	   the unmodified result verbatim. */
	HRESULT ret;

	ret = Old_WMI_Next(_this, lFlags, strName, pVal, pType, plFlavor);

	LOQ_hresult("system", "i", "Flags", (int)lFlags);
	return ret;
}

HOOKDEF(HRESULT, WINAPI, WMI_ExecQuery,
	_In_	PVOID					_this,
	_In_	const BSTR				strQueryLanguage,
	_In_	const BSTR				strQuery,
	_In_	LONG					lFlags,
	_In_	IWbemContext			*pCtx,
	_Out_	IEnumWbemClassObject	**ppEnum
)
{
HRESULT ret = 0;
	lasterror_t lasterror;
	BSTR forced_query;
	HRESULT sub;

	ret = Old_WMI_ExecQuery(_this, strQueryLanguage, strQuery, lFlags, pCtx, ppEnum);

	/* Samples enumerate registered AV products by connecting to the
	 * ROOT\SecurityCenter2 namespace and running
	 * "SELECT * FROM AntiVirusProduct" (or "SELECT displayName FROM
	 * AntiVirusProduct") via IWbemServices::ExecQuery, then walk the returned
	 * IEnumWbemClassObject with ::Next and read each object's 'displayName'
	 * with ::Get, testing that string against a commercial-AV vendor
	 * whitelist. On a freshly-imaged analysis VM the SecurityCenter2 query can
	 * fail outright (the class/namespace query errors, WBEM_E_INVALID_CLASS /
	 * WBEM_E_INVALID_NAMESPACE) or hand back no enumerator, so the caller's
	 * ::Next loop never starts and checkCondition() concludes there is no real
	 * third-party AV — its sandbox-detected branch. The companion WMI_Get hook
	 * already forces any 'displayName' read to a whitelisted, non-Defender
	 * vendor ("Norton Security"), but it needs at least one row for the ::Next
	 * loop to hand it. When the AntiVirusProduct query yields a failing or NULL
	 * enumerator, re-issue a guaranteed-non-empty query ("SELECT * FROM
	 * meta_class", the class-definition meta-query, which always returns at
	 * least one object in any namespace) on the same IWbemServices so *ppEnum
	 * is a valid, walkable, non-empty enumerator; the paired WMI_Next / WMI_Get
	 * hooks then supply the whitelisted 'Norton Security' displayName the loop
	 * reads. When the real query already returns an enumerator (e.g. a guest
	 * that registers Windows Defender in SecurityCenter2) it is passed through
	 * untouched and WMI_Get rewrites the displayName as before. lasterror is
	 * preserved around the forged response. */
	if (!g_config.no_stealth && strQuery != NULL && ppEnum != NULL &&
			wcsstr(strQuery, L"AntiVirusProduct") != NULL &&
			(FAILED(ret) || *ppEnum == NULL)) {
		get_lasterrors(&lasterror);

		forced_query = SysAllocString(L"SELECT * FROM meta_class");
		if (forced_query != NULL) {
			*ppEnum = NULL;
			sub = Old_WMI_ExecQuery(_this, strQueryLanguage, forced_query,
				lFlags, pCtx, ppEnum);
			if (SUCCEEDED(sub) && *ppEnum != NULL) {
				ret = S_OK;
				lasterror.Win32Error = ERROR_SUCCESS;
			}
			SysFreeString(forced_query);
		}

		set_lasterrors(&lasterror);
	}

	LOQ_hresult("system", "uu", "Query", strQuery, "QueryLanguage", strQueryLanguage);
	return ret;
}

HOOKDEF(HRESULT, WINAPI, WMI_ExecQueryAsync,
	_In_	PVOID			_this,
	_In_	const BSTR		strQueryLanguage,
	_In_	const BSTR		strQuery,
	_In_	LONG			lFlags,
	_In_	IWbemContext	*pCtx,
	_In_	IWbemObjectSink	*pResponseHandler
) {
	HRESULT ret = 0;
	LOQ_hresult("system", "uu", "Query", strQuery, "QueryLanguage", strQueryLanguage);
	return Old_WMI_ExecQueryAsync(_this, strQueryLanguage, strQuery, lFlags, pCtx, pResponseHandler);
}

HOOKDEF(HRESULT, WINAPI, WMI_ExecMethod,
	_In_	PVOID				_this,
	_In_	const BSTR			strObjectPath,
	_In_	const BSTR			strMethodName,
	_In_	LONG				lFlags,
	_In_	IWbemContext		*pCtx,
	_In_	IWbemClassObject	*pInParams,
	_Out_	IWbemClassObject	**ppOutParams,
	_Out_	IWbemCallResult		**ppCallResult
) {
	HRESULT ret = 0;
	LOQ_hresult("system", "uu", "ObjectPath", strObjectPath, "MethodName", strMethodName);
	return Old_WMI_ExecMethod(_this, strObjectPath, strMethodName, lFlags, pCtx, pInParams, ppOutParams, ppCallResult);
}

HOOKDEF(HRESULT, WINAPI, WMI_ExecMethodAsync,
	_In_	PVOID				_this,
	_In_	const BSTR			strObjectPath,
	_In_	const BSTR			strMethodName,
	_In_	LONG				lFlags,
	_In_	IWbemContext		*pCtx,
	_In_	IWbemClassObject	*pInParams,
	_In_	IWbemObjectSink		*pResponseHandler
) {
	HRESULT ret = 0;
	LOQ_hresult("system", "uu", "ObjectPath", strObjectPath, "MethodName", strMethodName);
	return Old_WMI_ExecMethodAsync(_this, strObjectPath, strMethodName, lFlags, pCtx, pInParams, pResponseHandler);
}

HOOKDEF(HRESULT, WINAPI, WMI_GetObject,
	_In_	PVOID				_this,
	_In_	const BSTR			strObjectPath,
	_In_	LONG				lFlags,
	_In_	IWbemContext		*pCtx,
	_Out_	IWbemClassObject	**ppObject,
	_Out_	IWbemCallResult		**ppCallResult
) {
	HRESULT ret = 0;
	if (strObjectPath && SysStringLen(strObjectPath) > 0)
		LOQ_hresult("system", "u", "ObjectPath", strObjectPath);
	else
		LOQ_hresult("system", "u", "ObjectPath", L"");

	return Old_WMI_GetObject(_this, strObjectPath, lFlags, pCtx, ppObject, ppCallResult);
}

HOOKDEF(HRESULT, WINAPI, WMI_GetObjectAsync,
	_In_	PVOID			_this,
	_In_	const BSTR		strObjectPath,
	_In_	LONG			lFlags,
	_In_	IWbemContext	*pCtx,
	_In_	IWbemObjectSink	*pResultHandler
) {
	HRESULT ret = 0;
	if (strObjectPath && SysStringLen(strObjectPath) > 0)
		LOQ_hresult("system", "u", "ObjectPath", strObjectPath);
	else
		LOQ_hresult("system", "u", "ObjectPath", L"");

	return Old_WMI_GetObjectAsync(_this, strObjectPath, lFlags, pCtx, pResultHandler);
}

HOOKDEF(HRESULT, WINAPI, WMI_CreateInstanceEnum,
	_In_	PVOID					_this,
	_In_	const BSTR				strFilter,
	_In_	long					lFlags,
	_In_	IWbemContext			*pCtx,
	_Out_	IEnumWbemClassObject	**ppEnum
) {
	HRESULT ret = 0;
	LOQ_hresult("system", "u", "QueryClass", strFilter);
	return Old_WMI_CreateInstanceEnum(_this, strFilter, lFlags, pCtx, ppEnum);
}

HOOKDEF(HRESULT, WINAPI, WMI_CreateInstanceEnumAsync,
	_In_	PVOID			_this,
	_In_	const BSTR		strFilter,
	_In_	long			lFlags,
	_In_	IWbemContext	*pCtx,
	_In_	IWbemObjectSink	*pResponseHandler
) {
	HRESULT ret = 0;
	LOQ_hresult("system", "u", "QueryClass", strFilter);
	return Old_WMI_CreateInstanceEnumAsync(_this, strFilter, lFlags, pCtx, pResponseHandler);
}
