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
		//
		// Samples read Win32_BIOS.SerialNumber and flag the VM when it
		// matches biosSerialNumber LIKE '%VMWare%'/'%Xen%'/'%Virtual%'/
		// '%A M I%' OR == '0'. Replace it with a plausible OEM service-tag
		// style serial that hits none of those signatures.
		//
		else if (!_wcsicmp(szClassName, L"Win32_BIOS") && !_wcsicmp(wszName, L"SerialNumber")) {
			SysFreeString(pVal->bstrVal);
			pVal->bstrVal = SysAllocString(L"7XKQZ13");
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
HRESULT ret;
	const wchar_t *spoof;
	lasterror_t lasterror;
	WCHAR szClassName[256] = L"";
	if (wszName && _wcsicmp(wszName, L"__CLASS") != 0) {
		VARIANT classVariant;
		IWbemClassObject* pWmiObject;
		HRESULT hr;

		VariantInit(&classVariant);
		pWmiObject = (IWbemClassObject*)_this;
		hr = pWmiObject->lpVtbl->Get(pWmiObject, L"__CLASS", 0, &classVariant, NULL, NULL);
		if (SUCCEEDED(hr) && classVariant.vt == VT_BSTR) {
			wcscpy_s(szClassName, _countof(szClassName), classVariant.bstrVal);
		}
		VariantClear(&classVariant);
	}

	ret = Old_WMI_Get(_this, wszName, lFlags, pVal, pType, plFlavor);
	SpoofWmiData(szClassName, wszName, pVal);

	/* Samples read board/system identity properties through
	 * IWbemClassObject::Get (flattened here as WMI_Get) and test them for VM
	 * signatures. Win32_BaseBoard is checked with Product LIKE '%VirtualBox%'
	 * OR Manufacturer LIKE '%Oracle Corporation%' (in native code,
	 * std::string::find("VirtualBox") != npos OR find("Oracle Corporation")
	 * != npos), betraying a VirtualBox VM. Win32_ComputerSystem is read after
	 * 'SELECT * FROM Win32_ComputerSystem' and its Manufacturer is scanned for
	 * the 'VMWare'/'Xen'/'innotek GmbH'/'QEMU' substrings. Any match reveals
	 * the VM and the sample refuses to run. When the requested property name is
	 * Product or Manufacturer (for any of these classes), replace the returned
	 * BSTR VARIANT with a realistic physical-vendor value
	 * (Manufacturer="Dell Inc.", Product="0A98") before it reaches the sample:
	 * "Dell Inc." contains none of the VM-vendor substrings, so the VirtualBox,
	 * VMware, Xen, VirtualBox/innotek and QEMU manufacturer checks all fail and
	 * checkCondition() reports a genuine user environment. The original variant
	 * is released with VariantClear and a fresh BSTR is allocated with
	 * SysAllocString so the caller's VariantClear frees it normally; the CIM
	 * type is reported as CIM_STRING to stay consistent. */
	if (!g_config.no_stealth && ret == S_OK && wszName != NULL && pVal != NULL) {
		spoof = NULL;
		if (!_wcsicmp(wszName, L"Manufacturer"))
			spoof = L"Dell Inc.";
		else if (!_wcsicmp(wszName, L"Product"))
			spoof = L"0A98";

		if (spoof != NULL) {
			BSTR bstr = SysAllocString(spoof);
			if (bstr != NULL) {
				get_lasterrors(&lasterror);

				VariantClear(pVal);
				pVal->vt = VT_BSTR;
				pVal->bstrVal = bstr;
				if (pType != NULL)
					*pType = CIM_STRING;

				set_lasterrors(&lasterror);
			}
		}
	}

	// Short circuit, return early for things we don't want to log
	if (!ret && !g_config.full_logs && wszName) {
		if (
			!_wcsicmp(wszName, L"__GENUS") ||
			!_wcsicmp(wszName, L"__PATH") ||
			!_wcsicmp(wszName, L"__RELPATH") ||
			!_wcsicmp(wszName, L"__SUPERCLASS") ||
			!_wcsicmp(wszName, L"SECURITY_DESCRIPTOR") ||
			!_wcsicmp(wszName, L"__NAMESPACE") ||
			!_wcsicmp(wszName, L"__CLASS") ||
			!_wcsicmp(wszName, L"__DERIVATION")
		) {
			return ret;
		}
	}

	LOQ_hresult("system", "unu", "Name", wszName, "Value", pVal, "Class", szClassName);
	return ret;
}

/* shared dispatch helper(s) called above — extend these, not the wrapper */

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
		//
		// Samples read Win32_BIOS.SerialNumber and flag the VM when it
		// matches biosSerialNumber LIKE '%VMWare%'/'%Xen%'/'%Virtual%'/
		// '%A M I%' OR == '0'. Replace it with a plausible OEM service-tag
		// style serial that hits none of those signatures.
		//
		else if (!_wcsicmp(szClassName, L"Win32_BIOS") && !_wcsicmp(wszName, L"SerialNumber")) {
			SysFreeString(pVal->bstrVal);
			pVal->bstrVal = SysAllocString(L"7XKQZ13");
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

/* shared dispatch helper(s) called above — extend these, not the wrapper */

HOOKDEF(HRESULT, WINAPI, WMI_Next,
	_In_		PVOID	_this,
	_In_		LONG	lFlags,
	_Out_		BSTR	*strName,
	_Out_		VARIANT	*pVal,
	_Out_opt_	CIMTYPE	*pType,
	_Out_opt_	LONG	*plFlavor
)
{
	HRESULT ret;
	HRESULT hr;
	lasterror_t lasterror;
	VARIANT classVariant;
	IWbemClassObject *pWmiObject;
	WCHAR szClassName[256] = L"";

	/* This hook sits on CWbemObject::Next (IWbemClassObject::Next, registered
	 * in hooks.c by the mangled '?Next@CWbemObject@@...' symbol), which walks
	 * the PROPERTIES of a single object and yields one name/value pair per
	 * call - it is not IEnumWbemClassObject::Next, which walks instances.
	 * So there is no object array or instance count to adjust here; the
	 * countermeasure for an empty instance enumeration (e.g. a sample counting
	 * rows of 'SELECT * FROM CIM_Memory') lives in the WMI_ExecQuery hook
	 * below, which substitutes a query that provably yields instances.
	 *
	 * What this hook can do is the same thing WMI_Get does for a directly
	 * requested property: resolve the owning class and run the enumerated
	 * value through SpoofWmiData, so a sample that reads memory size, disk
	 * size, CPU counts, GPU name or the BIOS serial by ENUMERATING properties
	 * sees the same consistent physical-machine values it would get from
	 * IWbemClassObject::Get, instead of the sandbox's real ones. */
	ret = Old_WMI_Next(_this, lFlags, strName, pVal, pType, plFlavor);

	/* Nothing to spoof or log: failed call, end of enumeration
	 * (WBEM_S_NO_MORE_DATA), or no usable name/value pair. */
	if (ret != S_OK || pVal == NULL || pVal->vt == VT_NULL ||
			strName == NULL || *strName == NULL)
		return ret;

	get_lasterrors(&lasterror);
	VariantInit(&classVariant);

	__try {
		/* Get(L"__CLASS") re-enters the WMI_Get hook, which skips its own
		 * class lookup for __CLASS, so this does not recurse. */
		pWmiObject = (IWbemClassObject *)_this;
		hr = pWmiObject->lpVtbl->Get(pWmiObject, L"__CLASS", 0, &classVariant, NULL, NULL);
		if (SUCCEEDED(hr) && classVariant.vt == VT_BSTR)
			wcscpy_s(szClassName, _countof(szClassName), classVariant.bstrVal);

		SpoofWmiData(szClassName, *strName, pVal);
		LOQ_hresult("system", "unu", "Name", *strName, "Value", pVal, "Class", szClassName);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		LOQ_hresult("system", "un", "Name", *strName, "Value", pVal);
	}

	VariantClear(&classVariant);
	set_lasterrors(&lasterror);
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
static const wchar_t forced_query[] = L"SELECT * FROM Win32_PhysicalMemory";
	HRESULT ret;
	lasterror_t lasterror;
	IEnumWbemClassObject *test_enum;
	HRESULT hr_test;

	ret = Old_WMI_ExecQuery(_this, strQueryLanguage, strQuery, lFlags, pCtx,
		ppEnum);

	/* Samples run the WQL query 'SELECT * FROM CIM_Memory' through
	 * IWbemServices::ExecQuery — aliased here as WMI_ExecQuery — and then walk
	 * the returned IEnumWbemClassObject with ::Next, counting rows. They never
	 * read a property; the verdict is purely the instance count, so a
	 * WMI_Get/WMI_Next property spoof is useless here. CIM_Memory is an abstract
	 * CIM base class that Windows does not populate with concrete instances, so
	 * on a bare analysis VM the enumerator comes back empty, the row count is
	 * zero, and checkCondition() takes its evasion branch. To keep the sample on
	 * its user-environment path we must make the enumerator the caller receives
	 * yield at least one row. We first probe the count on a throwaway enumerator
	 * (re-issuing the same query via the original API) so the caller's own
	 * enumerator and its cursor are never disturbed by our ::Next peek. If that
	 * probe yields a row, CIM_Memory is populated after all and we leave the
	 * caller's result untouched. If it is empty, we re-issue the query against
	 * the concrete, always-populated class Win32_PhysicalMemory, release the
	 * caller's empty enumerator, and hand back the populated one so the row
	 * count is non-zero. All intermediate COM references and the forged query
	 * BSTR are released. Lasterror is preserved around the forged response. */
	if (!g_config.no_stealth && ret == S_OK && ppEnum != NULL && *ppEnum != NULL &&
		strQuery != NULL && wcsstr(strQuery, L"CIM_Memory") != NULL) {
		get_lasterrors(&lasterror);

		test_enum = NULL;
		hr_test = Old_WMI_ExecQuery(_this, strQueryLanguage, strQuery, lFlags,
			pCtx, &test_enum);

		if (hr_test == S_OK && test_enum != NULL) {
			IWbemClassObject *obj = NULL;
			ULONG returned = 0;

			if (test_enum->lpVtbl->Next(test_enum, WBEM_INFINITE, 1, &obj,
				&returned) == S_OK && returned > 0) {
				/* CIM_Memory is populated — nothing to forge. */
				if (obj != NULL)
					obj->lpVtbl->Release(obj);
			}
			else {
				BSTR forged = SysAllocString(forced_query);
				IEnumWbemClassObject *new_enum = NULL;

				if (forged != NULL) {
					if (Old_WMI_ExecQuery(_this, strQueryLanguage, forged, lFlags,
						pCtx, &new_enum) == S_OK && new_enum != NULL) {
						(*ppEnum)->lpVtbl->Release(*ppEnum);
						*ppEnum = new_enum;
						ret = S_OK;
					}
					SysFreeString(forged);
				}
			}

			test_enum->lpVtbl->Release(test_enum);
		}

		set_lasterrors(&lasterror);
	}

	LOQ_hresult("system", "uu", "QueryLanguage", strQueryLanguage,
		"Query", strQuery);
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
