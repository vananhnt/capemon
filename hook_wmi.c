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
	   is passed as the first argument (_this). Call the original, then apply
	   the sandbox-transparency response for the per-instance fingerprinting
	   reads (Win32_PhysicalMemory.Manufacturer, Win32_BIOS.SerialNumber)
	   before logging and returning. */

	/* Benign OEM manufacturer forged for Win32_PhysicalMemory.Manufacturer.
	   "Dell Inc." carries none of the vendor tokens the sample's
	   isSuspiciousManufacturer() screens for (VMWARE / VIRTUAL /
	   NOT SPECIFIED / MICROSOFT / QEMU / XEN / KVM / PARALLELS / INNOTEK /
	   ORACLE / VBOX), so neither its substring-contains nor its
	   exactly-equals test fires. */
	static const OLECHAR mirage_phys_mem_manufacturer[] = L"Dell Inc.";
	/* Realistic, non-zero BIOS serial. The sample's IsAllZeroLike()
	   strips the separators ' -_:.' and then checks whether every
	   surviving character is '0'; this value contains plenty of
	   relevant non-'0' characters, so IsAllZeroLike() returns false. */
	static const OLECHAR mirage_bios_serial[] = L"5CD1234ABC";
	HRESULT ret;
	lasterror_t lasterror;
	const OLECHAR *forced_value;
	BSTR forged;
	int did_forge;

	ret = Old_WMI_Get(_this, wszName, lFlags, pVal, pType, plFlavor);

	/* After IEnumWbemClassObject::Next hands the sample an enumerated
	 * instance, it pulls the property it cares about via
	 * IWbemClassObject::Get. This is the per-instance value boundary where
	 * SpoofWmiData() answers each fingerprinting read with a benign value,
	 * selected by property name:
	 *
	 *   - "Manufacturer": the sample walks the
	 *     'SELECT Manufacturer FROM Win32_PhysicalMemory' enumerator and
	 *     screens each DIMM's Manufacturer with isSuspiciousManufacturer(),
	 *     which flags a hypervisor/placeholder vendor token (VMWARE / VIRTUAL
	 *     / NOT SPECIFIED / MICROSOFT / QEMU / XEN / KVM / PARALLELS / INNOTEK
	 *     / ORACLE / VBOX). A freshly-imaged VMware/VirtualBox/QEMU guest
	 *     reports exactly such a manufacturer for its emulated modules, so the
	 *     check fires and the sample takes its evasive branch. Forge the value
	 *     to the benign OEM string "Dell Inc." so the per-instance read is
	 *     also benign; the companion WMI_ExecQuery hook recognises the
	 *     Win32_PhysicalMemory query at the boundary so the two stay
	 *     consistent.
	 *   - "SerialNumber": the sample reads Win32_BIOS.SerialNumber and screens
	 *     it with IsAllZeroLike() (strip ' -_:.' then test empty/all-'0'),
	 *     treating a blank/all-zero serial as a VM placeholder. Forge a
	 *     realistic, non-zero serial ("5CD1234ABC") so relevant non-'0'
	 *     characters survive and IsAllZeroLike() returns false.
	 *
	 * We report CIM_STRING (value 8) through pType so the type tag stays
	 * consistent with the forged VT_BSTR. pType is passed as PVOID, so we
	 * cast it to the CIMTYPE (long) it really points at before writing. If
	 * the real call succeeded we VariantClear the existing value before
	 * overwriting (freeing any BSTR it allocated); otherwise we VariantInit a
	 * clean VARIANT so the overwrite never frees uninitialized memory. ret is
	 * forced to S_OK so the read looks like a successful property fetch, and
	 * the sample follows its normal task-routine path. Any other property
	 * passes straight through untouched. lasterror is preserved around the
	 * forged response. */
	did_forge = 0;
	forced_value = NULL;
	if (!g_config.no_stealth && wszName != NULL && pVal != NULL) {
		if (_wcsicmp(wszName, L"Manufacturer") == 0)
			forced_value = mirage_phys_mem_manufacturer;
		else if (_wcsicmp(wszName, L"SerialNumber") == 0)
			forced_value = mirage_bios_serial;
	}

	if (forced_value != NULL) {
		get_lasterrors(&lasterror);

		forged = SysAllocString(forced_value);
		if (forged != NULL) {
			if (SUCCEEDED(ret))
				VariantClear(pVal);
			else
				VariantInit(pVal);

			pVal->vt = VT_BSTR;
			pVal->bstrVal = forged;
			if (pType != NULL)
				*(long *)pType = 8;
			ret = S_OK;
			did_forge = 1;
		}

		set_lasterrors(&lasterror);
	}

	LOQ_hresult("system", "ui", "Name", wszName != NULL ? wszName : L"",
		"Forged", did_forge);

	return ret;
}

HOOKDEF(HRESULT, WINAPI, WMI_Next,
	_In_		PVOID	_this,
	_In_		LONG	lFlags,
	_Out_		BSTR	*strName,
	_Out_		VARIANT	*pVal,
	_Out_opt_	CIMTYPE	*pType,
	_Out_opt_	LONG	*plFlavor
) {
	HRESULT ret = Old_WMI_Next(_this, lFlags, strName, pVal, pType, plFlavor);

	// Return early for some cases we don't want to log / spoof
	if (ret != S_OK)
		return ret;

	if (!pVal)
		return ret;

	if (pVal->vt == VT_NULL)
		return ret;

	if (!strName || !*strName)
		return ret;

	// If all is well at this point, we should do the spoofs
	lasterror_t lasterror;
	get_lasterrors(&lasterror);
	VARIANT classVariant;
	VariantInit(&classVariant);

	__try {
		IWbemClassObject* pWmiObject = (IWbemClassObject*)_this;
		HRESULT hr = pWmiObject->lpVtbl->Get(pWmiObject, L"__CLASS", 0, &classVariant, NULL, NULL);
		WCHAR szClassName[256] = L"";
		if (SUCCEEDED(hr) && classVariant.vt == VT_BSTR) {
			wcscpy_s(szClassName, _countof(szClassName), classVariant.bstrVal);
		}
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
/* Benign OEM manufacturer forged for Win32_PhysicalMemory.Manufacturer.
	 * "Dell Inc." carries none of the vendor tokens the sample's
	 * isSuspiciousManufacturer() screens for (VMWARE / VIRTUAL /
	 * NOT SPECIFIED / MICROSOFT / QEMU / XEN / KVM / PARALLELS / INNOTEK /
	 * ORACLE / VBOX), so neither its substring-contains nor its
	 * exactly-equals test fires. */
	static const wchar_t mirage_phys_mem_manufacturer[] = L"Dell Inc.";
	HRESULT ret = 0;
	lasterror_t lasterror;
	BSTR forced_query;
	HRESULT sub;
	const wchar_t *p;
	int targets_phys_mem;
	int targets_bios;
	int did_detect;

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

	/* Samples fingerprint the physical RAM modules by running the WQL query
	 * 'SELECT Manufacturer FROM Win32_PhysicalMemory' through
	 * IWbemServices::ExecQuery, then walking the returned enumerator with
	 * IEnumWbemClassObject::Next and reading the Manufacturer property off
	 * each IWbemClassObject via ::Get. They normalize that string and feed it
	 * to isSuspiciousManufacturer(), which flags the host when the value
	 * exactly-equals or substring-contains a hypervisor/placeholder vendor
	 * token (VMWARE / VIRTUAL / NOT SPECIFIED / MICROSOFT / QEMU / XEN / KVM /
	 * PARALLELS / INNOTEK / ORACLE / VBOX). A freshly-imaged VMware/VirtualBox/
	 * QEMU guest reports exactly such a manufacturer for its emulated DIMMs, so
	 * the check fires and the sample takes its evasive branch. The value forge
	 * lives in the companion WMI_Get hook, which rewrites the Manufacturer
	 * property on the enumerated object to the benign OEM string "Dell Inc.";
	 * this ExecQuery hook only recognises the Win32_PhysicalMemory query at the
	 * boundary so the two stay consistent.
	 *
	 * Samples also fingerprint the BIOS by running the WQL query
	 * 'SELECT SerialNumber FROM Win32_BIOS', walking the enumerator with ::Next
	 * and reading SerialNumber off each object via ::Get. They screen that
	 * serial with IsAllZeroLike(): a blank or all-'0' value (the placeholder
	 * serial a freshly-imaged VMware/VirtualBox/QEMU guest exposes) is taken as
	 * proof of a sandbox. That serial forge also lives in WMI_Get (rewriting
	 * SerialNumber to the realistic non-zero "5CD1234ABC"), so we recognise the
	 * Win32_BIOS target here too.
	 *
	 * We detect either target with a case-insensitive scan of strQuery and log
	 * it so the pipeline can confirm the query path was reached, but we do NOT
	 * fabricate an enumerator or force S_OK on a failed query: when the real
	 * ExecQuery fails it never sets *ppEnum, so forcing success would hand the
	 * caller an uninitialized interface pointer to deref. A genuine success
	 * passes straight through untouched, and the enumerated object's property is
	 * spoofed downstream in WMI_Get. lasterror is preserved around the
	 * detection. */
	targets_phys_mem = 0;
	targets_bios = 0;
	did_detect = 0;
	if (!g_config.no_stealth && strQuery != NULL) {
		get_lasterrors(&lasterror);

		for (p = strQuery; *p != L'\0'; p++) {
			if (_wcsnicmp(p, L"Win32_PhysicalMemory", 20) == 0) {
				targets_phys_mem = 1;
				break;
			}
			if (_wcsnicmp(p, L"Win32_BIOS", 10) == 0) {
				targets_bios = 1;
				break;
			}
		}

		if ((targets_phys_mem || targets_bios) && SUCCEEDED(ret))
			did_detect = 1;

		set_lasterrors(&lasterror);
	}

	LOQ_hresult("system", "uuui", "Query", strQuery != NULL ? strQuery : L"",
		"QueryLanguage", strQueryLanguage,
		"ForgedManufacturer",
		targets_phys_mem ? mirage_phys_mem_manufacturer : L"",
		"QueryDetected", did_detect);
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
