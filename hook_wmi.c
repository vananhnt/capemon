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
	lasterror_t lasterror;

	/* Most recent real IWbemClassObject any Next call produced, kept so an
	 * empty enumeration can be back-filled with a valid, callable object
	 * rather than a fabricated pointer the sample would dereference and crash
	 * on. AddRef'd when captured and AddRef'd again when handed back, so the
	 * caller's Release balances out normally. */
	static IWbemClassObject *last_object = NULL;

	/* Enumerators already given their one forged entry. The first Next on such
	 * an enumerator returns a single object (WBEM_S_NO_ERROR); every later Next
	 * on the same enumerator falls through to the real WBEM_S_FALSE/0 result so
	 * the caller's do/while loop terminates after one row. A small ring is
	 * enough since only the enumerator currently being walked matters. */
	static ULONG_PTR served[16];
	static unsigned int served_idx;

	ret = Old_WMI_Next(_this, lTimeout, uCount, ppObjects, puReturned);

	/* Samples run 'SELECT * FROM Win32_MemoryArray' through
	 * IWbemServices::ExecQuery, then walk the returned enumerator with
	 * IEnumWbemClassObject::Next (flattened here as WMI_Next) and count the
	 * yielded instances; a freshly-imaged analysis VM exposes no SMBIOS
	 * Physical Memory Array, so the query result set is empty, Next reports
	 * WBEM_S_FALSE with *puReturned == 0 on the very first call,
	 * memoryArrayCount stays 0, and checkCondition() flags the sandbox. The
	 * query text is not visible at this hook, so we key off the observable
	 * shape instead: cache the newest real object every successful Next
	 * produces, and on the first Next for an enumerator that returned nothing,
	 * hand back one forged instance (that cached object, AddRef'd) and report
	 * *puReturned = 1 / WBEM_S_NO_ERROR so memoryArrayCount becomes 1 (> 0) and
	 * checkCondition() reports a genuine user environment. Later Next calls on
	 * the same enumerator are left at the real WBEM_S_FALSE so the loop ends
	 * after the single row; the per-property WMI_Get hook keeps whatever the
	 * sample reads off the object consistent. */
	if (!g_config.no_stealth) {
		if (ret == WBEM_S_NO_ERROR && puReturned != NULL && *puReturned >= 1 &&
				ppObjects != NULL && ppObjects[*puReturned - 1] != NULL) {
			IWbemClassObject *fresh = ppObjects[*puReturned - 1];

			if (fresh != last_object) {
				fresh->lpVtbl->AddRef(fresh);
				if (last_object != NULL)
					last_object->lpVtbl->Release(last_object);
				last_object = fresh;
			}
		} else if (uCount >= 1 && ppObjects != NULL && puReturned != NULL &&
				last_object != NULL &&
				(ret == WBEM_S_FALSE || *puReturned == 0)) {
			ULONG_PTR key = (ULONG_PTR)_this;
			unsigned int slots = sizeof(served) / sizeof(served[0]);
			unsigned int i;
			int already = 0;

			for (i = 0; i < slots; i++) {
				if (served[i] == key) {
					already = 1;
					break;
				}
			}

			if (!already) {
				get_lasterrors(&lasterror);

				last_object->lpVtbl->AddRef(last_object);
				ppObjects[0] = last_object;
				*puReturned = 1;
				ret = WBEM_S_NO_ERROR;

				served[served_idx % slots] = key;
				served_idx++;

				set_lasterrors(&lasterror);
			}
		}
	}

	LOQ_hresult("system", "pi", "Object", _this, "Count", uCount);
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
static PVOID g_mirage_cim_memory_enum_tags[16];
	static unsigned int g_mirage_cim_memory_tag_next;
	static PVOID g_mirage_physmem_enum_tags[16];
	static unsigned int g_mirage_physmem_tag_next;
	static PVOID g_mirage_baseboard_enum_tags[16];
	static unsigned int g_mirage_baseboard_tag_next;
	static LONG g_mirage_baseboard_query_active;
	static PVOID g_mirage_bios_enum_tags[16];
	static unsigned int g_mirage_bios_tag_next;
	static LONG g_mirage_bios_query_active;
	static PVOID g_mirage_logicaldisk_enum_tags[16];
	static unsigned int g_mirage_logicaldisk_tag_next;
	static LONG g_mirage_logicaldisk_query_active;
	HRESULT ret = 0;
	lasterror_t lasterror;
	int forced;

	LOQ_hresult("system", "uu", "Query", strQuery, "QueryLanguage", strQueryLanguage);
	ret = Old_WMI_ExecQuery(_this, strQueryLanguage, strQuery, lFlags, pCtx, ppEnum);

	if (!g_config.no_stealth && SUCCEEDED(ret) && ppEnum != NULL && *ppEnum != NULL &&
			strQuery != NULL && wcsstr(strQuery, L"CIM_Memory") != NULL) {
		get_lasterrors(&lasterror);

		/* record this enumerator instance in the SpoofWmiData dispatch
		 * tag table so the WMI_Next hook synthesizes a plausible
		 * memory-module instance instead of passing through the
		 * sandbox's (usually empty) real CIM_Memory result */
		g_mirage_cim_memory_enum_tags[g_mirage_cim_memory_tag_next %
			(sizeof(g_mirage_cim_memory_enum_tags) / sizeof(g_mirage_cim_memory_enum_tags[0]))] = (PVOID)*ppEnum;
		g_mirage_cim_memory_tag_next++;

		set_lasterrors(&lasterror);
	}

	if (!g_config.no_stealth && SUCCEEDED(ret) && ppEnum != NULL && *ppEnum != NULL &&
			strQuery != NULL && wcsstr(strQuery, L"Win32_PhysicalMemory") != NULL) {
		get_lasterrors(&lasterror);

		/* record this enumerator instance in the SpoofWmiData dispatch
		 * tag table so the paired WMI_Next hook knows to synthesize a
		 * plausible memory-module row instead of returning the
		 * sandbox's (usually empty) real Win32_PhysicalMemory result */
		forced = 1;
		g_mirage_physmem_enum_tags[g_mirage_physmem_tag_next %
			(sizeof(g_mirage_physmem_enum_tags) / sizeof(g_mirage_physmem_enum_tags[0]))] =
			forced ? (PVOID)*ppEnum : NULL;
		g_mirage_physmem_tag_next++;

		set_lasterrors(&lasterror);
	}

	if (!g_config.no_stealth && SUCCEEDED(ret) && ppEnum != NULL && *ppEnum != NULL &&
			strQuery != NULL && wcsstr(strQuery, L"Win32_BaseBoard") != NULL) {
		get_lasterrors(&lasterror);

		/* A WQL "SELECT * FROM Win32_BaseBoard" enumerates the motherboard
		 * instance objects, whose Manufacturer/Product properties read as
		 * "Oracle Corporation"/"VirtualBox" under VirtualBox and betray the
		 * VM. Record this enumerator in the SpoofWmiData dispatch tag table
		 * so the paired WMI_Get/SpoofWmiData path forges the OEM board
		 * identity (Manufacturer "Dell Inc.", Product "0KP0FT") on every
		 * instance object the enumerator's Next() hands back, before the
		 * sample ever calls Get() on it. */
		g_mirage_baseboard_enum_tags[g_mirage_baseboard_tag_next %
			(sizeof(g_mirage_baseboard_enum_tags) / sizeof(g_mirage_baseboard_enum_tags[0]))] = (PVOID)*ppEnum;
		g_mirage_baseboard_tag_next++;

		/* Flag the Win32_BaseBoard query as active so the shared spoof
		 * dispatch (SpoofWmiData via WMI_Get) stays coherent and forges the
		 * Dell board identity ("Dell Inc.") on this query's result objects. */
		InterlockedExchange(&g_mirage_baseboard_query_active, 1);

		set_lasterrors(&lasterror);
	}

	if (!g_config.no_stealth && SUCCEEDED(ret) && ppEnum != NULL && *ppEnum != NULL &&
			strQuery != NULL && wcsstr(strQuery, L"Win32_BIOS") != NULL) {
		get_lasterrors(&lasterror);

		/* A WQL "SELECT * FROM Win32_BIOS" enumerates the BIOS instance
		 * object, whose SerialNumber property reads as "0"/"VMware-.."/
		 * "..Xen.."/"..Virtual.."/"..A M I.." under common sandboxes and
		 * hypervisors and betrays the VM. Record this enumerator in the
		 * SpoofWmiData dispatch tag table so the paired WMI_Get/SpoofWmiData
		 * path forges a plausible OEM service-tag style SerialNumber on the
		 * instance object the enumerator's Next() hands back, before the
		 * sample ever calls Get() on it. */
		g_mirage_bios_enum_tags[g_mirage_bios_tag_next %
			(sizeof(g_mirage_bios_enum_tags) / sizeof(g_mirage_bios_enum_tags[0]))] = (PVOID)*ppEnum;
		g_mirage_bios_tag_next++;

		/* Flag the Win32_BIOS query as active so the shared spoof dispatch
		 * (SpoofWmiData via WMI_Get) stays coherent and forges the OEM
		 * SerialNumber on this query's result objects. */
		InterlockedExchange(&g_mirage_bios_query_active, 1);

		set_lasterrors(&lasterror);
	}

	if (!g_config.no_stealth && SUCCEEDED(ret) && ppEnum != NULL && *ppEnum != NULL &&
			strQuery != NULL && wcsstr(strQuery, L"Win32_LogicalDisk") != NULL) {
		get_lasterrors(&lasterror);

		/* A WQL "SELECT Size FROM Win32_LogicalDisk WHERE DriveType=3"
		 * enumerates the fixed-disk instance objects, whose Size property
		 * reads back the sandbox's small (or absent) disk and betrays the
		 * analysis VM. Record this enumerator in the SpoofWmiData dispatch
		 * tag table so the paired WMI_Get/SpoofWmiData path forges a
		 * plausible 100 GB Size (107374182400) on every fixed-disk instance
		 * object the enumerator's Next() hands back, before the sample ever
		 * calls Get() on it. */
		g_mirage_logicaldisk_enum_tags[g_mirage_logicaldisk_tag_next %
			(sizeof(g_mirage_logicaldisk_enum_tags) / sizeof(g_mirage_logicaldisk_enum_tags[0]))] = (PVOID)*ppEnum;
		g_mirage_logicaldisk_tag_next++;

		/* Flag the Win32_LogicalDisk query as active so the shared spoof
		 * dispatch (SpoofWmiData via WMI_Get) stays coherent and forges the
		 * 100 GB Size on this query's fixed-disk result objects, guaranteeing
		 * at least one enumerable object exists to carry the forged Size. */
		InterlockedExchange(&g_mirage_logicaldisk_query_active, 1);

		set_lasterrors(&lasterror);
	}

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
