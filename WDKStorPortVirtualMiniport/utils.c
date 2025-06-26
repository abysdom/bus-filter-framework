/****************************** Module Header ******************************\
* Module Name:  utils.c
* Project:      CppWDKStorPortVirtualMiniport
*
* Copyright (c) Microsoft Corporation.
* 
* MpQueryRegParameters()
* Does registry lookup of parameters.
*
* This source is subject to the Microsoft Public License.
* See http://www.microsoft.com/opensource/licenses.mspx#Ms-PL.
* All other rights reserved.
* 
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, 
* EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED 
* WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.
\***************************************************************************/     

#define localVersion "2.07"

#include "mp.h"
#include "trace.h"

#pragma warning(push)                            
#pragma warning(disable : 4204)                       /* Prevent C4204 messages from stortrce.h. */
#include <stortrce.h>
#pragma warning(pop)

#include "utils.tmh"

/**************************************************************************************************/ 
/*                                                                                                */ 
/* Note: DoStorageTraceETW may not be used here, since tracing won't have been set up.            */ 
/*                                                                                                */ 
/**************************************************************************************************/ 

// Helper to read a QWORD or DWORD and upgrade to QWORD if only DWORD found
static ULONGLONG MpQueryRegQwordAutoUpgrade(
    HANDLE hKey,
    PCWSTR pValueName,
    ULONGLONG defaultValue
)
{
    NTSTATUS status;
    ULONG resultLength;
    union {
        KEY_VALUE_PARTIAL_INFORMATION info;
        UCHAR buf[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(ULONGLONG)];
    } valueBuf;
    PKEY_VALUE_PARTIAL_INFORMATION pValue = &valueBuf.info;

    UNICODE_STRING valueName;
    RtlInitUnicodeString(&valueName, pValueName);

    // 1. Try QWORD
    status = ZwQueryValueKey(
        hKey,
        &valueName,
        KeyValuePartialInformation,
        pValue,
        sizeof(valueBuf),
        &resultLength
    );
    if (NT_SUCCESS(status) && pValue->Type == REG_QWORD && pValue->DataLength == sizeof(ULONGLONG)) {
        ULONGLONG val = *(ULONGLONG*)pValue->Data;
        DbgPrint("MpQueryRegQwordAutoUpgrade: Found QWORD for %ws: %llu\n", pValueName, val);
        return val;
    }

    // 2. Try DWORD
    status = ZwQueryValueKey(
        hKey,
        &valueName,
        KeyValuePartialInformation,
        pValue,
        sizeof(valueBuf),
        &resultLength
    );
    if (NT_SUCCESS(status) && pValue->Type == REG_DWORD && pValue->DataLength == sizeof(ULONG)) {
        ULONGLONG val = *(ULONG*)pValue->Data;
        DbgPrint("MpQueryRegQwordAutoUpgrade: Found DWORD for %ws: %lu, upgrading to QWORD.\n", pValueName, (ULONG)val);

        // Upgrade: write QWORD value
        ZwSetValueKey(
            hKey,
            &valueName,
            0,
            REG_QWORD,
            &val,
            sizeof(val)
        );
        return val;
    }

    DbgPrint("MpQueryRegQwordAutoUpgrade: %ws not found, using default %llu.\n", pValueName, defaultValue);
    return defaultValue;
}

VOID
MpQueryRegParameters(
                     __in PUNICODE_STRING pRegistryPath,
                     __in pMP_REG_INFO    pRegInfo
                    )
/*++

Routine Description:

    This routine is called from DriverEntry to get parameters from the registry.  If the registry query 
    fails, default values are used.

Return Value:

    None

--*/
{
    MP_REG_INFO defRegInfo;

    // Set default values.

    defRegInfo.BreakOnEntry       = DEFAULT_BREAK_ON_ENTRY;
    defRegInfo.DebugLevel         = DEFAULT_DEBUG_LEVEL;
    defRegInfo.InitiatorID        = DEFAULT_INITIATOR_ID;
    defRegInfo.PhysicalDiskSize   = DEFAULT_PHYSICAL_DISK_SIZE;
    defRegInfo.VirtualDiskSize    = DEFAULT_VIRTUAL_DISK_SIZE;
    defRegInfo.NbrVirtDisks       = DEFAULT_NbrVirtDisks;
    defRegInfo.NbrLUNsperHBA      = DEFAULT_NbrLUNsperHBA;
    defRegInfo.bCombineVirtDisks  = DEFAULT_bCombineVirtDisks;

    RtlInitUnicodeString(&defRegInfo.VendorId, VENDOR_ID);
    RtlInitUnicodeString(&defRegInfo.ProductId, PRODUCT_ID);
    RtlInitUnicodeString(&defRegInfo.ProductRevision, PRODUCT_REV);

    // The initialization of lclRtlQueryRegTbl is put into a subordinate block so that the initialized Buffer members of Unicode strings
    // in defRegInfo will be used.

    {
        NTSTATUS status;
        HANDLE hKey = NULL;
        OBJECT_ATTRIBUTES attr;
        UNICODE_STRING regKeyName;

        // Open the Parameters key
        WCHAR parametersKeyBuf[512];
        swprintf(parametersKeyBuf, L"%wZ\\Parameters", pRegistryPath);
        RtlInitUnicodeString(&regKeyName, parametersKeyBuf);

        InitializeObjectAttributes(&attr, &regKeyName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

        status = ZwOpenKey(&hKey, KEY_ALL_ACCESS, &attr);
        if (!NT_SUCCESS(status)) {
            DbgPrint("MpQueryRegParameters: ZwOpenKey failed 0x%08X, using defaults.\n", status);
            goto use_defaults;
        }

        // Read/upgrade QWORD or DWORD as needed
        pRegInfo->PhysicalDiskSize = MpQueryRegQwordAutoUpgrade(hKey, L"PhysicalDiskSize", defRegInfo.PhysicalDiskSize);
        pRegInfo->VirtualDiskSize  = MpQueryRegQwordAutoUpgrade(hKey, L"VirtualDiskSize",  defRegInfo.VirtualDiskSize);

        // Now use RtlQueryRegistryValues for the rest (DWORD/string)
        #pragma warning(push)
        #pragma warning(disable : 4204)
        #pragma warning(disable : 4221)

        RTL_QUERY_REGISTRY_TABLE lclRtlQueryRegTbl[] = {
            // The Parameters entry causes the registry to be searched under that subkey for the subsequent set of entries.
            {NULL, RTL_QUERY_REGISTRY_SUBKEY | RTL_QUERY_REGISTRY_NOEXPAND, L"Parameters",       NULL,                         (ULONG_PTR)NULL, NULL,                              (ULONG_PTR)NULL},

            {NULL, RTL_QUERY_REGISTRY_DIRECT | RTL_QUERY_REGISTRY_NOEXPAND, L"BreakOnEntry",     &pRegInfo->BreakOnEntry,      REG_DWORD,       &defRegInfo.BreakOnEntry,          sizeof(ULONG)},
            {NULL, RTL_QUERY_REGISTRY_DIRECT | RTL_QUERY_REGISTRY_NOEXPAND, L"DebugLevel",       &pRegInfo->DebugLevel,        REG_DWORD,       &defRegInfo.DebugLevel,            sizeof(ULONG)},
            {NULL, RTL_QUERY_REGISTRY_DIRECT | RTL_QUERY_REGISTRY_NOEXPAND, L"InitiatorID",      &pRegInfo->InitiatorID,       REG_DWORD,       &defRegInfo.InitiatorID,           sizeof(ULONG)},
            // QWORDs are handled above
            {NULL, RTL_QUERY_REGISTRY_DIRECT | RTL_QUERY_REGISTRY_NOEXPAND, L"VendorId",         &pRegInfo->VendorId,          REG_SZ,          defRegInfo.VendorId.Buffer,        0},
            {NULL, RTL_QUERY_REGISTRY_DIRECT | RTL_QUERY_REGISTRY_NOEXPAND, L"ProductId",        &pRegInfo->ProductId,         REG_SZ,          defRegInfo.ProductId.Buffer,       0},
            {NULL, RTL_QUERY_REGISTRY_DIRECT | RTL_QUERY_REGISTRY_NOEXPAND, L"ProductRevision",  &pRegInfo->ProductRevision,   REG_SZ,          defRegInfo.ProductRevision.Buffer, 0},
            {NULL, RTL_QUERY_REGISTRY_DIRECT | RTL_QUERY_REGISTRY_NOEXPAND, L"NbrVirtDisks",     &pRegInfo->NbrVirtDisks,      REG_DWORD,       &defRegInfo.NbrVirtDisks,          sizeof(ULONG)},
            {NULL, RTL_QUERY_REGISTRY_DIRECT | RTL_QUERY_REGISTRY_NOEXPAND, L"NbrLUNsperHBA",    &pRegInfo->NbrLUNsperHBA,     REG_DWORD,       &defRegInfo.NbrLUNsperHBA,         sizeof(ULONG)},
            {NULL, RTL_QUERY_REGISTRY_DIRECT | RTL_QUERY_REGISTRY_NOEXPAND, L"CombineVirtDisks", &pRegInfo->bCombineVirtDisks, REG_DWORD,       &defRegInfo.bCombineVirtDisks,     sizeof(ULONG)},

            // The null entry denotes the end of the array.                                                                    
            {NULL, 0,                                                       NULL,                NULL,                         (ULONG_PTR)NULL, NULL,                              (ULONG_PTR)NULL},
        };

        #pragma warning(pop)

        status = RtlQueryRegistryValues(
                                        RTL_REGISTRY_ABSOLUTE | RTL_REGISTRY_OPTIONAL,
                                        pRegistryPath->Buffer,
                                        lclRtlQueryRegTbl,
                                        NULL,
                                        NULL
                                       );

        DbgPrint("MpQueryRegParameters: Registry read status = 0x%08X\n", status);
        DbgPrint("MpQueryRegParameters: PhysicalDiskSize = %llu, VirtualDiskSize = %llu\n",
            pRegInfo->PhysicalDiskSize, pRegInfo->VirtualDiskSize);
        DbgPrint("MpQueryRegParameters: NbrVirtDisks = %lu, NbrLUNsperHBA = %lu\n",
            pRegInfo->NbrVirtDisks, pRegInfo->NbrLUNsperHBA);

        ZwClose(hKey);

        if (!NT_SUCCESS(status)) {
            goto use_defaults;
        }

        // Log final values for all registry parameters for debugging
        DbgPrint("MpQueryRegParameters: Final PhysicalDiskSize = %llu, VirtualDiskSize = %llu\n",
            pRegInfo->PhysicalDiskSize, pRegInfo->VirtualDiskSize);
        DbgPrint("MpQueryRegParameters: Final NbrVirtDisks = %lu, NbrLUNsperHBA = %lu\n",
            pRegInfo->NbrVirtDisks, pRegInfo->NbrLUNsperHBA);
        return;

use_defaults:
    pRegInfo->BreakOnEntry      = defRegInfo.BreakOnEntry;
    pRegInfo->DebugLevel        = defRegInfo.DebugLevel;
    pRegInfo->InitiatorID       = defRegInfo.InitiatorID;
    pRegInfo->PhysicalDiskSize  = defRegInfo.PhysicalDiskSize;
    pRegInfo->VirtualDiskSize   = defRegInfo.VirtualDiskSize;
    RtlCopyUnicodeString(&pRegInfo->VendorId,  &defRegInfo.VendorId);
    RtlCopyUnicodeString(&pRegInfo->ProductId, &defRegInfo.ProductId);
    RtlCopyUnicodeString(&pRegInfo->ProductRevision, &defRegInfo.ProductRevision);
    pRegInfo->NbrVirtDisks      = defRegInfo.NbrVirtDisks;
    pRegInfo->NbrLUNsperHBA     = defRegInfo.NbrLUNsperHBA;
    pRegInfo->bCombineVirtDisks = defRegInfo.bCombineVirtDisks;
    DbgPrint("MpQueryRegParameters: Registry read failed, using defaults.\n");
    }
}                                                     // End MpQueryRegParameters().