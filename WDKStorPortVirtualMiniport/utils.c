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
        NTSTATUS                 status;

        #pragma warning(push)
        #pragma warning(disable : 4204)
        #pragma warning(disable : 4221)

        RTL_QUERY_REGISTRY_TABLE lclRtlQueryRegTbl[] = {
            // The Parameters entry causes the registry to be searched under that subkey for the subsequent set of entries.
            {NULL, RTL_QUERY_REGISTRY_SUBKEY | RTL_QUERY_REGISTRY_NOEXPAND, L"Parameters",       NULL,                         (ULONG_PTR)NULL, NULL,                              (ULONG_PTR)NULL},

            {NULL, RTL_QUERY_REGISTRY_DIRECT | RTL_QUERY_REGISTRY_NOEXPAND, L"BreakOnEntry",     &pRegInfo->BreakOnEntry,      REG_DWORD,       &defRegInfo.BreakOnEntry,          sizeof(ULONG)},
            {NULL, RTL_QUERY_REGISTRY_DIRECT | RTL_QUERY_REGISTRY_NOEXPAND, L"DebugLevel",       &pRegInfo->DebugLevel,        REG_DWORD,       &defRegInfo.DebugLevel,            sizeof(ULONG)},
            {NULL, RTL_QUERY_REGISTRY_DIRECT | RTL_QUERY_REGISTRY_NOEXPAND, L"InitiatorID",      &pRegInfo->InitiatorID,       REG_DWORD,       &defRegInfo.InitiatorID,           sizeof(ULONG)},
            {NULL, RTL_QUERY_REGISTRY_DIRECT | RTL_QUERY_REGISTRY_NOEXPAND, L"VirtualDiskSize",  &pRegInfo->VirtualDiskSize,   REG_DWORD,       &defRegInfo.VirtualDiskSize,       sizeof(ULONG)},
            {NULL, RTL_QUERY_REGISTRY_DIRECT | RTL_QUERY_REGISTRY_NOEXPAND, L"PhysicalDiskSize", &pRegInfo->PhysicalDiskSize,  REG_DWORD,       &defRegInfo.PhysicalDiskSize,      sizeof(ULONG)},
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

        if (!NT_SUCCESS(status)) {                    // A problem?
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
        }
    }
}                                                     // End MpQueryRegParameters().

