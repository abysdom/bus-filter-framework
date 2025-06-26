/****************************** Module Header ******************************\
* Module Name:  scsi.c
* Project:      CppWDKStorPortVirtualMiniport
*
* Copyright (c) Microsoft Corporation.
* 
* a.       ScsiExecuteMain()
* Handles SCSI SRBs with opcodes needed to support file system operations by 
* calling subroutines. Fails SRBs with other opcodes.
* Note: In a real-world virtual miniport, it may be necessary to handle other opcodes.
* 
* b.      ScsiOpInquiry()
* Handles Inquiry, including creating a new LUN as needed.
* 
* c.       ScsiOpVPD()
* Handles Vital Product Data.
* 
* d.      ScsiOpRead()
* Beginning of a SCSI Read operation.
* 
* e.      ScsiOpWrite()
* Beginning of a SCSI Write operation.
* 
* f.        ScsiReadWriteSetup()
* Sets up a work element for SCSI Read or Write and enqueues the element.
* 
* g.       ScsiOpReportLuns()
* Handles Report LUNs.
* 
*
* This source is subject to the Microsoft Public License.
* See http://www.microsoft.com/opensource/licenses.mspx#Ms-PL.
* All other rights reserved.
* 
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, 
* EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED 
* WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.
\***************************************************************************/     

#define MPScsiFile     "2.025"

#include "mp.h"
#include "fat32_format.h"
#include "storport.h"
#include "disk_backend.h"
#include <ntddk.h>
#include <ntdef.h>
#include <windef.h>
#include <limits.h>

typedef struct _SYSTEM_BASIC_INFORMATION {
    ULONG Reserved;
    ULONG TimerResolution;
    ULONG PageSize;
    ULONG NumberOfPhysicalPages;
    ULONG LowestPhysicalPageNumber;
    ULONG HighestPhysicalPageNumber;
    ULONG AllocationGranularity;
    ULONG MinimumUserModeAddress;
    ULONG MaximumUserModeAddress;
    KAFFINITY ActiveProcessorsAffinityMask;
    CCHAR NumberOfProcessors;
} SYSTEM_BASIC_INFORMATION;

#define SystemBasicInformation 0

NTSYSAPI
NTSTATUS
NTAPI
ZwQuerySystemInformation(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

#pragma warning(push)
#pragma warning(disable : 4204)                       /* Prevent C4204 messages from stortrce.h. */
#include <stortrce.h>
#pragma warning(pop)

#include "trace.h"
#include "scsi.tmh"

// ================== RAM CACHING SUPPORT FUNCTION ==================
NTSTATUS CacheTotalPhysicalMemory(VOID)
{
    SYSTEM_BASIC_INFORMATION sbi = {0};
    ULONG retLen = 0;
    NTSTATUS status = ZwQuerySystemInformation(SystemBasicInformation, &sbi, sizeof(sbi), &retLen);
    if (NT_SUCCESS(status)) {
        g_TotalPhysicalMemoryBytes = (ULONGLONG)sbi.NumberOfPhysicalPages * sbi.PageSize;
        DbgPrint("Cached total physical RAM: %llu bytes\n", g_TotalPhysicalMemoryBytes);
    } else {
        g_TotalPhysicalMemoryBytes = 0;
        DbgPrint("Failed to cache physical RAM, status 0x%08X\n", status);
    }
    return status;
}
// =========================================================

/**************************************************************************************************/
/* Helper: flush the file backend after each write for persistence. */
static VOID FlushDiskBackend(DISK_BACKEND* backend) {
    if (backend && backend->ops && backend->ops->Flush) {
        backend->ops->Flush(backend->context);
    }
}

/**************************************************************************************************/     
/*                                                                                                */     
/**************************************************************************************************/     
UCHAR
ScsiExecuteMain(
                __in pHW_HBA_EXT          pHBAExt,    // Adapter device-object extension from StorPort.
                __in PSCSI_REQUEST_BLOCK  pSrb,
                __in PUCHAR               pResult
               )
{
    pHW_LU_EXTENSION pLUExt;
    UCHAR            status = SRB_STATUS_INVALID_REQUEST;

    DoStorageTraceEtw(DbgLvlLoud, MpDemoDebugInfo, "ScsiExecute: pSrb = 0x%p, CDB = 0x%x Path: %x TID: %x Lun: %x\n",
                      pSrb, pSrb->Cdb[0], pSrb->PathId, pSrb->TargetId, pSrb->Lun);

    *pResult = ResultDone;

    // For testing, return an error when the kernel debugger has set a flag.

    if (
        pHBAExt->LUNInfoArray[pSrb->Lun].bIODontUse   // No SCSI I/O to this LUN?
          &&
        SCSIOP_REPORT_LUNS!=pSrb->Cdb[0]              //   and not Report LUNs (which will be allowed)?
       ) {
        goto Done;
    }

    pLUExt = StorPortGetLogicalUnit(pHBAExt,          // Get the LU extension from StorPort.
                                    pSrb->PathId,
                                    pSrb->TargetId,
                                    pSrb->Lun 
                                   );

    if (!pLUExt) {
        DoStorageTraceEtw(DbgLvlErr, MpDemoDebugInfo, "Unable to get LUN extension for device %d:%d:%d\n",
                   pSrb->PathId, pSrb->TargetId, pSrb->Lun);

        status = SRB_STATUS_NO_DEVICE;
        goto Done;
    }

    // Test to get failure of I/O to this LUN on this path or on any path, except for Report LUNs.
    // Flag(s) to be set by kernel debugger. 

    if (
        (pLUExt->bIsMissing || (pLUExt->pLUMPIOExt && pLUExt->pLUMPIOExt->bIsMissingOnAnyPath)) 
          && 
        SCSIOP_REPORT_LUNS!=pSrb->Cdb[0]
       ) {
        status = SRB_STATUS_NO_DEVICE;
        goto Done;
    }

    // Handle sufficient opcodes to support a LUN suitable for a file system. Other opcodes are failed.

    switch (pSrb->Cdb[0]) {

        case SCSIOP_TEST_UNIT_READY:
        case SCSIOP_SYNCHRONIZE_CACHE:
        case SCSIOP_START_STOP_UNIT:
        case SCSIOP_VERIFY:
            status = SRB_STATUS_SUCCESS;
            break;

        case SCSIOP_INQUIRY:
            status = ScsiOpInquiry(pHBAExt, pLUExt, pSrb);
            break;

        case SCSIOP_READ_CAPACITY:
            status = ScsiOpReadCapacity(pHBAExt, pLUExt, pSrb);
            break;

        case SCSIOP_READ:
            status = ScsiOpRead(pHBAExt, pLUExt, pSrb, pResult);
            break;

        case SCSIOP_WRITE:
            status = ScsiOpWrite(pHBAExt, pLUExt, pSrb, pResult);
            break;

        case SCSIOP_MODE_SENSE:
            status = ScsiOpModeSense(pHBAExt, pLUExt, pSrb);
            break;

        case SCSIOP_REPORT_LUNS:                      
            status = ScsiOpReportLuns(pHBAExt, pLUExt, pSrb);
            break;

        default:
            status = SRB_STATUS_INVALID_REQUEST;
            break;

    } // switch (pSrb->Cdb[0])

Done:
    return status;
}                                                     // End ScsiExecuteMain.

/**************************************************************************************************/     
/*                                                                                                */     
/* Allocate a buffer to represent the in-memory disk.                                             */     
/*                                                                                                */     
/**************************************************************************************************/     
void
ScsiAllocDiskBuf(
    __in pHW_HBA_EXT pHBAExt,
    __out PVOID *ppDiskBuf,
    __out PULONG pMaxBlocks
)
{
    extern ULONGLONG g_TotalPhysicalMemoryBytes; // Declared in mp.h/mp.c
    ULONGLONG requestedBytes64 = pHBAExt->pMPDrvObj->MPRegInfo.PhysicalDiskSize;
    SIZE_T requestedBytes = (SIZE_T)requestedBytes64;
    *ppDiskBuf = NULL;

    // Debug log: requested disk size (64-bit)
    DbgPrint("ScsiAllocDiskBuf: Requested PhysicalDiskSize = %llu bytes\n", requestedBytes64);

#if !defined(_WIN64)
    // On 32-bit builds, clamp to 4GB max
    if (requestedBytes64 > (ULONGLONG)MAXUINT_PTR) {
        DbgPrint("ScsiAllocDiskBuf: WARNING - Requested disk size %llu exceeds 32-bit allocation limit (%u bytes). Will be truncated.\n",
            requestedBytes64, MAXUINT_PTR);
        requestedBytes64 = (ULONGLONG)MAXUINT_PTR;
        requestedBytes = (SIZE_T)requestedBytes64;
    }
#endif

    // Prevent allocation of 0 bytes, which can cause Driver Verifier BSOD
    if (requestedBytes == 0) {
        DbgPrint("ScsiAllocDiskBuf: ERROR - Refusing to allocate 0 bytes for DiskBuf.\n");
        DoStorageTraceEtw(DbgLvlErr, MpDemoDebugInfo,
            "Refusing to allocate 0 bytes for DiskBuf. Allocation skipped to prevent Driver Verifier bugcheck.\n");
        goto Done;
    }

    // Only check if we successfully obtained total RAM (cached at DriverEntry)
    if (g_TotalPhysicalMemoryBytes && requestedBytes > g_TotalPhysicalMemoryBytes) {
        DbgPrint("ScsiAllocDiskBuf: ERROR - Requested DiskBuf (%llu bytes) exceeds total physical RAM (%llu bytes). Allocation skipped.\n",
            (ULONGLONG)requestedBytes, g_TotalPhysicalMemoryBytes);
        DoStorageTraceEtw(DbgLvlErr, MpDemoDebugInfo,
            "Requested DiskBuf (%llu bytes) exceeds total physical RAM (%llu bytes). Allocation skipped.\n",
            (ULONGLONG)requestedBytes, g_TotalPhysicalMemoryBytes);
        goto Done;
    }

    *ppDiskBuf = ALLOCATE_NON_PAGED_POOL(requestedBytes);

    if (!*ppDiskBuf) {
        DbgPrint("ScsiAllocDiskBuf: ERROR - DiskBuf memory allocation failed!\n");
        DoStorageTraceEtw(DbgLvlErr, MpDemoDebugInfo, "DiskBuf memory allocation failed!\n");
        goto Done;
    }

    SIZE_T numBlocks = requestedBytes / MP_BLOCK_SIZE;

#if defined(_WIN64)
    if (numBlocks > 0xFFFFFFFFULL) { // 32-bit LBA limit for SCSI (READ CAPACITY(10))
        *pMaxBlocks = 0xFFFFFFFF;
    } else {
        *pMaxBlocks = (ULONG)numBlocks;
    }
#else
    if (numBlocks > (SIZE_T)0xFFFFFFFF) {
        *pMaxBlocks = 0xFFFFFFFF;
    } else {
        *pMaxBlocks = (ULONG)numBlocks;
    }
#endif

    // Debug log: success
    DbgPrint("ScsiAllocDiskBuf: Successfully allocated DiskBuf at %p, size = %llu bytes, MaxBlocks = %lu\n",
        *ppDiskBuf, (ULONGLONG)requestedBytes, *pMaxBlocks);

    // Format as FAT32 (universal, any size)
    FormatFat32Volume((UCHAR*)*ppDiskBuf, (ULONG)requestedBytes, "NEW VOLUME ");

Done:
    return;
}                                                     // End ScsiAllocDiskBuf.

/**************************************************************************************************/
/*                                                                                                */
/* Allocate a buffer to represent the in-memory disk, with persistent file backend if enabled.     */
/*                                                                                                */
/**************************************************************************************************/
BOOLEAN
ScsiAllocDiskBufPersistent(
    __in pHW_HBA_EXT pHBAExt,
    __out PVOID *ppDiskBuf,
    __out PULONG pMaxBlocks,
    __out_opt DISK_BACKEND **ppBackend
)
{
    extern ULONGLONG g_TotalPhysicalMemoryBytes;
    ULONGLONG requestedBytes64 = pHBAExt->pMPDrvObj->MPRegInfo.PhysicalDiskSize;
    SIZE_T requestedBytes = 0;
    *ppDiskBuf = NULL;
    if (ppBackend) *ppBackend = NULL;

    DbgPrint("ScsiAllocDiskBufPersistent: Requested PhysicalDiskSize = %llu bytes\n", requestedBytes64);

#if !defined(_WIN64)
    if (requestedBytes64 > (ULONGLONG)MAXUINT_PTR) {
        DbgPrint("ScsiAllocDiskBufPersistent: WARNING - Requested disk size %llu exceeds 32-bit allocation limit (%u bytes). Will be truncated.\n",
            requestedBytes64, MAXUINT_PTR);
        requestedBytes64 = (ULONGLONG)MAXUINT_PTR;
    }
#endif
    requestedBytes = (SIZE_T)requestedBytes64;

    if (requestedBytes == 0) {
        DbgPrint("ScsiAllocDiskBufPersistent: ERROR - Refusing to allocate 0 bytes for DiskBuf.\n");
        DoStorageTraceEtw(DbgLvlErr, MpDemoDebugInfo,
            "Refusing to allocate 0 bytes for DiskBuf. Allocation skipped to prevent Driver Verifier bugcheck.\n");
        goto Done;
    }
    if (g_TotalPhysicalMemoryBytes && requestedBytes > g_TotalPhysicalMemoryBytes) {
        DbgPrint("ScsiAllocDiskBufPersistent: ERROR - Requested DiskBuf (%llu bytes) exceeds total physical RAM (%llu bytes). Allocation skipped.\n",
            (ULONGLONG)requestedBytes, g_TotalPhysicalMemoryBytes);
        DoStorageTraceEtw(DbgLvlErr, MpDemoDebugInfo,
            "Requested DiskBuf (%llu bytes) exceeds total physical RAM (%llu bytes). Allocation skipped.\n",
            (ULONGLONG)requestedBytes, g_TotalPhysicalMemoryBytes);
        goto Done;
    }

    ULONG useFileBackend = pHBAExt->pMPDrvObj->MPRegInfo.UseFileBackend;
    UNICODE_STRING* diskImagePath = &pHBAExt->pMPDrvObj->MPRegInfo.DiskImagePath;
    BOOLEAN persistent = (useFileBackend && diskImagePath && diskImagePath->Length > 0 && diskImagePath->Buffer && diskImagePath->Buffer[0]);

    if (persistent) {
        DbgPrint("ScsiAllocDiskBufPersistent: Persistent file backend enabled. Path: %wZ\n", diskImagePath);
        // Allocate RAM buffer
        PVOID ramBuf = ALLOCATE_NON_PAGED_POOL(requestedBytes);
        if (!ramBuf) {
            DbgPrint("ScsiAllocDiskBufPersistent: ERROR - DiskBuf memory allocation failed!\n");
            DoStorageTraceEtw(DbgLvlErr, MpDemoDebugInfo, "DiskBuf memory allocation failed!\n");
            goto Done;
        }
        *ppDiskBuf = ramBuf;
        SIZE_T numBlocks = requestedBytes / MP_BLOCK_SIZE;

        #if defined(_WIN64)
          if (numBlocks > 0xFFFFFFFFULL) { // 32-bit LBA limit for SCSI (READ CAPACITY(10))
            *pMaxBlocks = 0xFFFFFFFF;
          } else {
            *pMaxBlocks = (ULONG)numBlocks;
          }
          #else
            if (numBlocks > (SIZE_T)0xFFFFFFFF) {
               *pMaxBlocks = 0xFFFFFFFF;
          } else {
               *pMaxBlocks = (ULONG)numBlocks;
          }
        #endif

        // Allocate backend structure
        DISK_BACKEND* backend = (DISK_BACKEND*)ALLOCATE_NON_PAGED_POOL(sizeof(DISK_BACKEND));
        if (!backend) {
            DbgPrint("ScsiAllocDiskBufPersistent: ERROR - Could not allocate DISK_BACKEND structure!\n");
            ExFreePoolWithTag(ramBuf, MP_TAG_GENERAL);
            *ppDiskBuf = NULL;
            goto Done;
        }
        NTSTATUS status = FileDiskBackend_Create(
            backend,
            diskImagePath->Buffer,
            requestedBytes,
            TRUE // create if not exist
        );
        if (!NT_SUCCESS(status)) {
            DbgPrint("ScsiAllocDiskBufPersistent: ERROR - FileDiskBackend_Create failed: 0x%08X\n", status);
            ExFreePoolWithTag(backend, MP_TAG_GENERAL);
            ExFreePoolWithTag(ramBuf, MP_TAG_GENERAL);
            *ppDiskBuf = NULL;
            goto Done;
        }

        // Try to load the persisted disk contents
        NTSTATUS readStatus = backend->ops->Read(backend->context, 0, ramBuf, (requestedBytes > (SIZE_T)ULONG_MAX) ? ULONG_MAX : (ULONG)requestedBytes);
        if (!NT_SUCCESS(readStatus)) {
            // File is empty/new, so format RAM and persist it
            ULONG safeBytes = (requestedBytes > (SIZE_T)ULONG_MAX) ? ULONG_MAX : (ULONG)requestedBytes;
            FormatFat32Volume((UCHAR*)ramBuf, safeBytes, "NEW VOLUME ");
            backend->ops->Write(backend->context, 0, ramBuf, safeBytes);
            FlushDiskBackend(backend);
        }
        if (ppBackend) *ppBackend = backend;
        else ExFreePoolWithTag(backend, MP_TAG_GENERAL);
        goto Success;
    } else {
        // RAM-only disk
        *ppDiskBuf = ALLOCATE_NON_PAGED_POOL(requestedBytes);
        if (!*ppDiskBuf) {
            DbgPrint("ScsiAllocDiskBufPersistent: ERROR - DiskBuf memory allocation failed!\n");
            DoStorageTraceEtw(DbgLvlErr, MpDemoDebugInfo, "DiskBuf memory allocation failed!\n");
            goto Done;
        }
        SIZE_T numBlocks = requestedBytes / MP_BLOCK_SIZE;

       #if defined(_WIN64)
         if (numBlocks > 0xFFFFFFFFULL) { // 32-bit LBA limit for SCSI (READ CAPACITY(10))
         *pMaxBlocks = 0xFFFFFFFF;
       } else {
        *pMaxBlocks = (ULONG)numBlocks;
       }
       #else
        if (numBlocks > (SIZE_T)0xFFFFFFFF) {
        *pMaxBlocks = 0xFFFFFFFF;
       } else {
        *pMaxBlocks = (ULONG)numBlocks;
       }
       #endif
        FormatFat32Volume((UCHAR*)*ppDiskBuf, (ULONG)requestedBytes, "NEW VOLUME ");
        goto Success;
    }
Success:
    DbgPrint("ScsiAllocDiskBufPersistent: Successfully allocated DiskBuf at %p, size = %llu bytes, MaxBlocks = %lu\n",
        *ppDiskBuf, (ULONGLONG)requestedBytes, *pMaxBlocks);
    return TRUE;
Done:
    *ppDiskBuf = NULL;
    *pMaxBlocks = 0;
    return FALSE;
}


/**************************************************************************************************/     
/*                                                                                                */     
/* Find an MPIO-collecting LUN object for the supplied (new) LUN, or allocate one.                */
/* Update: call new persistent API from MPIO and non-MPIO paths.                                  */     
/*                                                                                                */     
/**************************************************************************************************/     
pHW_LU_EXTENSION_MPIO
ScsiGetMPIOExt(
               __in pHW_HBA_EXT          pHBAExt,     // Adapter device-object extension from StorPort.
               __in pHW_LU_EXTENSION     pLUExt,      // LUN device-object extension from StorPort.
               __in PSCSI_REQUEST_BLOCK  pSrb
              )
{
    pHW_LU_EXTENSION_MPIO pLUMPIOExt = NULL;          // Prevent C4701.
#if defined(_AMD64_)
    KLOCK_QUEUE_HANDLE    LockHandle,
                          LockHandle2;
#else
    KIRQL                 SaveIrql,
                          SaveIrql2;
#endif
    PLIST_ENTRY           pNextEntry;

#if defined(_AMD64_)
    KeAcquireInStackQueuedSpinLock(&pHBAExt->pMPDrvObj->MPIOExtLock, &LockHandle);
#else
    KeAcquireSpinLock(&pHBAExt->pMPDrvObj->MPIOExtLock, &SaveIrql);
#endif

    for (                                             // Go through linked list of MPIO-collecting LUN objects.
         pNextEntry = pHBAExt->pMPDrvObj->ListMPIOExt.Flink;
         pNextEntry != &pHBAExt->pMPDrvObj->ListMPIOExt;
         pNextEntry = pNextEntry->Flink
        ) {
        pLUMPIOExt = CONTAINING_RECORD(pNextEntry, HW_LU_EXTENSION_MPIO, List);

        if (pSrb->PathId==pLUMPIOExt->ScsiAddr.PathId // Same SCSI address?
              &&
            pSrb->TargetId==pLUMPIOExt->ScsiAddr.TargetId
              &&
            pSrb->Lun==pLUMPIOExt->ScsiAddr.Lun
           ) {
            break;
        }
    }

    if (pNextEntry==&pHBAExt->pMPDrvObj->ListMPIOExt) { // No match? That is, is this to be a new MPIO LUN extension?

        pLUMPIOExt = ALLOCATE_NON_PAGED_POOL(sizeof(HW_LU_EXTENSION_MPIO));

        if (!pLUMPIOExt) {
            DoStorageTraceEtw(DbgLvlErr, MpDemoDebugInfo, "Failed to allocate HW_LU_EXTENSION_MPIO\n");
            goto Done;
        }

        RtlZeroMemory(pLUMPIOExt, sizeof(HW_LU_EXTENSION_MPIO));

        pLUMPIOExt->ScsiAddr.PathId   = pSrb->PathId;
        pLUMPIOExt->ScsiAddr.TargetId = pSrb->TargetId;
        pLUMPIOExt->ScsiAddr.Lun      = pSrb->Lun;

        KeInitializeSpinLock(&pLUMPIOExt->LUExtMPIOLock);

        InitializeListHead(&pLUMPIOExt->LUExtList);

        DISK_BACKEND* backend = NULL;
        ScsiAllocDiskBufPersistent(pHBAExt, &pLUMPIOExt->pDiskBuf, &pLUExt->MaxBlocks, &backend);
        pLUExt->pDiskBackend = backend;

        if (!pLUMPIOExt->pDiskBuf) {
            DoStorageTraceEtw(DbgLvlErr, MpDemoDebugInfo, "Failed to allocate DiskBuf\n");
            ExFreePoolWithTag(pLUMPIOExt, MP_TAG_GENERAL);
            pLUMPIOExt = NULL;
            goto Done;
        }

        InsertTailList(&pHBAExt->pMPDrvObj->ListMPIOExt, &pLUMPIOExt->List);

        pHBAExt->pMPDrvObj->DrvInfoNbrMPIOExtObj++;
    }
    else {
        pLUExt->MaxBlocks = (USHORT)(pHBAExt->pMPDrvObj->MPRegInfo.PhysicalDiskSize / MP_BLOCK_SIZE);
    }

Done:
    if (pLUMPIOExt) {                                 // Have an MPIO-collecting LUN object?
        // Add the real LUN to the MPIO-collecting LUN object.

#if defined(_AMD64_)
        KeAcquireInStackQueuedSpinLock(&pLUMPIOExt->LUExtMPIOLock, &LockHandle2);
#else
        KeAcquireSpinLock(&pLUMPIOExt->LUExtMPIOLock, &SaveIrql2);
#endif

        pLUExt->pLUMPIOExt = pLUMPIOExt;
        pLUExt->pDiskBuf = pLUMPIOExt->pDiskBuf;

        InsertTailList(&pLUMPIOExt->LUExtList, &pLUExt->MPIOList);
        pLUMPIOExt->NbrRealLUNs++;

#if defined(_AMD64_)
        KeReleaseInStackQueuedSpinLock(&LockHandle2); // Release serialization on MPIO-collecting LUN object.
#else
        KeReleaseSpinLock(&pLUMPIOExt->LUExtMPIOLock, SaveIrql2);
#endif
    }

#if defined(_AMD64_)
    KeReleaseInStackQueuedSpinLock(&LockHandle);      // Release the linked list of MPIO collector objects.
#else
    KeReleaseSpinLock(&pHBAExt->pMPDrvObj->MPIOExtLock, SaveIrql);
#endif

    return pLUMPIOExt;
}                                                     // End ScsiGetMPIOExt.

/**************************************************************************************************/     
/*                                                                                                */     
/* Robust SCSI INQUIRY data handling for correct device identity.                                 */     
/**************************************************************************************************/     
UCHAR
ScsiOpInquiry(
    __in pHW_HBA_EXT          pHBAExt,      // Adapter device-object extension from StorPort.
    __in pHW_LU_EXTENSION     pLUExt,       // LUN device-object extension from StorPort.
    __in PSCSI_REQUEST_BLOCK  pSrb
)
{
    PINQUIRYDATA          pInqData = pSrb->DataBuffer; // Point to Inquiry buffer.
    UCHAR                 deviceType, status = SRB_STATUS_SUCCESS;
    PCDB                  pCdb;
    pHW_LU_EXTENSION_MPIO pLUMPIOExt;
#if defined(_AMD64_)
    KLOCK_QUEUE_HANDLE    LockHandle;
#else
    KIRQL                 SaveIrql;
#endif

    // Robust fallback defaults (add 1 to size for NUL, but only copy field size)
    static const UCHAR DefaultVendorId[9]   = "PSS_LAB ";
    static const UCHAR DefaultProductId[17] = "PHANTOM DISK    ";
    static const UCHAR DefaultProductRev[5] = "1.00";

    UCHAR vendorId[8], productId[16], productRev[4];

    DoStorageTraceEtw(DbgLvlInfo, MpDemoDebugInfo, "Path: %d TID: %d Lun: %d\n",
                      pSrb->PathId, pSrb->TargetId, pSrb->Lun);

    // Debug: Report entry to Inquiry
    DbgPrint("ScsiOpInquiry: Path = %d, TID = %d, Lun = %d\n",
        pSrb->PathId, pSrb->TargetId, pSrb->Lun);

    RtlZeroMemory((PUCHAR)pSrb->DataBuffer, pSrb->DataTransferLength);

    deviceType = MpGetDeviceType(pHBAExt, pSrb->PathId, pSrb->TargetId, pSrb->Lun);

    if (DEVICE_NOT_FOUND == deviceType) {
        DbgPrint("ScsiOpInquiry: DEVICE_NOT_FOUND for Path = %d, TID = %d, Lun = %d\n",
            pSrb->PathId, pSrb->TargetId, pSrb->Lun);
        pSrb->DataTransferLength = 0;
        status = SRB_STATUS_INVALID_LUN;
        goto done;
    }

    pCdb = (PCDB)pSrb->Cdb;

    if (1 == pCdb->CDB6INQUIRY3.EnableVitalProductData) {
        DoStorageTraceEtw(DbgLvlLoud, MpDemoDebugInfo, "Received VPD request for page 0x%x\n",
                          pCdb->CDB6INQUIRY.PageCode);

        status = ScsiOpVPD(pHBAExt, pLUExt, pSrb);
        goto done;
    }

    pInqData->DeviceType = deviceType;
    pInqData->RemovableMedia = FALSE;
    pInqData->CommandQueue = TRUE;

    // --- Robust SCSI INQUIRY ID population ---
    // Always fill with defaults first
    RtlCopyMemory(vendorId, DefaultVendorId, 8);
    RtlCopyMemory(productId, DefaultProductId, 16);
    RtlCopyMemory(productRev, DefaultProductRev, 4);

    // If the driver extension has valid VendorId/ProductId/ProductRevision, use those (space padded)
    __try {
        if (pHBAExt && pHBAExt->VendorId && pHBAExt->VendorId[0]) {
            SIZE_T len = strnlen((const char*)pHBAExt->VendorId, 8);
            RtlCopyMemory(vendorId, pHBAExt->VendorId, len);
            if (len < 8) RtlFillMemory(vendorId + len, 8 - len, ' ');
        }
        if (pHBAExt && pHBAExt->ProductId && pHBAExt->ProductId[0]) {
            SIZE_T len = strnlen((const char*)pHBAExt->ProductId, 16);
            RtlCopyMemory(productId, pHBAExt->ProductId, len);
            if (len < 16) RtlFillMemory(productId + len, 16 - len, ' ');
        }
        if (pHBAExt && pHBAExt->ProductRevision && pHBAExt->ProductRevision[0]) {
            SIZE_T len = strnlen((const char*)pHBAExt->ProductRevision, 4);
            RtlCopyMemory(productRev, pHBAExt->ProductRevision, len);
            if (len < 4) RtlFillMemory(productRev + len, 4 - len, ' ');
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // Defensive: ignore exceptions, keep defaults
    }

    // Write to inquiry data (always exactly field size, no NUL)
    RtlCopyMemory(pInqData->VendorId, vendorId, 8);
    RtlCopyMemory(pInqData->ProductId, productId, 16);
    RtlCopyMemory(pInqData->ProductRevisionLevel, productRev, 4);

    // --- End robust population ---

    if (deviceType != DISK_DEVICE) {
        goto done;
    }

    // Check if the device has already been seen.
    if (GET_FLAG(pLUExt->LUFlags, LU_DEVICE_INITIALIZED)) {
        DbgPrint("ScsiOpInquiry: Device already initialized for Path = %d, TID = %d, Lun = %d\n",
            pSrb->PathId, pSrb->TargetId, pSrb->Lun);
        goto done;
    }

    // A new LUN.
    pLUExt->DeviceType = deviceType;
    pLUExt->TargetId   = pSrb->TargetId;
    pLUExt->Lun        = pSrb->Lun;

    if (pHBAExt->pMPDrvObj->MPRegInfo.bCombineVirtDisks) { // MPIO support?
        pLUMPIOExt = ScsiGetMPIOExt(pHBAExt, pLUExt, pSrb);
        if (!pLUMPIOExt) {
            DbgPrint("ScsiOpInquiry: ERROR - ScsiGetMPIOExt failed for Path = %d, TID = %d, Lun = %d\n",
                pSrb->PathId, pSrb->TargetId, pSrb->Lun);
            pSrb->DataTransferLength = 0;
            status = SRB_STATUS_ERROR;
            goto done;
        }
        SET_FLAG(pLUExt->LUFlags, LU_MPIO_MAPPED);
    } else {
        DISK_BACKEND* backend = NULL;
        ScsiAllocDiskBufPersistent(pHBAExt, &pLUExt->pDiskBuf, &pLUExt->MaxBlocks, &backend);
        pLUExt->pDiskBackend = backend;
        if (!pLUExt->pDiskBuf) {
            DbgPrint("ScsiOpInquiry: ERROR - Disk memory allocation failed for Path = %d, TID = %d, Lun = %d\n",
                pSrb->PathId, pSrb->TargetId, pSrb->Lun);
            DoStorageTraceEtw(DbgLvlErr, MpDemoDebugInfo, "Disk memory allocation failed!\n");
            pSrb->DataTransferLength = 0;
            status = SRB_STATUS_ERROR;
            goto done;
        }
    }

    SET_FLAG(pLUExt->LUFlags, LU_DEVICE_INITIALIZED);

#if defined(_AMD64_)
    KeAcquireInStackQueuedSpinLock(&pHBAExt->LUListLock, &LockHandle);
#else
    KeAcquireSpinLock(&pHBAExt->LUListLock, &SaveIrql);
#endif

    InsertTailList(&pHBAExt->LUList, &pLUExt->List);  // Add LUN extension to list in HBA extension.

#if defined(_AMD64_)
    KeReleaseInStackQueuedSpinLock(&LockHandle);
#else
    KeReleaseSpinLock(&pHBAExt->LUListLock, SaveIrql);
#endif

    DbgPrint("ScsiOpInquiry: New device created for Path = %d, TID = %d, Lun = %d\n",
        pSrb->PathId, pSrb->TargetId, pSrb->Lun);

done:
    return status;
}                                                     // End ScsiOpInquiry.

/**************************************************************************************************/     
/*                                                                                                */     
/**************************************************************************************************/     
UCHAR
ScsiOpVPD(
          __in pHW_HBA_EXT          pHBAExt,          // Adapter device-object extension from StorPort.
          __in pHW_LU_EXTENSION     pLUExt,           // LUN device-object extension from StorPort.
          __in PSCSI_REQUEST_BLOCK  pSrb
         )
{
    UCHAR                  status;
    ULONG                  len;
    struct _CDB6INQUIRY3 * pVpdInquiry = (struct _CDB6INQUIRY3 *)&pSrb->Cdb;;

    ASSERT(pLUExt != NULL);
    ASSERT(pSrb->DataTransferLength>0);

    if (0==pSrb->DataTransferLength) {
        DoStorageTraceEtw(DbgLvlErr, MpDemoDebugInfo, "pSrb->DataTransferLength = 0\n");

        return SRB_STATUS_DATA_OVERRUN;
      }

    RtlZeroMemory((PUCHAR)pSrb->DataBuffer,           // Clear output buffer.
                  pSrb->DataTransferLength);

    if (VPD_SUPPORTED_PAGES==pVpdInquiry->PageCode) { // Inquiry for supported pages?
      PVPD_SUPPORTED_PAGES_PAGE pSupportedPages;

      len = sizeof(VPD_SUPPORTED_PAGES_PAGE) + 8;

      if (pSrb->DataTransferLength < len) {
        return SRB_STATUS_DATA_OVERRUN;
      }

      pSupportedPages = pSrb->DataBuffer;             // Point to output buffer.

      pSupportedPages->DeviceType = DISK_DEVICE;
      pSupportedPages->DeviceTypeQualifier = 0;
      pSupportedPages->PageCode = VPD_SERIAL_NUMBER;
      pSupportedPages->PageLength = 8;                // Enough space for 4 VPD values.
      pSupportedPages->SupportedPageList[0] =         // Show page 0x80 supported.
        VPD_SERIAL_NUMBER;
      pSupportedPages->SupportedPageList[1] =         // Show page 0x83 supported.
        VPD_DEVICE_IDENTIFIERS;

      status = SRB_STATUS_SUCCESS;
    }
    else
    if (VPD_SERIAL_NUMBER==pVpdInquiry->PageCode) {   // Inquiry for serial number?
      PVPD_SERIAL_NUMBER_PAGE pVpd;

      len = sizeof(VPD_SERIAL_NUMBER_PAGE) + 8 + 32;
      if (pSrb->DataTransferLength < len) {
        return SRB_STATUS_DATA_OVERRUN;
      }

      pVpd = pSrb->DataBuffer;                        // Point to output buffer.

      pVpd->DeviceType = DISK_DEVICE;
      pVpd->DeviceTypeQualifier = 0;
      pVpd->PageCode = VPD_SERIAL_NUMBER;                
      pVpd->PageLength = 8 + 32;

      if (pHBAExt->pMPDrvObj->MPRegInfo.bCombineVirtDisks) { // MPIO support?
          /* Generate a constant serial number. */
//        sprintf((char *)pVpd->SerialNumber, "000%02d%03d0123456789abcdefghijABCDEFGHIJxx\n", 
//                pLUExt->TargetId, pLUExt->Lun);
      }
      else {
          /* Generate a changing serial number. */
//        sprintf((char *)pVpd->SerialNumber, "%03d%02d%03d0123456789abcdefghijABCDEFGHIJxx\n", 
//                pHBAExt->pMPDrvObj->DrvInfoNbrMPHBAObj, pLUExt->TargetId, pLUExt->Lun);
      }

      DoStorageTraceEtw(DbgLvlLoud, MpDemoDebugInfo,
                        "ScsiOpVPD:  VPD Page: %d Serial No.: %s", pVpd->PageCode, (const char *)pVpd->SerialNumber);

      status = SRB_STATUS_SUCCESS;
    }
    else
    if (VPD_DEVICE_IDENTIFIERS==pVpdInquiry->PageCode) { // Inquiry for device ids?
        PVPD_IDENTIFICATION_PAGE pVpid;
        PVPD_IDENTIFICATION_DESCRIPTOR pVpidDesc;

        #define VPIDNameSize 32
        #define VPIDName     "PSSLUNxxx"

        len = sizeof(VPD_IDENTIFICATION_PAGE) + sizeof(VPD_IDENTIFICATION_DESCRIPTOR) + VPIDNameSize;

        if (pSrb->DataTransferLength < len) {
          return SRB_STATUS_DATA_OVERRUN;
        }

        pVpid = pSrb->DataBuffer;                     // Point to output buffer.

        pVpid->PageCode = VPD_DEVICE_IDENTIFIERS;

        pVpidDesc =                                   // Point to first (and only) descriptor.
            (PVPD_IDENTIFICATION_DESCRIPTOR)pVpid->Descriptors;

        pVpidDesc->CodeSet = VpdCodeSetAscii;         // Identifier contains ASCII.
        pVpidDesc->IdentifierType =                   // 
            VpdIdentifierTypeFCPHName;

        if (pHBAExt->pMPDrvObj->MPRegInfo.bCombineVirtDisks) { // MPIO support?
            /* Generate a constant serial number. */
            sprintf((char *)pVpidDesc->Identifier, "000%02d%03d0123456789abcdefghij\n", 
                    pLUExt->TargetId, pLUExt->Lun);
        }
        else {
            /* Generate a changing serial number. */
            sprintf((char *)pVpidDesc->Identifier, "%03d%02d%03d0123456789abcdefghij\n", 
                    pHBAExt->pMPDrvObj->DrvInfoNbrMPHBAObj, pLUExt->TargetId, pLUExt->Lun);
        }

        pVpidDesc->IdentifierLength =                 // Size of Identifier.
            (UCHAR)strlen((const char *)pVpidDesc->Identifier) - 1;
        pVpid->PageLength =                           // Show length of remainder.
            (UCHAR)(FIELD_OFFSET(VPD_IDENTIFICATION_PAGE, Descriptors) + 
                    FIELD_OFFSET(VPD_IDENTIFICATION_DESCRIPTOR, Identifier) + 
                    pVpidDesc->IdentifierLength);

        DoStorageTraceEtw(DbgLvlLoud, MpDemoDebugInfo,
                          "ScsiOpVPD:  VPD Page 0x83");

        status = SRB_STATUS_SUCCESS;
    }
    else {
      status = SRB_STATUS_INVALID_REQUEST;
      len = 0;
    }

    pSrb->DataTransferLength = len;

    return status;
}                                                     // End ScsiOpVPD().

/**************************************************************************************************/     
/*                                                                                                */     
/**************************************************************************************************/     
UCHAR
ScsiOpReadCapacity(
                   __in pHW_HBA_EXT          pHBAExt, // Adapter device-object extension from StorPort.
                   __in pHW_LU_EXTENSION     pLUExt,  // LUN device-object extension from StorPort.
                   __in PSCSI_REQUEST_BLOCK  pSrb
                  )
{
    PREAD_CAPACITY_DATA  readCapacity = pSrb->DataBuffer;
    ULONGLONG            diskSizeBytes = pHBAExt->pMPDrvObj->MPRegInfo.VirtualDiskSize;
    ULONGLONG            maxBlocks64;
    ULONG                maxBlocks;
    ULONG                blockSize = MP_BLOCK_SIZE;

    UNREFERENCED_PARAMETER(pHBAExt);
    UNREFERENCED_PARAMETER(pLUExt);

    ASSERT(pLUExt != NULL);

    RtlZeroMemory((PUCHAR)pSrb->DataBuffer, pSrb->DataTransferLength );

    // Claim 512-byte blocks (big-endian)
    readCapacity->BytesPerBlock =
      (((PUCHAR)&blockSize)[0] << 24) |  (((PUCHAR)&blockSize)[1] << 16) |
      (((PUCHAR)&blockSize)[2] <<  8) | ((PUCHAR)&blockSize)[3];

    // Calculate max blocks (one less than total, per SCSI spec)
    maxBlocks64 = diskSizeBytes / MP_BLOCK_SIZE;
    if (maxBlocks64 != 0) {
        maxBlocks64 -= 1;
    }

#if !defined(_WIN64)
    if (maxBlocks64 > (ULONGLONG)MAXULONG) {
        DbgPrint("ScsiOpReadCapacity: WARNING - maxBlocks64 (%llu) exceeds 32-bit ULONG max (%lu). Truncating.\n",
            maxBlocks64, MAXULONG);
        maxBlocks = MAXULONG;
    } else {
        maxBlocks = (ULONG)maxBlocks64;
    }
#else
    // 64-bit build: allow >4GB disks
    if (maxBlocks64 > 0xFFFFFFFFULL) {
        // Per SCSI READ CAPACITY(10), the largest LBA is 0xFFFFFFFF (32 bits)
        // For larger disks, Windows will use the READ CAPACITY(16) command.
        // Here, just return 0xFFFFFFFF to indicate >2TB disk, if desired.
        maxBlocks = 0xFFFFFFFF;
    } else {
        maxBlocks = (ULONG)maxBlocks64;
    }
#endif

    DoStorageTraceEtw(DbgLvlInfo, MpDemoDebugInfo, "Block Size: 0x%x\n", blockSize);
    DoStorageTraceEtw(DbgLvlLoud, MpDemoDebugInfo, "Max Blocks: 0x%x (from %llu)\n", maxBlocks, maxBlocks64);

    readCapacity->LogicalBlockAddress =
      (((PUCHAR)&maxBlocks)[0] << 24) | (((PUCHAR)&maxBlocks)[1] << 16) |
      (((PUCHAR)&maxBlocks)[2] <<  8) | ((PUCHAR)&maxBlocks)[3];

    return SRB_STATUS_SUCCESS;
}                                                     // End ScsiOpReadCapacity.


/**************************************************************************************************/     
/*                                                                                                */     
/**************************************************************************************************/     
UCHAR
ScsiOpRead(
           __in pHW_HBA_EXT          pHBAExt,         // Adapter device-object extension from StorPort.
           __in pHW_LU_EXTENSION     pLUExt,          // LUN device-object extension from StorPort.
           __in PSCSI_REQUEST_BLOCK  pSrb,
           __in PUCHAR               pResult
          )
{
    UCHAR                        status;

    status = ScsiReadWriteSetup(pHBAExt, pLUExt, pSrb, ActionRead, pResult);

    return status;
}                                                     // End ScsiOpRead.

/**************************************************************************************************/     
/*                                                                                                */     
/**************************************************************************************************/     
UCHAR
ScsiOpWrite(
            __in pHW_HBA_EXT          pHBAExt,        // Adapter device-object extension from StorPort.
            __in pHW_LU_EXTENSION     pLUExt,         // LUN device-object extension from StorPort.
            __in PSCSI_REQUEST_BLOCK  pSrb,
            __in PUCHAR               pResult
           )
{
    UCHAR                        status;

    status = ScsiReadWriteSetup(pHBAExt, pLUExt, pSrb, ActionWrite, pResult);

    return status;
}                                                     // End ScsiOpWrite.

/**************************************************************************************************/     
/*                                                                                                */     
/* This routine does the setup for reading or writing. The reading/writing could be effected      */     
/* here rather than in MpGeneralWkRtn, but in the general case MpGeneralWkRtn is going to be the  */     
/* place to do the work since it gets control at PASSIVE_LEVEL and so could do real I/O, could    */     
/* wait, etc, etc.                                                                                */
/* Update: Now persists writes to file backend if present.                                        */     
/*                                                                                                */     
/**************************************************************************************************/     
UCHAR
ScsiReadWriteSetup(
    __in pHW_HBA_EXT          pHBAExt,
    __in pHW_LU_EXTENSION     pLUExt,
    __in PSCSI_REQUEST_BLOCK  pSrb,
    __in MpWkRtnAction        WkRtnAction,
    __in PUCHAR               pResult
)
{
    PCDB   pCdb = (PCDB)pSrb->Cdb;
    ULONG  startingSector, sectorOffset;
    USHORT numBlocks;
    pMP_WorkRtnParms pWkRtnParms = NULL;

    ASSERT(pLUExt != NULL);

    *pResult = ResultDone;

    startingSector = pCdb->CDB10.LogicalBlockByte3       |
                     (pCdb->CDB10.LogicalBlockByte2 << 8)  |
                     (pCdb->CDB10.LogicalBlockByte1 << 16) |
                     (pCdb->CDB10.LogicalBlockByte0 << 24);
    numBlocks      = (USHORT)(pSrb->DataTransferLength / MP_BLOCK_SIZE);
    sectorOffset   = startingSector * MP_BLOCK_SIZE;

    DoStorageTraceEtw(DbgLvlInfo, MpDemoDebugInfo, "ScsiReadWriteSetup action: %X, starting sector: 0x%X, number of blocks: 0x%X\n", WkRtnAction, startingSector, numBlocks);
    DoStorageTraceEtw(DbgLvlInfo, MpDemoDebugInfo, "ScsiReadWriteSetup pSrb: 0x%p, pSrb->DataBuffer: 0x%p\n", pSrb, pSrb->DataBuffer);

    if (startingSector >= pLUExt->MaxBlocks) {
        DoStorageTraceEtw(DbgLvlInfo, MpDemoDebugInfo, "*** ScsiReadWriteSetup Starting sector: %d, number of blocks: %d\n", startingSector, numBlocks);
        return SRB_STATUS_INVALID_REQUEST;
    }

    // Fast path: Only perform direct memory copy if at IRQL <= APC_LEVEL
    if (KeGetCurrentIrql() <= APC_LEVEL && numBlocks * MP_BLOCK_SIZE <= 64 * 1024) {
        PUCHAR diskBuf = (PUCHAR)pLUExt->pDiskBuf;
        if (WkRtnAction == ActionRead) {
            RtlCopyMemory(
                pSrb->DataBuffer,
                diskBuf + sectorOffset,
                numBlocks * MP_BLOCK_SIZE
            );
        } else {
            RtlCopyMemory(
                diskBuf + sectorOffset,
                pSrb->DataBuffer,
                numBlocks * MP_BLOCK_SIZE
            );
            // ---- Persistent backend write ----
            if (pLUExt->pDiskBackend) {
                NTSTATUS status = pLUExt->pDiskBackend->ops->Write(
                    pLUExt->pDiskBackend->context,
                    sectorOffset,
                    pSrb->DataBuffer,
                    numBlocks * MP_BLOCK_SIZE
                );
                if (NT_SUCCESS(status) && pLUExt->pDiskBackend->ops->Flush) {
                    pLUExt->pDiskBackend->ops->Flush(pLUExt->pDiskBackend->context);
                }
            }
        }
        *pResult = ResultDone;
        return SRB_STATUS_SUCCESS;
    }

    // Fallback: queue work item for larger or high-IRQL I/O
    pWkRtnParms = (pMP_WorkRtnParms)ALLOCATE_NON_PAGED_POOL(sizeof(MP_WorkRtnParms));

    if (NULL == pWkRtnParms) {
        DoStorageTraceEtw(DbgLvlErr, MpDemoDebugInfo, "ScsiReadWriteSetup Failed to allocate work parm structure\n");
        return SRB_STATUS_ERROR;
    }

    RtlZeroMemory(pWkRtnParms, sizeof(MP_WorkRtnParms));

    pWkRtnParms->pHBAExt = pHBAExt;
    pWkRtnParms->pLUExt = pLUExt;
    pWkRtnParms->pSrb = pSrb;
    pWkRtnParms->Action = (WkRtnAction == ActionRead) ? ActionRead : ActionWrite;

    pWkRtnParms->pQueueWorkItem = IoAllocateWorkItem((PDEVICE_OBJECT)pHBAExt->pDrvObj);

    if (NULL == pWkRtnParms->pQueueWorkItem) {
        DoStorageTraceEtw(DbgLvlErr, MpDemoDebugInfo, "ScsiReadWriteSetup: Failed to allocate work item\n");
        ExFreePoolWithTag(pWkRtnParms, MP_TAG_GENERAL);
        return SRB_STATUS_ERROR;
    }

    IoQueueWorkItem(pWkRtnParms->pQueueWorkItem, MpGeneralWkRtn, DelayedWorkQueue, pWkRtnParms);
    *pResult = ResultQueued;

    return SRB_STATUS_SUCCESS;
}                                                     // End ScsiReadWriteSetup.

/**************************************************************************************************/     
/*                                                                                                */     
/**************************************************************************************************/     
UCHAR
ScsiOpModeSense(
                __in pHW_HBA_EXT          pHBAExt,    // Adapter device-object extension from StorPort.
                __in pHW_LU_EXTENSION     pLUExt,     // LUN device-object extension from StorPort.
                __in PSCSI_REQUEST_BLOCK  pSrb
               )
{
    UNREFERENCED_PARAMETER(pHBAExt);
    UNREFERENCED_PARAMETER(pLUExt);

    RtlZeroMemory((PUCHAR)pSrb->DataBuffer, pSrb->DataTransferLength);

    return SRB_STATUS_SUCCESS;
}

/**************************************************************************************************/     
/*                                                                                                */     
/**************************************************************************************************/     
UCHAR
ScsiOpReportLuns(                                     
                 __in __out pHW_HBA_EXT         pHBAExt,   // Adapter device-object extension from StorPort.
                 __in       pHW_LU_EXTENSION    pLUExt,    // LUN device-object extension from StorPort.
                 __in       PSCSI_REQUEST_BLOCK pSrb
                )
{
    UCHAR     status = SRB_STATUS_SUCCESS;
    PLUN_LIST pLunList = (PLUN_LIST)pSrb->DataBuffer; // Point to LUN list.
    ULONG     i, 
              GoodLunIdx;

    UNREFERENCED_PARAMETER(pLUExt);

    // Debug: Entering ReportLuns
    DbgPrint("ScsiOpReportLuns: Entered. NbrLUNsperHBA = %lu\n", pHBAExt->NbrLUNsperHBA);

    if (FALSE==pHBAExt->bReportAdapterDone) {         // This opcode will be one of the earliest I/O requests for a new HBA (and may be received later, too).
        MpHwReportAdapter(pHBAExt);                   // WMIEvent test.

        MpHwReportLink(pHBAExt);                      // WMIEvent test.

        MpHwReportLog(pHBAExt);                       // WMIEvent test.

        pHBAExt->bReportAdapterDone = TRUE;
    }

    if (
        0==pSrb->PathId && 0==pSrb->TargetId          // Handle only if 0.0.x    
          &&                                          //   and
        !pHBAExt->bDontReport                         //     if not prevented for the HBA.
       ) {
        RtlZeroMemory((PUCHAR)pSrb->DataBuffer, pSrb->DataTransferLength);

        pLunList->LunListLength[3] =                  // Set length needed for LUNs.
            (UCHAR)(8*pHBAExt->NbrLUNsperHBA);

        // Set the LUN numbers if there is enough room, and set only those LUNs to be reported.

        if (pSrb->DataTransferLength>=FIELD_OFFSET(LUN_LIST, Lun) + (sizeof(pLunList->Lun[0])*pHBAExt->NbrLUNsperHBA)) {
            for (i = 0, GoodLunIdx = 0; i < pHBAExt->NbrLUNsperHBA; i ++) {
                // LUN to be reported?
                if (FALSE==pHBAExt->LUNInfoArray[i].bReportLUNsDontUse) {
                    pLunList->Lun[GoodLunIdx][1] = (UCHAR)i;
                    GoodLunIdx++;
                }
            }
            DbgPrint("ScsiOpReportLuns: Reported %lu LUN(s)\n", GoodLunIdx);
        }
    }

    return status;
}                                                     // End ScsiOpReportLuns.
