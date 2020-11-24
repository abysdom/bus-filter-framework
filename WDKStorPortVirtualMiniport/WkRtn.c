/****************************** Module Header ******************************\
* Module Name:  WkRtn.c
* Project:      CppWDKStorPortVirtualMiniport
*
* Copyright (c) Microsoft Corporation.
* 
* a.      MpGeneralWkRtn()
* Handles queued work elements by calling MpWkRtn.
*
* b.      MpWkRtn()
* Handles work elements, completes them.
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
#define WkRtnVer     "1.013"

#define _MP_H_skip_includes

#include "mp.h"

#pragma warning(push)
#pragma warning(disable : 4204)                       /* Prevent C4204 messages from stortrce.h. */
#include <stortrce.h>
#pragma warning(pop)

#include "trace.h"
#include "WkRtn.tmh"

/**************************************************************************************************/ 
/*                                                                                                */ 
/* Globals, forward definitions, etc.                                                             */ 
/*                                                                                                */ 
/**************************************************************************************************/ 

/**************************************************************************************************/ 
/*                                                                                                */ 
/* This is the work routine, which always runs in System under an OS-supplied worker thread.      */ 
/*                                                                                                */ 
/**************************************************************************************************/ 
VOID                                                                                                                                               
MpGeneralWkRtn(
               __in PVOID           pDummy,           // Not used.
               __in PVOID           pWkParms          // Parm list pointer.
              )
{
    pMP_WorkRtnParms        pWkRtnParms = (pMP_WorkRtnParms)pWkParms;

    UNREFERENCED_PARAMETER(pDummy);

    IoFreeWorkItem(pWkRtnParms->pQueueWorkItem);      // Free queue item.

    pWkRtnParms->pQueueWorkItem = NULL;               // Be neat.

    // If the next starts, it has to be stopped by a kernel debugger.

    while (pWkRtnParms->SecondsToDelay) {
       LARGE_INTEGER delay;

       delay.QuadPart = - 10 * 1000 * 1000 * pWkRtnParms->SecondsToDelay;

       KeDelayExecutionThread(KernelMode, TRUE, &delay);
    }

    MpWkRtn(pWkParms);                                // Do the actual work.
}                                                     // End MpGeneralWkRtn().

/**************************************************************************************************/ 
/*                                                                                                */ 
/* This routine does the "read"/"write" work, by copying to/from the miniport's buffers.          */ 
/*                                                                                                */ 
/**************************************************************************************************/ 
VOID                                                                                                                                               
MpWkRtn(__in PVOID pWkParms)                          // Parm list pointer.
{
    pMP_WorkRtnParms          pWkRtnParms = (pMP_WorkRtnParms)pWkParms;
    pHW_HBA_EXT               pHBAExt = pWkRtnParms->pHBAExt;
    pHW_LU_EXTENSION          pLUExt = pWkRtnParms->pLUExt;
    PSCSI_REQUEST_BLOCK       pSrb = pWkRtnParms->pSrb;
    PCDB                      pCdb = (PCDB)pSrb->Cdb;
    ULONG                     startingSector,
                              sectorOffset,
                              lclStatus;
    PVOID                     pX = NULL;
    UCHAR                     status;

    startingSector = pCdb->CDB10.LogicalBlockByte3       |
                     pCdb->CDB10.LogicalBlockByte2 << 8  |
                     pCdb->CDB10.LogicalBlockByte1 << 16 |
                     pCdb->CDB10.LogicalBlockByte0 << 24;

    sectorOffset = startingSector * MP_BLOCK_SIZE;

    DoStorageTraceEtw(DbgLvlInfo, MpDemoDebugInfo, "MpWkRtn Action: %X, starting sector: 0x%X, sector offset: 0x%X\n", pWkRtnParms->Action, startingSector, sectorOffset);
    DoStorageTraceEtw(DbgLvlInfo, MpDemoDebugInfo, "MpWkRtn pSrb: 0x%p, pSrb->DataBuffer: 0x%p\n", pSrb, pSrb->DataBuffer); 

    // Note:  Obviously there's going to be a problem if pSrb->DataBuffer points to something in user space, since the correct user space
    //        is probably not that of the System process.  Less obviously, in the paging path at least, even an address in kernel space 
    //        proved not valid; that is, not merely not backed by real storage but actually not valid.  The reason for this behavior is
    //        still under investigation.  For now, in all cases observed, it has been found sufficient to get a new kernel-space address 
    //        to use.

    lclStatus = StorPortGetSystemAddress(pHBAExt, pSrb, &pX);

    if (STOR_STATUS_SUCCESS!=lclStatus || !pX) {
        DoStorageTraceEtw(DbgLvlInfo, MpDemoDebugInfo, "MpWkRtn Failed to get system address for pSrb = 0x%p, pSrb->DataBuffer=0x%p, status = 0x%08x, pX = 0x%p\n", 
                          pSrb, pSrb->DataBuffer, lclStatus, pX);
        status = SRB_STATUS_ERROR;   

        goto Done;
    }

    DoStorageTraceEtw(DbgLvlInfo, MpDemoDebugInfo, "MpWkRtn Using pX=0x%p\n", pX);

    if (ActionRead==pWkRtnParms->Action) {            // Read?
      RtlMoveMemory(pX, &pLUExt->pDiskBuf[sectorOffset], pSrb->DataTransferLength);
    }
    else {                                            // Write.
      RtlMoveMemory(&pLUExt->pDiskBuf[sectorOffset], pX, pSrb->DataTransferLength);
    }

    status = SRB_STATUS_SUCCESS;   

Done:
    pSrb->SrbStatus = status;   

    // Tell StorPort this action has been completed.

    StorPortNotification(RequestComplete, pHBAExt, pSrb);

    ExFreePoolWithTag(pWkParms, MP_TAG_GENERAL);      // Free parm list.
}                                                     // End MpWkRtn().

