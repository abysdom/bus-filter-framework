/****************************** Module Header ******************************\
* Module Name:  mp.c
* Project:      CppWDKStorPortVirtualMiniport

* Copyright (c) Microsoft Corporation.
* 
* a.       DriverEntry()
* Gets some resources, call StorPortInitialize().
*
* b.      MpHwFindAdapter()
* Gets more resources, sets configuration parameters.
*
* c.       MpHwStartIo()
* Entry point for an I/O. This calls the appropriate support routine, e.g., ScsiExecuteMain().
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

#define MPDriverVer     "5.022"

#include "mp.h"

#pragma warning(push)
#pragma warning(disable : 4204)                       /* Prevent C4204 messages from stortrce.h. */
#include <stortrce.h>
#pragma warning(pop)

#include <wdf.h>
#include "trace.h"
#include "mp.tmh"
#include "hbapiwmi.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text( INIT, DriverEntry )
#endif // ALLOC_PRAGMA

/**************************************************************************************************/ 
/*                                                                                                */ 
/* Globals.                                                                                       */ 
/*                                                                                                */ 
/**************************************************************************************************/ 

#ifdef MP_DrvInfo_Inline

MPDriverInfo  lclDriverInfo;

#endif

pMPDriverInfo pMPDrvInfoGlobal = NULL;

/**************************************************************************************************/ 
/*                                                                                                */ 
/*                                                                                                */ 
/**************************************************************************************************/ 
__declspec(dllexport)                                 // Ensure DriverEntry entry point visible to WinDbg even without a matching .pdb.            
ULONG                                                                                                                                              
DriverEntry(
            __in PVOID           pDrvObj,
            __in PUNICODE_STRING pRegistryPath
           )
{
    NTSTATUS                       status = STATUS_SUCCESS;
    VIRTUAL_HW_INITIALIZATION_DATA hwInitData;
    pMPDriverInfo                  pMPDrvInfo;

#ifdef MP_DrvInfo_Inline

    // Because there's no good way to clean up the allocation of the global driver information, 
    // the global information is kept in an inline structure.

    pMPDrvInfo = &lclDriverInfo;

#else

    //
    // Allocate basic miniport driver object (shared across instances of miniport). The pointer is kept in the driver binary's static storage.
    //
    // Because there's no good way to clean up the allocation of the global driver information, 
    // the global information will be leaked.  This is deemed acceptable since it's not expected
    // that DriverEntry will be invoked often in the life of a Windows boot.
    //

    pMPDrvInfo = ExAllocatePoolWithTag(NonPagedPool, sizeof(MPDriverInfo), MP_TAG_GENERAL);

    if (!pMPDrvInfo) {                                // No good?
        status = STATUS_INSUFFICIENT_RESOURCES;

        goto Done;
    }

#endif

    pMPDrvInfoGlobal = pMPDrvInfo;                    // Save pointer in binary's storage.

    RtlZeroMemory(pMPDrvInfo, sizeof(MPDriverInfo));  // Set pMPDrvInfo's storage to a known state.

    pMPDrvInfo->pDriverObj = pDrvObj;                 // Save pointer to driver object.

    KeInitializeSpinLock(&pMPDrvInfo->DrvInfoLock);   // Initialize spin lock.
    KeInitializeSpinLock(&pMPDrvInfo->MPIOExtLock);   //   "

    InitializeListHead(&pMPDrvInfo->ListMPHBAObj);    // Initialize list head.
    InitializeListHead(&pMPDrvInfo->ListMPIOExt);   

    // Get registry parameters.

    MpQueryRegParameters(pRegistryPath, &pMPDrvInfo->MPRegInfo);

    // Ensure number of LUNs per HBA doesn't exceed maximum supported.
    if (pMPDrvInfo->MPRegInfo.NbrLUNsperHBA > LUNInfoMax)  
        pMPDrvInfo->MPRegInfo.NbrLUNsperHBA = LUNInfoMax;

    if (pMPDrvInfo->MPRegInfo.VirtualDiskSize != pMPDrvInfo->MPRegInfo.PhysicalDiskSize) {
        // Physical & Virtual size must match for using full disk
        pMPDrvInfo->MPRegInfo.VirtualDiskSize = pMPDrvInfo->MPRegInfo.PhysicalDiskSize;
    }

    // Set up information for StorPortInitialize().

    RtlZeroMemory(&hwInitData, sizeof(VIRTUAL_HW_INITIALIZATION_DATA));

    hwInitData.HwInitializationDataSize = sizeof(VIRTUAL_HW_INITIALIZATION_DATA);

    hwInitData.HwInitialize             = MpHwInitialize;       // Required.
    hwInitData.HwStartIo                = MpHwStartIo;          // Required.
    hwInitData.HwFindAdapter            = MpHwFindAdapter;      // Required.
    hwInitData.HwResetBus               = MpHwResetBus;         // Required.
    hwInitData.HwAdapterControl         = MpHwAdapterControl;   // Required.
    hwInitData.HwFreeAdapterResources   = MpHwFreeAdapterResources;
    hwInitData.HwInitializeTracing      = MPTracingInit;
    hwInitData.HwCleanupTracing         = MPTracingCleanup;
    hwInitData.HwProcessServiceRequest  = MpProcServReq;
    hwInitData.HwCompleteServiceIrp     = MpCompServReq;

    hwInitData.AdapterInterfaceType     = Internal;

    hwInitData.DeviceExtensionSize      = sizeof(HW_HBA_EXT);
    hwInitData.SpecificLuExtensionSize  = sizeof(HW_LU_EXTENSION);
    hwInitData.SrbExtensionSize         = sizeof(HW_SRB_EXTENSION);

    status =  StorPortInitialize(                     // Tell StorPort we're here.
                                 pDrvObj,
                                 pRegistryPath,
                                 (PHW_INITIALIZATION_DATA)&hwInitData,     // Note: Have to override type!
                                 NULL
                                );

    if (STATUS_SUCCESS!=status) {                     // Port driver said not OK?                                        
      goto Done;
    }                                                 // End 'port driver said not OK'?
    
Done:    
    if (STATUS_SUCCESS!=status) {                     // A problem?
    
#ifndef MP_DrvInfo_Inline

      if (NULL!=pMPDrvInfo) {
        ExFreePoolWithTag(pMPDrvInfo, MP_TAG_GENERAL);
      }

#endif

    }
    
    return status;
}                                                     // End DriverEntry().

/**************************************************************************************************/ 
/*                                                                                                */ 
/* Callback for a new HBA.                                                                        */ 
/*                                                                                                */ 
/**************************************************************************************************/ 
ULONG                                                 
MpHwFindAdapter(
                __in       pHW_HBA_EXT                     pHBAExt,           // Adapter device-object extension from StorPort.
                __in       PVOID                           pHwContext,        // Pointer to context.
                __in       PVOID                           pBusInformation,   // Miniport's FDO.
                __in       PVOID                           pLowerDO,          // Device object beneath FDO.
                __in       PCHAR                           pArgumentString,
                __in __out PPORT_CONFIGURATION_INFORMATION pConfigInfo,
                __in       PBOOLEAN                        pBAgain            
               )
{
    ULONG              i,
                       len,
                       status = SP_RETURN_FOUND;
    PCHAR              pChar;

#if defined(_AMD64_)

    KLOCK_QUEUE_HANDLE LockHandle;

#else

    KIRQL              SaveIrql;

#endif

    UNREFERENCED_PARAMETER(pHwContext);
    UNREFERENCED_PARAMETER(pBusInformation);
    UNREFERENCED_PARAMETER(pLowerDO);
    UNREFERENCED_PARAMETER(pArgumentString);

    DoStorageTraceEtw(DbgLvlLoud, MpDemoDebugInfo,
                      "MpHwFindAdapter:  pHBAExt = 0x%p, pConfigInfo = 0x%p\n", pHBAExt, pConfigInfo);

    pHBAExt->pMPDrvObj = pMPDrvInfoGlobal;            // Copy master object from static variable.

    InitializeListHead(&pHBAExt->MPIOLunList);        // Initialize list head.
    InitializeListHead(&pHBAExt->LUList);

    KeInitializeSpinLock(&pHBAExt->WkItemsLock);      // Initialize locks.     
    KeInitializeSpinLock(&pHBAExt->WkRoutinesLock);     
    KeInitializeSpinLock(&pHBAExt->MPHBAObjLock);     
    KeInitializeSpinLock(&pHBAExt->LUListLock);     

    pHBAExt->HostTargetId = (UCHAR)pHBAExt->pMPDrvObj->MPRegInfo.InitiatorID;

    pHBAExt->pDrvObj = pHBAExt->pMPDrvObj->pDriverObj;

    MpCreateDeviceList(pHBAExt, pHBAExt->pMPDrvObj->MPRegInfo.NbrLUNsperHBA);
     
    if (!pHBAExt->pPrevDeviceList) {
        pHBAExt->pPrevDeviceList = pHBAExt->pDeviceList;
    }
     
    pConfigInfo->VirtualDevice                  = TRUE;                        // Inidicate no real hardware.
    pConfigInfo->WmiDataProvider                = TRUE;                        // Indicate WMI provider.
    pConfigInfo->MaximumTransferLength          = SP_UNINITIALIZED_VALUE;      // Indicate unlimited.
    pConfigInfo->AlignmentMask                  = 0x3;                         // Indicate DWORD alignment.
    pConfigInfo->CachesData                     = FALSE;                       // Indicate miniport wants flush and shutdown notification.
    pConfigInfo->MaximumNumberOfTargets         = SCSI_MAXIMUM_TARGETS;        // Indicate maximum targets.
    pConfigInfo->NumberOfBuses                  = 1;                           // Indicate number of busses.
    pConfigInfo->SynchronizationModel           = StorSynchronizeFullDuplex;   // Indicate full-duplex.
    pConfigInfo->ScatterGather                  = TRUE;                        // Indicate scatter-gather (explicit setting needed for Win2003 at least).
   
    // Save Vendor Id, Product Id, Revision in device extension.

    pChar = (PCHAR)pHBAExt->pMPDrvObj->MPRegInfo.VendorId.Buffer;
    len = min(8, (pHBAExt->pMPDrvObj->MPRegInfo.VendorId.Length/2));
    for ( i = 0; i < len; i++, pChar+=2)
      pHBAExt->VendorId[i] = *pChar;

    pChar = (PCHAR)pHBAExt->pMPDrvObj->MPRegInfo.ProductId.Buffer;
    len = min(16, (pHBAExt->pMPDrvObj->MPRegInfo.ProductId.Length/2));
    for ( i = 0; i < len; i++, pChar+=2)
      pHBAExt->ProductId[i] = *pChar;

    pChar = (PCHAR)pHBAExt->pMPDrvObj->MPRegInfo.ProductRevision.Buffer;
    len = min(4, (pHBAExt->pMPDrvObj->MPRegInfo.ProductRevision.Length/2));
    for ( i = 0; i < len; i++, pChar+=2)
      pHBAExt->ProductRevision[i] = *pChar;

    pHBAExt->NbrLUNsperHBA = pHBAExt->pMPDrvObj->MPRegInfo.NbrLUNsperHBA;

    // Add HBA extension to master driver object's linked list.

#if defined(_AMD64_)

    KeAcquireInStackQueuedSpinLock(&pHBAExt->pMPDrvObj->DrvInfoLock, &LockHandle);

#else

    KeAcquireSpinLock(&pHBAExt->pMPDrvObj->DrvInfoLock, &SaveIrql);

#endif

    InsertTailList(&pHBAExt->pMPDrvObj->ListMPHBAObj, &pHBAExt->List);

    pHBAExt->pMPDrvObj->DrvInfoNbrMPHBAObj++;

#if defined(_AMD64_)

    KeReleaseInStackQueuedSpinLock(&LockHandle);

#else

    KeReleaseSpinLock(&pHBAExt->pMPDrvObj->DrvInfoLock, SaveIrql);

#endif

    InitializeWmiContext(pHBAExt);
    
    *pBAgain = FALSE;    
    
    return status;
}                                                     // End MpHwFindAdapter().

/**************************************************************************************************/ 
/*                                                                                                */ 
/**************************************************************************************************/ 
BOOLEAN
MpHwInitialize(__in pHW_HBA_EXT pHBAExt)
{
    UNREFERENCED_PARAMETER(pHBAExt);

    return TRUE;
}                                                     // End MpHwInitialize().

#define StorPortMaxWMIEventSize 0x80                  // Maximum WMIEvent size StorPort will support.
#define InstName L"vHBA"

/**************************************************************************************************/ 
/*                                                                                                */ 
/**************************************************************************************************/ 
void
MpHwReportAdapter(__in pHW_HBA_EXT pHBAExt)
{
    NTSTATUS               status;
    PWNODE_SINGLE_INSTANCE pWnode;
    ULONG                  WnodeSize,
                           WnodeSizeInstanceName,
                           WnodeSizeDataBlock,
                           length,
                           size;
    GUID                   lclGuid = MSFC_AdapterEvent_GUID;
    UNICODE_STRING         lclInstanceName;
    UCHAR                  myPortWWN[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    PMSFC_AdapterEvent     pAdapterArr;

    // With the instance name used here and with the rounding-up to 4-byte alignment of the data portion used here,
    // 0x34 (52) bytes are available for the actual data of the WMI event.  (The 0x34 bytes result from the fact that
    // StorPort at present (August 2008) allows 0x80 bytes for the entire WMIEvent (header, instance name and data);
    // the header is 0x40 bytes; the instance name used here results in 0xA bytes, and the rounding up consumes 2 bytes;
    // in other words, 0x80 - (0x40 + 0x0A + 0x02)).

    RtlInitUnicodeString(&lclInstanceName, InstName); // Set Unicode descriptor for instance name.

    // A WMIEvent structure consists of header, instance name and data block.

    WnodeSize             = sizeof(WNODE_SINGLE_INSTANCE);

    // Because the first field in the data block, EventType, is a ULONG, ensure that the data block begins on a
    // 4-byte boundary (as will be calculated in DataBlockOffset).

    WnodeSizeInstanceName = sizeof(USHORT) +          // Size of USHORT at beginning plus
                            lclInstanceName.Length;   //   size of instance name.
    WnodeSizeInstanceName =                           // Round length up to multiple of 4 (if needed).
      (ULONG)WDF_ALIGN_SIZE_UP(WnodeSizeInstanceName, sizeof(ULONG));

    WnodeSizeDataBlock    = MSFC_AdapterEvent_SIZE;   // Size of data block.

    size = WnodeSize             +                    // Size of WMIEvent.         
           WnodeSizeInstanceName + 
           WnodeSizeDataBlock;

    pWnode = ExAllocatePoolWithTag(NonPagedPool, size, MP_TAG_GENERAL);

    if (NULL!=pWnode) {                               // Good?
        RtlZeroMemory(pWnode, size);
        
        // Fill out most of header. StorPort will set the ProviderId and TimeStamp in the header.

        pWnode->WnodeHeader.BufferSize = size;
        pWnode->WnodeHeader.Version    = 1;
        RtlCopyMemory(&pWnode->WnodeHeader.Guid, &lclGuid, sizeof(lclGuid));  
        pWnode->WnodeHeader.Flags      = WNODE_FLAG_EVENT_ITEM |
                                         WNODE_FLAG_SINGLE_INSTANCE;

        // Say where to find instance name and the data block and what is the data block's size.

        pWnode->OffsetInstanceName     = WnodeSize;
        pWnode->DataBlockOffset        = WnodeSize + WnodeSizeInstanceName;
        pWnode->SizeDataBlock          = WnodeSizeDataBlock;

        // Copy the instance name.
                   
        size -= WnodeSize;                            // Length remaining and available.
        status = WDF_WMI_BUFFER_APPEND_STRING(        // Copy WCHAR string, preceded by its size.
            WDF_PTR_ADD_OFFSET(pWnode, pWnode->OffsetInstanceName),
            size,                                     // Length available for copying.
            &lclInstanceName,                         // Unicode string whose WCHAR buffer is to be copied.
            &length                                   // Variable to receive size needed.
            );

        if (STATUS_SUCCESS!=status) {                 // A problem?
            ASSERT(FALSE);
        }

        pAdapterArr =                                 // Point to data block.
          WDF_PTR_ADD_OFFSET(pWnode, pWnode->DataBlockOffset);

        // Copy event code and WWN.

        pAdapterArr->EventType = HBA_EVENT_ADAPTER_ADD;

        RtlCopyMemory(pAdapterArr->PortWWN, myPortWWN, sizeof(myPortWWN));

        // Ask StorPort to announce the event.

        StorPortNotification(WMIEvent, 
                             pHBAExt, 
                             pWnode, 
                             0xFF);                   // Notification pertains to an HBA.

        ExFreePoolWithTag(pWnode, MP_TAG_GENERAL);
    }
    else {
    }
}                                                     // End MpHwReportAdapter().

/**************************************************************************************************/ 
/*                                                                                                */ 
/**************************************************************************************************/ 
void
MpHwReportLink(__in pHW_HBA_EXT pHBAExt)
{
    NTSTATUS               status;
    PWNODE_SINGLE_INSTANCE pWnode;
    PMSFC_LinkEvent        pLinkEvent;
    ULONG                  WnodeSize,
                           WnodeSizeInstanceName,
                           WnodeSizeDataBlock,
                           length,
                           size;
    GUID                   lclGuid = MSFC_LinkEvent_GUID;
    UNICODE_STRING         lclInstanceName;
             
    #define RLIRBufferArraySize 0x10                  // Define 16 entries in MSFC_LinkEvent.RLIRBuffer[].
             
    UCHAR                  myAdapterWWN[8] = {1, 2, 3, 4, 5, 6, 7, 8},
                           myRLIRBuffer[RLIRBufferArraySize] = {10, 11, 12, 13, 14, 15, 16, 17, 20, 21, 22, 23, 24, 25, 26, 0xFF};

    RtlInitUnicodeString(&lclInstanceName, InstName); // Set Unicode descriptor for instance name.

    WnodeSize             = sizeof(WNODE_SINGLE_INSTANCE);
    WnodeSizeInstanceName = sizeof(USHORT) +          // Size of USHORT at beginning plus
                            lclInstanceName.Length;   //   size of instance name.
    WnodeSizeInstanceName =                           // Round length up to multiple of 4 (if needed).
      (ULONG)WDF_ALIGN_SIZE_UP(WnodeSizeInstanceName, sizeof(ULONG));
    WnodeSizeDataBlock    =                           // Size of data.
                            FIELD_OFFSET(MSFC_LinkEvent, RLIRBuffer) +
                            sizeof(myRLIRBuffer);

    size = WnodeSize             +                    // Size of WMIEvent.         
           WnodeSizeInstanceName + 
           WnodeSizeDataBlock;

    pWnode = ExAllocatePoolWithTag(NonPagedPool, size, MP_TAG_GENERAL);

    if (NULL!=pWnode) {                               // Good?
        RtlZeroMemory(pWnode, size);
        
        // Fill out most of header. StorPort will set the ProviderId and TimeStamp in the header.

        pWnode->WnodeHeader.BufferSize = size;
        pWnode->WnodeHeader.Version    = 1;
        RtlCopyMemory(&pWnode->WnodeHeader.Guid, &lclGuid, sizeof(lclGuid));  
        pWnode->WnodeHeader.Flags      = WNODE_FLAG_EVENT_ITEM |
                                         WNODE_FLAG_SINGLE_INSTANCE;

        // Say where to find instance name and the data block and what is the data block's size.

        pWnode->OffsetInstanceName     = WnodeSize;
        pWnode->DataBlockOffset        = WnodeSize + WnodeSizeInstanceName;
        pWnode->SizeDataBlock          = WnodeSizeDataBlock;

        // Copy the instance name.
                   
        size -= WnodeSize;                            // Length remaining and available.
        status = WDF_WMI_BUFFER_APPEND_STRING(        // Copy WCHAR string, preceded by its size.
            WDF_PTR_ADD_OFFSET(pWnode, pWnode->OffsetInstanceName),
            size,                                     // Length available for copying.
            &lclInstanceName,                         // Unicode string whose WCHAR buffer is to be copied.
            &length                                   // Variable to receive size needed.
            );

        if (STATUS_SUCCESS!=status) {                 // A problem?
            ASSERT(FALSE);
        }

        pLinkEvent =                                  // Point to data block.
          WDF_PTR_ADD_OFFSET(pWnode, pWnode->DataBlockOffset);

        // Copy event code, WWN, buffer size and buffer contents.

        pLinkEvent->EventType = HBA_EVENT_LINK_INCIDENT;

        RtlCopyMemory(pLinkEvent->AdapterWWN, myAdapterWWN, sizeof(myAdapterWWN));

        pLinkEvent->RLIRBufferSize = sizeof(myRLIRBuffer);

        RtlCopyMemory(pLinkEvent->RLIRBuffer, myRLIRBuffer, sizeof(myRLIRBuffer));

        StorPortNotification(WMIEvent, 
                             pHBAExt, 
                             pWnode, 
                             0xFF);                   // Notification pertains to an HBA.

        ExFreePoolWithTag(pWnode, MP_TAG_GENERAL);
    }
    else {
    }
}                                                     // End MpHwReportLink().

/**************************************************************************************************/ 
/*                                                                                                */ 
/**************************************************************************************************/ 
void
MpHwReportLog(__in pHW_HBA_EXT pHBAExt)
{
    NTSTATUS               status;
    PWNODE_SINGLE_INSTANCE pWnode;
    ULONG                  WnodeSize,
                           WnodeSizeInstanceName,
                           WnodeSizeDataBlock,
                           length,
                           size;
    UNICODE_STRING         lclInstanceName;
    PIO_ERROR_LOG_PACKET   pLogError;

    RtlInitUnicodeString(&lclInstanceName, InstName); // Set Unicode descriptor for instance name.

    WnodeSize             = sizeof(WNODE_SINGLE_INSTANCE);
    WnodeSizeInstanceName = sizeof(USHORT) +          // Size of USHORT at beginning plus
                            lclInstanceName.Length;   //   size of instance name.
    WnodeSizeInstanceName =                           // Round length up to multiple of 4 (if needed).
      (ULONG)WDF_ALIGN_SIZE_UP(WnodeSizeInstanceName, sizeof(ULONG));
    WnodeSizeDataBlock    = sizeof(IO_ERROR_LOG_PACKET);       // Size of data.

    size = WnodeSize             +                    // Size of WMIEvent.         
           WnodeSizeInstanceName + 
           WnodeSizeDataBlock;

    pWnode = ExAllocatePoolWithTag(NonPagedPool, size, MP_TAG_GENERAL);

    if (NULL!=pWnode) {                               // Good?
        RtlZeroMemory(pWnode, size);
        
        // Fill out most of header. StorPort will set the ProviderId and TimeStamp in the header.

        pWnode->WnodeHeader.BufferSize = size;
        pWnode->WnodeHeader.Version    = 1;
        pWnode->WnodeHeader.Flags      = WNODE_FLAG_EVENT_ITEM |
                                         WNODE_FLAG_LOG_WNODE;

        pWnode->WnodeHeader.HistoricalContext = 9;

        // Say where to find instance name and the data block and what is the data block's size.

        pWnode->OffsetInstanceName     = WnodeSize;
        pWnode->DataBlockOffset        = WnodeSize + WnodeSizeInstanceName;
        pWnode->SizeDataBlock          = WnodeSizeDataBlock;

        // Copy the instance name.
                   
        size -= WnodeSize;                            // Length remaining and available.
        status = WDF_WMI_BUFFER_APPEND_STRING(        // Copy WCHAR string, preceded by its size.
            WDF_PTR_ADD_OFFSET(pWnode, pWnode->OffsetInstanceName),
            size,                                     // Length available for copying.
            &lclInstanceName,                         // Unicode string whose WCHAR buffer is to be copied.
            &length                                   // Variable to receive size needed.
            );

        if (STATUS_SUCCESS!=status) {                 // A problem?
            ASSERT(FALSE);
        }

        pLogError =                                    // Point to data block.
          WDF_PTR_ADD_OFFSET(pWnode, pWnode->DataBlockOffset);

        pLogError->UniqueErrorValue = 0x40;
        pLogError->FinalStatus = 0x41;
        pLogError->ErrorCode = 0x42;

        StorPortNotification(WMIEvent, 
                             pHBAExt, 
                             pWnode, 
                             0xFF);                   // Notification pertains to an HBA.

        ExFreePoolWithTag(pWnode, MP_TAG_GENERAL);
    }
    else {
    }
}                                                     // End MpHwReportLog().

/**************************************************************************************************/ 
/*                                                                                                */ 
/**************************************************************************************************/ 
BOOLEAN
MpHwResetBus(
             __in pHW_HBA_EXT          pHBAExt,       // Adapter device-object extension from StorPort.
             __in ULONG                BusId
            )
{
    UNREFERENCED_PARAMETER(pHBAExt);
    UNREFERENCED_PARAMETER(BusId);

    // To do: At some future point, it may be worthwhile to ensure that any SRBs being handled be completed at once.
    //        Practically speaking, however, it seems that the only SRBs that would not be completed very quickly
    //        would be those handled by the worker thread. In the future, therefore, there might be a global flag
    //        set here to instruct the thread to complete outstanding I/Os as they appear; but a period for that
    //        happening would have to be devised (such completion shouldn't be unbounded).

    return TRUE;
}                                                     // End MpHwResetBus().

/**************************************************************************************************/ 
/*                                                                                                */ 
/**************************************************************************************************/ 
NTSTATUS                                              
MpHandleRemoveDevice(
                     __in pHW_HBA_EXT             pHBAExt,// Adapter device-object extension from StorPort.
                     __in PSCSI_PNP_REQUEST_BLOCK pSrb
                    )
{
    UNREFERENCED_PARAMETER(pHBAExt);

    pSrb->SrbStatus = SRB_STATUS_BAD_FUNCTION;

    return STATUS_UNSUCCESSFUL;
}                                                     // End MpHandleRemoveDevice().

/**************************************************************************************************/ 
/*                                                                                                */ 
/**************************************************************************************************/ 
NTSTATUS                                           
MpHandleQueryCapabilities(
                          __in pHW_HBA_EXT             pHBAExt,// Adapter device-object extension from StorPort.
                          __in PSCSI_PNP_REQUEST_BLOCK pSrb
                         )
{
    NTSTATUS                  status = STATUS_SUCCESS;
    PSTOR_DEVICE_CAPABILITIES pStorageCapabilities = (PSTOR_DEVICE_CAPABILITIES)pSrb->DataBuffer;

    UNREFERENCED_PARAMETER(pHBAExt);

    RtlZeroMemory(pStorageCapabilities, pSrb->DataTransferLength);

    pStorageCapabilities->Removable = FALSE;
    pStorageCapabilities->SurpriseRemovalOK = FALSE;

    pSrb->SrbStatus = SRB_STATUS_SUCCESS;

    return status;
}                                                     // End MpHandleQueryCapabilities().

/**************************************************************************************************/ 
/*                                                                                                */ 
/**************************************************************************************************/ 
NTSTATUS                                              
MpHwHandlePnP(
              __in pHW_HBA_EXT              pHBAExt,  // Adapter device-object extension from StorPort.
              __in PSCSI_PNP_REQUEST_BLOCK  pSrb
             )
{
    NTSTATUS status = STATUS_SUCCESS;

    switch(pSrb->PnPAction) {

      case StorRemoveDevice:
        status = MpHandleRemoveDevice(pHBAExt, pSrb);

        break;

      case StorQueryCapabilities:
        status = MpHandleQueryCapabilities(pHBAExt, pSrb);

        break;

      default:
        pSrb->SrbStatus = SRB_STATUS_SUCCESS;         // Do nothing.
    }

    if (STATUS_SUCCESS!=status) {
    }

    return status;
}                                                     // End MpHwHandlePnP().

/**************************************************************************************************/ 
/*                                                                                                */ 
/**************************************************************************************************/ 
BOOLEAN
MpHwStartIo(
            __in       pHW_HBA_EXT          pHBAExt,  // Adapter device-object extension from StorPort.
            __in __out PSCSI_REQUEST_BLOCK  pSrb
           )
{
    UCHAR                     srbStatus = SRB_STATUS_INVALID_REQUEST;
    BOOLEAN                   bFlag;
    NTSTATUS                  status;
    UCHAR                     Result = ResultDone;

    DoStorageTraceEtw(DbgLvlLoud, MpDemoDebug04,
                      "MpHwStartIo:  SCSI Request Block = %!SRB!\n",
                      pSrb);

    _InterlockedExchangeAdd((volatile LONG *)&pHBAExt->SRBsSeen, 1);   // Bump count of SRBs encountered.

    // Next, if true, will cause StorPort to remove the associated LUNs if, for example, devmgmt.msc is asked "scan for hardware changes."

    if (pHBAExt->bDontReport) {                       // Act as though the HBA/path is gone?
        srbStatus = SRB_STATUS_INVALID_LUN;
        goto done;
    }

    switch (pSrb->Function) {

        case SRB_FUNCTION_EXECUTE_SCSI:
            srbStatus = ScsiExecuteMain(pHBAExt, pSrb, &Result);
            break;

        case SRB_FUNCTION_WMI:
            _InterlockedExchangeAdd((volatile LONG *)&pHBAExt->WMISRBsSeen, 1);
            bFlag = HandleWmiSrb(pHBAExt, (PSCSI_WMI_REQUEST_BLOCK)pSrb);
            srbStatus = TRUE==bFlag ? SRB_STATUS_SUCCESS : SRB_STATUS_INVALID_REQUEST;
            break;
            
        case SRB_FUNCTION_RESET_LOGICAL_UNIT:
            StorPortCompleteRequest(
                                    pHBAExt,
                                    pSrb->PathId,
                                    pSrb->TargetId,
                                    pSrb->Lun,
                                    SRB_STATUS_BUSY
                                   );
            srbStatus = SRB_STATUS_SUCCESS;
            break;
            
        case SRB_FUNCTION_RESET_DEVICE:
            StorPortCompleteRequest(
                                    pHBAExt,
                                    pSrb->PathId,
                                    pSrb->TargetId,
                                    SP_UNTAGGED,
                                    SRB_STATUS_TIMEOUT
                                   );
            srbStatus = SRB_STATUS_SUCCESS;
            break;
            
        case SRB_FUNCTION_PNP:                        
            status = MpHwHandlePnP(pHBAExt, (PSCSI_PNP_REQUEST_BLOCK)pSrb);
            srbStatus = pSrb->SrbStatus;
            
            break;

        case SRB_FUNCTION_POWER:                      
            // Do nothing.
            srbStatus = SRB_STATUS_SUCCESS;

            break;

        case SRB_FUNCTION_SHUTDOWN:                   
            // Do nothing.
            srbStatus = SRB_STATUS_SUCCESS;

            break;

        default:
            DoStorageTraceEtw(DbgLvlErr, MpDemoDebugInfo, "MpHwStartIo: Unknown Srb Function = 0x%x\n", pSrb->Function);
            srbStatus = SRB_STATUS_INVALID_REQUEST;
            break;

    } // switch (pSrb->Function)

done:
    if (ResultDone==Result) {                         // Complete now?
      pSrb->SrbStatus = srbStatus;

      // Note:  A miniport with real hardware would not always be calling RequestComplete from HwStorStartIo.  Rather,
      //        the miniport would typically be doing real I/O and would call RequestComplete only at the end of that
      //        real I/O, in its HwStorInterrupt or in a DPC routine.

      StorPortNotification(RequestComplete, pHBAExt, pSrb);
    }
     
    DoStorageTraceEtw(DbgLvlInfo, MpDemoDebugInfo, "MpHwStartIo - OUT\n");

    return TRUE;
}                                                     // End MpHwStartIo().

/**************************************************************************************************/ 
/*                                                                                                */ 
/**************************************************************************************************/ 
SCSI_ADAPTER_CONTROL_STATUS
MpHwAdapterControl(
                   __in pHW_HBA_EXT               pHBAExt, // Adapter device-object extension from StorPort.
                   __in SCSI_ADAPTER_CONTROL_TYPE ControlType,
                   __in PVOID                     pParameters
                  )
{
    PSCSI_SUPPORTED_CONTROL_TYPE_LIST pCtlTypList;
    ULONG                             i;

    DoStorageTraceEtw(DbgLvlLoud, MpDemoDebugInfo,
                      "MpHwAdapterControl:  ControlType = %d\n", ControlType);

    pHBAExt->AdapterState = ControlType;

    switch (ControlType) {
        case ScsiQuerySupportedControlTypes:
            DoStorageTraceEtw(DbgLvlLoud, MpDemoDebugInfo, "MpHwAdapterControl: ScsiQuerySupportedControlTypes\n");

            // Ggt pointer to control type list
            pCtlTypList = (PSCSI_SUPPORTED_CONTROL_TYPE_LIST)pParameters;

            // Cycle through list to set TRUE for each type supported
            // making sure not to go past the MaxControlType
            for (i = 0; i < pCtlTypList->MaxControlType; i++)
                if ( i == ScsiQuerySupportedControlTypes ||
                     i == ScsiStopAdapter   || i == ScsiRestartAdapter ||
                     i == ScsiSetBootConfig || i == ScsiSetRunningConfig )
                {
                    pCtlTypList->SupportedTypeList[i] = TRUE;
                }
            break;

        case ScsiStopAdapter:
            DoStorageTraceEtw(DbgLvlLoud, MpDemoDebugInfo, "MpHwAdapterControl:  ScsiStopAdapter\n");

            // Free memory allocated for disk
            MpStopAdapter(pHBAExt);

            break;

        case ScsiRestartAdapter:
            DoStorageTraceEtw(DbgLvlInfo, MpDemoDebugInfo, "MpHwAdapterControl:  ScsiRestartAdapter\n");

            /* To Do: Add some function. */

            break;

        case ScsiSetBootConfig:
            DoStorageTraceEtw(DbgLvlInfo, MpDemoDebugInfo, "MpHwAdapterControl:  ScsiSetBootConfig\n");

            break;
            
        case ScsiSetRunningConfig:
            DoStorageTraceEtw(DbgLvlInfo, MpDemoDebugInfo, "MpHwAdapterControl:  ScsiSetRunningConfig\n");

            break;

        default:
            DoStorageTraceEtw(DbgLvlInfo, MpDemoDebugInfo, "MpHwAdapterControl:  UNKNOWN\n");

            break;
    } 

    DoStorageTraceEtw(DbgLvlInfo, MpDemoDebugInfo, "MpHwAdapterControl - OUT\n");

    return ScsiAdapterControlSuccess;
}                                                     // End MpHwAdapterControl().

/**************************************************************************************************/ 
/*                                                                                                */ 
/**************************************************************************************************/ 
VOID
MpStopAdapter(__in pHW_HBA_EXT pHBAExt)               // Adapter device-object extension from StorPort.
{
    pHW_LU_EXTENSION      pLUExt, 
                          pLUExt2;
    PLIST_ENTRY           pNextEntry, 
                          pNextEntry2;
    pMPDriverInfo         pMPDrvInfo = pHBAExt->pMPDrvObj;
    pHW_LU_EXTENSION_MPIO pLUMPIOExt = NULL;          // Prevent C4701 warning.

#if defined(_AMD64_)
    KLOCK_QUEUE_HANDLE    LockHandle;
#else
    KIRQL                 SaveIrql;
#endif

    // Clean up the "disk buffers."

    for (                                             // Go through linked list of LUN extensions for this HBA.
         pNextEntry = pHBAExt->LUList.Flink;
         pNextEntry != &pHBAExt->LUList;
         pNextEntry = pNextEntry->Flink
        ) {
        pLUExt = CONTAINING_RECORD(pNextEntry, HW_LU_EXTENSION, List);

        if (pMPDrvInfo->MPRegInfo.bCombineVirtDisks) {// MPIO support?
            pLUMPIOExt = pLUExt->pLUMPIOExt;
    
            if (!pLUMPIOExt) {                        // No MPIO extension?
                break;
            }
    
#if defined(_AMD64_)
            KeAcquireInStackQueuedSpinLock(&pLUMPIOExt->LUExtMPIOLock, &LockHandle);   
#else
            KeAcquireSpinLock(&pLUMPIOExt->LUExtMPIOLock, &SaveIrql);
#endif
    
            for (                                     // Go through linked list of LUN extensions for the MPIO collector object (HW_LU_EXTENSION_MPIO).
                 pNextEntry2 = pLUMPIOExt->LUExtList.Flink;
                 pNextEntry2 != &pLUMPIOExt->LUExtList;
                 pNextEntry2 = pNextEntry2->Flink
                ) {
                pLUExt2 = CONTAINING_RECORD(pNextEntry2, HW_LU_EXTENSION, MPIOList);

                if (pLUExt2==pLUExt) {                // Pointing to same LUN extension?
                    break;
                }
            }
    
            if (pNextEntry2!=&pLUMPIOExt->LUExtList) {// Found it?
                RemoveEntryList(pNextEntry2);         // Remove LU extension from MPIO collector object.    
    
                pLUMPIOExt->NbrRealLUNs--;    
    
                if (0==pLUMPIOExt->NbrRealLUNs) {     // Was this the last LUN extension in the MPIO collector object?
                    ExFreePool(pLUExt->pDiskBuf);
                }
            }

#if defined(_AMD64_)
            KeReleaseInStackQueuedSpinLock(&LockHandle);
#else
            KeReleaseSpinLock(&pLUMPIOExt->LUExtMPIOLock, SaveIrql);
#endif
        }
        else {
            ExFreePool(pLUExt->pDiskBuf);
        }
    }

    // Clean up the linked list of MPIO collector objects, if needed.

    if (pMPDrvInfo->MPRegInfo.bCombineVirtDisks) {    // MPIO support?
#if defined(_AMD64_)
        KeAcquireInStackQueuedSpinLock(               // Serialize the linked list of MPIO collector objects.
                                       &pMPDrvInfo->MPIOExtLock, &LockHandle);   
#else
        KeAcquireSpinLock(&pMPDrvInfo->MPIOExtLock, &SaveIrql);
#endif

        for (                                         // Go through linked list of MPIO collector objects for this miniport driver.
             pNextEntry = pMPDrvInfo->ListMPIOExt.Flink;
             pNextEntry != &pMPDrvInfo->ListMPIOExt;
             pNextEntry = pNextEntry2
            ) {
            pLUMPIOExt = CONTAINING_RECORD(pNextEntry, HW_LU_EXTENSION_MPIO, List);

            if (!pLUMPIOExt) {                        // No MPIO extension?
                break;
            }
    
            pNextEntry2 = pNextEntry->Flink;          // Save forward pointer in case MPIO collector object containing forward pointer is freed.

            if (0==pLUMPIOExt->NbrRealLUNs) {         // No real LUNs (HW_LU_EXTENSION) left?
                RemoveEntryList(pNextEntry);          // Remove MPIO collector object from miniport driver object.    

                ExFreePoolWithTag(pLUMPIOExt, MP_TAG_GENERAL);
            }
        }

#if defined(_AMD64_)
        KeReleaseInStackQueuedSpinLock(&LockHandle);
#else
        KeReleaseSpinLock(&pMPDrvInfo->MPIOExtLock, SaveIrql);
#endif
    }

//done:
    return;
}                                                     // End MpStopAdapter().

/**************************************************************************************************/ 
/*                                                                                                */ 
/* Create list of LUNs for specified HBA extension.                                               */ 
/*                                                                                                */ 
/**************************************************************************************************/ 
NTSTATUS
MpCreateDeviceList(
                   __in       pHW_HBA_EXT    pHBAExt,
                   __in       ULONG          NbrLUNs
                  )
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG    i,
             len = FIELD_OFFSET(MP_DEVICE_LIST, DeviceInfo) + (NbrLUNs * sizeof(MP_DEVICE_INFO));

    if (pHBAExt->pDeviceList) {
        ExFreePoolWithTag(pHBAExt->pDeviceList, MP_TAG_GENERAL);
    }

    pHBAExt->pDeviceList = ExAllocatePoolWithTag(NonPagedPool, len, MP_TAG_GENERAL);

    if (!pHBAExt->pDeviceList) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto done;
    }

    RtlZeroMemory(pHBAExt->pDeviceList, len);

    pHBAExt->pDeviceList->DeviceCount = NbrLUNs; 

    for (i = 0; i < NbrLUNs; i ++) {
        pHBAExt->pDeviceList->DeviceInfo[i].LunID = (UCHAR)i;
    }

done:
    return status;
}                                                     // End MpCreateDeviceList().

/**************************************************************************************************/ 
/*                                                                                                */ 
/* Return device type for specified device on specified HBA extension.                            */ 
/*                                                                                                */ 
/**************************************************************************************************/ 
UCHAR 
MpGetDeviceType(
                __in pHW_HBA_EXT          pHBAExt,    // Adapter device-object extension from StorPort.
                __in UCHAR                PathId,
                __in UCHAR                TargetId,
                __in UCHAR                Lun
               )
{
    pMP_DEVICE_LIST pDevList = pHBAExt->pDeviceList;
    ULONG           i;
    UCHAR           type = DEVICE_NOT_FOUND;

    UNREFERENCED_PARAMETER(PathId);

    if (!pDevList || 0==pDevList->DeviceCount) {
        goto done;
    }

    for (i = 0; i < pDevList->DeviceCount; i ++) {    // Find the matching LUN (if any).
        if (
            TargetId==pDevList->DeviceInfo[i].TargetID
              &&
            Lun==pDevList->DeviceInfo[i].LunID
           ) {
            type = pDevList->DeviceInfo[i].DeviceType;
            goto done;
        }
    }

done:
    return type;
}                                                     // End MpGetDeviceType().

/**************************************************************************************************/                         
/*                                                                                                */                         
/* MPTracingInit.                                                                                 */                         
/*                                                                                                */                         
/**************************************************************************************************/                         
VOID                                                                                                                         
MPTracingInit(                                                                                                            
              __in PVOID pArg1,                                                                                  
              __in PVOID pArg2
             )                                                                                                            
{                                                                                                                            
    WPP_INIT_TRACING(pArg1, pArg2);
}                                                     // End MPTracingInit().

/**************************************************************************************************/                         
/*                                                                                                */                         
/* MPTracingCleanUp.                                                                              */                         
/*                                                                                                */                         
/* This is called when the driver is being unloaded.                                              */                         
/*                                                                                                */                         
/**************************************************************************************************/                         
VOID                                                                                                                         
MPTracingCleanup(__in PVOID pArg1)                                                                                                            
{                                                                                                                            
    DoStorageTraceEtw(DbgLvlLoud, MpDemoDebugInfo, "MPTracingCleanUp entered\n");                                                                       

    WPP_CLEANUP(pArg1);
}                                                     // End MPTracingCleanup().

/**************************************************************************************************/                         
/*                                                                                                */                         
/* MpHwFreeAdapterResources.                                                                      */                         
/*                                                                                                */                         
/**************************************************************************************************/                         
VOID
MpHwFreeAdapterResources(__in pHW_HBA_EXT pHBAExt)
{
    PLIST_ENTRY           pNextEntry; 
    pHW_HBA_EXT           pLclHBAExt;
#if defined(_AMD64_)
    KLOCK_QUEUE_HANDLE    LockHandle;
#else
    KIRQL                 SaveIrql;
#endif

    DoStorageTraceEtw(DbgLvlLoud, MpDemoDebugInfo, "MpHwFreeAdapterResources entered, pHBAExt = 0x%p\n", pHBAExt);                                                                       

#if defined(_AMD64_)
    KeAcquireInStackQueuedSpinLock(&pHBAExt->pMPDrvObj->DrvInfoLock, &LockHandle);
#else
    KeAcquireSpinLock(&pHBAExt->pMPDrvObj->DrvInfoLock, &SaveIrql);
#endif

    for (                                             // Go through linked list of HBA extensions.
         pNextEntry =  pHBAExt->pMPDrvObj->ListMPHBAObj.Flink;
         pNextEntry != &pHBAExt->pMPDrvObj->ListMPHBAObj;
         pNextEntry =  pNextEntry->Flink
        ) {
        pLclHBAExt = CONTAINING_RECORD(pNextEntry, HW_HBA_EXT, List);

        if (pLclHBAExt==pHBAExt) {                    // Is this entry the same as pHBAExt?
            RemoveEntryList(pNextEntry);
            pHBAExt->pMPDrvObj->DrvInfoNbrMPHBAObj--;
            break;
        }
    }

#if defined(_AMD64_)
    KeReleaseInStackQueuedSpinLock(&LockHandle);
#else
    KeReleaseSpinLock(&pHBAExt->pMPDrvObj->DrvInfoLock, SaveIrql);
#endif

    ExFreePoolWithTag(pHBAExt->pDeviceList, MP_TAG_GENERAL);
}                                                     // End MpHwFreeAdapterResources().

/**************************************************************************************************/                         
/*                                                                                                */                         
/* MpCompleteIrp.                                                                                 */                         
/*                                                                                                */                         
/**************************************************************************************************/                         
VOID
MpCompleteIrp(
              __in pHW_HBA_EXT   pHBAExt,             // Adapter device-object extension from StorPort.
              __in PIRP          pIrp
             )
{
    #define            minLen 16

    DoStorageTraceEtw(DbgLvlLoud, MpDemoDebugInfo, "MpCompleteIrp entered\n");

    if (NULL!=pIrp) {
      NTSTATUS           Status = STATUS_SUCCESS;
      PIO_STACK_LOCATION pIrpStack = IoGetCurrentIrpStackLocation(pIrp);
      ULONG              inputBufferLength;

      inputBufferLength = 
        pIrpStack->Parameters.DeviceIoControl.InputBufferLength;

      switch (pIrpStack->Parameters.DeviceIoControl.IoControlCode) {
        case IOCTL_MINIPORT_PROCESS_SERVICE_IRP: 

          if (inputBufferLength < minLen) {

            Status = STATUS_BUFFER_TOO_SMALL;
          }

          break;

        default:
          Status = STATUS_INVALID_DEVICE_REQUEST;

          break;
      }

      RtlMoveMemory(pIrp->AssociatedIrp.SystemBuffer, "123412341234123", minLen);

      pIrp->IoStatus.Status = Status;
      pIrp->IoStatus.Information = 16;

      StorPortCompleteServiceIrp(pHBAExt, pIrp);
    }
}                                                     // End MpCompleteIrp().

/**************************************************************************************************/                         
/*                                                                                                */                         
/* MpQueueServiceIrp.                                                                             */                         
/*                                                                                                */                         
/* If there is already an IRP queued, it will be dequeued (and then completed) to make way for    */                         
/* the IRP supplied here.                                                                         */                         
/*                                                                                                */                         
/**************************************************************************************************/                         
VOID
MpQueueServiceIrp(
                  __in pHW_HBA_EXT          pHBAExt,  // Adapter device-object extension from StorPort.
                  __in PIRP                 pIrp      // IRP pointer to be queued.
                 )
{
    PIRP pOldIrp;

    DoStorageTraceEtw(DbgLvlLoud, MpDemoDebugInfo, "MpQueueServiceIrp entered\n");

    pOldIrp = InterlockedExchangePointer(&pHBAExt->pReverseCallIrp, pIrp);

    if (NULL!=pOldIrp) {                              // Found an IRP already queued?
      MpCompleteIrp(pHBAExt, pIrp);                   // Complete it.
    }
}                                                     // End MpQueueServiceIrp().

/**************************************************************************************************/                         
/*                                                                                                */                         
/* MpProcServReq.                                                                                 */                         
/*                                                                                                */                         
/**************************************************************************************************/                         
VOID
MpProcServReq(
              __in pHW_HBA_EXT          pHBAExt,      // Adapter device-object extension from StorPort.
              __in PIRP                 pIrp          // IRP pointer received.
             )
{
    DoStorageTraceEtw(DbgLvlLoud, MpDemoDebugInfo, "MpProcServReq entered\n");

    MpQueueServiceIrp(pHBAExt, pIrp);
}                                                     // End MpProcServReq().

/**************************************************************************************************/                         
/*                                                                                                */                         
/* MpCompServReq.                                                                                 */                         
/*                                                                                                */                         
/**************************************************************************************************/                         
VOID
MpCompServReq(__in pHW_HBA_EXT          pHBAExt)      // Adapter device-object extension from StorPort.
{
    DoStorageTraceEtw(DbgLvlLoud, MpDemoDebugInfo, "MpHwCompServReq entered\n");

    MpQueueServiceIrp(pHBAExt, NULL);
}                                                     // End MpCompServReq().

