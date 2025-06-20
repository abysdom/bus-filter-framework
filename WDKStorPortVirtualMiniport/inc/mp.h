/**************************************************************************************************/     
/*                                                                                                */     
/* Copyright (c) 2008-2011 Microsoft Corporation.  All Rights Reserved.                           */     
/*                                                                                                */     
/**************************************************************************************************/    

/*++

Module Name:

    mp.h

Abstract:

Author:

Environment:

--*/


#ifndef _MP_H_
#define _MP_H_

#if !defined(_MP_User_Mode_Only)                      // User-mode only.

#if       !defined(_MP_H_skip_WDM_includes)

#include <wdm.h>

#endif // !defined(_MP_H_skip_WDM_includes)

#include <ntdef.h>  
#include <storport.h>  
#include <devioctl.h>
#include <ntddscsi.h>
#include <scsiwmi.h>
#include "common.h"

#if       !defined(_MP_H_skip_includes)

#include <stdio.h>
#include <stdarg.h>

#endif // !defined(_MP_H_skip_includes)

#define VENDOR_ID                   L"PSS_LAB "
#define VENDOR_ID_ascii             "PSS_LAB "
#define PRODUCT_ID                  L"PHANTOM         "
#define PRODUCT_ID_ascii            "PHANTOM         "
#define PRODUCT_REV                 L"1234"
#define PRODUCT_REV_ascii           "1234"
#define MP_TAG_GENERAL              'gTpM'

#define MAX_TARGETS                 8
#define MAX_LUNS                    24
#define MP_MAX_TRANSFER_SIZE        (32 * 1024)
#define TIME_INTERVAL               (1 * 1000 * 1000) //1 second.
#define DEVLIST_BUFFER_SIZE         1024
#define DEVICE_NOT_FOUND            0xFF
#define SECTOR_NOT_FOUND            0xFFFF

#define MINIMUM_DISK_SIZE           (1540 * 1024)    // Minimum size required for Disk Manager
#define MAXIMUM_MAP_DISK_SIZE       (256 * 1024)

#define MP_BLOCK_SIZE                  (512)
#define BUF_SIZE                    (1540 * 1024)
#define MAX_BLOCKS                  (BUF_SIZE / MP_BLOCK_SIZE)

#define DEFAULT_BREAK_ON_ENTRY      0                // No break
#define DEFAULT_DEBUG_LEVEL         2               
#define DEFAULT_INITIATOR_ID        7
#define DEFAULT_VIRTUAL_DISK_SIZE   (8 * 1024 * 1024)  // 8 MB.  JAntogni, 03.12.2005.
#define DEFAULT_PHYSICAL_DISK_SIZE  DEFAULT_VIRTUAL_DISK_SIZE
#define DEFAULT_USE_LBA_LIST        0
#define DEFAULT_NUMBER_OF_BUSES     1
#define DEFAULT_NbrVirtDisks        1
#define DEFAULT_NbrLUNsperHBA       1
#define DEFAULT_bCombineVirtDisks   FALSE

#define GET_FLAG(Flags, Bit)        ((Flags) & (Bit))
#define SET_FLAG(Flags, Bit)        ((Flags) |= (Bit))
#define CLEAR_FLAG(Flags, Bit)      ((Flags) &= ~(Bit))

typedef struct _DEVICE_LIST          DEVICE_LIST, *pDEVICE_LIST;
typedef struct _MPDriverInfo         MPDriverInfo, *pMPDriverInfo;
typedef struct _MP_REG_INFO          MP_REG_INFO, *pMP_REG_INFO;
typedef struct _HW_LU_EXTENSION      HW_LU_EXTENSION, *pHW_LU_EXTENSION;
typedef struct _HW_LU_EXTENSION_MPIO HW_LU_EXTENSION_MPIO, *pHW_LU_EXTENSION_MPIO;
typedef struct _LBA_LIST             LBA_LIST, *PLBA_LIST;

extern 
pMPDriverInfo pMPDrvInfoGlobal;  

typedef struct _MP_REG_INFO {
    UNICODE_STRING   VendorId;
    UNICODE_STRING   ProductId;
    UNICODE_STRING   ProductRevision;
    ULONG            BreakOnEntry;       // Break into debugger
    ULONG            DebugLevel;         // Debug log level
    ULONG            InitiatorID;        // Adapter's target ID
    ULONG            VirtualDiskSize;    // Disk size to be reported
    ULONG            PhysicalDiskSize;   // Disk size to be allocated
    ULONG            NbrVirtDisks;       // Number of virtual disks.
    ULONG            NbrLUNsperHBA;      // Number of LUNs per HBA.
    ULONG            bCombineVirtDisks;  // 0 => do not combine virtual disks a la MPIO.
} MP_REG_INFO, * pMP_REG_INFO;

typedef struct _MPDriverInfo {                        // The master miniport object. In effect, an extension of the driver object for the miniport.
    MP_REG_INFO                    MPRegInfo;
    KSPIN_LOCK                     DrvInfoLock;
    KSPIN_LOCK                     MPIOExtLock;       // Lock for ListMPIOExt, header of list of HW_LU_EXTENSION_MPIO objects, 
    LIST_ENTRY                     ListMPHBAObj;      // Header of list of HW_HBA_EXT objects.
    LIST_ENTRY                     ListMPIOExt;       // Header of list of HW_LU_EXTENSION_MPIO objects.
    PDRIVER_OBJECT                 pDriverObj;
    ULONG                          DrvInfoNbrMPHBAObj;// Count of items in ListMPHBAObj.
    ULONG                          DrvInfoNbrMPIOExtObj; // Count of items in ListMPIOExt.
} MPDriverInfo, * pMPDriverInfo;

typedef struct _LUNInfo {
    UCHAR     bReportLUNsDontUse;
    UCHAR     bIODontUse;
} LUNInfo, *pLUNInfo;

#define LUNInfoMax 8

typedef struct _HW_HBA_EXT {                          // Adapter device-object extension allocated by StorPort.
    LIST_ENTRY                     List;              // Pointers to next and previous HW_HBA_EXT objects.
    LIST_ENTRY                     LUList;            // Pointers to HW_LU_EXTENSION objects.
    LIST_ENTRY                     MPIOLunList;
    pMPDriverInfo                  pMPDrvObj;
    PDRIVER_OBJECT                 pDrvObj;
    pMP_DEVICE_LIST                pDeviceList;
    pMP_DEVICE_LIST                pPrevDeviceList;
    SCSI_WMILIB_CONTEXT            WmiLibContext;
    PIRP                           pReverseCallIrp;
    KSPIN_LOCK                     WkItemsLock;
    KSPIN_LOCK                     WkRoutinesLock;
    KSPIN_LOCK                     MPHBAObjLock;
    KSPIN_LOCK                     LUListLock;   
    ULONG                          SRBsSeen;
    ULONG                          WMISRBsSeen;
    ULONG                          NbrMPIOLuns;
    ULONG                          NbrLUNsperHBA;
    ULONG                          Test;        
    UCHAR                          HostTargetId;
    UCHAR                          AdapterState;
    UCHAR                          VendorId[9];
    UCHAR                          ProductId[17];
    UCHAR                          ProductRevision[5];
    BOOLEAN                        bDontReport;       // TRUE => no Report LUNs. This is to be set/unset only by a kernel debugger.
    BOOLEAN                        bReportAdapterDone;
    LUNInfo                        LUNInfoArray[LUNInfoMax]; // To be set only by a kernel debugger.
} HW_HBA_EXT, * pHW_HBA_EXT;

typedef struct _HW_LU_EXTENSION_MPIO {                // Collector for LUNs that are represented by MPIO as 1 pseudo-LUN.
    LIST_ENTRY            List;                       // Pointers to next and previous HW_LU_EXTENSION_MPIO objects.
    LIST_ENTRY            LUExtList;                  // Header of list of HW_LU_EXTENSION objects.
    KSPIN_LOCK            LUExtMPIOLock;
    ULONG                 NbrRealLUNs;
    SCSI_ADDRESS          ScsiAddr;
    PUCHAR                pDiskBuf;
    USHORT                MaxBlocks;
    BOOLEAN               bIsMissingOnAnyPath;        // At present, this is set only by a kernel debugger, for testing.
} HW_LU_EXTENSION_MPIO, * pHW_LU_EXTENSION_MPIO;

// Flag definitions for LUFlags.

#define LU_DEVICE_INITIALIZED   0x0001
#define LU_MPIO_MAPPED          0x0004

typedef struct _HW_LU_EXTENSION {                     // LUN extension allocated by StorPort.
    LIST_ENTRY            List;                       // Pointers to next and previous HW_LU_EXTENSION objects, used in HW_HBA_EXT.
    LIST_ENTRY            MPIOList;                   // Pointers to next and previous HW_LU_EXTENSION objects, used in HW_LU_EXTENSION_MPIO.
    pHW_LU_EXTENSION_MPIO pLUMPIOExt;
    PUCHAR                pDiskBuf;
    ULONG                 LUFlags;
    ULONG                MaxBlocks;
    USHORT                BlocksUsed;
    BOOLEAN               bIsMissing;                 // At present, this is set only by a kernel debugger, for testing.
    UCHAR                 DeviceType;
    UCHAR                 TargetId;
    UCHAR                 Lun;
} HW_LU_EXTENSION, * pHW_LU_EXTENSION;

typedef struct _HW_SRB_EXTENSION {
    SCSIWMI_REQUEST_CONTEXT WmiRequestContext;
} HW_SRB_EXTENSION, * PHW_SRB_EXTENSION;

typedef enum {
  ActionRead,
  ActionWrite 
} MpWkRtnAction;

typedef struct _MP_WorkRtnParms {
    pHW_HBA_EXT          pHBAExt;
    pHW_LU_EXTENSION     pLUExt;
    PSCSI_REQUEST_BLOCK  pSrb;
    PIO_WORKITEM         pQueueWorkItem;
    PEPROCESS            pReqProcess;
    MpWkRtnAction        Action;                
    ULONG                SecondsToDelay;
} MP_WorkRtnParms, * pMP_WorkRtnParms;

enum ResultType {
  ResultDone,
  ResultQueued
} ;

#define RegWkBfrSz  0x1000

typedef struct _RegWorkBuffer {
  pHW_HBA_EXT          pAdapterExt;
  UCHAR                Work[256];
} RegWorkBuffer, * pRegWorkBuffer;

__declspec(dllexport)                                 // Ensure DriverEntry entry point visible to WinDbg even without a matching .pdb.            
ULONG                                                                                                                                              
DriverEntry(
            IN PVOID,
            IN PUNICODE_STRING 
           );

ULONG
MpHwFindAdapter(
    __in       pHW_HBA_EXT DevExt,
    __in       PVOID HwContext,
    __in       PVOID BusInfo,
    __in       PVOID LowerDevice,
    __in       PCHAR ArgumentString,
    __in __out PPORT_CONFIGURATION_INFORMATION ConfigInfo,
         __out PBOOLEAN Again
);

VOID
MpHwTimer(
    __in pHW_HBA_EXT DevExt
);

BOOLEAN
MpHwInitialize(
    __in pHW_HBA_EXT 
);

void
MpHwReportAdapter(
                  __in pHW_HBA_EXT
                 );

void
MpHwReportLink(
               __in pHW_HBA_EXT
              );

void
MpHwReportLog(__in pHW_HBA_EXT);

VOID
MpHwFreeAdapterResources(
    __in pHW_HBA_EXT
);

BOOLEAN
MpHwStartIo(
            __in pHW_HBA_EXT,
            __in PSCSI_REQUEST_BLOCK
);

BOOLEAN 
MpHwResetBus(
             __in pHW_HBA_EXT,
             __in ULONG       
            );

SCSI_ADAPTER_CONTROL_STATUS
MpHwAdapterControl(
    __in pHW_HBA_EXT DevExt,
    __in SCSI_ADAPTER_CONTROL_TYPE ControlType, 
    __in PVOID Parameters 
);

UCHAR
ScsiExecuteMain(
                __in pHW_HBA_EXT DevExt,
                __in PSCSI_REQUEST_BLOCK,
                __in PUCHAR             
               );

UCHAR
ScsiExecute(
    __in pHW_HBA_EXT DevExt,
    __in PSCSI_REQUEST_BLOCK Srb
    );

UCHAR
ScsiOpInquiry(
    __in pHW_HBA_EXT DevExt,
    __in pHW_LU_EXTENSION LuExt,
    __in PSCSI_REQUEST_BLOCK Srb
    );

UCHAR
ScsiOpReadCapacity(
    IN pHW_HBA_EXT DevExt,
    IN pHW_LU_EXTENSION LuExt,
    IN PSCSI_REQUEST_BLOCK Srb
    );

UCHAR
ScsiOpRead(
    IN pHW_HBA_EXT          DevExt,
    IN pHW_LU_EXTENSION     LuExt,
    IN PSCSI_REQUEST_BLOCK  Srb,
    IN PUCHAR               Action
    );

UCHAR
ScsiOpWrite(
    IN pHW_HBA_EXT          DevExt,
    IN pHW_LU_EXTENSION     LuExt,
    IN PSCSI_REQUEST_BLOCK  Srb,
    IN PUCHAR               Action
    );

UCHAR
ScsiOpModeSense(
    IN pHW_HBA_EXT         DevExt,
    IN pHW_LU_EXTENSION    LuExt,
    IN PSCSI_REQUEST_BLOCK pSrb
    );

UCHAR                                                                                   
ScsiOpReportLuns(                                 
    IN pHW_HBA_EXT          DevExt,                                                     
    IN pHW_LU_EXTENSION     LuExt,                                                      
    IN PSCSI_REQUEST_BLOCK  Srb                                                         
    );                                                                                   

VOID
MpQueryRegParameters(
    IN PUNICODE_STRING,
    IN pMP_REG_INFO       
    );

NTSTATUS
MpCreateDeviceList(
    __in       pHW_HBA_EXT,
    __in       ULONG
    );

UCHAR
MpGetDeviceType(
    __in pHW_HBA_EXT DevExt,
    __in UCHAR PathId,
    __in UCHAR TargetId,
    __in UCHAR Lun
    );

UCHAR MpFindRemovedDevice(
    __in pHW_HBA_EXT,
    __in PSCSI_REQUEST_BLOCK
    );

VOID MpStopAdapter(
    __in pHW_HBA_EXT DevExt
    );

VOID                                                                                                                         
MPTracingInit(                                                                                                            
              __in PVOID,                                                                                  
              __in PVOID
             );

VOID                                                                                                                         
MPTracingCleanup(__in PVOID);

VOID
MpProcServReq(
              __in pHW_HBA_EXT,
              __in PIRP                 
             );

VOID
MpCompServReq(
              __in pHW_HBA_EXT
             );
 
UCHAR
ScsiOpVPD(
    __in pHW_HBA_EXT,
    __in pHW_LU_EXTENSION,
    __in PSCSI_REQUEST_BLOCK
    );

void
InitializeWmiContext(__in pHW_HBA_EXT);

BOOLEAN
HandleWmiSrb(
    __in       pHW_HBA_EXT,
    __in __out PSCSI_WMI_REQUEST_BLOCK
    );

UCHAR
ScsiReadWriteSetup(
           __in pHW_HBA_EXT          pDevExt,
           __in pHW_LU_EXTENSION     pLUExt,
           __in PSCSI_REQUEST_BLOCK  pSrb,
           __in MpWkRtnAction        WkRtnAction,
           __in PUCHAR               pResult
          );

VOID                                                                                                                                               
MpGeneralWkRtn(
               __in PVOID, 
               __in PVOID
              );
ULONG                                                                                                                                              
MpThreadWkRtn(__in PVOID);

VOID                                                                                                                                               
MpWkRtn(IN PVOID);

VOID
MpCompleteIrp(
              __in pHW_HBA_EXT,
              __in PIRP       
             );

VOID
MpQueueServiceIrp(
                  __in pHW_HBA_EXT          pDevExt,
                  __in PIRP                 pIrp        
                 );

VOID
MpProcServReq(
              __in pHW_HBA_EXT          pDevExt,
              __in PIRP                 pIrp            
             );

VOID
MpCompServReq(
              __in pHW_HBA_EXT pDevExt
             );

#endif    //   #if !defined(_MP_User_Mode_Only)
#endif    // _MP_H_

