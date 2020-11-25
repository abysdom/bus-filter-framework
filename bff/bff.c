/*******************************************************************************
    Bus Filter Framework (BFF)

    A framework for KMDF-based upper filter drivers to behave as bus filters.
    You don't need to write WDM drivers any more!

    https://bus-filter-framework.blogspot.com/

    Copyright (C) 2017 Yang Yuanzhi <yangyuanzhi@gmail.com>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*******************************************************************************/
//#include <initguid.h>
#include "bff.h"
#include "private.h"
#include "bffguid.h"
#include <ntstrsafe.h>

/**
Global variables
**/
static PDRIVER_DISPATCH WdfMajorFunction[IRP_MJ_MAXIMUM_FUNCTION + 1];
// {9B72BA39-1052-4D96-9EE8-500629E4EAF1}
//DEFINE_GUID(GUID_BUS_FILTER_FRAMEWORK,
//	0x9b72ba39, 0x1052, 0x4d96, 0x9e, 0xe8, 0x50, 0x6, 0x29, 0xe4, 0xea, 0xf1);
//static GUID GUID_BUS_FILTER_FRAMEWORK = { 0x9b72ba39, 0x1052, 0x4d96, { 0x9e, 0xe8, 0x50, 0x6, 0x29, 0xe4, 0xea, 0xf1 } };
static BFF_INITIALIZATION_DATA BffInitializationData;

static FORCEINLINE VOID
BffRemoveDevice(IN PDEVICE_OBJECT DeviceObject)
/*++

Routine Description:

This routine is called when the device is to be removed.
It will de-register itself from WMI first, detach itself from the
stack before deleting itself.

Arguments:

    DeviceObject - a pointer to the device object


Return Value:
    None
--*/
{
    PDEVICE_EXTENSION deviceExtension = DeviceObject->DeviceExtension;
    PBFF_PARENT_CONTEXT parentContext = BffGetParentContext(deviceExtension->Parent);
    KLOCK_QUEUE_HANDLE handle;

    PAGED_CODE();

    //
    // parentContext could be NULL if BffAllocateContext had not been called yet.
    //
    if (!parentContext)
        return;

    //
    // Quoted from https://msdn.microsoft.com/en-us/library/windows/hardware/ff561048(v=vs.85).aspx
    // If the device is still present when the PnP manager sends the
    // IRP_MN_REMOVE_DEVICE request, the bus driver retains the PDO. If, at
    // some later time, the device is physically removed from the bus, the
    // PnP manager sends another IRP_MN_REMOVE_DEVICE. Upon receipt of the
    // subsequent remove IRP, the bus driver deletes the PDO for the device.
    //
    // A bus driver must be able to handle an IRP_MN_REMOVE_DEVICE for a
    // device it has already removed and whose PDO is marked for deletion.
    // In response to such an IRP, the bus driver can succeed the IRP or
    // return STATUS_NO_SUCH_DEVICE. The PDO for the device has not yet been
    // deleted in this case, despite the bus driver's previous call to
    // IoDeleteDevice, because some component still has a reference to the
    // object. Therefore, the bus driver can access the PDO while handling
    // the second remove IRP. The bus driver must not call IoDeleteDevice a
    // second time for the PDO; the I/O system deletes the PDO when its
    // reference count reaches zero.
    //
    // A bus driver does not remove its data structures for a child device
    // until it receives an IRP_MN_REMOVE_DEVICE request for the device. A
    // bus driver might detect that a device has been removed and call
    // IoInvalidateDeviceRelations, but it must not delete the device's PDO
    // until the PnP manager sends an IRP_MN_REMOVE_DEVICE request.
    //
    if (deviceExtension->Existing)
        return;

    KeAcquireInStackQueuedSpinLock(&parentContext->Lock, &handle);
    RemoveEntryList(&deviceExtension->List);
    KeReleaseInStackQueuedSpinLock(&handle);

    if (BffInitializationData.DeviceConfig.DeviceRemove)
        BffInitializationData.DeviceConfig.DeviceRemove(deviceExtension->Parent, deviceExtension->Child);

    WdfObjectDelete(deviceExtension->Child);
    IoDetachDevice(deviceExtension->TargetDeviceObject);
    IoDeleteDevice(DeviceObject);
}

static FORCEINLINE NTSTATUS
BffDispatchPnp(PDEVICE_OBJECT DeviceObject, PIRP Irp, UCHAR minor)
{
    PDEVICE_EXTENSION deviceExtension = DeviceObject->DeviceExtension;

    ASSERT(minor <= IRP_MN_DEVICE_ENUMERATED);
    /* Both 0x0E and 0x18 are undefined minor functions. */
    ASSERT(minor != 0x0E);
    ASSERT(minor != 0x18);

    if (minor == IRP_MN_REMOVE_DEVICE)
        BffRemoveDevice(DeviceObject);
    else if (BffInitializationData.PnPMinorFunction[minor])
        return BffInitializationData.PnPMinorFunction[minor](deviceExtension->Child, Irp);

    //
    // Forward to the parent bus driver
    //
    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(deviceExtension->TargetDeviceObject, Irp);
}

static NTSTATUS
BffDispatchAny(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp
    )

/*++

Routine Description:

This routine sends the Irp to the next driver in line
when the Irp is not processed by this driver.

Arguments:

    DeviceObject
    Irp

Return Value:

    NTSTATUS

--*/

{
    PDEVICE_EXTENSION deviceExtension = DeviceObject->DeviceExtension;
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    UCHAR major = stack->MajorFunction;

    if (!IsEqualGUID(&deviceExtension->Signature, &GUID_BUS_FILTER_FRAMEWORK)) {
        //
        // This must be the upper filter device object managed by WDF.
        //
        return WdfMajorFunction[major](DeviceObject, Irp);
    }

    //
    // This must be a Bus Filter device object.
    //
    if (major == IRP_MJ_PNP)
        return BffDispatchPnp(DeviceObject, Irp, stack->MinorFunction);

    //
    // Forward to the parent bus driver
    //
    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(deviceExtension->TargetDeviceObject, Irp);

} // end BffDispatchAny()

static FORCEINLINE VOID
BffLogError(
    IN PDEVICE_OBJECT DeviceObject,
    IN ULONG UniqueId,
    IN NTSTATUS ErrorCode,
    IN NTSTATUS Status
    )

    /*++

    Routine Description:

    Routine to log an error with the Error Logger

    Arguments:

    DeviceObject - the device object responsible for the error
    UniqueId     - an id for the error
    Status       - the status of the error

    Return Value:

    None

    --*/

{
    PIO_ERROR_LOG_PACKET errorLogEntry;

    errorLogEntry = (PIO_ERROR_LOG_PACKET)
        IoAllocateErrorLogEntry(
            DeviceObject,
            (UCHAR)sizeof(IO_ERROR_LOG_PACKET)
            );

    if (errorLogEntry != NULL) {
        errorLogEntry->MajorFunctionCode = IRP_MJ_PNP;
        errorLogEntry->ErrorCode = ErrorCode;
        errorLogEntry->UniqueErrorValue = UniqueId;
        errorLogEntry->FinalStatus = Status;
        IoWriteErrorLogEntry(errorLogEntry);
    }
}

static FORCEINLINE NTSTATUS
BffAddDevice(
    IN WDFDEVICE Device,
    IN PDEVICE_OBJECT PhysicalDeviceObject
    )
{
    NTSTATUS                status;
    PDEVICE_OBJECT		DeviceObject = WdfDeviceWdmGetDeviceObject(Device);
    PDEVICE_OBJECT          filterDeviceObject;
    PBFF_PARENT_CONTEXT	parentContext = BffGetParentContext(Device);
    PDEVICE_EXTENSION	childExtension;
    KLOCK_QUEUE_HANDLE	handle;
    PLIST_ENTRY		entry;
    BOOLEAN			duplicated = FALSE;
    WDF_OBJECT_ATTRIBUTES	attr;
    WDFOBJECT		child;
    PBFF_DEVICE_CONTEXT	childContext;

    PAGED_CODE();

    //
    // Do not proceed if BFF has not been initialized yet.
    //
    if (BffInitializationData.Size != sizeof(BFF_INITIALIZATION_DATA))
        return STATUS_NOT_SUPPORTED;

    //
    // parentContext could be NULL if BffAllocateContext had not been called yet.
    //
    if (!parentContext)
        return STATUS_NOT_SUPPORTED;

    //
    // Skip if PhysicalDeviceObject is an existing child.
    //
    KeAcquireInStackQueuedSpinLock(&parentContext->Lock, &handle);
    for (entry = parentContext->List.Flink;
        entry != &parentContext->List;
        entry = entry->Flink) {
        childExtension = CONTAINING_RECORD(entry,
            DEVICE_EXTENSION, List);
        if (childExtension->PhysicalDeviceObject ==
            PhysicalDeviceObject) {
            duplicated = TRUE;
            childExtension->Existing = TRUE;
            break;
        }
    }
    KeReleaseInStackQueuedSpinLock(&handle);

    if (duplicated)
        return STATUS_SUCCESS;

    //
    // Create a filter device object for this device (disk).
    //

    KdPrint(("%s: Driver %X Device %X\n", __FUNCTION__,
        DeviceObject->DriverObject, PhysicalDeviceObject));

    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attr, BFF_DEVICE_CONTEXT);
    attr.ParentObject = Device;
    status = WdfObjectCreate(&attr, &child);
    if (!NT_SUCCESS(status)) {
        KdPrint(("%s: failed to create WDF object for child device: %x\n", __FUNCTION__, status));
        return status;
    }

    status = IoCreateDevice(DeviceObject->DriverObject,
        DEVICE_EXTENSION_SIZE,
        NULL,
        BffInitializationData.DeviceConfig.DeviceType,
        FILE_DEVICE_SECURE_OPEN | BffInitializationData.DeviceConfig.DeviceCharacteristics,
        FALSE,
        &filterDeviceObject);

    if (!NT_SUCCESS(status)) {
        KdPrint(("%s: Cannot create filterDeviceObject: %x\n", __FUNCTION__, status));
        goto deleteobj;
    }

    //
    // Save the filter device object in the child context
    //
    childContext = BffGetDeviceContext(child);
    childContext->DeviceObject = filterDeviceObject;

    childExtension = (PDEVICE_EXTENSION)filterDeviceObject->DeviceExtension;
    RtlZeroMemory(childExtension, DEVICE_EXTENSION_SIZE);
    RtlCopyMemory(&childExtension->Signature, &GUID_BUS_FILTER_FRAMEWORK, sizeof(GUID));
    childExtension->Parent = Device;
    childExtension->Child = child;

    //
    // Attaches the device object to the highest device object in the chain and
    // return the previously highest device object, which is passed to
    // IoCallDriver when pass IRPs down the device stack
    //

    childExtension->PhysicalDeviceObject = PhysicalDeviceObject;

    childExtension->TargetDeviceObject =
        IoAttachDeviceToDeviceStack(filterDeviceObject, PhysicalDeviceObject);

    if (childExtension->TargetDeviceObject == NULL) {
        KdPrint(("%s: Unable to attach %X to target %X\n", __FUNCTION__,
            filterDeviceObject, PhysicalDeviceObject));
        status = STATUS_NO_SUCH_DEVICE;
        goto deletedev;
    }

    filterDeviceObject->Flags |=
        childExtension->TargetDeviceObject->Flags &
        (DO_BUFFERED_IO | DO_DIRECT_IO |
        DO_POWER_INRUSH | DO_POWER_PAGABLE);

    if (BffInitializationData.DeviceConfig.DeviceAdd) {
        status = BffInitializationData.DeviceConfig.DeviceAdd(Device,
            child);
        if (!NT_SUCCESS(status)) {
            KdPrint(("%s: Client's DeviceAdd failed: %x\n",
                __FUNCTION__, status));
            goto detachdev;
        }
    }

    KeAcquireInStackQueuedSpinLock(&parentContext->Lock, &handle);
    childExtension->Existing = TRUE;
    InsertTailList(&parentContext->List, &childExtension->List);
    KeReleaseInStackQueuedSpinLock(&handle);


    //
    // Clear the DO_DEVICE_INITIALIZING flag
    //

    filterDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    return STATUS_SUCCESS;

detachdev:
    IoDetachDevice(childExtension->TargetDeviceObject);
deletedev:
    IoDeleteDevice(filterDeviceObject);
deleteobj:
    WdfObjectDelete(child);
    return status;
}

static NTSTATUS
BffCompleteQueryBusRelations(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp,
    IN WDFDEVICE Device
    )
{
    if (Irp->PendingReturned)
        IoMarkIrpPending(Irp);

    if (NT_SUCCESS(Irp->IoStatus.Status)) {
        PBFF_PARENT_CONTEXT parentContext = BffGetParentContext(Device);
        PDEVICE_RELATIONS dr = (PDEVICE_RELATIONS)Irp->IoStatus.Information;
        ULONG i;

        if (parentContext) {
            PDEVICE_EXTENSION	childExtension;
            KLOCK_QUEUE_HANDLE	handle;
            PLIST_ENTRY		entry;

            //
            // Assume that all child devices do not exist; if any
            // child device is found duplicated in BffAddDevice, it
            // will be reverted to 'existing' then.
            //
            KeAcquireInStackQueuedSpinLock(&parentContext->Lock,
                &handle);
            for (entry = parentContext->List.Flink;
                entry != &parentContext->List;
                entry = entry->Flink) {
                childExtension = CONTAINING_RECORD(entry,
                    DEVICE_EXTENSION, List);
                childExtension->Existing = FALSE;
            }
            KeReleaseInStackQueuedSpinLock(&handle);
        }

        for (i = 0; i < dr->Count; i++) {
            NTSTATUS status = BffAddDevice(Device, dr->Objects[i]);
            if (!NT_SUCCESS(status)) {
                KdPrint(("%s: failed to add a child:%x\n", __FUNCTION__, status));
                BffLogError(DeviceObject, IRP_MN_QUERY_DEVICE_RELATIONS, IO_ERR_INTERNAL_ERROR, status);
                break;
            }
        }
    }

    return STATUS_CONTINUE_COMPLETION;
}

/***************************************************************************//**
 * APIs for upper filter device objects.
 ******************************************************************************/
/** Prepare the initialization data for BFF. Obviously, this routine must be
 *  called before BffInitialize. After this call,
 *  InitData->PnPMinorFunction[IRP_MN_*] will be NULL-initialized. You may
 *  selectively re-initialize InitData->PnPMinorFunction[IRP_MN_*] with your own
 *  handlers before calling BffInitialize.
 *  @param InitData		The pointer to the initialization data,
 *				typically declared as a local variable.
 *  @param Type			The device type for creation of a bus filter
 *				device object.
 *  @param Characteristics	The device characteristics for creation of a bus
 *				filter device object.
 *  @param DeviceAdd		The callback function for creation of a bus
 *				filter device object.
 *  @param DeviceRemove		The callback function for removal of a bus
 *				filter device object.
 */
VOID
BffSetInitializationData(PBFF_INITIALIZATION_DATA InitData, DEVICE_TYPE Type,
    ULONG Characteristics,
    PBFF_DEVICE_ADD DeviceAdd, PBFF_DEVICE_REMOVE DeviceRemove)
{
    RtlZeroMemory(InitData, sizeof(BFF_INITIALIZATION_DATA));
    InitData->Size = sizeof(BFF_INITIALIZATION_DATA);
    InitData->DeviceConfig.DeviceType = Type;
    InitData->DeviceConfig.DeviceCharacteristics = Characteristics;
    InitData->DeviceConfig.DeviceAdd = DeviceAdd;
    InitData->DeviceConfig.DeviceRemove = DeviceRemove;
}

/** Initialize Bus Filter Framework with the initialization data. This routine
 *  must be invoked in DriverEntry after a call to WdfDriverCreate. Furthermore,
 *  a BFF-based driver must be installed with a valid license key to unlock
 *  functionality of BFF.
 *  @param DriverObject	The same as DriverEntry's first parameter.
 *  @param RegistryPath	The same as DriverEntry's second parameter.
 *  @param InitData	The initialization data previously prepared by a call to
 *			BffSetInitializationData.
 *  @return		One of the following values:
 *			(a) 0 or any positive value for success;
 *			(b) STATUS_NOT_SUPPORTED if the driver has not called
 *			    WdfDriverCreate;
 *			(c) STATUS_INVALID_PARAMETER if an invalid parameter is
 *			    speciifed;
 *			(d) STATUS_INVALID_SIGNATURE if no valid license key in
 *			    registry; or
 *			(e) Any other negative value for failure.
 */
NTSTATUS
BffInitialize(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath, PBFF_INITIALIZATION_DATA InitData)
{
    NTSTATUS status;

    KdPrint(("%s: RegistryPath=%wZ\n", __FUNCTION__, RegistryPath));

    //
    // Do not proceed if WdfDriverCreate has not been called yet.
    //
    if (!WdfGetDriver())
        return STATUS_NOT_SUPPORTED;

    status = STATUS_INVALID_PARAMETER;
    if (DriverObject && InitData &&
        InitData->Size == sizeof(BFF_INITIALIZATION_DATA)) {
        ULONG ulIndex;
        PDRIVER_DISPATCH *dispatch;
        //
        // Create dispatch points
        //
        for (ulIndex = 0, dispatch = DriverObject->MajorFunction;
            ulIndex <= IRP_MJ_MAXIMUM_FUNCTION;
            ulIndex++, dispatch++) {
            WdfMajorFunction[ulIndex] = *dispatch;
            *dispatch = BffDispatchAny;
        }

        RtlCopyMemory(&BffInitializationData, InitData,
            sizeof(BFF_INITIALIZATION_DATA));
        //
        // Clear illegal settings
        //
        BffInitializationData.DeviceConfig.DeviceCharacteristics &=
            ~(FILE_AUTOGENERATED_DEVICE_NAME |
            FILE_CHARACTERISTIC_TS_DEVICE |
            FILE_CHARACTERISTIC_WEBDAV_DEVICE |
            FILE_DEVICE_IS_MOUNTED |
            FILE_VIRTUAL_VOLUME);
        status = STATUS_SUCCESS;
    }

    return status;
}

/** Allocate context space for an upper filter device object on behalf of Bus
 *  Filter Framework. This routine is typically called in the EvtDriverDeviceAdd
 *  callback function.
 *  @param Device	The WDF device object representing an upper filter
 *			device object.
 *  @return		The value that WdfObjectAllocateContext returns.
 */
NTSTATUS
BffAllocateContext(WDFDEVICE Device)
{
    NTSTATUS status;
    PBFF_PARENT_CONTEXT parentContext;
    WDF_OBJECT_ATTRIBUTES attr;
    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attr, BFF_PARENT_CONTEXT);
    status = WdfObjectAllocateContext(Device, &attr, &parentContext);
    if (NT_SUCCESS(status)) {
        ASSERT(BffGetParentContext(Device) == parentContext);
        InitializeListHead(&parentContext->List);
        KeInitializeSpinLock(&parentContext->Lock);
    }
    return status;
}

/** The callback function for an upper filter driver to preprocess
 *  IRP_MN_QUERY_DEVICE_RELATIONS/BusRelations before KMDF. This routine can be
 *  passed as EvtDeviceWdmIrpPreprocess into
 *  WdfDeviceInitAssignWdmIrpPreprocessCallback for IRP_MJ_PNP/
 *  IRP_MN_QUERY_DEVICE_RELATIONS, or be invoked in an upper filter driver's
 *  EvtDeviceWdmIrpPreprocess callback function. In the latter case, the upper
 *  filter driver must return the value that this routine returns.
 *  @param Device	The WDF device object representing an upper filter
 *			device object.
 *  @param Irp		The IRP_MN_QUERY_DEVICE_RELATIONS I/O request packet.
 *  @return		The value that WdfDeviceWdmDispatchPreprocessedIrp
 *			returns.
 */
NTSTATUS
BffPreprocessQueryBusRelations(WDFDEVICE Device, PIRP Irp)
{
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    if (stack->MajorFunction != IRP_MJ_PNP ||
        stack->MinorFunction != IRP_MN_QUERY_DEVICE_RELATIONS ||
        stack->Parameters.QueryDeviceRelations.Type != BusRelations)
        IoSkipCurrentIrpStackLocation(Irp);
    else {
        IoCopyCurrentIrpStackLocationToNext(Irp);
        IoSetCompletionRoutine(Irp, BffCompleteQueryBusRelations,
            Device, TRUE, TRUE, TRUE);
    }

    return WdfDeviceWdmDispatchPreprocessedIrp(Device, Irp);
}

/***************************************************************************//**
 * APIs for bus filter device objects.
 ******************************************************************************/
/** Retrieve the WDM bus filter device object that is associated with the
 *  specified WDF object.
 *  @param BffDevice	The WDF object as a bus filter device object.
 *  @return		The WDM bus filter device object for success; NULL
 *			otherwise.
 */
PDEVICE_OBJECT
BffDeviceWdmGetDeviceObject(WDFOBJECT BffDevice)
{
    PBFF_DEVICE_CONTEXT childContext = BffGetDeviceContext(BffDevice);
    if (childContext)
        return childContext->DeviceObject;
    return NULL;
}

/** Retrieve the next lower WDM device object in the device stack of the
 *  specified WDF object.
 *  @param BffDevice	The WDF object as a bus filter device object.
 *  @return		The next lower WDM device object for success; NULL
 *			otherwise.
 */
PDEVICE_OBJECT
BffDeviceWdmGetAttachedDevice(WDFOBJECT BffDevice)
{
    PBFF_DEVICE_CONTEXT childContext = BffGetDeviceContext(BffDevice);
    if (childContext) {
        PDEVICE_EXTENSION deviceExtension = childContext->DeviceObject->DeviceExtension;
        if (IsEqualGUID(&deviceExtension->Signature, &GUID_BUS_FILTER_FRAMEWORK))
            return deviceExtension->TargetDeviceObject;
    }
    return NULL;
}

/** Retrieve the PDO from the device stack of the specified WDF object.
 *  @param BffDevice	The WDF object as a bus filter device object.
 *  @return		The PDO for success; NULL otherwise.
 */
PDEVICE_OBJECT
BffDeviceWdmGetPhysicalDevice(WDFOBJECT BffDevice)
{
    PBFF_DEVICE_CONTEXT childContext = BffGetDeviceContext(BffDevice);
    if (childContext) {
        PDEVICE_EXTENSION deviceExtension = childContext->DeviceObject->DeviceExtension;
        if (IsEqualGUID(&deviceExtension->Signature, &GUID_BUS_FILTER_FRAMEWORK))
            return deviceExtension->PhysicalDeviceObject;
    }
    return NULL;
}
