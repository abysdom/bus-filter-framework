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
#include <ntddk.h>
#include <initguid.h>
#include "bff.h"
#include "private.h"
#include <ntstrsafe.h>

/**
Global variables
**/
// {9B72BA39-1052-4D96-9EE8-500629E4EAF1}
DEFINE_GUID(GUID_BUS_FILTER_FRAMEWORK, 0x9b72ba39, 0x1052, 0x4d96, 0x9e, 0xe8, 0x50, 0x6, 0x29, 0xe4, 0xea, 0xf1);
static PBFF_PRIVATE_CONTEXT BffPrivateContext;

_IRQL_requires_max_(PASSIVE_LEVEL)
_IRQL_requires_same_
static
NTSTATUS
BffDeviceRemove(
    _In_ BFFDEVICE           BffDevice,
    _In_ PBFF_DEVICE_CONTEXT ChildContext,
    _In_ PIRP                Irp
    );

static DRIVER_DISPATCH BffDispatchAny;
static IO_COMPLETION_ROUTINE BffCompleteQueryBusRelations;

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, BffSetInitializationData)
#pragma alloc_text(INIT, BffInitialize)
#pragma alloc_text(PAGE, BffDeviceRemove)
#pragma alloc_text(PAGE, BffAllocateContext)
#pragma alloc_text(PAGE, BffPreprocessQueryBusRelations)
#endif

_Use_decl_annotations_
static
NTSTATUS
BffDeviceRemove(
    _In_ BFFDEVICE           BffDevice,
    _In_ PBFF_DEVICE_CONTEXT ChildContext,
    _In_ PIRP                Irp
    )
/*++

Routine Description:

    This routine is called when the device is to be removed.
    It will detach itself from the stack before deleting itself.

Arguments:

    BffDevice - The bus filter device object to be removed.
    ChildContext - The context of BffDevice.
    Irp - The PnP IRP that requests the removal of the device.

Return Value:
    NTSTATUS
--*/
{
    WDFDEVICE device = ChildContext->Parent;

    PAGED_CODE();

    if (!IoForwardIrpSynchronously(ChildContext->TargetDeviceObject, Irp))
    {
        Irp->IoStatus.Status = STATUS_NO_SUCH_DEVICE;
    }

    NTSTATUS status = Irp->IoStatus.Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    KdPrint(("%s: Driver %X Device %X\n",
            __FUNCTION__,
            WdfDriverWdmGetDriverObject(WdfGetDriver()),
            BffDeviceWdmGetPhysicalDevice(BffDevice)));
    // Allow queued I/O operations to complete
    IoReleaseRemoveLockAndWait(&ChildContext->RemoveLock, Irp);

    //
    // At this point, all outstanding acquisitions of RemoveLock have been
    // released; the bus filter device object is ready to be removed.
    //
    PBFF_PARENT_CONTEXT parentContext = BffGetParentContext(ChildContext->Parent);
    WdfWaitLockAcquire(parentContext->Lock, NULL);
    RemoveEntryList(&ChildContext->List);

    PBFF_DEVICE_REMOVE deviceRemove = BffPrivateContext->BffInitializationData.DeviceConfig.DeviceRemove;
    if (deviceRemove)
        deviceRemove(ChildContext->Parent, BffDevice);

    IoDetachDevice(ChildContext->TargetDeviceObject);
    WdfWaitLockRelease(parentContext->Lock);

    IoDeleteDevice(ChildContext->DeviceObject);
    WdfObjectDelete(BffDevice);
    WdfObjectDereference(device);   // paired with BffDeviceAdd

    return status;
}

_Use_decl_annotations_
static
NTSTATUS
BffDispatchAny(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP           Irp
    )
/*++

Routine Description:

This routine sends the Irp to the next driver in line
when the Irp is not processed by this driver.

Arguments:

    DeviceObject - The WDM device object that Irp is targeting
    Irp - The I/O request packet

Return Value:

    NTSTATUS

--*/
{
    PDEVICE_EXTENSION childExtension = DeviceObject->DeviceExtension;
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    UCHAR major = stack->MajorFunction;

    if (!IsEqualGUID(&childExtension->Signature, &GUID_BUS_FILTER_FRAMEWORK))
    {
        //
        // This must be the upper filter device object managed by WDF.
        //
        return BffPrivateContext->WdfMajorFunction[major](DeviceObject, Irp);
    }

    //
    // This must be a Bus Filter device object.
    //
    BFFDEVICE bffDevice = childExtension->Child;
    PBFF_DEVICE_CONTEXT childContext = BffDeviceGetContext(bffDevice);
    UCHAR minor = stack->MinorFunction;
    NTSTATUS status = IoAcquireRemoveLock(&childContext->RemoveLock, Irp);
    if (!NT_SUCCESS(status))
    {
        // Failure to acquire a remove lock indicates that DeviceObject is being deleted.
        Irp->IoStatus.Status = STATUS_DELETE_PENDING;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_DELETE_PENDING;
    }

    if (major == IRP_MJ_PNP && minor <= IRP_MN_DEVICE_ENUMERATED)
    {
        if (minor == IRP_MN_REMOVE_DEVICE)
        {
            // RemoveLock will be released within BffDeviceRemove.
            status = BffDeviceRemove(bffDevice, childContext, Irp);
            return status;
        }
        else
        {
            PBFF_DISPATCH_PNP dispatchPnp = BffPrivateContext->BffInitializationData.PnPMinorFunction[minor];
            if (dispatchPnp)
            {
                status = dispatchPnp(bffDevice, Irp);
                IoReleaseRemoveLock(&childContext->RemoveLock, Irp);
                return status;
            }
        }
    }

    //
    // Forward to the parent bus driver
    //
    IoSkipCurrentIrpStackLocation(Irp);
    status = IoCallDriver(childContext->TargetDeviceObject, Irp);

    //
    // For I/O operations that do not set an IoCompletion routine, a driver should call IoReleaseRemoveLock after
    // passing the current IRP to the next-lower driver, but before exiting the dispatch routine.
    //
    IoReleaseRemoveLock(&childContext->RemoveLock, Irp);

    return status;
} // end BffDispatchAny()

_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_requires_same_
static
VOID
BffLogError(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ ULONG          UniqueId,
    _In_ NTSTATUS       ErrorCode,
    _In_ NTSTATUS       Status
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

    errorLogEntry = (PIO_ERROR_LOG_PACKET)IoAllocateErrorLogEntry(DeviceObject, (UCHAR)sizeof(IO_ERROR_LOG_PACKET));

    if (errorLogEntry != NULL)
    {
        errorLogEntry->MajorFunctionCode = IRP_MJ_PNP;
        errorLogEntry->ErrorCode = ErrorCode;
        errorLogEntry->UniqueErrorValue = UniqueId;
        errorLogEntry->FinalStatus = Status;
        IoWriteErrorLogEntry(errorLogEntry);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_IRQL_requires_same_
static
FORCEINLINE
NTSTATUS
BffFindExistingChild(
    _In_ PBFF_PARENT_CONTEXT    ParentContext,
    _In_ PDEVICE_OBJECT         PhysicalDeviceObject
    )
{
    NTSTATUS status = STATUS_NO_SUCH_DEVICE;
    PBFF_DEVICE_CONTEXT childContext;
    PLIST_ENTRY entry;

    //
    // Check if the child device has already been added to the list of children.
    //
    WdfWaitLockAcquire(ParentContext->Lock, NULL);
    for (entry = ParentContext->List.Flink; entry != &ParentContext->List; entry = entry->Flink)
    {
        childContext = CONTAINING_RECORD(entry, BFF_DEVICE_CONTEXT, List);
        if (childContext->PhysicalDeviceObject == PhysicalDeviceObject)
        {
            status = STATUS_SUCCESS;
            break;
        }
    }
    WdfWaitLockRelease(ParentContext->Lock);

    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_IRQL_requires_same_
static
FORCEINLINE
VOID
BffCommitChild(
    _In_ PBFF_PARENT_CONTEXT ParentContext,
    _In_ PBFF_DEVICE_CONTEXT ChildContext
    )
{
    WdfWaitLockAcquire(ParentContext->Lock, NULL);
    InsertTailList(&ParentContext->List, &ChildContext->List);
    WdfWaitLockRelease(ParentContext->Lock);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_IRQL_requires_same_
static
FORCEINLINE
NTSTATUS
BffDeviceAdd(
    _In_ WDFDEVICE              Device,
    _In_ PBFF_PARENT_CONTEXT    ParentContext,
    _In_ PDEVICE_OBJECT         PhysicalDeviceObject
    )
/*++

Routine Description:

    Create and attach a bus filter DO to a PDO for an upper filter device

Arguments:

    Device - The WDF device object representing an upper filter device object
    ParentContext - The context of Device
    PhysicalDeviceObject - The PDO to which a bus filter DO is going to attach

Return Value:

    NTSTATUS

--*/
{
    //
    // Create a filter device object for this device.
    //

    PDRIVER_OBJECT driverObject = WdfDriverWdmGetDriverObject(WdfGetDriver());
    KdPrint(("%s: Driver %X Device %X\n", __FUNCTION__, driverObject, PhysicalDeviceObject));

    PDEVICE_OBJECT filterDeviceObject;
    ULONG deviceType = BffPrivateContext->BffInitializationData.DeviceConfig.DeviceType;
    ULONG deviceCharacteristics = BffPrivateContext->BffInitializationData.DeviceConfig.DeviceCharacteristics;
    NTSTATUS status = IoCreateDevice(driverObject, DEVICE_EXTENSION_SIZE, NULL, deviceType,
                                     FILE_DEVICE_SECURE_OPEN | deviceCharacteristics, FALSE, &filterDeviceObject);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("%s: Cannot create filterDeviceObject: %x\n", __FUNCTION__, status));
        return status;
    }

    //
    // Create a WDF object for the filter device object, so that we can store the filter device object in its context.
    //

    WDF_OBJECT_ATTRIBUTES attr;
    BFFDEVICE child;
    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attr, BFF_DEVICE_CONTEXT);
    attr.ParentObject = Device;
    status = WdfObjectCreate(&attr, &child);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("%s: failed to create WDF object for child device: %x\n", __FUNCTION__, status));
        goto deleteDev;
    }

    PBFF_DEVICE_CONTEXT childContext = BffDeviceGetContext(child);
    childContext->DeviceObject = filterDeviceObject;
    childContext->TargetDeviceObject = NULL;
    childContext->PhysicalDeviceObject = PhysicalDeviceObject;
    childContext->Parent = Device;
    WdfObjectReference(Device);
    IoInitializeRemoveLock(&childContext->RemoveLock, 'tFFB', 0, 0);

    //
    // Initialize the device extension of the filter device object.
    //

    PDEVICE_EXTENSION childExtension = (PDEVICE_EXTENSION)filterDeviceObject->DeviceExtension;
    RtlZeroMemory(childExtension, DEVICE_EXTENSION_SIZE);
    RtlCopyMemory(&childExtension->Signature, &GUID_BUS_FILTER_FRAMEWORK, sizeof(GUID));
    childExtension->Child = child;

    //
    // Attaches the device object to the highest device object in the chain and
    // return the previously highest device object, which is passed to
    // IoCallDriver when pass IRPs down the device stack
    //

    //
    // IoAttachDeviceToDeviceStackSafe updates childContext->TargetDeviceObject
    // while holding the I/O system database lock, hence avoidance of a race
    // condition that could otherwise occur if the filterDeviceObject received
    // an IRP before childContext->TargetDeviceObject was updated.
    //
    status = IoAttachDeviceToDeviceStackSafe(filterDeviceObject,
                                             PhysicalDeviceObject,
                                             &childContext->TargetDeviceObject);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("%s: Unable to attach %X to target %X\n", __FUNCTION__, filterDeviceObject, PhysicalDeviceObject));
        goto deleteObj;
    }

    //
    // Set the device flags of the filter device object to be the same as those of the target device object.
    //

    PDEVICE_OBJECT targetDeviceObject = childContext->TargetDeviceObject;
    filterDeviceObject->Flags |= targetDeviceObject->Flags &
                                 (DO_BUFFERED_IO | DO_DIRECT_IO | DO_POWER_INRUSH | DO_POWER_PAGABLE);

    //
    // Call the client's DeviceAdd callback function if it exists.
    //

    PBFF_DEVICE_ADD deviceAdd = BffPrivateContext->BffInitializationData.DeviceConfig.DeviceAdd;
    if (deviceAdd)
    {
        status = deviceAdd(Device, child);
        if (!NT_SUCCESS(status))
        {
            KdPrint(("%s: Client's DeviceAdd failed: %x\n", __FUNCTION__, status));
            goto detachDev;
        }
    }

    BffCommitChild(ParentContext, childContext);

    //
    // Clear the DO_DEVICE_INITIALIZING flag
    //

    filterDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    return STATUS_SUCCESS;

detachDev:
    IoDetachDevice(targetDeviceObject);
deleteObj:
    WdfObjectDelete(child);
    WdfObjectDereference(Device);
deleteDev:
    IoDeleteDevice(filterDeviceObject);
    return status;
}

_Use_decl_annotations_
static
NTSTATUS
BffCompleteQueryBusRelations(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP           Irp,
    _In_ PVOID          Event
    )
/*++

Routine Description:

    Complete a Query-Bus-Relations IRP

Arguments:

    DeviceObject - The WDM upper filter device object that Irp is targeting
    Irp - The I/O request packet that queries bus relations
    Event - The KEVENT object passed by BffPreprocessQueryBusRelations

Return Value:

    NTSTATUS

--*/
{
    UNREFERENCED_PARAMETER(DeviceObject);

    if (Irp->PendingReturned == TRUE)
    {
        //
        // You will set the event only if the lower driver has returned
        // STATUS_PENDING earlier. This optimization removes the need to
        // call KeSetEvent unnecessarily and improves performance because the
        // system does not have to acquire an internal lock.
        //
        KdPrint(("%s: lower driver has completed", __FUNCTION__));
        KeSetEvent((PKEVENT)Event, IO_NO_INCREMENT, FALSE);
    }
    // This is the only status you can return.
    return STATUS_MORE_PROCESSING_REQUIRED;
}

/*******************************************************************************
 * APIs for upper filter device objects.
 ******************************************************************************/
/** Prepare the initialization data for BFF. Obviously, this routine must be
 *  called before BffInitialize. After this call,
 *  InitData->PnPMinorFunction[IRP_MN_*] will be NULL-initialized. You may
 *  selectively re-initialize InitData->PnPMinorFunction[IRP_MN_*] with your own
 *  handlers before calling BffInitialize.
 *  @param InitData         The pointer to the initialization data,
 *                          typically declared as a local variable.
 *  @param Type             The device type for creation of a bus filter
 *                          device object.
 *  @param Characteristics  The device characteristics for creation of a bus
 *                          filter device object.
 *  @param DeviceAdd        The callback function for creation of a bus
 *                          filter device object.
 *  @param DeviceRemove     The callback function for removal of a bus
 *                          filter device object.
 */
_Use_decl_annotations_
VOID
BffSetInitializationData(
    _Out_ PBFF_INITIALIZATION_DATA  InitData,
    _In_  DEVICE_TYPE               Type,
    _In_  ULONG                     Characteristics,
    _In_  PBFF_DEVICE_ADD           DeviceAdd,
    _In_  PBFF_DEVICE_REMOVE        DeviceRemove
    )
{
    RtlZeroMemory(InitData, sizeof(BFF_INITIALIZATION_DATA));
    InitData->Size = sizeof(BFF_INITIALIZATION_DATA);
    InitData->DeviceConfig.DeviceType = Type;
    InitData->DeviceConfig.DeviceCharacteristics = Characteristics;
    InitData->DeviceConfig.DeviceAdd = DeviceAdd;
    InitData->DeviceConfig.DeviceRemove = DeviceRemove;
}

/** Initialize Bus Filter Framework with the initialization data. This routine
 *  must be invoked in DriverEntry after a call to WdfDriverCreate.
 *  @param DriverObject The same as DriverEntry's first parameter.
 *  @param RegistryPath The same as DriverEntry's second parameter.
 *  @param InitData     The initialization data previously prepared by a call to
 *                      BffSetInitializationData.
 *  @param Driver       The WDF driver object.
 *  @return             One of the following values:
 *                      (a) 0 or any positive value for success;
 *                      (b) STATUS_NOT_SUPPORTED if the driver has not called
 *                          WdfDriverCreate, or if this routine is called for a
 *                          second time;
 *                      (c) STATUS_INVALID_PARAMETER if an invalid parameter is
 *                          speciifed;
 *                      (d) STATUS_INVALID_SIGNATURE if no valid license key in
 *                          registry; or
 *                      (e) Any other negative value for failure.
 */
_Use_decl_annotations_
NTSTATUS
BffInitialize(
    _In_ PDRIVER_OBJECT             DriverObject,
    _In_ PUNICODE_STRING            RegistryPath,
    _In_ PBFF_INITIALIZATION_DATA   InitData,
    _In_ WDFDRIVER                  Driver
    )
{
    NTSTATUS status;

    KdPrint(("%s: RegistryPath=%wZ\n", __FUNCTION__, RegistryPath));

    //
    // Do not proceed if WdfDriverCreate has not been called yet.
    //
    if (!Driver)
        return STATUS_NOT_SUPPORTED;

    //
    // Do not proceed if the BFF private context is existing.
    //
    if (BffPrivateContext)
        return STATUS_NOT_SUPPORTED;

    status = STATUS_INVALID_PARAMETER;
    if (DriverObject && InitData && InitData->Size == sizeof(BFF_INITIALIZATION_DATA))
    {
        //
        // Create the BFF private context
        //
        WDF_OBJECT_ATTRIBUTES attr;
        WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attr, BFF_PRIVATE_CONTEXT);
        status = WdfObjectAllocateContext(Driver, &attr, &BffPrivateContext);
        if (NT_SUCCESS(status))
        {
            ULONG ulIndex;
            PDRIVER_DISPATCH *dispatch;
            //
            // Create dispatch points
            //
            for (ulIndex = 0, dispatch = DriverObject->MajorFunction; ulIndex <= IRP_MJ_MAXIMUM_FUNCTION;
                 ulIndex++, dispatch++)
            {
                BffPrivateContext->WdfMajorFunction[ulIndex] = *dispatch;
                *dispatch = BffDispatchAny;
            }

            RtlCopyMemory(&BffPrivateContext->BffInitializationData, InitData, sizeof(BFF_INITIALIZATION_DATA));
            //
            // Clear illegal settings
            //
            BffPrivateContext->BffInitializationData.DeviceConfig.DeviceCharacteristics &=
                ~(FILE_AUTOGENERATED_DEVICE_NAME | FILE_CHARACTERISTIC_TS_DEVICE | FILE_CHARACTERISTIC_WEBDAV_DEVICE |
                  FILE_DEVICE_IS_MOUNTED | FILE_VIRTUAL_VOLUME);
        }
    }

    return status;
}

/** Allocate context space for an upper filter device object on behalf of Bus
 *  Filter Framework. This routine is typically called in the EvtDriverDeviceAdd
 *  callback function.
 *  @param Device   The WDF device object representing an upper filter
 *                  device object.
 *  @return         The value that WdfObjectAllocateContext returns.
 */
_Use_decl_annotations_
NTSTATUS
BffAllocateContext(
    _In_ WDFDEVICE Device
    )
{
    NTSTATUS status;
    PBFF_PARENT_CONTEXT parentContext;
    WDF_OBJECT_ATTRIBUTES attr;

    PAGED_CODE();

    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attr, BFF_PARENT_CONTEXT);
    status = WdfObjectAllocateContext(Device, &attr, &parentContext);
    if (NT_SUCCESS(status))
    {
        ASSERT(BffGetParentContext(Device) == parentContext);
        InitializeListHead(&parentContext->List);
        WDF_OBJECT_ATTRIBUTES_INIT(&attr);
        attr.ParentObject = Device;
        WDFWAITLOCK lock;
        status = WdfWaitLockCreate(&attr, &lock);
        if (NT_SUCCESS(status))
        {
            parentContext->Lock = lock;
        }
        else
        {
            KdPrint(("%s: failed to create wait lock:%x", __FUNCTION__, status));
            BffLogError(WdfDeviceWdmGetDeviceObject(Device),
                        BFF_ERR_NO_WAITLOCK_CREATED,
                        IO_ERR_INSUFFICIENT_RESOURCES,
                        status);
            parentContext->Lock = NULL;
        }
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
 *  @param Device   The WDF device object representing an upper filter
 *                  device object.
 *  @param Irp      The IRP_MN_QUERY_DEVICE_RELATIONS I/O request packet.
 *  @return         The value that WdfDeviceWdmDispatchPreprocessedIrp returns.
 */
_Use_decl_annotations_
NTSTATUS
BffPreprocessQueryBusRelations(
    _In_ WDFDEVICE  Device,
    _In_ PIRP       Irp
    )
{
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);

    PAGED_CODE();

    if (stack->MajorFunction != IRP_MJ_PNP || stack->MinorFunction != IRP_MN_QUERY_DEVICE_RELATIONS ||
        stack->Parameters.QueryDeviceRelations.Type != BusRelations)
    {
        IoSkipCurrentIrpStackLocation(Irp);
        return WdfDeviceWdmDispatchPreprocessedIrp(Device, Irp);
    }

    //
    // https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/different-ways-of-handling-irps-cheat-sheet
    // Refer to Scenario 2 of the web page above.
    //
    KEVENT event;
    KeInitializeEvent(&event, NotificationEvent, FALSE);
    IoCopyCurrentIrpStackLocationToNext(Irp);
    IoSetCompletionRoutine(Irp, BffCompleteQueryBusRelations, &event, TRUE, TRUE, TRUE);
    NTSTATUS status = WdfDeviceWdmDispatchPreprocessedIrp(Device, Irp);
    if (status == STATUS_PENDING)
    {
        KdPrint(("%s: wait for lower driver to complete", __FUNCTION__));
        KeWaitForSingleObject(&event,
                              Executive, // WaitReason
                              KernelMode, // must be Kernelmode to prevent the stack getting paged out
                              FALSE,
                              NULL // indefinite wait
                              );
        status = Irp->IoStatus.Status;
    }

    PDEVICE_OBJECT deviceObject = WdfDeviceWdmGetDeviceObject(Device);
    //
    // BffPrivateContext could be NULL if BffInitialize has not been called yet.
    //
    if (!BffPrivateContext)
    {
        KdPrint(("%s: BFF has not been initialized yet:%x\n", __FUNCTION__, STATUS_NOT_SUPPORTED));
        BffLogError(deviceObject, IRP_MN_QUERY_DEVICE_RELATIONS, IO_ERR_INTERNAL_ERROR, STATUS_NOT_SUPPORTED);
    }

    //
    // parentContext could be NULL if BffAllocateContext has not been called yet.
    //
    PBFF_PARENT_CONTEXT parentContext = BffGetParentContext(Device);
    if (!parentContext)
    {
        KdPrint(("%s: BffAllocateContext has not been called yet:%x\n", __FUNCTION__, STATUS_NOT_SUPPORTED));
        BffLogError(deviceObject, IRP_MN_QUERY_DEVICE_RELATIONS, IO_ERR_INTERNAL_ERROR, STATUS_NOT_SUPPORTED);
    }

    if (NT_SUCCESS(Irp->IoStatus.Status) && BffPrivateContext && parentContext)
    {
        PDEVICE_RELATIONS dr = (PDEVICE_RELATIONS)Irp->IoStatus.Information;
        DEVICE_RELATIONS dummyDR;

        if (!dr)
        {
            KdPrint(("%s: failed to retreive device relations:%x\n", __FUNCTION__, Irp->IoStatus.Status));
            BffLogError(deviceObject, IRP_MN_QUERY_DEVICE_RELATIONS, IO_ERR_INTERNAL_ERROR, Irp->IoStatus.Status);
            //
            // Workaround for a buggy bus driver that returns NULL device relations. We will treat it as an empty
            // device relations.
            //
            dummyDR.Count = 0;
            dr = &dummyDR;
        }

        //
        // Add new child devices to the list of children.
        //
        for (ULONG i = 0; i < dr->Count; i++)
        {
            NTSTATUS internalStatus = BffFindExistingChild(parentContext, dr->Objects[i]);
            if (NT_SUCCESS(internalStatus))
            {
                continue; // This child device has already been added to the list of children.
            }

            internalStatus = BffDeviceAdd(Device, parentContext, dr->Objects[i]);
            if (!NT_SUCCESS(internalStatus))
            {
                KdPrint(("%s: failed to add a child:%x\n", __FUNCTION__, internalStatus));
                BffLogError(deviceObject, IRP_MN_QUERY_DEVICE_RELATIONS, IO_ERR_INTERNAL_ERROR, internalStatus);
                // continue to add other new child devices
            }
        }
    }

    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

/*******************************************************************************
 * APIs for bus filter device objects.
 ******************************************************************************/
/** Retrieve the WDM bus filter device object that is associated with the
 *  specified WDF object. Never call this function in EvtDestroyCallback of
 *  BffDevice.
 *  @param BffDevice    The WDF object as a bus filter device object.
 *  @return             The WDM bus filter device object for success; NULL
 *                      otherwise.
 */
_Use_decl_annotations_
PDEVICE_OBJECT
BffDeviceWdmGetDeviceObject(
    _In_ BFFDEVICE BffDevice
    )
{
    PBFF_DEVICE_CONTEXT childContext = BffDeviceGetContext(BffDevice);
    ASSERT(childContext);
    return childContext->DeviceObject;
}

/** Retrieve the next lower WDM device object in the device stack of the
 *  specified WDF object. Never call this function in EvtDestroyCallback of
 *  BffDevice.
 *  @param BffDevice    The WDF object as a bus filter device object.
 *  @return             The next lower WDM device object for success; NULL
 *                      otherwise.
 */
_Use_decl_annotations_
PDEVICE_OBJECT
BffDeviceWdmGetAttachedDevice(
    _In_ BFFDEVICE BffDevice
    )
{
    PBFF_DEVICE_CONTEXT childContext = BffDeviceGetContext(BffDevice);
    ASSERT(childContext);
    return childContext->TargetDeviceObject;
}

/** Retrieve the PDO from the device stack of the specified WDF object. Never
 *  call this function in EvtDestroyCallback of BffDevice.
 *  @param BffDevice    The WDF object as a bus filter device object.
 *  @return             The PDO for success; NULL otherwise.
 */
_Use_decl_annotations_
PDEVICE_OBJECT
BffDeviceWdmGetPhysicalDevice(
    _In_ BFFDEVICE BffDevice
    )
{
    PBFF_DEVICE_CONTEXT childContext = BffDeviceGetContext(BffDevice);
    ASSERT(childContext);
    return childContext->PhysicalDeviceObject;
}

/** Acquire the RemoveLock of the specified BFF device. Call this function only
 *  in BFF_DISPATCH_PNP or in the processing of Irp.
 *  @param BffDevice    The WDF object as a bus filter device object.
 *  @param Irp          The PnP IRP.
 */
_Use_decl_annotations_
VOID
BffDeviceWdmAcquireRemoveLock(
    _In_ BFFDEVICE  BffDevice,
    _In_ PIRP       Irp
    )
{
    PBFF_DEVICE_CONTEXT childContext = BffDeviceGetContext(BffDevice);
    ASSERT(childContext);
    IoAcquireRemoveLock(&childContext->RemoveLock, Irp);
}

/** Release the RemoveLock of the specified BFF device. Call this function only
 *  in BFF_DISPATCH_PNP or in the processing of Irp.
 *  @param BffDevice    The WDF object as a bus filter device object.
 *  @param Irp          The PnP IRP.
 */
_Use_decl_annotations_
VOID
BffDeviceWdmReleaseRemoveLock(
    _In_ BFFDEVICE  BffDevice,
    _In_ PIRP       Irp
    )
{
    PBFF_DEVICE_CONTEXT childContext = BffDeviceGetContext(BffDevice);
    ASSERT(childContext);
    IoReleaseRemoveLock(&childContext->RemoveLock, Irp);
}
