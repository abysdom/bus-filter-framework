/*******************************************************************************
    Bus Filter Framework Sample Driver
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
/*++

Bus filter sameple driver, based on Bus Filter Framework, or BFF for short,
which is a framework for KMDF-based upper filter drivers to behave as bus
filters. You don't need to write WDM drivers any more!

https://bus-filter-framework.blogspot.com/

This sample driver registers a device interface for every child device, and
prepends "BffDevice" to the compatible IDs list.

Module Name:

    driver.c

Abstract:

    This file contains the driver entry points and callbacks.

Environment:

    Kernel-mode Driver Framework

--*/

#include "driver.h"
#include "driver.tmh"
#include "..\bff\bff.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text (INIT, DriverEntry)
#pragma alloc_text (PAGE, BusFilterEvtDeviceAdd)
#pragma alloc_text (PAGE, BusFilterEvtDriverContextCleanup)
#endif


NTSTATUS
BusFilterDeviceEnumerated(
	WDFOBJECT BffDevice,
	PIRP Irp)
{
	PBUS_FILTER_CONTEXT busFilterContext = BusFilterGetContext(BffDevice);
	KIRQL irql = KeGetCurrentIrql();
	if (irql != PASSIVE_LEVEL) {
		KdPrint(("IRP_MN_DEVICE_ENUMERATED not at PASSIVE_LEVEL\n"));
	}
	else {
		NTSTATUS status = IoRegisterDeviceInterface(BffDeviceWdmGetPhysicalDevice(BffDevice), &GUID_DEVINTERFACE_BusFilter, NULL, &busFilterContext->SymbolicLink);
		if (NT_SUCCESS(status))
			busFilterContext->IsRegistered = TRUE;
	}

	//
	// Forward to the parent bus driver
	//
	IoSkipCurrentIrpStackLocation(Irp);
	return IoCallDriver(BffDeviceWdmGetAttachedDevice(BffDevice), Irp);
}

NTSTATUS
BusFilterStartDevice(
	IN WDFOBJECT BffDevice,
	IN PIRP Irp
	)
{
	PBUS_FILTER_CONTEXT busFilterContext = BusFilterGetContext(BffDevice);
	NTSTATUS            status;

	PAGED_CODE();

	if (!IoForwardIrpSynchronously(BffDeviceWdmGetAttachedDevice(BffDevice), Irp))
		Irp->IoStatus.Status = STATUS_NO_SUCH_DEVICE;
	else if (NT_SUCCESS(Irp->IoStatus.Status) && busFilterContext->IsRegistered)
		Irp->IoStatus.Status = IoSetDeviceInterfaceState(&busFilterContext->SymbolicLink, TRUE);

	//
	// Complete the Irp
	//
	status = Irp->IoStatus.Status;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return status;
}

static NTSTATUS
BusFilterAddDevice(WDFDEVICE Device, WDFOBJECT BffDevice)
{
	NTSTATUS status;
	WDF_OBJECT_ATTRIBUTES attr;
	PBUS_FILTER_CONTEXT busFilterContext;
	WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attr, BUS_FILTER_CONTEXT);
	attr.ParentObject = Device;
	status = WdfObjectAllocateContext(BffDevice, &attr, &busFilterContext);
	if (!NT_SUCCESS(status))
		KdPrint(("%s: failed to allocate BUS_FILTER_CONTEXT: %x\n", __FUNCTION__, status));
	else {
		ASSERT(BusFilterGetContext(BffDevice) == busFilterContext);
		busFilterContext->Parent = Device;
	}
	return status;
}

static VOID
BusFilterRemoveDevice(WDFDEVICE Device, WDFOBJECT BffDevice)
{
	PBUS_FILTER_CONTEXT busFilterContext = BusFilterGetContext(BffDevice);
	if (busFilterContext->IsRegistered) {
		IoSetDeviceInterfaceState(&busFilterContext->SymbolicLink, FALSE);
		RtlFreeUnicodeString(&busFilterContext->SymbolicLink);
	}
}

static NTSTATUS
BusFilterQueryID(WDFOBJECT BffDevice, PIRP Irp)
{
	NTSTATUS status;
	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
	ASSERT(stack->MajorFunction == IRP_MJ_PNP);
	ASSERT(stack->MinorFunction == IRP_MN_QUERY_ID);
	if (stack->Parameters.QueryId.IdType != BusQueryCompatibleIDs) {
		IoSkipCurrentIrpStackLocation(Irp);
		return IoCallDriver(BffDeviceWdmGetAttachedDevice(BffDevice), Irp);
	}

	if (!IoForwardIrpSynchronously(BffDeviceWdmGetAttachedDevice(BffDevice), Irp))
		Irp->IoStatus.Status = STATUS_NO_SUCH_DEVICE;
	else if (NT_SUCCESS(Irp->IoStatus.Status)) {
		WCHAR *newCompatibleIDs = ExAllocatePool(PagedPool, 200 * sizeof(WCHAR));
		if (newCompatibleIDs) {
			WCHAR *newIDs = newCompatibleIDs;
			WCHAR *oldIDs = (WCHAR *)Irp->IoStatus.Information;
			size_t length = wcslen(L"BffDevice") + 1;
			wcscpy(newIDs, L"BffDevice");
			newIDs += length;
			//
			// oldIDs is a multi-sz list, hence two NULL characters
			// terminated.
			//
			while (oldIDs && *oldIDs && length + wcslen(oldIDs) + 2 <= 200) {
				wcscpy(newIDs, oldIDs);
				length += wcslen(oldIDs) + 1;
				newIDs += wcslen(oldIDs)+1;
				oldIDs += wcslen(oldIDs)+1;
			}
			*newIDs = 0;
			ExFreePool((PVOID)Irp->IoStatus.Information);
			Irp->IoStatus.Information = (ULONG_PTR)newCompatibleIDs;
		}
	}
	//
	// Complete the Irp
	//
	status = Irp->IoStatus.Status;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return status;
}

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
/*++

Routine Description:
    DriverEntry initializes the driver and is the first routine called by the
    system after the driver is loaded. DriverEntry specifies the other entry
    points in the function driver, such as EvtDevice and DriverUnload.

Parameters Description:

    DriverObject - represents the instance of the function driver that is loaded
    into memory. DriverEntry must initialize members of DriverObject before it
    returns to the caller. DriverObject is allocated by the system before the
    driver is loaded, and it is released by the system after the system unloads
    the function driver from memory.

    RegistryPath - represents the driver specific path in the Registry.
    The function driver can use the path to store driver related data between
    reboots. The path does not store hardware instance specific data.

Return Value:

    STATUS_SUCCESS if successful,
    STATUS_UNSUCCESSFUL otherwise.

--*/
{
    WDF_DRIVER_CONFIG config;
    NTSTATUS status;
    WDF_OBJECT_ATTRIBUTES attributes;
	BFF_INITIALIZATION_DATA initData;
	BffSetInitializationData(&initData, FILE_DEVICE_DISK, 0, BusFilterAddDevice, BusFilterRemoveDevice);
	initData.PnPMinorFunction[IRP_MN_START_DEVICE] = BusFilterStartDevice;
	initData.PnPMinorFunction[IRP_MN_DEVICE_ENUMERATED] = BusFilterDeviceEnumerated;
	initData.PnPMinorFunction[IRP_MN_QUERY_ID] = BusFilterQueryID;

    //
    // Initialize WPP Tracing
    //
    WPP_INIT_TRACING( DriverObject, RegistryPath );

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Entry");

    //
    // Register a cleanup callback so that we can call WPP_CLEANUP when
    // the framework driver object is deleted during driver unload.
    //
    WDF_OBJECT_ATTRIBUTES_INIT(&attributes);
    attributes.EvtCleanupCallback = BusFilterEvtDriverContextCleanup;

    WDF_DRIVER_CONFIG_INIT(&config,
                           BusFilterEvtDeviceAdd
                           );

    status = WdfDriverCreate(DriverObject,
                             RegistryPath,
                             &attributes,
                             &config,
                             WDF_NO_HANDLE
                             );

    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_ERROR, TRACE_DRIVER, "WdfDriverCreate failed %!STATUS!", status);
        WPP_CLEANUP(DriverObject);
        return status;
    }

	status = BffInitialize(DriverObject, RegistryPath, &initData);
	if (!NT_SUCCESS(status)) {
		KdPrint(("%s: failed to initialize BFF:%x\n", __FUNCTION__, status));
		WPP_CLEANUP(DriverObject);
		return status;
	}

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Exit");

    return status;
}

NTSTATUS
BusFilterEvtDeviceAdd(
    _In_    WDFDRIVER       Driver,
    _Inout_ PWDFDEVICE_INIT DeviceInit
    )
/*++
Routine Description:

    EvtDeviceAdd is called by the framework in response to AddDevice
    call from the PnP manager. We create and initialize a device object to
    represent a new instance of the device.

Arguments:

    Driver - Handle to a framework driver object created in DriverEntry

    DeviceInit - Pointer to a framework-allocated WDFDEVICE_INIT structure.

Return Value:

    NTSTATUS

--*/
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER(Driver);

    PAGED_CODE();

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Entry");

    status = BusFilterCreateDevice(DeviceInit);

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Exit");

    return status;
}

VOID
BusFilterEvtDriverContextCleanup(
    _In_ WDFOBJECT DriverObject
    )
/*++
Routine Description:

    Free all the resources allocated in DriverEntry.

Arguments:

    DriverObject - handle to a WDF Driver object.

Return Value:

    VOID.

--*/
{
    UNREFERENCED_PARAMETER(DriverObject);

    PAGED_CODE ();

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Entry");

    //
    // Stop WPP Tracing
    //
    WPP_CLEANUP( WdfDriverWdmGetDriverObject( (WDFDRIVER) DriverObject) );

}
