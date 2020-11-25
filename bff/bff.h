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
#pragma once
#include <wdm.h>
#include <wdf.h>

/** Callback function for creation of a bus filter device object. Before this
 *  call, a WDF object, BffDevice, and its underlying WDM device object had
 *  been created, and the latter in particular was then attached to the next
 *  lower device object.
 *  @param Device	The parent WDF device object, i.e., the upper filter
 *			device object.
 *  @param BffDevice	The WDF object as a bus filter device object.
 *  @return		0 or any positive value for success; otherwise for
 *			failure.
 */
typedef NTSTATUS BFF_DEVICE_ADD(WDFDEVICE Device, WDFOBJECT BffDevice);
typedef BFF_DEVICE_ADD *PBFF_DEVICE_ADD;

/** Callback function for removal of a bus filter device object. After this
 *  call, the WDF object, BffDevice, will be deleted, and its underlying WDM
 *  device object will be detached, and then deleted as well.
 *  @param Device	The parent WDF device object, i.e., the upper filter
 *			device object.
 *  @param BffDevice	The WDF object as a bus filter device object.
 */
typedef VOID BFF_DEVICE_REMOVE(WDFDEVICE Device, WDFOBJECT BffDevice);
typedef BFF_DEVICE_REMOVE *PBFF_DEVICE_REMOVE;

/** Data structure for configuration of a bus filter device object.
 */
typedef struct _BFF_DEVICE_CONFIG {
    ///
    /// Same as DeviceType parameter of IoCreateDevice (Mandatory)
    ///
    DEVICE_TYPE DeviceType;

    ///
    /// Same as DeviceCharacteristics parameter of IoCreateDevice (Mandatory)
    ///
    ULONG DeviceCharacteristics;

    ///
    /// Callback function for creation of a bus filter device object (Optional)
    ///
    PBFF_DEVICE_ADD DeviceAdd;

    ///
    /// Callback function for removal of a bus filter device object (Optional)
    ///
    PBFF_DEVICE_REMOVE DeviceRemove;
} BFF_DEVICE_CONFIG, *PBFF_DEVICE_CONFIG;

/** Callback function for processing a PnP IRP. It must either complete that IRP
 *  or, optionally register an IoCompletion routine, and pass that IRP to the
 *  next lower driver before returning to BFF.
 *  Example#1:
 *  NTSTATUS callback1(WDFOBJECT BffDevice, PIRP Irp)
 *  {
 *	...
 *	IoCompleteRequest(Irp, IO_NO_INCREMENT);
 *	return status;
 *  }
 *
 *  Example#2:
 *  NTSTATUS callback2(WDFOBJECT BffDevice, PIRP Irp)
 *  {
 *	...
 *	IoSkipCurrentIrpStackLocation(Irp);
 *	status = IoCallDriver(BffDeviceWdmGetAttachedDevice(BffDevice), Irp);
 *	...
 *	return status;
 *  }
 *
 *  Example#3:
 *  NTSTATUS callback3(WDFOBJECT BffDevice, PIRP Irp)
 *  {
 *	...
 *	IoCopyCurrentIrpStackLocationToNext(Irp);
 *	IoSetCompletionRoutine(Irp, IoCompletion, BffDevice, ...);
 *	status = IoCallDriver(BffDeviceWdmGetAttachedDevice(BffDevice), Irp);
 *	...
 *	return status;
 *  }
 *  @param BffDevice	The WDF object as a bus filter device object.
 *  @param Irp		The PnP I/O request packet.
 *  @return		0 or any positive value for success; otherwise for
 *			failure.
 */
typedef NTSTATUS BFF_DISPATCH_PNP(WDFOBJECT BffDevice, PIRP Irp);
typedef BFF_DISPATCH_PNP *PBFF_DISPATCH_PNP;

/** Data structure for initialization of Bus Filter Framework. Typically, you
 *  declare a local variable of this type, and call BffSetInitializationData to
 *  initialize it. Then, you selectively re-initialize
 *  PnPMinorFunction[IRP_MN_*] with your own handlers before calling
 *  BffInitialize.
 */
typedef struct _BFF_INITIALIZATION_DATA {
    ///
    /// Size of this structure (Mandatory)
    ///
    ULONG Size;

    BFF_DEVICE_CONFIG DeviceConfig;

    PBFF_DISPATCH_PNP PnPMinorFunction[IRP_MN_DEVICE_ENUMERATED+1];
} BFF_INITIALIZATION_DATA, *PBFF_INITIALIZATION_DATA;

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
VOID BffSetInitializationData(PBFF_INITIALIZATION_DATA InitData,
    DEVICE_TYPE Type, ULONG Characteristics,
    PBFF_DEVICE_ADD DeviceAdd, PBFF_DEVICE_REMOVE DeviceRemove);

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
NTSTATUS BffInitialize(PDRIVER_OBJECT DriverObject,
    PUNICODE_STRING RegistryPath, PBFF_INITIALIZATION_DATA InitData);

/** Allocate context space for an upper filter device object on behalf of Bus
 *  Filter Framework. This routine is typically called in the EvtDriverDeviceAdd
 *  callback function.
 *  @param Device	The WDF device object representing an upper filter
 *			device object.
 *  @return		The value that WdfObjectAllocateContext returns.
 */
NTSTATUS BffAllocateContext(WDFDEVICE Device);

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
NTSTATUS BffPreprocessQueryBusRelations(WDFDEVICE Device, PIRP Irp);

/***************************************************************************//**
 * APIs for bus filter device objects.
 ******************************************************************************/
/** Retrieve the WDM bus filter device object that is associated with the
 *  specified WDF object.
 *  @param BffDevice	The WDF object as a bus filter device object.
 *  @return		The WDM bus filter device object for success; NULL
 *			otherwise.
 */
PDEVICE_OBJECT BffDeviceWdmGetDeviceObject(WDFOBJECT BffDevice);

/** Retrieve the next lower WDM device object in the device stack of the
 *  specified WDF object.
 *  @param BffDevice	The WDF object as a bus filter device object.
 *  @return		The next lower WDM device object for success; NULL
 *			otherwise.
 */
PDEVICE_OBJECT BffDeviceWdmGetAttachedDevice(WDFOBJECT BffDevice);

/** Retrieve the PDO from the device stack of the specified WDF object.
 *  @param BffDevice	The WDF object as a bus filter device object.
 *  @return		The PDO for success; NULL otherwise.
 */
PDEVICE_OBJECT BffDeviceWdmGetPhysicalDevice(WDFOBJECT BffDevice);
