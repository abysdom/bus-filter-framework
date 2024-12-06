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

//
// Bus Filter Device Extension
//

typedef struct _DEVICE_EXTENSION
{
    GUID Signature;
    //
    // Target Device Object
    //

    PDEVICE_OBJECT TargetDeviceObject;

    //
    // Physical device object
    //
    PDEVICE_OBJECT PhysicalDeviceObject;

    LIST_ENTRY List;
    WDFDEVICE Parent; // The upper filter of the parent bus
    WDFOBJECT Child;
    BOOLEAN Existing;
} DEVICE_EXTENSION, *PDEVICE_EXTENSION;

#define DEVICE_EXTENSION_SIZE sizeof(DEVICE_EXTENSION)

typedef struct _BFF_DEVICE_CONTEXT
{
    //
    // Back pointer to device object
    //

    PDEVICE_OBJECT DeviceObject;
} BFF_DEVICE_CONTEXT, *PBFF_DEVICE_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(BFF_DEVICE_CONTEXT, BffGetDeviceContext)

//
// The device context performs the same job as
// a WDM device extension in the driver frameworks
//
typedef struct _BFF_PARENT_CONTEXT
{
    LIST_ENTRY List; // Child list
    KSPIN_LOCK Lock; // Lock for child list
} BFF_PARENT_CONTEXT, *PBFF_PARENT_CONTEXT;

//
// This macro will generate an inline function called BffGetParentContext
// which will be used to get a pointer to the device context memory
// in a type safe manner.
//
WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(BFF_PARENT_CONTEXT, BffGetParentContext)
