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

    device.h

Abstract:

    This file contains the device definitions.

Environment:

    Kernel-mode Driver Framework

--*/

#pragma once
#include "public.h"

EXTERN_C_START

typedef struct _BUS_FILTER_CONTEXT
{
    WDFDEVICE Parent;
    BOOLEAN IsRegistered;
    UNICODE_STRING SymbolicLink;
} BUS_FILTER_CONTEXT, *PBUS_FILTER_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(BUS_FILTER_CONTEXT, BusFilterGetContext)

//
// The device context performs the same job as
// a WDM device extension in the driver frameworks
//
typedef struct _DEVICE_CONTEXT
{
    ULONG PrivateDeviceData; // just a placeholder

} DEVICE_CONTEXT, *PDEVICE_CONTEXT;

//
// This macro will generate an inline function called DeviceGetContext
// which will be used to get a pointer to the device context memory
// in a type safe manner.
//
WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(DEVICE_CONTEXT, DeviceGetContext)

//
// Function to initialize the device and its callbacks
//
NTSTATUS
BusFilterCreateDevice(_Inout_ PWDFDEVICE_INIT DeviceInit);

EXTERN_C_END
