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

    driver.h

Abstract:

    This file contains the driver definitions.

Environment:

    Kernel-mode Driver Framework

--*/

#define INITGUID

#include <ntddk.h>
#include <wdf.h>

#include "device.h"
#include "queue.h"
#include "trace.h"

EXTERN_C_START

//
// WDFDRIVER Events
//

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_DEVICE_ADD BusFilterEvtDeviceAdd;
EVT_WDF_OBJECT_CONTEXT_CLEANUP BusFilterEvtDriverContextCleanup;

EXTERN_C_END
