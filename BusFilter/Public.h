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

    public.h

Abstract:

    This module contains the common declarations shared by driver
    and user applications.

Environment:

    user and kernel

--*/

//
// Define an Interface Guid so that app can find the device and talk to it.
//

DEFINE_GUID (GUID_DEVINTERFACE_BusFilter,
    0x4ce515f5,0x2aeb,0x43ca,0x80,0xc2,0x34,0x13,0xcf,0x20,0xcb,0x85);
// {4ce515f5-2aeb-43ca-80c2-3413cf20cb85}
