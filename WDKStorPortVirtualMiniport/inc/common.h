/*++

Copyright (c) 1990-2011 Microsoft Corporation.  All Rights Reserved

Module Name:
    common.h

Abstract: 

Author:

Enviroment:

Revision History:

--*/

#ifndef _COMMON_H_
#define _COMMON_H_

#define DISK_DEVICE         0x00

typedef struct _MP_DEVICE_INFO {
    UCHAR    DeviceType;
    UCHAR    TargetID;
    UCHAR    LunID;
} MP_DEVICE_INFO, *pMP_DEVICE_INFO;

typedef struct _MP_DEVICE_LIST {
    ULONG          DeviceCount;
    MP_DEVICE_INFO DeviceInfo[1];
} MP_DEVICE_LIST, *pMP_DEVICE_LIST;

#endif    // _COMMON_H_
