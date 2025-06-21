#pragma once
#include <ntddk.h>

BOOLEAN FormatFat32Volume(
    UCHAR* pDiskBuf,       // Pointer to disk buffer
    ULONG disk_size_bytes, // Total size in bytes
    const char* volume_label // 11 bytes, padded with spaces
);