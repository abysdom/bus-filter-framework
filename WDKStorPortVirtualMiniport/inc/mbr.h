#pragma once
#include <ntddk.h>
#pragma pack(push,1)
typedef struct _MBR_PARTITION_ENTRY {
    UCHAR  status;
    UCHAR  chs_first[3];
    UCHAR  type;
    UCHAR  chs_last[3];
    ULONG  lba_first;
    ULONG  sectors_total;
} MBR_PARTITION_ENTRY, *PMBR_PARTITION_ENTRY;

typedef struct _MBR {
    UCHAR              boot_code[446];
    MBR_PARTITION_ENTRY  partition[4];
    USHORT             signature;
} MBR, *PMBR;
#pragma pack(pop)

void FillDiskBufWithMBR(UCHAR* pDiskBuf, ULONG disk_size_bytes);
