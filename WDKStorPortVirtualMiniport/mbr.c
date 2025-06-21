#include "mbr.h"
#include <ntddk.h>

void FillDiskBufWithMBR(UCHAR* pDiskBuf, ULONG disk_size_bytes)
{
    RtlZeroMemory(pDiskBuf, 512);
    PMBR mbr = (PMBR)pDiskBuf;
    mbr->partition[0].status = 0x00;
    mbr->partition[0].type = 0x07; // NTFS/exFAT
    mbr->partition[0].chs_first[0] = 0x00; mbr->partition[0].chs_first[1] = 0x02; mbr->partition[0].chs_first[2] = 0x00;
    mbr->partition[0].chs_last[0]  = 0xFF; mbr->partition[0].chs_last[1]  = 0xFF; mbr->partition[0].chs_last[2]  = 0xFF;
    mbr->partition[0].lba_first = 1;
    ULONG total_sectors = disk_size_bytes / 512;
    mbr->partition[0].sectors_total = (total_sectors > 1) ? (total_sectors - 1) : 0;
    mbr->signature = 0xAA55;
}
