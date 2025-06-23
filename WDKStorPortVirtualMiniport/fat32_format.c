#include <ntddk.h>
#include <windef.h>

#define SECTOR_SIZE 512
#define PARTITION_ALIGNMENT_SECTORS 2048 // 1MB alignment for best performance
#define PARTITION_START_SECTOR PARTITION_ALIGNMENT_SECTORS  // Start partition at 1MB boundary

static void SetVolumeLabel(UCHAR* buf, const char* label) {
    for (int i = 0; i < 11; ++i)
        buf[i] = (label && label[i]) ? label[i] : ' ';
}

BOOLEAN FormatFat32Volume(UCHAR* pDiskBuf, ULONG disk_size_bytes, const char* volume_label) {
    if (!pDiskBuf || disk_size_bytes < (PARTITION_START_SECTOR + 10) * SECTOR_SIZE) return FALSE;
    ULONG total_sectors = disk_size_bytes / SECTOR_SIZE;

    // Compute usable sectors (partition size)
    ULONG partition_sectors = total_sectors - PARTITION_START_SECTOR;

    // Cluster size selection (Windows rules of thumb)
    ULONG sectors_per_cluster = 8;
    if (partition_sectors > 0x400000) sectors_per_cluster = 16;      // >2GB
    if (partition_sectors > 0x800000) sectors_per_cluster = 32;      // >4GB
    if (partition_sectors > 0x1000000) sectors_per_cluster = 64;     // >8GB
    if (partition_sectors > 0x2000000) sectors_per_cluster = 128;    // >16GB

    ULONG reserved_sectors = 32;
    ULONG num_fats = 2;
    ULONG root_dir_first_cluster = 2;

    // Calculate FAT size (in sectors)
    ULONG data_sectors = partition_sectors - reserved_sectors - (num_fats * 0); // temp
    ULONG num_clusters = data_sectors / sectors_per_cluster;
    if (num_clusters < 65525) num_clusters = 65525; // FAT32 spec minimum
    ULONG fat_size = (num_clusters * 4 + (SECTOR_SIZE - 1)) / SECTOR_SIZE;
    if (fat_size < 32) fat_size = 32;
    data_sectors = partition_sectors - reserved_sectors - (num_fats * fat_size);
    num_clusters = data_sectors / sectors_per_cluster;
    fat_size = (num_clusters * 4 + (SECTOR_SIZE - 1)) / SECTOR_SIZE;
    if (fat_size < 32) fat_size = 32;

    // Zero the buffer for MBR, partition gap, and reserved area
    RtlZeroMemory(pDiskBuf, (PARTITION_START_SECTOR + reserved_sectors) * SECTOR_SIZE);

    // --- MBR (sector 0) ---
    // Mark partition as active (bootable): 0x80
    pDiskBuf[0x1BE] = 0x80; // Bootable flag (active)
    // CHS fields are not relevant for modern LBA, fill with typical values
    pDiskBuf[0x1BE + 1] = 0x01; // head
    pDiskBuf[0x1BE + 2] = 0x01; // sector
    pDiskBuf[0x1BE + 3] = 0x00; // cylinder
    pDiskBuf[0x1BE + 4] = 0x0C; // Partition type: FAT32 LBA
    pDiskBuf[0x1BE + 5] = 0xFE; // end head
    pDiskBuf[0x1BE + 6] = 0xFF; // end sector
    pDiskBuf[0x1BE + 7] = 0xFF; // end cylinder
    *(ULONG*)(pDiskBuf + 0x1BE + 8) = PARTITION_START_SECTOR; // LBA start
    *(ULONG*)(pDiskBuf + 0x1BE + 12) = partition_sectors;
    pDiskBuf[510] = 0x55; pDiskBuf[511] = 0xAA;

    // --- FAT32 Boot Sector (at LBA PARTITION_START_SECTOR) ---
    UCHAR* bs = pDiskBuf + PARTITION_START_SECTOR * SECTOR_SIZE;
    RtlZeroMemory(bs, SECTOR_SIZE);
    bs[0] = 0xEB; bs[1] = 0x58; bs[2] = 0x90; // JMP short
    RtlCopyMemory(bs + 3, "MSWIN4.1", 8); // OEM Name

    // Fix 1: Always specify 512 as bytes/sector in BPB
    *(USHORT*)(bs + 11) = (USHORT)SECTOR_SIZE; // Bytes per sector (512)
    bs[13] = (UCHAR)sectors_per_cluster;
    *(USHORT*)(bs + 14) = (USHORT)reserved_sectors;
    bs[16] = (UCHAR)num_fats;
    *(USHORT*)(bs + 17) = 0; // Root dir entries (0 for FAT32)
    *(USHORT*)(bs + 19) = 0; // Total sectors (16-bit, not used)
    bs[21] = 0xF8;           // Media descriptor
    *(USHORT*)(bs + 22) = 0; // FAT size 16 (0 for FAT32)
    *(USHORT*)(bs + 24) = 63; // Sectors per track (typical LBA)
    *(USHORT*)(bs + 26) = 255; // Number of heads
    *(ULONG*)(bs + 28) = PARTITION_START_SECTOR;  // Hidden sectors
    *(ULONG*)(bs + 32) = partition_sectors; // Total sectors (32-bit)
    *(ULONG*)(bs + 36) = fat_size; // FAT size (FAT32)
    *(USHORT*)(bs + 44) = 2; // FSInfo sector = 2
    *(USHORT*)(bs + 48) = 6; // Backup boot sector = 6
    *(ULONG*)(bs + 44) = root_dir_first_cluster;
    // Volume Serial Number (unique, non-zero)
    LARGE_INTEGER sysTime;
    KeQuerySystemTime(&sysTime);
    *(ULONG*)(bs + 67) = (ULONG)(sysTime.LowPart ^ sysTime.HighPart);

    // Volume Label (offset 71, 11 bytes)
    SetVolumeLabel(bs + 71, volume_label);

    RtlCopyMemory(bs + 82, "FAT32   ", 8); // File system type
    bs[510] = 0x55; bs[511] = 0xAA;

    // --- FSInfo sector (at PARTITION_START_SECTOR + 2) ---
    UCHAR* fsinfo = pDiskBuf + (PARTITION_START_SECTOR + 2) * SECTOR_SIZE;
    RtlZeroMemory(fsinfo, SECTOR_SIZE);
    *(ULONG*)(fsinfo) = 0x41615252;       // Lead signature
    *(ULONG*)(fsinfo + 484) = 0x61417272; // Struct signature
    *(ULONG*)(fsinfo + 488) = 0xFFFFFFFF; // Free cluster count (unknown)
    *(ULONG*)(fsinfo + 492) = 0x00000002; // Next free cluster
    *(USHORT*)(fsinfo + 510) = 0xAA55;

    // --- Backup boot sector (at PARTITION_START_SECTOR + 6) ---
    UCHAR* backup_bs = pDiskBuf + (PARTITION_START_SECTOR + 6) * SECTOR_SIZE;
    RtlCopyMemory(backup_bs, bs, SECTOR_SIZE);

    // --- Backup FSInfo sector (at PARTITION_START_SECTOR + 7) ---
    UCHAR* backup_fsinfo = pDiskBuf + (PARTITION_START_SECTOR + 7) * SECTOR_SIZE;
    RtlCopyMemory(backup_fsinfo, fsinfo, SECTOR_SIZE);

    // --- FAT tables (zeroed and initialized clusters 0, 1, and 2 as reserved/EOC) ---
    for (ULONG fat = 0; fat < num_fats; ++fat) {
        UCHAR* fat_area = pDiskBuf + (PARTITION_START_SECTOR + reserved_sectors + fat * fat_size) * SECTOR_SIZE;
        RtlZeroMemory(fat_area, fat_size * SECTOR_SIZE);

        // Cluster 0: media descriptor + reserved
        fat_area[0] = 0xF8; fat_area[1] = 0xFF; fat_area[2] = 0xFF; fat_area[3] = 0x0F;
        // Cluster 1: reserved
        fat_area[4] = 0xFF; fat_area[5] = 0xFF; fat_area[6] = 0xFF; fat_area[7] = 0x0F;
        // Cluster 2: (root dir) EOC
        fat_area[8] = 0xFF; fat_area[9] = 0xFF; fat_area[10] = 0xFF; fat_area[11] = 0x0F;
    }

    // --- Compute first data sector for root directory ---
    ULONG first_data_sector = PARTITION_START_SECTOR + reserved_sectors + (num_fats * fat_size);
    UCHAR* root_dir = pDiskBuf + first_data_sector * SECTOR_SIZE;
    RtlZeroMemory(root_dir, sectors_per_cluster * SECTOR_SIZE);

    // "." entry
    RtlZeroMemory(root_dir, 32);
    memcpy(root_dir, ".          ", 11);
    root_dir[11] = 0x10; // ATTR_DIRECTORY
    root_dir[20] = 0x00; root_dir[21] = 0x00; // cluster high
    root_dir[26] = 0x02; root_dir[27] = 0x00; // cluster low

    // ".." entry
    RtlZeroMemory(root_dir + 32, 32);
    memcpy(root_dir + 32, "..         ", 11);
    root_dir[32 + 11] = 0x10; // ATTR_DIRECTORY
    root_dir[32 + 20] = 0x00; root_dir[32 + 21] = 0x00; // cluster high
    root_dir[32 + 26] = 0x02; root_dir[32 + 27] = 0x00; // cluster low

    return TRUE;
}