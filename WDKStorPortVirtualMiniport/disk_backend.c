#include "disk_backend.h"
#include "common.h"
#include <ntstrsafe.h>
#include <limits.h> // For ULONG_MAX

// Add this declaration if not already present
NTSYSAPI
NTSTATUS
NTAPI
ZwFlushBuffersFile(
    IN HANDLE FileHandle,
    OUT PIO_STATUS_BLOCK IoStatusBlock
);

// ================== RAM DISK BACKEND ======================

typedef struct _RAMDISK_CTX {
    PUCHAR buffer;
    ULONG64 size;
} RAMDISK_CTX;

static NTSTATUS RamDisk_Read(void* ctx, ULONGLONG offset, void* buffer, ULONG length) {
    RAMDISK_CTX* ram = (RAMDISK_CTX*)ctx;
    if (offset + length > ram->size) return STATUS_INVALID_PARAMETER;
    RtlCopyMemory(buffer, ram->buffer + offset, length);
    return STATUS_SUCCESS;
}
static NTSTATUS RamDisk_Write(void* ctx, ULONGLONG offset, const void* buffer, ULONG length) {
    RAMDISK_CTX* ram = (RAMDISK_CTX*)ctx;
    if (offset + length > ram->size) return STATUS_INVALID_PARAMETER;
    RtlCopyMemory(ram->buffer + offset, buffer, length);
    return STATUS_SUCCESS;
}
static NTSTATUS RamDisk_Flush(void* ctx) { UNREFERENCED_PARAMETER(ctx); return STATUS_SUCCESS; }
static NTSTATUS RamDisk_Close(void* ctx) {
    RAMDISK_CTX* ram = (RAMDISK_CTX*)ctx;
    if (ram->buffer) ExFreePool(ram->buffer); // Use tagless free for compatibility
    ExFreePool(ram);
    return STATUS_SUCCESS;
}
static const DISK_BACKEND_OPS RamDiskOps = {
    RamDisk_Read, RamDisk_Write, RamDisk_Flush, RamDisk_Close
};

NTSTATUS RamDiskBackend_Create(DISK_BACKEND* backend, ULONG64 size) {
    RAMDISK_CTX* ctx = (RAMDISK_CTX*)ALLOCATE_NON_PAGED_POOL(sizeof(RAMDISK_CTX));
    if (!ctx) return STATUS_INSUFFICIENT_RESOURCES;
    ctx->buffer = (PUCHAR)ALLOCATE_NON_PAGED_POOL((SIZE_T)size);
    if (!ctx->buffer) { ExFreePool(ctx); return STATUS_INSUFFICIENT_RESOURCES; }
    ctx->size = size;
    backend->context = ctx;
    backend->ops = &RamDiskOps;
    backend->size = size;
    return STATUS_SUCCESS;
}

// ================ FILE DISK BACKEND ========================

typedef struct _FILEDISK_CTX {
    HANDLE fileHandle;
    ULONG64 size;
} FILEDISK_CTX;

static NTSTATUS FileDisk_Read(void* ctx, ULONGLONG offset, void* buffer, ULONG length) {
    FILEDISK_CTX* fctx = (FILEDISK_CTX*)ctx;
    IO_STATUS_BLOCK iosb;
    LARGE_INTEGER fileOffset;
    fileOffset.QuadPart = offset;
    return ZwReadFile(fctx->fileHandle, NULL, NULL, NULL, &iosb, buffer, length, &fileOffset, NULL);
}
static NTSTATUS FileDisk_Write(void* ctx, ULONGLONG offset, const void* buffer, ULONG length) {
    FILEDISK_CTX* fctx = (FILEDISK_CTX*)ctx;
    IO_STATUS_BLOCK iosb;
    LARGE_INTEGER fileOffset;
    fileOffset.QuadPart = offset;
    return ZwWriteFile(fctx->fileHandle, NULL, NULL, NULL, &iosb, (PVOID)buffer, length, &fileOffset, NULL);
}
static NTSTATUS FileDisk_Flush(void* ctx) {
    FILEDISK_CTX* fctx = (FILEDISK_CTX*)ctx;
    IO_STATUS_BLOCK iosb;
    return ZwFlushBuffersFile(fctx->fileHandle, &iosb);
}
static NTSTATUS FileDisk_Close(void* ctx) {
    FILEDISK_CTX* fctx = (FILEDISK_CTX*)ctx;
    if (fctx->fileHandle) ZwClose(fctx->fileHandle);
    ExFreePool(fctx); // Use tagless free for compatibility
    return STATUS_SUCCESS;
}
static const DISK_BACKEND_OPS FileDiskOps = {
    FileDisk_Read, FileDisk_Write, FileDisk_Flush, FileDisk_Close
};

NTSTATUS FileDiskBackend_Create(DISK_BACKEND* backend, const wchar_t* path, ULONG64 size, BOOLEAN createIfNotExist) {
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING usPath;
    IO_STATUS_BLOCK iosb;
    HANDLE hFile;
    NTSTATUS status;

    RtlInitUnicodeString(&usPath, path);
    InitializeObjectAttributes(&oa, &usPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    ULONG fdisp = createIfNotExist ? FILE_OVERWRITE_IF : FILE_OPEN;
    status = ZwCreateFile(&hFile, GENERIC_READ|GENERIC_WRITE, &oa, &iosb, NULL,
        FILE_ATTRIBUTE_NORMAL, 0, fdisp, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if (!NT_SUCCESS(status)) return status;

    // Set file size if needed
    if (createIfNotExist) {
        FILE_END_OF_FILE_INFORMATION eofInfo = {0};
        eofInfo.EndOfFile.QuadPart = size;
        ZwSetInformationFile(hFile, &iosb, &eofInfo, sizeof(eofInfo), FileEndOfFileInformation);
    }

    FILEDISK_CTX* ctx = (FILEDISK_CTX*)ALLOCATE_NON_PAGED_POOL(sizeof(FILEDISK_CTX));
    if (!ctx) { ZwClose(hFile); return STATUS_INSUFFICIENT_RESOURCES; }
    ctx->fileHandle = hFile;
    ctx->size = size;
    backend->context = ctx;
    backend->ops = &FileDiskOps;
    backend->size = size;
    return STATUS_SUCCESS;
}