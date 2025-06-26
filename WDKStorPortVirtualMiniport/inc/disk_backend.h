#pragma once
#include <ntddk.h>

// Disk backend operations interface
typedef struct _DISK_BACKEND_OPS {
    NTSTATUS (*Read)(
        void* context,
        ULONGLONG offset,
        void* buffer,
        ULONG length
    );
    NTSTATUS (*Write)(
        void* context,
        ULONGLONG offset,
        const void* buffer,
        ULONG length
    );
    NTSTATUS (*Flush)(void* context);
    NTSTATUS (*Close)(void* context);
} DISK_BACKEND_OPS;

typedef struct _DISK_BACKEND {
    void* context; // Pointer to backend-specific state (buffer, file handle, etc)
    const DISK_BACKEND_OPS* ops;
    ULONG64 size;
} DISK_BACKEND;

// RAM backend
NTSTATUS RamDiskBackend_Create(DISK_BACKEND* backend, ULONG64 size);

// File backend
NTSTATUS FileDiskBackend_Create(DISK_BACKEND* backend, const wchar_t* path, ULONG64 size, BOOLEAN createIfNotExist);