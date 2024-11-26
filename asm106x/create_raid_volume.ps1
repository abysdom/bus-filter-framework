# Step 1: Define the target Compatible ID and desired RAID type
$targetCompatibleId = "BffDevice"
$raidType = "RAID5"  # Options: "RAID0" or "RAID5"

# Step 2: Identify disks with the specified Compatible ID
Write-Host "Searching for disks with Compatible ID: $targetCompatibleId..." -ForegroundColor Cyan
$devices = Get-PnpDevice -Class "DiskDrive"

# Filter devices based on Compatible ID
$matchingDevices = foreach ($device in $devices) {
    $deviceDetails = Get-PnpDeviceProperty -InstanceId $device.InstanceId -KeyName "DEVPKEY_Device_CompatibleIds"
    if ($deviceDetails.Data -contains $targetCompatibleId) {
        $device
    }
}

# Check if any matching disks are found
if ($matchingDevices.Count -eq 0) {
    Write-Host "No disks found with the specified Compatible ID." -ForegroundColor Red
    exit
}

Write-Host "Disks found with the specified Compatible ID:" -ForegroundColor Green
$matchingDevices | ForEach-Object { Write-Host "Device ID: $($_.InstanceId)" }

# Step 3: Convert matching devices to PhysicalDisks
$physicalDisks = foreach ($device in $matchingDevices) {
    Get-PhysicalDisk | Where-Object DeviceId -EQ $device.InstanceId
}

# Check if enough disks are available for the specified RAID type
if ($raidType -eq "RAID5" -and $physicalDisks.Count -lt 3) {
    Write-Host "RAID 5 requires at least 3 disks. Only $($physicalDisks.Count) found." -ForegroundColor Red
    exit
}
if ($raidType -eq "RAID0" -and $physicalDisks.Count -lt 2) {
    Write-Host "RAID 0 requires at least 2 disks. Only $($physicalDisks.Count) found." -ForegroundColor Red
    exit
}

# Step 4: Create the storage pool
$poolFriendlyName = "MyStoragePool"
Write-Host "Creating storage pool: $poolFriendlyName..." -ForegroundColor Cyan
$pool = New-StoragePool -FriendlyName $poolFriendlyName -PhysicalDisks $physicalDisks -StorageSubsystemFriendlyName "Windows Storage Spaces*"

# Step 5: Create the RAID volume
$volumeFriendlyName = "MyRAIDVolume"
$usableSize = (Get-StoragePool -FriendlyName $poolFriendlyName).Size

if ($raidType -eq "RAID5") {
    Write-Host "Creating RAID 5 volume: $volumeFriendlyName..." -ForegroundColor Cyan
    New-VirtualDisk -StoragePoolFriendlyName $poolFriendlyName -FriendlyName $volumeFriendlyName `
        -Size $usableSize -ResiliencySettingName Parity -NumberOfColumns $physicalDisks.Count
} elseif ($raidType -eq "RAID0") {
    Write-Host "Creating RAID 0 volume: $volumeFriendlyName..." -ForegroundColor Cyan
    New-VirtualDisk -StoragePoolFriendlyName $poolFriendlyName -FriendlyName $volumeFriendlyName `
        -Size $usableSize -ResiliencySettingName Simple
} else {
    Write-Host "Invalid RAID type specified: $raidType" -ForegroundColor Red
    exit
}

# Step 6: Initialize, partition, and format the new virtual disk
$disk = Get-Disk | Where-Object PartitionStyle -EQ "RAW" | Sort-Object -Property Size -Descending | Select-Object -First 1
Initialize-Disk -Number $disk.Number
New-Partition -DiskNumber $disk.Number -UseMaximumSize -AssignDriveLetter | Format-Volume -FileSystem NTFS -Confirm:$false

Write-Host "RAID volume successfully created and formatted." -ForegroundColor Green
