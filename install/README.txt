Bus Filter Framework Sample Driver
Copyright (c) 2016 Yang Yuanzhi <yangyuanzhi@gmail.com>

This sample driver, based upon Bus Filter Framework, adds a bus filter to the device stack of a disk drive enumerated by the storport virtual miniport driver. Furthermore, a device interface is registered for such a disk drive, and a new compatible ID, "BffDevice", is prepended to the existing compatible IDs list thereof.