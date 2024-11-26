# Bus Filter Framework
A framework for KMDF-based upper filter drivers to behave as bus filters. You don't need to write WDM drivers any more!
# Sample Driver
Check the code in the BusFilter directory as well as ReadMe.htm in the WDKStorPortVirtualMiniport directory. To build the sample driver, open WDKStorPortVirtualMiniport\mp\mp.sln with Visual Studio Community Edition.

If you have an old CalDight T3/T4, you may also try to open and build caldigit\caldigit.sln. This experimental driver will add "BffDevice" compatible ID to each of the disks inserted to T3/T4. Thereafter, you may run as administrator asm106x\create_raid_volume.ps1 in PowerShell to create a RAID 5 volume with those disks.

Caution: Make sure you have backed up data in your disks before you run asm106x\create_raid_volume.ps1.
# Documentation
Please navigate to [here](https://bus-filter-framework.blogspot.tw/p/documentation.html).
# FAQ
Please navigate to [here](https://bus-filter-framework.blogspot.tw/p/faq.html).
# Donations
If this piece of work eases your pains and you would like to encourage the author, [donations](https://bus-filter-framework.blogspot.com/p/donation.html) are welcome and appreciated!
# License
If you need a software license other than GNU GPL v3, please contact the author.
