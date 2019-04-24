. "$PSScriptRoot\utils.ps1"
# Importing Hyper-V Module 
Import-Module Hyper-V

# Getting VMs 
$VMs = Get-VM

# Process each VM
foreach($VM in $VMs)
{
    # Getting Disk(s) for VM
    $HardDiskDrives = $VM | Get-VMHardDiskDrive
	
	Try
    {
		#General Information and Inventory Call Outs
        $VirtualDisks       = $HardDiskDrives.Path | Get-VHD -ErrorAction SilentlyContinue
		
		#Calculated Disk Usage
		if($VirtualDisks.Path -ne $null) {$storage_used =($VirtualDisks.FileSize/$VirtualDisks.Size)*100 }
    }
    Catch
    {
        WriteExceptionToLog($_.Exception)
    }
	Finally
	{
		if($storage_used -eq $null) {$storage_used=0}
	}
	  
    foreach($HD in $HardDiskDrives)
    {
    # Get VHD Info
       $LHD     = $null
       $VHD     = $null
       $WMIDisk = $null
       if($HD.DiskNumber)
       {
            $LHD    = Get-Disk -Number $HD.DiskNumber
            $WMIDisk    = Get-WmiObject Win32_DiskDrive 
       }
       elseif($HD.Path)
       {
            $VHD = $HD | Get-VHD
       }

        # Creating inventory event hash table
        $InventoryEvent = @{

            # Fields from Hyper-V Powershell Module Get-VMHardDiskDrive
            # Type: Microsoft.HyperV.PowerShell.HardDiskDrive
            disknumber              = $HD.disknumber
            controllertype          = $HD.ControllerType
            controllernumber        = $HD.ControllerNumber
            controllerlocation      = $HD.ControllerLocation
            name                    = $HD.Name
            poolname                = $HD.PoolName
            path                    = $HD.Path
            disk                    = $HD.Disk
            computername            = $HD.ComputerName
            id                      = $HD.Id
            isdeleted               = $HD.IsDeleted
            vm_id                   = $HD.VMId
            vm_name                 = $HD.VMName
            vmsnapshotid            = $HD.VMSnapshotId
            vmsnapshotname          = $HD.VMSnapshotName          
            vhdformat               = $VHD.VhdFormat
            vhdtype                 = $VHD.VhdType
            filesize                = $VHD.FileSize  
            size                    = $VHD.Size
            minimumsize             = $VHD.MinimumSize
            logicalsectorsize       = $VHD.LogicalSectorSize
            physicalsectorsize      = $VHD.PhysicalSectorSize
            blocksize               = $VHD.BlockSize
            diskidentifier          = $VHD.DiskIdentifier
            parentpath              = $VHD.ParentPath  
            fragmentationpercentage = $VHD.FragmentationPercentage
            alignment               = $VHD.Alignment
            attached                = $VHD.Attached
            number                  = $VHD.Number
            allocatedsize           = $LHD.AllocatedSize
            bootfromdisk            = $LHD.BootFromDisk
            bustype                 = $LHD.BusType
            firmwareversion         = $LHD.FirmwareVersion
            friendlyname            = $LHD.FriendlyName
            guid                    = $LHD.Guid
            healthstatus            = $LHD.HealthStatus
            isboot                  = $LHD.IsBoot
            is_clustered            = $LHD.IsClustered
            is_offline              = $LHD.ISsOffline
            is_readonly             = $LHD.IsReadOnly
            is_system               = $LHD.IsSystem
            largest_free_extent     = $LHD.LargestFreeExtent
            location                = $LHD.Location
            logical_sector_size     = $LHD.LogicalSectorSize
            manufacturer            = $LHD.Manufacturer
            model                   = $LHD.Model
            lhd_number              = $LHD.Number
            number_of_partitions    = $LHD.NumberOfPartitions
            objectid                = $LHD.ObjectId
            offline_reason          = $LHD.OfflineReason
            operational_status      = $LHD.OperationalStatus
            partition_style         = $LHD.PartitionStyle
            lhd_path                = $LHD.Path
            physical_sector_size    = $LHD.PhysicalSectorSize
            provisioning_type       = $LHD.ProvisioningType
            serial_number           = $LHD.SerialNumber
            signature               = $LHD.Signature
            lhd_size                = $LHD.Size
            unique_id               = $LHD.UniqueId
            unique_id_format        = $LHD.UniqueIdFormat
            ps_computer_name        = $LHD.PSComputerName
            lun_id                  = $WMIDisk.SCSILogicalUnit 
			storage_used            = $storage_used
        }
    
        # Convert Inventory event hash table to object
        # Dynamically add CdataWrapper based on splunk instance's version
        $VMObject = New-Object -Property (UseCdataWrapper $InventoryEvent) -TypeName PSObject

        # Serializing object to string 
        $VMObject
    }
}
