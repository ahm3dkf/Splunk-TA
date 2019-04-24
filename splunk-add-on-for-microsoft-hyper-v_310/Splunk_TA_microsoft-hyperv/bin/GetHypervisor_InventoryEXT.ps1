. "$PSScriptRoot\utils.ps1"
# Importing Hyper-V Module 
Import-Module Hyper-V

# Get VM Host (Hypervisor)
$VMHost = Get-VMHost 

# Getting data from WMI for Computer 
$HypervisorID = Get-ItemProperty "hklm:\SOFTWARE\Microsoft\Cryptography" | foreach {$_.MachineGuid}


# Creating inventory event hash table
$InventoryEvent = @{

    # Fields from Hyper-V Powershell Module Get-VMHost
    # Type: Microsoft.HyperV.PowerShell.VMHost 
    hypervisor_id                                  = $HypervisorID
    hyp_virtualharddiskpath                        = $VMHost.VirtualHardDiskPath
    hyp_virtualmachinepath                         = $VMHost.VirtualMachinePath
    hyp_fqdn                                       = $VMHost.FullyQualifiedDomainName
    hyp_name                                       = $VMHost.Name
    hyp_macaddressminimum                          = $VMHost.MacAddressMinimum
    hyp_macaddressmaximum                          = $VMHost.MacAddressMaximum
    hyp_maximumstoragemigrations                   = $VMHost.MaximumStorageMigrations
    hyp_maximumvirtualmachinemigrations            = $VMHost.MaximumVirtualMachineMigrations
    hyp_virtualmachinemigrationenabled             = $VMHost.VirtualMachineMigrationEnabled
    hyp_virtualmachinemigrationauthenticationtype  = $VMHost.VirtualMachineMigrationAuthenticationType
    hyp_useanynetworkformigration                  = $VMHost.UseAnyNetworkForMigration
    hyp_fibrechannelwwnn                           = $VMHost.FibreChannelWwnn
    hyp_fibrechannelwwpnmaximum                    = $VMHost.FibreChannelWwpnMaximum
    hyp_fibrechannelwwpnminimum                    = $VMHost.FibreChannelWwpnMinimum
    hyp_logicalprocessorcount                      = $VMHost.LogicalProcessorCount
    hyp_memorycapacity                             = $VMHost.MemoryCapacity
    hyp_resourcemeteringsaveinterval               = $VMHost.ResourceMeteringSaveInterval
    hyp_numaspanningenabled                        = $VMHost.NumaSpanningEnabled     
    hyp_iovsupport                                 = $VMHost.IovSupport
}
    
# Convert Inventory event hash table to object
# Dynamically add CdataWrapper based on splunk instance's version
$VMObject = New-Object -Property (UseCdataWrapper $InventoryEvent) -TypeName PSObject

# Serializing object to string 
$VMObject
