. "$PSScriptRoot\utils.ps1"
# Importing Hyper-V Module 
Import-Module Hyper-V

# Getting VMs 
$VMs = Get-VM

# Process each VM
foreach($VM in $VMs)
{
    try
    {
    # Getting Network adapater(s) for VM
        $Adapaters = $VM | Get-VMNetworkAdapter
    }
    catch
    {
        WriteExceptionToLog($_.Exception)
    }
    
    foreach($NIC in $Adapaters)
    {
        # Creating inventory event hash table
        $InventoryEvent = @{
            # Fields from Hyper-V Powershell Module Get-VMNetworkAdapter
            # Type: Microsoft.HyperV.PowerShell.VMNetworkAdapter

            iovweight                 = $NIC.IovWeight
            iovqueuepairsrequested    = $NIC.IovQueuePairsAssigned
            iovqueuepairsassigned     = $NIC.IovQueuePairsAssigned
            iovinterruptmoderation    = $NIC.IovInterruptModeration
            iovusage                  = $NIC.IovUsage
            virtualfunction           = $NIC.VirtualFunction
            islegacy                  = $NIC.IsLegacy
            ismanagementos            = $NIC.IsManagementOs
            isexternaladapter         = $NIC.IsExternalAdapter
            id                        = $NIC.Id
            adapterid                 = $NIC.AdapterId
            dynamicmacaddressenabled  = $NIC.DynamicMacAddressEnabled
            macaddress                = $NIC.MacAddress
            macaddressspoofing        = $NIC.MacAddressSpoofing
            switchid                  = $NIC.SwitchId
            connected                 = $NIC.Connected
            poolname                  = $NIC.PoolName
            switchname                = $NIC.SwitchName
            dhcpguard                 = $NIC.DhcpGuard
            routerguard               = $NIC.RouterGuard
            portmirroringmode         = $NIC.PortMirroringMode
            ieeeprioritytag           = $NIC.IeeePriorityTag
            virtualsubnetid           = $NIC.VirtualSubnetId
            allowteaming              = $NIC.AllowTeaming
            vmqweight                 = $NIC.VMQWeight
            ipsecoffloadmaxsa         = $NIC.IPsecOffloadMaxSA
            vmqusage                  = $NIC.VmqUsage
            ipsecoffloadsausage       = $NIC.IPsecOffloadSAUsage
            vfdatapathactive          = $NIC.VFDataPathActive
            vmqueue                   = $NIC.VMQueue
            mandatoryfeatureid        = $NIC.MandatoryFeatureId | Out-String
            mandatoryfeaturename      = $NIC.MandatoryFeatureName | Out-String
            vlansetting               = $NIC.VlanSetting.OperationMode.ToString()
            bandwidthsetting          = $NIC.BandwidthSetting
            bandwidthpercentage       = $NIC.BandwidthPercentage
            testreplicapoolname       = $NIC.TestReplicaPoolName
            testreplicaswitchname     = $NIC.TestReplicaSwitchName
            statusdescription         = $NIC.StatusDescription | Out-String
            status                    = $NIC.Status | Out-String
            ipaddresses               = $NIC.IPAddresses -join " ; "
            computername              = $NIC.ComputerName
            name                      = $NIC.Name
            isdeleted                 = $NIC.IsDeleted
            vm_id                     = $NIC.VMId
            vm_name                   = $NIC.VMName
            vmsnapshotid              = $NIC.VMSnapshotId
            vmsnapshotname            = $NIC.VMSnapshotName
	}
        # Convert Inventory event hash table to object
        # Dynamically add CdataWrapper based on splunk instance's version
        $VMObject = New-Object -Property (UseCdataWrapper $InventoryEvent) -TypeName PSObject

        # Serializing object to string 
        $VMObject
    }
}
