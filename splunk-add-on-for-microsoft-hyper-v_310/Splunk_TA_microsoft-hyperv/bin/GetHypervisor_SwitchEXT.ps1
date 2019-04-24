. "$PSScriptRoot\utils.ps1"
# Importing Hyper-V Module 
Import-Module Hyper-V

# Get VM Host (Hypervisor)
$VMHost = Get-VMHost

#Get ComputerIformation
$HypervisorID = Get-ItemProperty "hklm:\SOFTWARE\Microsoft\Cryptography" | foreach {$_.MachineGuid}

# Getting Virtual Switches 
$Switches = Get-VMSwitch

# Process each Switch
foreach($Switch in $Switches)
{
    # Creating inventory event hash table
    $InventoryEvent = @{

        # Fields from Hyper-V Powershell Module Get-VMSwitch
        # Type: Microsoft.HyperV.PowerShell.VMSwitch
        hypervisor                            = $VMHost.Name          # alias to dest for Compute Inventory CIM
    	hypervisor_id                         = $HypervisorID
	computername                          = $Switch.ComputerName
        name                                  = $Switch.Name
        id                                    = $Switch.Id
        notes                                 = $Switch.Notes
        switchtype                            = $Switch.SwitchType
        allowmanagementos                     = $Switch.AllowManagementOS
        netadapterinterfacedescription        = $Switch.NetAdapterInterfaceDescription
        availablevmqueues                     = $Switch.AvailableVMQueues
        numbervmqallocated                    = $Switch.NumberVmqAllocated
        iovenabled                            = $Switch.IovEnabled
        iovvirtualfunctioncount               = $Switch.IovVirtualFunctionCount
        iovvirtualfunctionsinuse              = $Switch.IovVirtualFunctionsInUse
        iovqueuepaircount                     = $Switch.IovQueuePairCount
        iovqueuepairsinuse                    = $Switch.IovQueuePairsInUse
        availableipsecsa                      = $Switch.AvailableIPSecSA
        numberipsecsaallocated                = $Switch.NumberIPSecSAAllocated
        bandwidthpercentage                   = $Switch.BandwidthPercentage
        bandwidthreservationmode              = $Switch.BandwidthReservationMode
        defaultflowminimumbandwidthabsolute   = $Switch.DefaultFlowMinimumBandwidthAbsolute
        defaultflowminimumbandwidthweight     = $Switch.DefaultFlowMinimumBandwidthWeight
        extensions                            = ($Switch.Extensions | %{$_.Name}) -join " ; "
        iovsupport                            = $Switch.IovSupport
        isdeleted                             = $Switch.IsDeleted
    }
    # Convert Inventory event hash table to object
    # Dynamically add CdataWrapper based on splunk instance's version
    $VMObject = New-Object -Property (UseCdataWrapper $InventoryEvent) -TypeName PSObject

    # Serializing object to string 
    $VMObject
} 
