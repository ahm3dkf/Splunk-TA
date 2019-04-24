. "$PSScriptRoot\utils.ps1"
# Importing Hyper-V Module 
Import-Module Hyper-V

# Getting VMs 
$VMs = Get-VM

# Process each VM
foreach($VM in $VMs)
{
    # Creating inventory event hash table
	$InventoryEvent = @{

        # Fields from Hyper-V Powershell Module Get-VM
        # Type: Microsoft.HyperV.PowerShell.VirtualMachine
	       vm_vmid	 	               = $VM.VMId
	       vm_name  		           = $VM.VMName
           vm_state                    = $VM.State
           vm_heartbeat                = $VM.Heartbeat
           vm_replicationstate         = $VM.ReplicationState
           vm_replicationhealth        = $VM.ReplicationHealth
           vm_replicationmode          = $VM.ReplicationMode
           vm_cpuusage                 = $VM.CPUUsage
           vm_memoryassigned           = $VM.MemoryAssigned
           vm_memorydemand             = $VM.MemoryDemand
           vm_memorystatus             = $VM.MemoryStatus
           vm_memorystartup            = $VM.MemoryStartup
           vm_dynamicmemoryenabled     = $VM.DynamicMemoryEnabled
           vm_memoryminimum            = $VM.MemoryMinimum
           vm_memorymaximum            = $VM.MemoryMaximum    
           vm_smartpagingfileinuse     = $VM.SmartPagingFileInUse
           vm_resourcemeteringenabled  = $VM.ResourceMeteringEnabled
           vm_configurationlocation    = $VM.ConfigurationLocation
           vm_snapshotfilelocation     = $VM.SnapshotFileLocation
           vm_smartpagingfilepath      = $VM.SmartPagingFilePath
           vm_automaticstartaction     = $VM.AutomaticStartAction
           vm_automaticstopaction      = $VM.AutomaticStopAction
           vm_automaticstartdelay      = $VM.AutomaticStartDelay
           vm_numaaligned              = $VM.NumaAligned
           vm_numanodescount           = $VM.NumaNodesCount
           vm_numasocketcount          = $VM.NumaSocketCount
           vm_isdeleted                = $VM.IsDeleted
           vm_isclustered              = $VM.IsClustered
           vm_notes                    = $VM.Notes
           vm_path                     = $VM.Path
           vm_sizeofsystemfiles        = $VM.SizeOfSystemFiles
           vm_parentsnapshotid         = $VM.ParentSnapshotId
           vm_parentsnapshotname       = $VM.ParentSnapshotName
           vm_uptime                   = $VM.Uptime | foreach { $_.TotalSeconds }
	       vm_installdate	           = $VM.CreationTime.ToString("MM/dd/yy H:mm:ss zzz")
	       vm_toolstack_version	       = $VM.IntegrationServicesVersion
	}

    #Fix for ADDON-10462
	if($VM.VMId -and $VM.VMName)
    {
        # Convert Inventory event hash table to object
        # Dynamically add CdataWrapper based on splunk instance's version
        $VMObject = New-Object -Property (UseCdataWrapper $InventoryEvent) -TypeName PSObject   

        # Serializing object to string 
	    $VMObject
	}
}

	
