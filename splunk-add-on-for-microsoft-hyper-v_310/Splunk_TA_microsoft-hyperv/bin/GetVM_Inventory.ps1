. "$PSScriptRoot\utils.ps1"
# Importing Hyper-V Module 
Import-Module Hyper-V

function Get-VMKVP($VM)
{
    # Creating HASH Table for object creation
    $MyObj = @{}
    $GUID = $VM.Id
    try
    {
        # Getting VM Details
        $Kvp = Get-WmiObject -Namespace Root\Virtualization\V2 -Query "Select * From Msvm_KvpExchangeComponent Where SystemName='$GUID'"

        # Converting XML to Object
        foreach($CimXml in $Kvp.GuestIntrinsicExchangeItems)
        {
            $XML = [XML]$CimXml
            if($XML)
            {
                foreach ($CimProperty in $XML.SelectNodes("/INSTANCE/PROPERTY"))
                {
                    switch -exact ($CimProperty.Name)
                    {
                        "Data"      { $Value = $CimProperty.VALUE }
                        "Name"      { $Name  = $CimProperty.VALUE }
                    }
                }
                $MyObj.add($Name,$Value)
            }
        }
        # Outputting Object
        New-Object -TypeName PSCustomObject -Property $MyObj -ea 0
    }
    catch
    {
        $MyObj.add("empty","unknown")
        New-Object -TypeName PSCustomObject -Property $MyObj -ea 0
    }
}


$HypervisorID = Get-ItemProperty "hklm:\SOFTWARE\Microsoft\Cryptography" | foreach {$_.MachineGuid}

# Getting VMs 
$VMs = Get-VM

# Process each VM

foreach($VM in $VMs)
{
    # Get KVP data (hyperv agent) and store in varable. 
    $KVP = Get-VMKVP $VM

    # Extracting Network Adapters to process later
    $NetworkAdapaters = $VM.NetworkAdapters

    # Extracting Snapshots to process later
    $Snapshots = $VM | Get-VMSnapshot

    #Test if Clustered Environment Set values approapriatly
    if(Get-Command Get-Cluster -ErrorAction SilentlyContinue)
    {  
       #$domain            = Get-Cluster | % {$_.Domain}
       $cluster_name       = Get-Cluster | % {$_.Name}
       $cluster_id         = Get-Cluster | % {$_.Id}
    }
    else
    {
       #$domain            = $VMHost.FullyQualifiedDomainName
       $cluster_name       = "Non Clustered"
       $cluster_id         = ""
    }
    
    # Creating inventory event hash table
    $InventoryEvent = @{

        # Splunk Compute Inventory CIM Fields
        
        # All_Inventory
        vm_id			= $VM.VMId
	description             = $VM.VMName
        hypervisor              = $VM.ComputerName                 # alias to dest for Compute Inventory CIM
        hypervisor_id           = $HypervisorID
        status                  = $VM.Status
        vendor                  = "Microsoft"
        hypervisor_os_version   = $VM.Version
        os_version              = $KVP.OSVersion
        os                      = $KVP.OSName                      # alias to product for Compute Inventory CIM
        osbuildnumber           = $KVP.OSBuildNumber               # alias to product_version for Compute Inventory CIM
        # cpu
        cpu_count               = $VM.ProcessorCount
        resource_type           = "virtual"

        # Memory
        mem                     = $VM.MemoryAssigned/1mb
        
        # Network
        ip                      = ($NetworkAdapaters | %{$_.IPAddresses -join " , "}) -join ","
        interface               = ($NetworkAdapaters | %{$_.SwitchName -join " , "}) -join ","
        mac                     = ($NetworkAdapaters | %{$_.MacAddress -join " ,"}) -join ","
        
        # Snapshot ( only last one )
        size                    = if($Snapshots){$Snapshots | select -Last 1 | %{$_.SizeOfSystemFiles}} else {"none"}
        snapshot                = if($Snapshots){$Snapshots | select -Last 1 | %{$_.Name}} else {"none"}
        time                    = if($Snapshots){$Snapshots | select -Last 1 | %{$_.CreationTime.ToString("MM/dd/yy H:mm:ss zzz")}} else {"none"}
        #cluster values
        cluster_id              = $cluster_id
        cluster_name            = $cluster_name
        # non CIM 
        vm_fqdn                 = $KVP.FullyQualifiedDomainName 
    }
    
    #Fix for ADDON-10462 - protection against Cmdlet returning null values for VMs
    if($VM.VMId -and $VM.VMName)
    {
        # Convert Inventory event hash table to object
        # Dynamically add CdataWrapper based on splunk instance's version
        $VMObject = New-Object -Property (UseCdataWrapper $InventoryEvent) -TypeName PSObject

    	# Serializing object to string 
    	$VMObject
    }
}
