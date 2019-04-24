. "$PSScriptRoot\utils.ps1"
# Importing Hyper-V Module 
Import-Module Hyper-V

function Get-IP
{
    [Cmdletbinding()]
    Param(
        [alias('dnsHostName')]
        [Parameter(ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$true)]
        [string]$ComputerName = $Env:COMPUTERNAME
    )
    Process
    {
        $NICs = Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "IPEnabled='$True'" -ComputerName $ComputerName
        foreach($Nic in $NICs)
        {
            $myobj = @{
                dest          = $ComputerName
                Name          = $Nic.Description
                MacAddress    = $Nic.MACAddress
                IP4           = $Nic.IPAddress | where{$_ -match "\d+\.\d+\.\d+\.\d+"}
                IP6           = $Nic.IPAddress | where{$_ -match "\:\:"}
                IP4Subnet     = $Nic.IPSubnet  | where{$_ -match "\d+\.\d+\.\d+\.\d+"}
				IP6Subnet     = $Nic.IPSubnet  | where{$_ -notmatch "\d+\.\d+\.\d+\.\d+"}
                DefaultGWY    = $Nic.DefaultIPGateway | Select -First 1
                DNSServer     = $Nic.DNSServerSearchOrder
                WINSPrimary   = $Nic.WINSPrimaryServer
                WINSSecondary = $Nic.WINSSecondaryServer
            }
			
            $obj = New-Object PSObject -Property $myobj
            $obj.PSTypeNames.Clear()
            $obj.PSTypeNames.Add('BSonPosh.IPInfo')
            $obj
        }
    }
}

# Get VM Host (Hypervisor)
$VMHost = Get-VMHost 

# Getting data from WMI for Computer, OS, and CPU 
$CompInfo = get-WmiObject Win32_computersystem 
$OSInfo   = get-WmiObject Win32_OperatingSystem 
$CPUInfo  = get-WmiObject Win32_processor | select -First 1
$HypervisorID = Get-ItemProperty "hklm:\SOFTWARE\Microsoft\Cryptography" | foreach {$_.MachineGuid}

# Creating empty arrays
$IPs        = @()
$DNS        = @()
$Interfaces = @()
$MACs       = @()

# Creating Description Field
$Description = "{0} ({1}) - MAC Address Range: {2}-{3}" -f $VMHost.Name,$OSInfo.Version,$VMHost.MacAddressMinimum,$VMHost.MacAddressMaximum  

# Getting NIC info and populating IP, DNS, Interface, and MAC
foreach($NIC in Get-IP)
{
    $IPs += $NIC.IP4
    foreach($entry in $NIC.DNSServer)
    {
        if($DNS -notcontains $entry)
        {
            $DNS += $entry
        }
    }
    $Interfaces += $NIC.Name
    $MACs += $NIC.MacAddress
}

#Getting HyperThreading field
if($CompInfo.NumberOfLogicalProcessors -gt $CompInfo.NumberOfProcessors)
{
    $hyperthreading = "true"
}
else
{
    $hyperthreading = "false"
}

#Get List of NetAdapters
$NetAdap = Get-NetAdapter | foreach {$_.InterfaceDescription}

#Test if Clustered Environment Set values appropriately
if(Get-Command Get-Cluster -ErrorAction SilentlyContinue)
{
    $domain		= Get-Cluster | % {$_.Domain}
    $cluster_name 	= Get-Cluster | % {$_.Name}
    $cluster_id   	= Get-Cluster | % {$_.Id}
}
else
{
    $domain		= $VMHost.FullyQualifiedDomainName
    $cluster_name	= "Non Clustered"
    $cluster_id	    	= ""
}

# Creating inventory event hash table
$InventoryEvent = @{
    # Splunk Compute Inventory CIM Fields
        
    # All_Inventory
    description             = $Description          # alias to hyp_desc for ServerVirt App
    hypervisor              = $VMHost.Name          # alias to dest for Compute Inventory CIM
    hypervisor_id           = $HypervisorID
    product                 = "Hyper-V"
    product_version         = $OSInfo.BuildNumber
    status                  = "online"
    vendor                  = "Microsoft"
    version                 = $OSInfo.Version
    
    # Cluster
    domain                  = $domain
    cluster_id              = $cluster_id
    cluster_name            = $cluster_name

    # cpu
    cpu_count               = $CompInfo.NumberOfProcessors
    cpu_cores               = $CompInfo.NumberOfLogicalProcessors
    cpu_model               = $CPUInfo.Description
    cpu_mhz                 = $CPUInfo.MaxClockSpeed
    cpu_vendor              = $CPUInfo.Manufacturer
    cpu_family              = $CPUInfo.Family
    resource_type           = "physical"
    hyperthreading          = $hyperthreading
    
    # Memory
    mem                     = $CompInfo.TotalPhysicalMemory/1mb
        
    # Network
    dns                     = $DNS -join " ; "
    interface               = $Interfaces -join " ; "
    ip                      = $IPs -join " ; "
    mac                     = $MACs -join " ; "
    nic_count               = @(Get-NetAdapter).count
    nic_type                = $NetAdap -join " ; "
    # OS
    os                      = $OSInfo.Caption
}
    
# Convert Inventory event hash table to object
# Dynamically add CdataWrapper based on splunk instance's version
$VMObject = New-Object -Property (UseCdataWrapper $InventoryEvent) -TypeName PSObject

# Serializing object to string 
$VMObject
