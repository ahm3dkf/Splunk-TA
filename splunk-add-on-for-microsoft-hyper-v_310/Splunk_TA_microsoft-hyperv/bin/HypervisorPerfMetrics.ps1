. "$PSScriptRoot\utils.ps1"
# Get VM Host (Hypervisor)
$VMHost = Get-VMHost

# Getting data from WMI for Computer, OS, and CPU 
$OSInfo   = get-WmiObject Win32_OperatingSystem
$HypervisorID = Get-ItemProperty "hklm:\SOFTWARE\Microsoft\Cryptography" | foreach {$_.MachineGuid}

#CPU Perfmon Counters
$LogicalCPUPerfMonPaths  = (Get-Counter -ListSet "Hyper-V Hypervisor Logical Processor").paths

$LogicalCPUGuestRunTimeCounter 	     = "\Hyper-V Hypervisor Logical Processor(_Total)\% guest run time"
$LogicalCPUHyperVisorRunTimeCounter  = "\Hyper-V Hypervisor Logical Processor(_Total)\% hypervisor run time"
$LogicalCPUTotalRunTime		         = "\Hyper-V Hypervisor Logical Processor(_Total)\% total run time"

$LogicalCPUResults = Get-Counter -Counter $LogicalCPUPerfMonPaths

$LCPUGuestRun = $LogicalCPUResults | %{$_.CounterSamples} | Where-Object {$_.path -like "*$LogicalCPUGuestRunTimeCounter*"}  | %{$_.CookedValue}
$LCPUHostRun  = $LogicalCPUResults | %{$_.CounterSamples} | Where-Object {$_.path -like "*$LogicalCPUHyperVisorRunTimeCounter*"}  | %{$_.CookedValue}
$LCPUTotalRun = $LogicalCPUResults | %{$_.CounterSamples} | Where-Object {$_.path -like "*$LogicalCPUTotalRunTime*"} | %{$_.CookedValue}

#Memory Perfmon Counters
$MemoryPerfMonPaths  = (Get-Counter -ListSet "Memory").paths

$MemoryCommittedBytesCounter    = "\Memory\% committed bytes in use"
$MemoryPageRateCounter          = "\Memory\pages/sec"

$MemoryResults = Get-Counter -Counter $MemoryPerfMonPaths

$MemoryCommittedBytes   = $MemoryResults | %{$_.CounterSamples} | Where-Object {$_.path -like "*$MemoryCommittedBytesCounter*"} | %{$_.CookedValue}
$MemoryPageRate         = $MemoryResults | %{$_.CounterSamples} | Where-Object {$_.path -like "*$MemoryPageRateCounter*"} | %{$_.CookedValue}


#Memory Provisoned Calculation
$VMs = Get-VM
$MemTotal = 0

foreach ($VM in $VMs)
{
    $MemVM = $VM.MemoryAssigned
    $MemTotal += $MemVM
}

#Network Usage Calculation
$NetworkBytesTotalStats     = Get-Counter -Counter "\Network Interface(*)\Bytes Total/sec"
$NetworkBytesReceivedStats  = Get-Counter -Counter "\Network Interface(*)\Bytes Received/sec"
$NetworkBytesSentStats      = Get-Counter -Counter "\Network Interface(*)\Bytes Sent/sec"

$NetworkBytesTotal  = 0
$NetworkBytesIn     = 0
$NetworkBytesOut    = 0

for ($i=0; $i -lt $NetworkBytesTotalStats.CounterSamples.Length; $i++)
{
    $NetworkUsageSample = $NetworkBytesTotalStats.CounterSamples[$i].CookedValue
    $NetworkBytesTotal += $NetworkUsageSample
}

for ($i=0; $i -lt $NetworkBytesReceivedStats.CounterSamples.Length; $i++)
{
    $NetworkUsageINSample = $NetworkBytesReceivedStats.CounterSamples[$i].CookedValue
    $NetworkBytesIn += $NetworkUsageINSample
}

for ($i=0; $i -lt $NetworkBytesSentStats.CounterSamples.Length; $i++)
{
    $NetworkUsageOutSample = $NetworkBytesSentStats.CounterSamples[$i].CookedValue
    $NetworkBytesOut += $NetworkUsageOutSample
}

#Network Errors Calculation
$NetworkBytesInDroppedStats  = Get-Counter -Counter "\Network Interface(*)\Packets Received Discarded"
$NetworkBytesOutDroppedStats = Get-Counter -Counter "\Network Interface(*)\Packets Outbound Discarded"

$NetworkBytesInDropped = 0
$NetworkBytesOutDropped = 0

for($i=0; $i -lt $NetworkBytesInDroppedStats.CounterSamples.Length; $i++)
{
    $NetworkBytesDropedSample = $NetworkBytesInDroppedStats[$i].CookedValue
    $NetworkBytesInDropped += $NetworkBytesDropedSample
}


for($i=0; $i -lt $NetworkBytesOutDroppedStats.CounterSamples.Length; $i++)
{
    $NetworkBytesDropedSample = $NetworkBytesOutDroppedStats[$i].CookedValue
    $NetworkBytesOutDropped += $NetworkBytesDropedSample
}

#Disk Usage Metrics
#$DiskBytesPerSecStats   = Get-Counter -Counter "\PhysicalDisk(_total)\Disk Bytes/sec"
#$DiskBytesPerSec = $DiskBytesPerSecStats.CounterSamples.CookedValue


#Disk Latency Metrics
$ReadLatencyStats     = Get-Counter -Counter "\PhysicalDisk(*)\Avg. Disk sec/Read"
$WriteLatencyStats    = Get-Counter -Counter "\PhysicalDisk(*)\Avg. Disk sec/Write"

$ReadLatency 		= 0 
$WriteLatency 		= 0
$HighestReadLatency 	= 0
$HighestWriteLatency 	= 0
$ReadLatencyCount    = 0

for ($i=0; $i -lt $ReadLatencyStats.CounterSamples.Length; $i++)
{
    if($ReadLatencyStats.CounterSamples[$i].path -notlike "*_total*")
    {	
		$ReadLatencyCookedValue = $ReadLatencyStats.CounterSamples[$i].CookedValue
	
		# Calculating number of samples with value not equal to 0
        if($ReadLatencyCookedValue -ne 0)
        {
            $ReadLatencyCount += 1
        }
		
        $ReadLatency += $ReadLatencyCookedValue
        if( $ReadLatencyCookedValue -gt $HighestReadLatency) 
        {
	        $HighestReadLatency = $ReadLatencyCookedValue
        }
    }
}

# To prevent division by 0 when calculating ReadLatency below
if($ReadLatencyCount -eq 0)
{
    $ReadLatencyCount = 1
}

for ($i=0; $i -lt $WriteLatencyStats.CounterSamples.Length; $i++)
{
    if($WriteLatencyStats.CounterSamples[$i].path -notlike "*_total*")
    {
        $WriteLatency += $WriteLatencyStats.CounterSamples[$i].CookedValue
	if( $WriteLatencyStats.CounterSamples[$i].CookedValue -gt $HighestWriteLatency)
        {
            $HighestWriteLatency = $WriteLatencyStats.CounterSamples[$i].CookedValue
        }
    }
}

#Highest Latency Calculation
if ($HighestReadLatency -gt $HighestWriteLatency) {$HighestLatency = $HighestReadLatency} else {$HighestLatency = $HighestWriteLatency}

Start-Sleep -s 10

$PerformanceEvent = @{

    # All_Inventory
    hypervisor                  = $VMHost.Name
    hypervisor_id               = $HypervisorID
    cpu_load_percent            = $LCPUTotalRun
    cpu_host_runtime            = $LCPUHostRun
    cpu_allocation_percent      = $LCPUGuestRun
    mem_usage_percent           = $MemoryCommittedBytes
    mem_page_rate               = $MemoryPageRate
    mem_provisioned             = $MemTotal
    network_usage               = $NetworkBytesTotal
    network_usage_in            = $NetworkBytesIn
    network_usage_out           = $NetworkBytesOut
    highest_latency             = $HighestLatency
    packets_dropped_out         = $NetworkBytesOutDropped
    packets_dropped_in          = $NetworkBytesInDropped
    read_latency                = $ReadLatency/$ReadLatencyCount
    write_latency               = $WriteLatency/($WriteLatencyStats.CounterSamples.Length -1)
#   storage_usage               = $DiskBytesPerSec
}

# Convert Inventory event hash table to object
# Dynamically add CdataWrapper based on splunk instance's version
$PerfHostObject = New-Object -Property (UseCdataWrapper $PerformanceEvent) -TypeName PSObject

# Serializing object to string
$PerfHostObject
