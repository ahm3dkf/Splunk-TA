. "$PSScriptRoot\utils.ps1"
Import-Module Hyper-V

#Enable Resource Metering for VMs
Get-VM | Enable-VMResourceMetering

$VMs = Get-VM

$HypervisorID = Get-ItemProperty "hklm:\SOFTWARE\Microsoft\Cryptography" | foreach {$_.MachineGuid}

foreach ($VM in $VMs)
{
    Try
    {
    #General Information and Inventory Call Outs
        $HardDiskDrives     = $VM | Get-VMHardDiskDrive
        $VirtualNIC         = $VM | Get-VMNetworkAdapter
        $ConstructedNICID   = ($VM.VMName + "_" + $VirtualNIC.Name + "_"  + $VM.VMId + "--" + $VirtualNIC.AdapterId).ToLower()
	$VMMemory           = $VM | Get-VMMemory
        $VirtualDisks       = $HardDiskDrives.Path | Get-VHD -ErrorAction SilentlyContinue

    #All VM's need the have the command Enable-VMResourceMetering
        $VMStats            = Measure-VM $VM -ErrorAction SilentlyContinue
        $VMVHDStats         = $VMStats.HardDiskMetrics
        $VMNetworkStats     = $VMStats.NetworkMeteredTrafficReport
    }
    Catch
    {
        WriteExceptionToLog($_.Exception)
    }
#Network Perfmon Counters

    $NetTotBandwidth = "0"
    $NetBytesRec = "0"
    $NetBytesSent = "0"
    $NetPacketDropIN ="0"
    $NetPacketDropOUT = "0"

    if($VM.VMName -and $VirtualNIC.Name -and $VM.VMId -and $VirtualNIC.AdapterId)
    {
        $VirtualNICPerfMonPaths   = (Get-Counter -ListSet "Hyper-V Virtual Network Adapter").paths

        $NetworkTotalBytesCount    = "\Hyper-V Virtual Network Adapter($ConstructedNICID)\Bytes/sec"
        $NetworkBytesReceived      = "\Hyper-V Virtual Network Adapter($ConstructedNICID)\Bytes received/sec"
        $NetworkBytesSent          = "\Hyper-V Virtual Network Adapter($ConstructedNICID)\Bytes sent/sec"
        $NetworkPacketsDroppedInc  = "\Hyper-V Virtual Network Adapter($ConstructedNICID)\Dropped Packets Incoming/sec"
        $NetworkPacketsDroppedOut  = "\Hyper-V Virtual Network Adapter($ConstructedNICID)\Dropped Packets Outgoing/sec"

        $VirtualNICResults = Get-Counter -Counter $VirtualNICPerfMonPaths

        $NetTotBandwidth  = $VirtualNICResults | %{$_.CounterSamples} | Where-Object {$_.path -like "*$NetworkTotalBytesCount*"} | %{$_.CookedValue}
        $NetBytesRec      = $VirtualNICResults | %{$_.CounterSamples} | Where-Object {$_.path -like "*$NetworkBytesReceived*"} | %{$_.CookedValue}
        $NetBytesSent     = $VirtualNICResults | %{$_.CounterSamples} | Where-Object {$_.path -like "*$NetworkBytesSent*"} | %{$_.CookedValue}
        $NetPacketDropIN  = $VirtualNICResults | %{$_.CounterSamples} | Where-Object {$_.path -like "*$NetworkPacketsDroppedInc*"} | %{$_.CookedValue}
        $NetPacketDropOUT = $VirtualNICResults | %{$_.CounterSamples} | Where-Object {$_.path -like "*$NetworkPacketsDroppedOut*"} | %{$_.CookedValue}
    }

#CPU Perfmon Counters 
    $VirtualCPUPerfMonPaths  = (Get-Counter -ListSet "Hyper-V Hypervisor Virtual Processor").paths
     
    $vm_id_counter = $VM.VMName 
    $VirtualCPUGuestRunTimeCounter 	     = "\Hyper-V Hypervisor Virtual Processor($vm_id_counter*)\% guest run time"
    $VirtualCPUHyperVisorRunTimeCounter      = "\Hyper-V Hypervisor Virtual Processor($vm_id_counter*)\% hypervisor run time"
    $VirtualCPUTotalRunTime		     = "\Hyper-V Hypervisor Virtual Processor($vm_id_counter*)\% total run time"
    
    $VirtualCPUResults = Get-Counter -Counter $VirtualCPUPerfMonPaths

    $VCPUGuestRun = $VirtualCPUResults | %{$_.CounterSamples} | Where-Object {$_.path -like "*$VirtualCPUGuestRunTimeCounter*"} | %{$_.CookedValue}
    $VCPUHostRun  = $VirtualCPUResults | %{$_.CounterSamples} | Where-Object {$_.path -like "*$VirtualCPUHyperVisorRunTimeCounter*"} | %{$_.CookedValue}
    $VCPUTotalRun = $VirtualCPUResults | %{$_.CounterSamples} | Where-Object {$_.path -like "*$VirtualCPUTotalRunTime*"} | %{$_.CookedValue}

    #Set default values
    $VHDDReadOps = 0
    $VHDDWriteOps = 0
    $VHDDHighestOps = 0

#Storage Device Counters
    if($VirtualDisks.Path)
    {
    	$VirtualHDDPerfMonPaths = (Get-Counter -ListSet "Hyper-V Virtual Storage Device").paths
   
    	$hdd_path = $VirtualDisks.Path.Replace('\','-')
    	$VirtualHDDReadOpsCounter		    = "\Hyper-V Virtual Storage Device($hdd_path)\read operations/sec"
    	$VirtualHDDWriteOpsCounter          = "\Hyper-V Virtual Storage Device($hdd_path)\write operations/sec"

    	$VirtualHDDResults = Get-Counter -Counter $VirtualHDDPerfMonPaths

    	$VHDDReadOps  = $VirtualHDDResults | %{$_.CounterSamples} | Where-Object {$_.path -like "*$VirtualHDDReadOpsCounter*"} | %{$_.CookedValue}
    	$VHDDWriteOps = $VirtualHDDResults | %{$_.CounterSamples} | Where-Object {$_.path -like "*$VirtualHDDWriteOpsCounter*"} | %{$_.CookedValue}

    	if ($VHDDReadOps -gt $VHDDWriteOps) {$VHDDHighestOps = $VHDDReadOps} else {$VHDDHighestOps = $VHDDWriteOps}

    }
#Calculated Dynamic Memory Values
    if($VMMemory.DynamicMemoryEnabled -eq $false){$mem_provisioned=0} else {$mem_provisioned=$VMMemory.Maximum - $VMMemory.Startup}

#Calculated Disk Usage
    if($VirtualDisks.Path -ne $null) {$storage_used =($VirtualDisks.FileSize/$VirtualDisks.Size)*100 } else {$storage_used=0}

    #Creating Perfmon Event Hash Table
    $PerfmonEvent = @{
        hypervisor_id           = $HypervisorID
        hypervisor              = $VM.ComputerName
        vm_name                 = $VM.VMName
        vm_id                   = $VM.VMId
        memory_assigned         = $VM.MemoryAssigned/1mb
        mem_provisioned         = $mem_provisioned
        average_cpu             = $VMStats.AvgCPU
        average_ram             = $VMStats.AvgRAM
        minumum_ram             = $VMStats.MinRAM
        maximum_ram             = $VMStats.MaxRAM
        total_disk              = $VMStats.TotalDisk
        average_proc_usage      = $VMStats.AverageProcessorUsage
        average_mem_usage       = $VMStats.AverageMemoryUsage
        maximum_mem_usage       = $VMStats.MaximumMemoryUsage
        minimum_mem_usage       = $VMStats.MinimumMemoryUsage
        total_disk_alloc        = $VMStats.TotalDiskAllocation
        agg_avg_normalisedIOPS  = $VMStats.AggregatedAverageNormalizedIOPS
        agg_average_latency     = $VMStats.AggregatedAverageLatency
        agg_disk_data_read      = $VMStats.AggregatedDiskDataRead
        agg_disk_data_written   = $VMStats.AggregatedDiskDataWritten
        average_normalized_IOPS = $VMVHDStats.AverageNormalizedIOPS
        average_latency         = $VMVHDStats.AverageLatency
        data_read               = $VMVHDStats.DataRead
        data_written            = $VMVHDStats.DataWritten
        network_total_bandwidth = $NetTotBandwidth
        network_bytes_received  = $NetBytesRec
        network_bytes_sent      = $NetBytesSent
        packets_dropped_in      = $NetPacketDropIN
        packets_dropped_out     = $NetPacketDropOUT
	guest_cpu_load_percent  = $VCPUGuestRun -join ', '
	host_cpu_load_percent   = $VCPUHostRun -join ', '
	cpu_load_percent        = $VCPUTotalRun -join ', '
	storage_used            = $storage_used
	storage_usage           = $VirtualDisks.FileSize
    	mem_reserved            = $VMMemory.Maximum
        read_latency            = $VHDDReadOps
	write_latency           = $VHDDWriteOps
	highest_latency         = $VHDDHighestOps
    }

    #Fix for ADDON-10462 - protection against Cmdlet returning null values for VMs
    if($VM.VMId -and $VM.VMName)
    {
       # Convert PerfmonEvent hash table to object
       # Dynamically add CdataWrapper based on splunk instance's version
       $VMPerfObject = New-Object -Property (UseCdataWrapper $PerfmonEvent) -TypeName PSObject

       #serialze object to Sting
       $VMPerfObject
   }
}
