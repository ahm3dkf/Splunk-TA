. "$PSScriptRoot\utils.ps1"
Import-Module Hyper-V

$VMs = Get-VM
$HypervisorID = Get-ItemProperty "hklm:\SOFTWARE\Microsoft\Cryptography" | foreach {$_.MachineGuid}

foreach ($VM in $VMs)
{
    $HardDiskDrives = $VM | Get-VMHardDiskDrive
    $CompInfomation = Get-WmiObject Win32_ComputerSystem

    foreach($HD in $HardDiskDrives)
    {
        if(!$HD.disknumber -and $HD.Path) {
            $VHD = $HD | Get-VHD
            $path = $VHD.Path.Replace('\','-')
	    $DriveLetter = $path.Substring(0,2)
    
            #Storage Perfmon Counters
	    $VirtualStoragePerfMonPaths   = (Get-Counter -ListSet "Hyper-V Virtual Storage Device").paths

	    $QueueLengthCounter 	  = "\Hyper-V Virtual Storage Device($path)\Queue Length"
            $WriteOpsCounter		  = "\Hyper-V Virtual Storage Device($path)\Write Operations/sec"
            $ReadOpsCounter		  = "\Hyper-V Virtual Storage Device($path)\Read Operations/sec"
            $WriteBytesCounter		  = "\Hyper-V Virtual Storage Device($path)\Write Bytes/sec"
            $ReadBytesCounter		  = "\Hyper-V Virtual Storage Device($path)\Read Bytes/sec" 
            
	    $state = $VHD.Attached

            if($state -eq 'True') {
                #Call Outs to Perfmon and capture of Virtual Storage Device Metrics
                $VirtualStorageResults    = Get-Counter -Counter $VirtualStoragePerfMonPaths

                $queueLength    = $VirtualStorageResults | %{$_.CounterSamples} | Where-Object {$_.path -like "*$QueueLengthCounter*"} | %{$_.CookedValue}
                $writeops       = $VirtualStorageResults | %{$_.CounterSamples} | Where-Object {$_.path -like "*$WriteOpsCounter*"} | %{$_.CookedValue}
                $readops        = $VirtualStorageResults | %{$_.CounterSamples} | Where-Object {$_.path -like "*$ReadOpsCounter*"} | %{$_.CookedValue}
                $writebytes     = $VirtualStorageResults | %{$_.CounterSamples} | Where-Object {$_.path -like "*$WriteBytesCounter*"} | %{$_.CookedValue}
                $readbytes      = $VirtualStorageResults | %{$_.CounterSamples} | Where-Object {$_.path -like "*$ReadBytesCounter*"} | %{$_.CookedValue}

                
                #Disk Latency Metrics
                $ReadLatencyStats     = Get-Counter -Counter "\PhysicalDisk(*)\Avg. Disk sec/Read"
                $WriteLatencyStats    = Get-Counter -Counter "\PhysicalDisk(*)\Avg. Disk sec/Write"

                $ReadLatency                = 0
                $WriteLatency               = 0
                $HighestReadLatency         = 0
                $HighestWriteLatency        = 0
                $DriveReadLatency           = 0
                $DriveWriteLatency          = 0

                for ($i=0; $i -lt $ReadLatencyStats.CounterSamples.Length; $i++)
                {
                    if($ReadLatencyStats.CounterSamples[$i].path -like "*$DriveLetter)avg. disk sec/read")
                    {
                        $DriveReadLatency = $ReadLatencyStats.CounterSamples[$i].CookedValue
                    }

                    if($WriteLatencyStats.CounterSamples[$i].path -like "*$DriveLetter)avg. disk sec/write")
                    {
                        $DriveWriteLatency = $WriteLatencyStats.CounterSamples[$i].CookedValue
                    }

                    if($ReadLatencyStats.CounterSamples[$i].path -notlike "*_total*")
                    {
                        $ReadLatency += $ReadLatencyStats.CounterSamples[$i].CookedValue
                        if( $ReadLatencyStats.CounterSamples[$i].CookedValue -gt $HighestReadLatency)
                        {
                            $HighestReadLatency = $ReadLatencyStats.CounterSamples[$i].CookedValue
                        }
                    }

                    if($WriteLatencyStats.CounterSamples[$i].path -notlike "*_total*")
                    {
                        $WriteLatency += $WriteLatencyStats.CounterSamples[$i].CookedValue
                        if( $ReadLatencyStats.CounterSamples[$i].CookedValue -gt $HighestReadLatency)
                        {
                            $HighestWriteLatency = $WriteLatencyStats.CounterSamples[$i].CookedValue
                        }
                    }
                }

                #Highest Latency Calculation
                if ($HighestReadLatency -gt $HighestWriteLatency) {$HighestLatency = $HighestReadLatency} else {$HighestLatency = $HighestWriteLatency}

                #Creating Perfmon Event Hash Table
		$PerfmonEvent = @{
                    hypervisor_id = $HypervisorID
                    hypervisor = $VHD.ComputerName
                    datastore_id = $VHD.DiskIdentifier
                    vm_name = $HD.VMName
                    vm_id = $HD.VMId
                    datastore_queuelength = $queueLength
                    datastore_writeops = $writeops
                    datastore_readops = $readops
                    datastore_writebytes = $writebytes
                    datastore_readbytes = $readbytes
                    datastore_currentsize = $VHD.FileSize
                    datastore_max_store = $VHD.Size
                    datastore_read_latency = $DriveReadLatency
                    datastore_write_latency = $DriveWriteLatency
                    datastore_highest_read_latency = $HighestReadLatency
                    datastore_highest_write_latency = $HighestWriteLatency
                    datastore_highest_latency = $HighestLatency
                }
		#implemented exception handling to atempt diagnosing powershell buffer errors
                Try
	        {
                # Convert PerfmonEvent hash table to object
                # Dynamically add CdataWrapper based on splunk instance's version
                $VMObject = New-Object -Property (UseCdataWrapper $PerfmonEvent) -TypeName PSObject
            
                #serialze object to String
                   $VMObject
                }
                Catch
                {
                   WriteExceptionToLog($_.Exception)  
                }
            }
        }
    }
}
