Function AddCdataWrapper($dict){
	$out_dict = @{}
	foreach($prop_key in $dict.keys){
		$value = $dict.$prop_key
		$value_str = @()
		foreach($val in $value){
			if($val -eq $null){
				continue
			}
			$str = $val.ToString()
			$value_str += $str
		}
		$prop_str = $value_str -Join ", "
		$prop_str = $prop_str.Trim("[","]")
        $prop_str = $prop_str.replace("]]>","]]]]><![CDATA[>")
        $out_dict.$prop_key = "<![CDATA[" + $prop_str + "]]>"		
	}
	return $out_dict
}

Function WriteExceptionToLog($excep) {
    Start-Transcript -Path "..\..\..\..\var\log\splunk\Splunk_Ta_microsoft-hyperv.log" -Append
    $excep | select *
    Stop-Transcript
}

# Checks the Splunk version of the instance and decides the requirement of CDATA Wrapper
Function UseCdataWrapper($Event){
	$splunk_version_command = "&'$SplunkHome\bin\splunk' version"
    $splunk_version =Invoke-Expression $splunk_version_command
	$splunk_version -match "^.*?(?<content>\d.*?)\." > $null
	if([int]$matches['content'] -ge 7){
		return $Event
	}
	else{
		return AddCdataWrapper $Event
	}
}