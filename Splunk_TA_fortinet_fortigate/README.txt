*********************************************
*
* Add-On: Fortinet Fortigate Add-On for Splunk
* Current Version: 1.6
* Last Modified: Jul 2017
* Splunk Version: 6.x
* Author: Fortinet Inc.
*
*********************************************



**** Overview ****

Fortinet FortiGate Add-On for Splunk is the technical add-on (TA) developed by
Fortinet, Inc. The add-on enables Splunk Enterprise to ingest or map security
and traffic data collected from FortiGate physical and virtual appliances
across domains. The key features include:

1. Streamlining authentication and access from FortiGate such as administrator
  login, user login, VPN termination authentication into to Splunk Enterprise
  Security Access Center

2. Mapping FortiGate virus report into Splunk Enterprise Security Endpoint Malware
  Center

3. Ingesting traffic logs, IPS logs, system configuration logs and Web filtering
  data etc.

Fortinet FortiGate Add-On for Splunk provides common information model (CIM)
knowledge, advanced “saved search”, indexers and macros to use with other
Splunk Enterprise apps such as Splunk App for Enterprise Security.


**** Configuration Steps ****
Please refer to https://splunkbase.splunk.com/app/2846/#/details
for detailed configuration steps

**** sourcetypes and eventtypes ****

	fgt_traffic
		ftnt_fgt_traffic
	fgt_utm
		ftnt_fgt_utm
		ftnt_fgt_ips
		ftnt_fgt_virus
		ftnt_fgt_netscan
		ftnt_fgt_spam
		ftnt_fgt_webfilter
		ftnt_fgt_appctrl
	fgt_event
		ftnt_fgt_vpn
		ftnt_fgt_vpn_auth
		ftnt_fgt_vpn_start
		ftnt_fgt_vpn_end
		ftnt_fgt_wireless
		ftnt_fgt_wireless_client_auth
		ftnt_fgt_system
		ftnt_fgt_auth
		ftnt_fgt_auth_privileged
		ftnt_fgt_perf_stats
		ftnt_fgt_config_change
		ftnt_fgt_restart

**** CIM mappings ****

	Authentication
	Change Analysis
	Email
	Intrusion Detection
	Malware
	Network Sessions
	Network Traffic
	Performance
	Web



**** Release Notes ****

v1.0: Aug 2015
        - Initial release

v1.1: Oct 2015
        - Fix FortiWifi Platform Log problem

v1.2: Feb 2016
        - Change for splunk certification
        - Remove default sourcetype wildcard matching, use fgt_log sourcetype instead
        - Add csv log format support

v1.3: May 2016
        - Change for splunk certification

v1.4: Oct 2016
        - Modify regex to accommodate logs from other forwarding sources

v1.5: Jul 2017
        - Modify regex to accommodate FOS5.6 log format
