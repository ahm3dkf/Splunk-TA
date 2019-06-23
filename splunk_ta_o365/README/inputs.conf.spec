[splunk_ta_o365_management_activity://<name>]
tenant_name = Which Office 365 tenant will be used
content_type = What kind of activity will be ingested. [Audit.AzureActiveDirectory | Audit.Exchange | Audit.SharePoint | Audit.General | DLP.All]
number_of_threads = The number of threads used to download content blob in parallel
token_refresh_window = The number of seconds before the token's expiration time when the token should be refreshed. For example if the token is expiring at 01:00 PM and user has entered the 600 as a value of parameter token_refresh_window then the token will be refreshed at 12:50 PM. The range for the parameter is from 400 seconds to 3600 seconds.
request_timeout = The number of seconds to wait before timeout while getting response from the subscription api. The range for the parameter is from 10 seconds to 600 seconds.

[splunk_ta_o365_service_status://<name>]
tenant_name = Which Office 365 tenant will be used
content_type = What kind of status will be ingested. [Current | Historical].

[splunk_ta_o365_service_message://<name>]
tenant_name = Which Office 365 tenant will be used
