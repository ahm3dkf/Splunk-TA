Author: Nimish Doshi

These 2 add-ons provide 2 different ways to perform a whois. The external
web sites that are used are for demonstration and the user should use their
own web sites if possible. They are both used in the context of a Splunk app.
A requirement is that your data contains external IP addreses that can be used
for workflow actions and/or look up commands. First extract your IP addresses
from your index data. See the Splunk Docs on how to extract a field. For
example, I have used ip as the name of my field. This is then used as input
to the look up and and the work flow actions.

Installation

First, identify the app that you would like to use for this add-on. As
mentioned, the app's indexed data  must have a field that contains an IP
address. If you do not have an app that  has been created, but you do
have data that has been indexed with an extractable IP address, you can use
the Splunk search app.

Look UP

Copy this add-on's bin/whois_lookup.py into your own app's bin directory.
Then, within the app's local directory (or default directory if you wrote
it yourself), copy the content of this add-on's default/transforms.conf into
your own transforms.conf file. If you do not have a transforms.conf, create
a new one in your apps's local or default directory

Search Usage:

*|lookup whoisLookup ip OUTPUT whois

This will create a new whois field for all events that contain an extracted
field called ip at search time. The whois field contains whois information
in XML format created by an external web site used for testing. You can use
your own web site changing the LOCATION_URL variable in the whois_lookup.py
file.

NOTE: Because there is no caching used here, it will not be a good idea to
send thousands of events to this lookup command as each event will make
an external call to the LOCATION_URL web site. It may be better to narrow
down your search such as:

*|head 50|lookup whoisLookup ip OUTPUT whois

Or

ip=192.168.50.1|head 1|lookup whoisLookup ip OUTPUT whois

Options: If you are using the URL that is provided in the whois_lookup.py
program, the developer has put in other options for output. Change the line
LOCATION_URL="http://adam.kahtava.com/services/whois.xml?query="

to

LOCATION_URL="http://adam.kahtava.com/services/whois.csv?query="

for CSV output. If you want the output in JSON format, change the line to:

LOCATION_URL="http://adam.kahtava.com/services/whois.json?query="

Version 2.x and onward (OPTIONAL)

Version 2.x and onward adds support for the Redis key value database to cache
all responses from the whois lookup query. The theory is that the whois
response hardly changes for an address, so having a local cache of the data
speeds up the query. Here's what you have to do to use this version,
whois_redis_lookup.py

1) First, install Redis from http://redis.io/
You will need access to make (and possibly gcc). On a Mac, install XCode first.

2) Next, install the Redis Python Module, which produces an egg file.

https://github.com/andymccurdy/redis-py

3) Finally, in the whois_redis_lookup.py file, change the following lines:

Change: sys.path.append("/Library/Python/2.6/site-packages/redis-2.4.5-py2.6.eg
g")
by putting in the absolute path to your redis...egg file.

Change: pool = redis.ConnectionPool(host='localhost', port=6379, db=0)
by putting in the name of your your host, port, and db, if different.

Start the redis-server. See the Redis docs on how to start it.
Now instead of using whois_lookup.py as described above in your transforms.conf
and lookup searches, you can now use whois_redis_lookup.py in its place.



Workflow Action

Copy the contents of the default/workflow_actions.conf into your own app's
local or default/workflow_actions.conf file. If you do not have such a file,
create a new one.

Usage: After retrieving data that has an IP address, use the field picker menu
on the UI to pick ip as a field to view on the events list. Then, under the
ip field in the events list, you will see a pulldown menu that will have
a new entry called whois. Click on this whois menu item to perform a whois
for this particular field value.

Note that if your extracted field is called something other than ip, you can
change the contents of workflow_actions.conf for this workflow action to use
your field extraction name instead of the word ip.



