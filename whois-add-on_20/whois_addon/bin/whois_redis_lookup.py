# An aadapter that takes CSV as input, performs a lookup to whois, then returns the CSV results
import csv,sys
import urllib

##### CHANGE PATH TO your distribution FIRST ############
sys.path.append("/Library/Python/2.6/site-packages/redis-2.4.5-py2.6.egg")
import redis

LOCATION_URL="http://adam.kahtava.com/services/whois.xml?query="


# Given an ip, return the whois response. First check redis and then the URL
def lookup(redp, ip):
    try:
        ret = redp.get(ip)
        if ret!=None and ret!='':
            return ret
        else:
            whois_ret = urllib.urlopen(LOCATION_URL + ip)
            lines = whois_ret.readlines()
            if lines!='':
                redp.set(ip, lines)
            return lines
    except:
        return ''

def main():
    if len(sys.argv) != 3:
        print "Usage: python whois_lookup.py [ip field] [whois field]"
        sys.exit(0)

# Connect to redis CHANGE for your DISTRIBTUION
    red = None
    pool = redis.ConnectionPool(host='localhost', port=6379, db=0)
    red = redis.Redis(connection_pool=pool)


    ipf = sys.argv[1]
    whoisf = sys.argv[2]
    r = csv.reader(sys.stdin)
    w = None
    header = []
    first = True

    for line in r:
        if first:
            header = line
            if whoisf not in header or ipf not in header:
                print "IP and whois fields must exist in CSV data"
                sys.exit(0)
            csv.writer(sys.stdout).writerow(header)
            w = csv.DictWriter(sys.stdout, header)
            first = False
            continue

        # Read the result
        result = {}
        i = 0
        while i < len(header):
            if i < len(line):
                result[header[i]] = line[i]
            else:
                result[header[i]] = ''
            i += 1

        # Perform the whois lookup if necessary
        if len(result[ipf]) and len(result[whoisf]):
            w.writerow(result)

        elif len(result[ipf]):
            result[whoisf] = lookup(red, result[ipf])
            if len(result[whoisf]):
                w.writerow(result)

main()
