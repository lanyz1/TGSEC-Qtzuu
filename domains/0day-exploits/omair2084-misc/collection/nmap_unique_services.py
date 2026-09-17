#Python3
#Print unique services found on the network
#using the xml output from nmap
#nmaprun > host > ports > port > service

import xml.etree.ElementTree
import sys

if len(sys.argv) < 3:
    print("[-] Supply nmap.xml and output file")
    print("Help: python3 %s scanOutput.xml storeOutput.txt" % sys.argv[0])
    sys.exit(-1)

e = xml.etree.ElementTree.parse(sys.argv[1]).getroot()
fe = open(sys.argv[2],"w")
for elem in e.findall('host/ports/port/service'):
    z = str(elem.get('product'))+"\n"
    fe.write(z)
fe.close()

f = open(sys.argv[2], "r")
lines = set(f.readlines())
print (''.join(lines))


