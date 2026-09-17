import sys

if len(sys.argv) < 3:
    print('Syntax: python3 {} http scan.gnmap'.format(sys.argv[0]))
    sys.exit(1)

with open(sys.argv[2]) as f:
    for line in f:
         if 'Status' not in line and '#' not in line:
            data = line.split('\t')
            #print(data[0],data[1])
            hosts = data[0]
            ports = data[1]
            
            hostname = hosts.split(' ')[1]
            # Remove Ports:+space 
            ports_split = ports[7:].split('/, ')

            for port in ports_split:
                each_port = port.split('/')
                #print('test output {}'.format(each_port))
                # 172.16.50.46 ['139', 'open', 'tcp', '', 'netbios-ssn', '', 'Microsoft Windows netbios-ssn', '']
                if sys.argv[1] == 'http':
                    if 'ssl|http' in each_port[4] or 'ssl|https' in each_port[4] :
                        print ('https://{}:{}'.format(hostname,each_port[0]))
                    elif 'http' in each_port[4]:
                        print ('http://{}:{}'.format(hostname,each_port[0]))

                if sys.argv[1] == 'service':
                    if each_port[6] != '':
                        print(each_port[6])

