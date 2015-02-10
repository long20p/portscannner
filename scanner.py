__author__ = 'root'

import optparse
import nmap
from socket import *
from threading import *


screenLock = Semaphore(value=1)


def main():
    parser = optparse.OptionParser('usage %prog -H <target host> -p <target port>')
    parser.add_option('-H', dest='tgtHost', type='string', help='specify host')
    parser.add_option('-p', dest='tgtPort', type='string', help='specify ports')
    (options, args) = parser.parse_args()
    tgtHost = options.tgtHost
    tgtPorts = str(options.tgtPort).split(',')
    if (tgtHost == None) | (tgtPorts[0] == None):
        print(parser.usage)
        exit(0)
    port_scan(tgtHost, tgtPorts)


def nmap_scan(host, port):
    nmScanner = nmap.PortScanner()
    nmScanner.scan(host, port)
    state = nmScanner[host]['tcp'][int(port)]['state']
    print(" [*] " + host + " tcp/" + port + " " + state)


def conn_scan(host, port):
    try:
        conn = socket(AF_INET, SOCK_STREAM)
        conn.connect((host, port))
        conn.send('Scouting\r\n')
        result = conn.recv(100)
        screenLock.acquire()
        print('[+] tcp open {}'.format(port))
        print('[+] ' + str(result))
    except:
        screenLock.acquire()
        print('[-] tcp closed {}'.format(port))
    finally:
        screenLock.release()
        conn.close()


def port_scan(host, ports):
    try:
        ip = gethostbyname(host)
    except:
        print('Cannot resolve "{}"'.format(host))

    try:
        tgtParams = gethostbyaddr(ip)
        print('[+] Scan result for: {}'.format(tgtParams[0]))
    except:
        print('[+] Scan result for: {}'.format(ip))

    setdefaulttimeout(1)

    for port in ports:
        print('Scanning port ' + port)
        # t = Thread(target=conn_scan, args=(host, int(port)))
        # t = Thread(target=nmap_scan, args=(host, port))
        # t.start()
        nmap_scan(ip, port)


if __name__ == '__main__':
    main()