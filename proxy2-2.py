import sys
import socket
import thread
import time
from scapy.all import *

localip = '10.0.0.2'
localport = 1234
local = (localip, localport)
serverip = '10.0.0.3'
serverport = 1234
proxyip = '10.0.0.4'
#proxyport =
bufsize = 2048
#proxy_1_ip = ''
#proxy_1_port = 9999


def check_sum(data):
    s = str(data)
    check = int(0)
    check = 0xa02+0xa03  # srcip+dstip
    check = check + 0x06 + len(s)   # type:06 length:len(s)
    length = len(s)
    #    print "length ", length
    #    print ord(s[16])
    #    print ord(s[17])
    #    print ord(s[18])
    #    print ord(s[19])
    #    print ord(s[20])
    #    print ord(s[21])
    #    print ord(s[22])
    #    print ord(s[23])
    #    print ord(s[24])
    #    print ord(s[25])
    #    print ord(s[26])
    if length & 1:
        s = s + chr(0)
    cnt = 0
    while cnt < length:
        tmp = ord(s[cnt])*256 + ord(s[cnt+1])
        check = check + tmp#ord(s[cnt])*256 + ord(s[cnt+1])
        cnt = cnt+2

    check = check-(ord(s[16])*256 + ord(s[17]))
    check = int(check)
    ans = int(0)

    while check:
        ans = ans + (check % 65536)
        check = check >> 16

    check = 0xffff - ans
#    print hex(check)
    #   s = s[:17] + '00' + s[19:]
    s = s[:17] + chr(check % 256) + s[18:]
    check = check / 256
    s = s[:16] + chr(check) + s[17:]

    if length & 1:
        return s[:-1]
    else:
        return s


def soc(c):
    num = 0
    while True:
        data = c.recv(bufsize)
        print "Client says: ", data
        data = check_sum(data)
        if(len(data) > 0):
            send(IP(dst=serverip, src=localip, proto=6, id=num)/data)
            num = num + 1
            num = num % 65536


def solve_tcp(c, pkts):
    for buf in pkts:
        data = buf[TCP]
        print
        "capture packet ", data
        try:
            c.send(str(data))
        except Exception, e:
            print
            e.message
            c.close()
            break


def raw_sniff(c):
    while True:
        pkts = sniff(iface="en0", filter='tcp and ip src 10.0.0.3 and tcp port 1234', count=1)
        for buf in pkts:
            data = buf[TCP]
            print
            "capture packet ", data
            try:
                c.send(str(data))
            except Exception, e:
                print
                e.message
                c.close()
                break


def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(local)
    s.listen(10)
    print "begin to listen "
    #while True:
    c, addr = s.accept()
    print "Connected from: ", addr
    thread.start_new_thread(raw_sniff, (c, ))
    thread.start_new_thread(soc, (c, ))
    while True:
        #print "ok"
        time.sleep(5)

if __name__ == '__main__':
    main()
