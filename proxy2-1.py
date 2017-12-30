import sys
import socket
import thread
import time
from scapy.all import *

proxy2ip = '10.0.0.2'
proxy2port = 1234
clientip = '10.0.0.8'
#clientport =
bufsize = 2048
localip = '10.0.0.4'
#localport = 1234
#to proxy1

def check_sum(data):

    s = str(data)
    check = int(0)
    check = 0xa08+0xa04  # srcip+dstip
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
    print hex(check)
    #   s = s[:17] + '00' + s[19:]
    s = s[:17] + chr(check % 256) + s[18:]
    check = check / 256
    s = s[:16] + chr(check) + s[17:]

    if length & 1:
        return s[:-1]
    else:
        return s


def wwtest():
    while True:
        pkts = sniff(iface="enp0s31f6", filter='tcp and ip src 10.0.0.8 and tcp port 1234 ', count=1)
        #len = str(str1)
        for buf in pkts:
            data = buf[TCP]
            print type(data)
            data = str(data)
            print data
            data = check_sum(data)
            print len(data)
            print data


def raw(s):
    while True:
        pkts = sniff(iface="enp0s31f6", filter='tcp and ip src 10.0.0.8 ', count=1)
        for buf in pkts:
            data = buf[TCP]
            try:
#                print "data is ", data
#                print "data length is ", len(data)
#                print "data str is ", str(data)
                s.send(str(data))
            except Exception, e:
                print e.message
                s.close()
                break
# to server


def soc(s):
    num = 0
    while True:
        data = s.recv(bufsize)
#        print "data is ", data
#        print "data length ", len(data)
        data = check_sum(data)
        if(len(data)>0):
            send(IP(dst=clientip, src=localip, proto=6, id=num)/data)
            num = num+1
            num = num % 65535


def main():
    print "@@"
    c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    while True:
        try:
            c.connect((proxy2ip, proxy2port))
        except Exception, e:
            print "failed to connect "
            c.close()
        else:
            thread.start_new_thread(soc, (c, ))
            thread.start_new_thread(raw, (c, ))
            break
    while True:
        time.sleep(5)
        #print "ok"
    print "Finish!"

if __name__ == '__main__':
    main()
#    test()

