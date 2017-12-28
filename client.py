import socket
import sys

localip = ''
localport =
dstip = ''
dstport =
bufsize = 2048

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((dstip, dstport))
    except Exception, e:
        print e.message()
        s.close()
    else:
        print "succeed connceting ", (dstip, dstport)
        while True:
            data = raw_input()
            s.send(data)
            buf = s.recv(bufsize)
            print "server says : ", buf
    print "finish."


if __name__ == '__main__':
    main()