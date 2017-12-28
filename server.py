import socket
import sys


localport =
localip = ''
dstport =
dstip =
bufsize = 2048


def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((localip, localport))
    s.listen(10)
    while True:
        c, addr = s.accept()
        print "Connected from ", addr
        while True:
            data = c.recv(bufsize)
            print "client says: ",data
            buf = raw_input()
            c.send(buf)
    print "finish!"

if __name__ == '__main__':
    main()