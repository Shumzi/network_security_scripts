import socket
import fcntl
import struct
from scapy.all import *

def getHwAddr(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', ifname[:15]))
    return ':'.join(['%02x' % ord(char) for char in info[18:24]])

def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', ifname[:15])
    )[20:24])

def isInconsistent(pkt):
    if pkt.src != pkt.hwsrc or pkt.dst != pkt.hwdst:
        return True
    return False
myIP = get_ip_address('eth0')
myhwaddress = getHwAddr('eth0') # maybe of choice later.
dict = {}
fullinfo = False
alarm = False
def arpRequest(pkt):
    print 'request'
    bpfreq = 'arp[6:2] = 1 and src host ' + myIP
    # updating table. 0 is amount of flags we have for this person, and 0 for no. of occurrences of replies.
    cur = dict[pkt.pdst] = [pkt, False, False, False, 0]
    print cur
    if fullinfo:
        print pkt[0].summary()
        print 'src: ' + pkt[0].psrc
        print 'dst: ' + pkt[0].pdst

def arpReply(pkt):
    if pkt.psrc not in dict.keys():
        print "didn't ask for you, creating you though"
        dict[pkt.psrc] = [pkt, True, False, False, 0]
    # take current instance
    cur = dict[pkt.psrc]
    print cur
    if cur[0].op != 1:      # if I didn't ask for you but you at least exist, just tick flag.
        print "didn't ask for you"
        cur[1] = True
    # update last request.
    cur[0] = pkt
    if isInconsistent(pkt):
        print 'inconsistent'
        cur[2] = True
    cur[4] += 1
    if(cur[4] >= 5):
        print "too many requests for no apparent reason."
        cur[3] = True
    print cur
    # sum = sumthem (cur) - later, sum trues and just see if over 2
    if (cur[1] and cur[2]) or (cur[1] and cur[3]) or (cur[2] and cur[3]):
        print 'arpspoofing :) :) :)'
        print 'the culprit: '
        print cur
        return True
    if fullinfo:
        print pkt[0].summary()
        print 'src: ' + pkt[0].psrc
        print 'dst: ' + pkt[0].pdst
    return False
def reqrep():
    myIP = get_ip_address('eth0')
    bpfquery = '(arp[6:2] = 2 and dst host ' + myIP + ') '
    bpfquery += 'or (arp[6:2] = 1 and src host ' + myIP + ')'
    print bpfquery
    print 'reqrep biaatchhh'
    while True:
        if alarm:
            return
        pkt = sniff(count=1, filter=bpfquery)[0]
        # pkt = Ether()/ARP(op='is-at')
        if pkt.op == 1:  # 1 = 'who-has'
            arpRequest(pkt)
            # pass
        elif pkt.op == 2:  # 2 = 'is-at'
            if arpReply(pkt):
                return

reqrep()
