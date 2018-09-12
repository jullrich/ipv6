#!/usr/bin/env python

from scapy.all import *
dst = "172.16.29.171"
ipid=random.randint(0,65535)
icmpid=random.randint(0,65535)
request=IP(dst=dst,id=ipid)/ICMP(type=8,code=0,id=icmpid)/('NORMAL__'*10)
print "Sending unfragmented packet"
reply=sr1(request,verbose=0)
print "Request payload ",request.load
print "  Reply payload ",reply.load

ipid=random.randint(0,65535)
icmpid=random.randint(0,65535)
request=IP(dst=dst,id=ipid)/ICMP(type=8,code=0,id=icmpid)/('1STLAST_'*10)
frags=fragment(request,fragsize=16)
print "sending fragments"
for f in frags:
	send(f,verbose=0)
print "sending first fragment last"
for i in range(1,len(frags)):
	send(frags[i],verbose=0)
send(frags[0],verbose=0)
print "overlapping two fragments"
ipid=random.randint(0,65535)
icmpid=random.randint(0,65535)
request=IP(dst=dst,id=ipid)/ICMP(type=8,code=0,id=icmpid)/('OVERLAPS'*3)
frags=fragment(request,fragsize=16)
frags[0].load=frags[0].load+'OVERLAPS'
send(frags[0],verbose=0)
send(frags[1],verbose=0)
