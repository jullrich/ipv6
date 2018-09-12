#!/usr/bin/env python

from scapy.all import *
import random

#
#  This script is the starting point for many of the other scripts.
#  It implements a "normal" 3-way handshake, and sends a simple
#  HTTP GET request that is split into two packets. 
#
#  I split the request into two packets because later, this will
#  be used to experiment with TCP overlaps.
#
#  The assumption is that the recipient is a web server that will
#  echo back the "Host" header.

#  Adjust destination port and IP address here. There are the
#  only parameters you should have to adjust.

dstport=80
dstip='2001:db8::1'

####

# we use a source port in the IANA suggested ephemeral range.
# source port and sequence number are selected at random to prevent
# using the same number twice if the script is run multiple times
srcport=random.randint(49152,65535)
# random initial sequence number
isn=random.randint(0,4294967295)

# create IPv6 header. We only set the destination IP
i=IPv6(dst=dstip);

# TCP SYN Header
syn=TCP(srcport=srcport, dstport=dstport, seq=isn, flags='S', ack=0, options=[(MSS,1460)]);
synack=sr1(syn);
ack=syn(flags='SA',seq=isn+1,ack=synack.seq+1);
ackresp=sr1(ack);

