#!/usr/bin/env python

# $Id: autohomenet.py 2008/10/16
"""A simple tool to passively discover routable address space by observing bitmask changes on captured packets""" 
 

import os, sys, struct,curses,binascii,socket
import discovery

if __name__ == "__main__":

		if (len(sys.argv) < 2) or (len(sys.argv) > 3):
				print("\nUsage: %s <device or capture file> <upstream gateway MAC>\n" % sys.argv[0])
				os._exit(1)
		else:
				print("\n          Automatic HOME_NET passive discovery tool: using %s for data source\n"  % sys.argv[1])
				
		if len(sys.argv) == 3:
				print("Using source MAC address of %s as upstream gateway >>>" % sys.argv[2])
				filtermac = sys.argv[2]
		else:
				print("    Automatically determining upstream gateway >>>\n")
				filtermac = discovery.gateway.findupstream(device=sys.argv[1])
				print("\n    Using " + filtermac + " as upstream gateway MAC\n")
		try:
				print("done")
				print(discovery.networks.passive(sys.argv[1],filtermac))
		except KeyboardInterrupt:
				print('%s' % sys.exc_info()[0])
				print('shutting down')
				print('%d packets received, %d packets dropped, %d packets dropped by interface' % p.stats())
				os._exit(1)


