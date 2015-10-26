if __name__ == "__main__":
	Exit()

import os,sys,struct,curses,binascii,socket,pcap,dpkt

def findupstream(device='eth0'):
		"""
		determine the upstream router MAC address by tallying up observed occurences of its MAC address
		The gatway with the highest total occurences as src or destination is assumed to be the upstream router
		"""
		gateways = {}
		try:
				capture = pcap.pcap(name=device, snaplen=4096, promisc=True)
				capture.setfilter('ip')
		except OSError:
				print("\n%s does not exist, or you do not have permission to open it\n" % device)	
				os._exit(1)
		
		print("capturing 10,000 packets of data to determine gateway address")
		
		for workpacket in range(10000):
				try:
						workpacket = dpkt.ethernet.Ethernet(capture.next()[1])
						if workpacket.dst not in gateways:
								gateways[workpacket.dst] = 0
						if workpacket.src not in gateways:
								gateways[workpacket.src] = 0
						gateways[workpacket.dst] = gateways[workpacket.dst] +1 
						gateways[workpacket.src] = gateways[workpacket.src] +1
				except KeyboardInterrupt:
						print('%s' % sys.exc_info()[0])
						print('shutting down')
						print('%d packets received, %d packets dropped, %d packets dropped by interface' % capture.stats())
						os._exit(1)

		highestcount = 0
		broadcastmac = 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
		if struct.pack('BBBBBB',0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF) in gateways:				
			del gateways[struct.pack('BBBBBB',0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF)]
		
		print("Discovered local MAC addresses")
		for mac in gateways:
			count = gateways[mac]
			mac = binascii.b2a_hex(mac)
			print(mac[0:2] + ":" +  mac[2:4] + ":" + mac[4:6] + ":" + mac[6:8] + ":" + mac[8:10] + ":" +  mac[10:12]  + " - " + str(count))

		for mac in gateways:                                 	                					# assume that the most-referenced MAC is the upstream gateway
			if cmp(gateways[mac], highestcount) == 1:
				highestcount = gateways[mac]
				chosengate = mac
		chosengate = binascii.b2a_hex(chosengate)
		chosengate = chosengate[0:2] + ":" +  chosengate[2:4] + ":" + chosengate[4:6] + ":" + chosengate[6:8] + ":" + chosengate[8:10] + ":" +  chosengate[10:12]
		return chosengate
