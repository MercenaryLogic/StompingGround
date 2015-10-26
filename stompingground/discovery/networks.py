if __name__ == "__main__":
	Exit()

import os, sys, struct,curses,binascii,socket,pcap,dpkt 
from util import bitmasks
from collections import defaultdict

class recursivedefaultdict(defaultdict):
    def __init__(self):
        self.default_factory = type(self)



def passive(device,filtermac):
		"""start the construction of a valid network/mask by capturing and processing SYNACK packets incoming via an upstream gateway"""

		try:
			capture = pcap.pcap(name=device, promisc=True, snaplen=65535)
			capture.setfilter("(not broadcast) and (not multicast) and (tcp[13] = 18) and ether src " + filtermac)
			print("Beginning Packet Capture on " + device +  " for outbound connections via upstream router " + filtermac)
			print("using following PCAP filter >>> " + capture.filter + "\n")
		except OSError:
			print("%s does not exist, or you do not have permission to open it" % device)
		
		observednetworks = recursivedefaultdict()									#Address Dictionary for final output -- multidimensional dictionary
		numpackets = 0
		homenet = "HOME_NET = ("

		try:
			while True == True:
				packet = dpkt.ethernet.Ethernet(capture.next()[1])							#Get next packet
				numpackets = numpackets+1				
				addr = struct.unpack('!I',packet.data.dst)[0]								#get the current IP address
				ip = socket.inet_ntoa(struct.pack('!L',addr))
				firstoctet,secondoctet,thirdoctet,hostip = ip.split(".")
				observednetworks[firstoctet][secondoctet] = thirdoctet
				
				packetlog = "Packets processed so far : " + str(numpackets) +"   - Last Address seen: " + ip +"\r"
				sys.stderr.write(packetlog)

		except (KeyboardInterrupt, StopIteration):
			print('\n\nFinished enumerating networks\n')
			print("Observed Networks:")

			for first in sorted(observednetworks.keys()):
				print(first)
				for second in list(observednetworks[first].keys()):
						print(" - " + first + "." + second +"." + observednetworks[first][second] + ".0/24")
						homenet = homenet + first + "." + second +"." + observednetworks[first][second] + ".0/24, "
			print('With upstream gateway with MAC of : ' + filtermac)
			homenet = homenet + ");"			

#		except OSError as xxx_todo_changeme:
#			(strerror) = xxx_todo_changeme
#			print(strerror)
		
		return homenet
		
