import socket
import struct
import geoip2.database

#file to store US IP addresses
us_IPs = open("us_IPs.txt", 'a')
us_IPs.writelines("\n United States IP addresses \n")

#file to store the IP address that have disconnected
file_txt = open("blocked_IPs.txt",'a')
file_txt.writelines("\nBlocked IPs \n")

#All incomming IP address and their locations
file_IP_adrs = open("incoming_IPs.txt", 'a')
file_IP_adrs.writelines("\n Incoming IP Addresses \n")


#IP address location databases
reader = geoip2.database.Reader('./GeoLite2-Country_20191203/GeoLite2-Country.mmdb')
reader2 = geoip2.database.Reader('./GeoLite2-City_20191203/GeoLite2-City.mmdb')

while True:
	s=socket.socket(socket.PF_PACKET, socket.SOCK_RAW,8) #create new socket s --> socket.socket(family, type, porto)
	pkt =s.recvfrom(2048)	# Recieve data from socket 2048 buffer size -> returns (bytes, address)
	ipheader = pkt[0][14:34] # Extract IP header data from the recieved packet
	ip_hdr = struct.unpack("!8sB3s4s4s", ipheader) # Unpack the ipheader with CAN frame format "!8sB3s4s4s"
	IP = socket.inet_ntoa(ip_hdr[3]) # Covert packed 32-bit IPv4 address to standard dot form

	try:														#Check to see if the IP address is valid
		reader.country(IP)
		response = reader.country(IP)							
		print('Source IP address: ', IP)
		print('Country Name: ', format(response. country.name))	
		file_IP_adrs.writelines(IP)								#Write the IP address to the incomming IP txt file
		file_IP_adrs.writelines("\t")
		file_IP_adrs.writelines(format(response. country.name)) # Write IP country origin
		file_IP_adrs.writelines("\n")

		if(format(response. country.name) == 'United States'):	# Check to see if IP address is from the US
			city = reader2.city(IP)
			us_IPs.writelines(IP)
			us_IPs.writelines("\t")
			us_IPs.writelines(format(city. city.name))
			us_IPs.writelines("\n")
		else:													# Close any of the sockets for IP addresses 
			file_txt.writelines(IP)								# outside of the US
			file_txt.writelines("\t")
			file_txt.writelines(format(response. country.name))
			s.close()
			file_txt.writelines("\t Connection Closed \n")
	except:														#If IP is not valid jump here and close the connection
		print("Invalid IP")
		s.close()
		print("\t Connection Closed")
		pass

us_IPs.close()
file_txt.close()
file_IP_adrs.close()
reader.close()
reader2.close()
