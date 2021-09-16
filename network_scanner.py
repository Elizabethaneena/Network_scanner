#Network scanning tool(Menu driven)

#!/usr/bin/python3
import nmap

def scan_singlehost():
	#Create object of nmap port scannet class
	nm = nmap.PortScanner() 
	ip_address = input("\tEnter the IP : ")
	print("Wait __________________________________________________________")
	try:
		scan = nm.scan(hosts=ip_address,ports="1-2000",arguments = "-v -sS -O -Pn") #Returns Dictionary
		print(scan)
		for port in scan["scan"][ip_address]['tcp'].items():
			print(f"{port[0]}, {port[1]['state']} , {port[1]['name']}")
	except:
		print("Use root priviliege")
		
def scan_range():
	nm = nmap.PortScanner() 
	ip_address = input("\tEnter the IP : ")
	print("Wait __________________________________________________________")
	try:
		scan = nm.scan(hosts=ip_address,arguments = "-sS -O -Pn")
		for port in scan["scan"][ip_address]['tcp'].items():
			print(f"{port[0]}, {port[1]['state']} , {port[1]['name']}")
	except:
		print("Use root priviliege")
	
	
def scan_network():
	nm = nmap.PortScanner() 
	ip_address = input("\tEnter the IP : ")
	print("Wait __________________________________________________________")
	try:
		scan = nm.scan(hosts=ip_address,arguments = "-sS -O -Pn")
		for i in scan["scan"][ip_address]['osmatch']:
			print(f"Name -> {i['name']}")
			print(f"Accuracy -> {i['accuracy']}")
			print(f"OSClass -> {i['osclass']}\n")
		
	except:
		print("Use root priviliege")
	

def aggressive_scan():
	nm = nmap.PortScanner() 
	ip_address = input("\tEnter the IP : ")
	print("Wait __________________________________________________________")
	try:
		scan = nm.scan(hosts=ip_address,arguments = "-sS -O -Pn -T4")
		for i in scan["scan"][ip_address]['osmatch']:
			print(f"Name -> {i['name']}")
			print(f"Accuracy -> {i['accuracy']}")
			print(f"OSClass -> {i['osclass']}\n")
		
	except:
		print("Use root priviliege")
	

def arp_packets():
	nm = nmap.PortScanner() 
	ip_address = input("\tEnter the IP : ")
	print("Wait __________________________________________________________")
	try:
		scan = nm.scan(hosts=ip_address,arguments = "-sS -O -PR")
		print(scan)
	except:
		print("Use root priviliege")
		

def scan_all_ports():
	nm = nmap.PortScanner() 
	ip_address = input("\tEnter the IP : ")
	print("Wait __________________________________________________________")
	try:
		scan = nm.scan(hosts = ip_address,ports = "1-3",arguments = "-sS -O -Pn")
		for port in scan["scan"][ip_address]['tcp'].items():
			print(f"{port[0]}, {port[1]['state']} , {port[1]['name']}")
	except:
		print("Use root priviliege")
	

def scan_verbose():
	nm = nmap.PortScanner() 
	ip_address = input("\tEnter the IP : ")
	print("Wait __________________________________________________________")
	try:
		scan = nm.scan(hosts = ip_address,arguments = "-sS -O -Pn -v")
		for i in scan["scan"][ip_address]['osmatch']:
			print(f"Name -> {i['name']}")
			print(f"Accuracy -> {i['accuracy']}")
			print(f"OSClass -> {i['osclass']}\n")
	except:
		print("Use root priviliege")
		
	
def menu():
	# Main menu
	print("1. Scan single host")
	print("2. Scan range")
	print("3. Scan network")
	print("4. Aggressive scan")
	print("5. Scan ARP packet")
	print("6. Scan All port only")
	print("7. Scan in verbose mode")
	print("8.Exit")
	
while True:
	menu()
	ch =  int(input("Enter the choice : "))
	if ch == 1:
		scan_singlehost()
	elif ch == 2:
		scan_range()
	elif ch == 3:
		scan_network()
	elif ch == 4:
		aggressive_scan()
	elif ch == 5:
		arp_packets()
	elif ch == 6:
		scan_all_ports()
	elif ch == 7:
		scan_verbose()
	elif ch == 8:
		break;
	else:
		print("Invalid Choice")
