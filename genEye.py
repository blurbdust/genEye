import sys, argparse, ipaddress, textwrap

def format_masscan(ip, port, http, https, rdp, vnc):
	ret = ""
	if (http):
		ret += "http://" + str(ip) + ":" + port + "/\n"
	if (https):
		ret += "https://" + str(ip) + ":" + port + "/\n"
	if (rdp):
		ret += "rdp://" + str(ip) + ":" + port + "/\n"
	if (vnc):
		ret += "vnc://" + str(ip) + ":" + port + "/\n"
	return ret

def process_masscan(filename, outfile):
	count = 0
	buf = ""
	cur = ""
	output = None

	if (outfile != None):
		output = open(outfile, "w")			

	with open(filename, "r") as f:
		for line in f:
			http = False
			https = False
			rdp = False
			vnc = False
			
			lin = line.split(" ")

			ip = str(lin[5]).replace("\n", "")
			port = str(str(lin[3]).split("/")[0])

			if ("80" in port):
				#cur += "http://"
				http = True
			elif ("443" in port):
				#cur += "https://"
				https = True
			elif ("3389" in port):
				#cur += "rdp://"
				rdp = True
			elif ((int(port) < 5011) and (int(port) > 4999)):
				#cur += "vnc://"
				vnc = True
			else:
				cur = ""
				continue

			count += 1

			cur = format_masscan(ip, port, http, https, rdp, vnc)
			buf += cur
			cur = ""

			if ((count % 2000) == 0):
				if (output != None):
					output.write(buf)
				buf = ""

		if (output != None):
			output.write(buf)
		else:
			print(buf[:-1])

def ip_options(ip, http, https, rdp, vnc):
	ret = ""
	if (http != None):
		ret += "http://" + str(ip) + ":80/\n"
	if (https != None):
		ret += "https://" + str(ip) + ":443/\n"
	if (rdp != None):
		ret += "rdp://" + str(ip) + ":3389/\n"
	if (vnc != None):
		ret += "vnc://" + str(ip) + ":5001/\n"
	return ret

def process_ips(outfile, http, https, rdp, vnc):
	cur = ""
	buf = ""
	count = 0
	if (outfile != None):
		with open(outfile, "w") as out:
			for arg in args.ip:
				for ip in ipaddress.IPv4Network(arg):
					# saving output to file
					# don't thrash io 
					count += 1

					cur = ip_options(ip, http, https, rdp, vnc)

					buf += cur
					cur = ""
	
					if ((count % 2000) == 0):
						out.write(buf)
						buf = ""
			out.write(buf)
	else:
		for arg in args.ip:
			for ip in ipaddress.IPv4Network(arg):
				print(ip_options(ip, http, https, rdp, vnc)[:-1])
	#print("yee")

if __name__ == '__main__':
	parser = argparse.ArgumentParser(
		formatter_class=argparse.RawDescriptionHelpFormatter,
		description='Process a list or range of IPs to match EyeWitness\'s format', 
		epilog=textwrap.dedent('''Examples:\npython3 genEye.py 192.168.1.0/24 192.168.2.0/24 --https --http\npython3 genEye.py --masscan tests/test.masscan.txt --outfile out.txt''')
		)
	parser.add_argument('--masscan', dest='load_file', help='Load list of IPs from a file')
	parser.add_argument('--outfile', dest='out_file', help='Output results to file')
	parser.add_argument('ip', metavar='ip', type=str, nargs='*', help='IPs to parse')
	parser.add_argument('--http', dest='http', const=sum, nargs='?', help='Used with ip, prepends http and postpends port 80')
	parser.add_argument('--https', dest='https', const=sum, nargs='?', help='Used with ip, prepends https and postpends port 443')
	parser.add_argument('--rdp', dest='rdp', const=sum, nargs='?', help='Used with ip, prepends rdp and postpends port 3389')
	parser.add_argument('--vnc', dest='vnc', const=sum, nargs='?', help='Used with ip, prepends vnc and postpends port 5001')

	args = parser.parse_args()

	#print(args)

	#print(args)
	if (args.load_file != None):
		#print("true")
		#print("Parsing masscan file...")
		process_masscan(args.load_file, args.out_file)
	elif (args.ip != []):
		#print("Expanding IPs...")
		process_ips(args.out_file, args.http, args.https, args.rdp, args.vnc)
		#print(args.expand(args.ip))
	else:
		parser.print_help()

# --http --https
# Discovered open port $PORT/$PROTO on $IP