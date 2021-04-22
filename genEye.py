import sys, argparse, ipaddress, textwrap

def format_nmap(ip, port, http, https, rdp, vnc):
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

def process_nmap(filename, outfile):
    count = 0
    buf = ""
    cur = ""
    output = None

    if (outfile != None):
        output = open(outfile, "w")

    with open(filename, "r") as f:
        for line in f:
            if ("#" in line):
                continue
            if ("Ports:" not in line):
                continue
            if ("open" not in line):
                continue
            http = False
            https = False
            rdp = False
            vnc = False

            lin = line.split(" ")
            ip = str(lin[1]).replace("\n", "").replace("\r", "").replace(" ", "")
            #consume until we hit "Ports"
            try:
                lin = line[line.index("Ports:") + len("Ports: ") : line.index("Ignored State:")]
            except ValueError:
                lin = line[line.index("Ports:") + len("Ports: ") : ]
            ports = str(str(lin).split("  ")[0]).split(" ")
            for port in ports:
                port = port.split("/")[0]

                if ("80" in port):
                    #cur += "http://"
                    http = True
                elif ("43" in port):
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

                cur = format_nmap(ip, port, http, https, rdp, vnc)
                buf += cur
                cur = ""
                http = False
                https = False
                rdp = False
                vnc = False

                if ((count % 2000) == 0):
                    if (output != None):
                        output.write(buf)
                    buf = ""

        if (output != None):
            output.write(buf)
        else:
            print(buf[:-1])


def format_masscan(ip, port, http, https, rdp, vnc):
    ret = ""
    if (http):
        ret += "http://" + str(ip) + ":" + port + "/\n"
    if (https):
        ret += "https://" + str(ip) + ":" + port + "/\n"
    if (rdp):
        ret += "rdp://" + str(ip) + ":" + port + "\n"
    if (vnc):
        ret += "vnc://" + str(ip) + ":" + port + "\n"
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
            if ("#" in line):
                continue
            http = False
            https = False
            rdp = False
            vnc = False

            lin = line.split(" ")
            #print(lin)
            #sys.exit(1)
            ip = str(lin[5]).replace("\n", "").replace("\r", "").replace(" ", "")
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

def process_shodan(filename, outfile):
    count = 0
    buf = ""
    cur = ""
    output = None

    if (outfile != None):
        output = open(outfile, "w")

    with open(filename, "r") as f:
        for line in f:
            if ("#" in line):
                continue
            if ("here" in line):
                continue
            if ("interesting" in line):
                continue
            if ("Ports:" not in line):
                continue

            ip = line.split(";")[0].split(":")[1].replace(" ", "")
            ports = line.split(";")[1].split(":")[1].split(",")

            for port in ports:
                http = False
                https = False
                rdp = False
                vnc = False

                port = port.replace(" ", "").replace("\n", "").replace("\r", "")
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

def ip_options(ip, http, https, rdp, vnc, none_):
    ret = ""
    if (http != None):
        ret += "http://" + str(ip) + ":80/\n"
    if (https != None):
        ret += "https://" + str(ip) + ":443/\n"
    if (rdp != None):
        ret += "rdp://" + str(ip) + ":3389/\n"
    if (vnc != None):
        ret += "vnc://" + str(ip) + ":5001\n"
    if (none_ != None):
        ret += str(ip) + "\n"
    return ret

def process_raw_file(infile, outfile, http, https, rdp, vnc, none_):
    cur = ""
    buf = ""
    count = 0
    out = None
    if (outfile != None):
        out = open(outfile, "w")


    with open(infile, "r") as infil:
        for line in infil:
            line = line.replace("\n","").replace("\r","").replace("\t","")
            if ("/" in line):
                for ip in ipaddress.IPv4Network(line):
                    count += 1
                    cur = ip_options(ip, http, https, rdp, vnc, none_)
                    buf += cur
                    cur = ""
            else:
                count += 1

                cur = ip_options(line, http, https, rdp, vnc, none_)

                buf += cur
                cur = ""

            if ((count % 2000) == 0):
                out.write(buf)
                buf = ""
        if (out != None):
            out.write(buf)
        else:
            print(buf[:-1])

def process_ips(outfile, http, https, rdp, vnc, none_):
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

                    cur = ip_options(ip, http, https, rdp, vnc, none_)

                    buf += cur
                    cur = ""

                    if ((count % 2000) == 0):
                        out.write(buf)
                        buf = ""
            out.write(buf)
    else:
        for arg in args.ip:
            for ip in ipaddress.IPv4Network(arg, False):
                print(ip_options(ip, http, https, rdp, vnc, none_)[:-1])
    #print("yee")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
            formatter_class=argparse.RawDescriptionHelpFormatter,
            description='Process a list or range of IPs to match EyeWitness\'s format',
            epilog=textwrap.dedent('''Examples:\npython3 genEye.py 192.168.1.0/24 192.168.2.0/24 --https --http\npython3 genEye.py --masscan tests/test.masscan.txt --outfile out.txt\npython3 genEye.py --nmap tests/test.nmap.txt --outfile out.txt''')
            )
    parser.add_argument('--masscan', dest='load_file', help='Load list of IPs from a file (masscan)')
    parser.add_argument('--nmap', dest='load_file_nmap', help='Load list of IPs from a file (nmap)')
    parser.add_argument('--shodan', dest='load_file_sho', help='Load list of IPs from a file (shodan)')
    parser.add_argument('--raw', dest='load_file_raw', help='Load list of IPs from a file (raw)')
    parser.add_argument('--outfile', dest='out_file', help='Output results to file')
    parser.add_argument('ip', metavar='ip', type=str, nargs='*', help='IPs to parse')
    parser.add_argument('--http', dest='http', const=sum, nargs='?', help='Used with ip or --raw, prepends http and postpends port 80')
    parser.add_argument('--https', dest='https', const=sum, nargs='?', help='Used with ip or --raw, prepends https and postpends port 443')
    parser.add_argument('--rdp', dest='rdp', const=sum, nargs='?', help='Used with ip or --raw, prepends rdp and postpends port 3389')
    parser.add_argument('--vnc', dest='vnc', const=sum, nargs='?', help='Used with ip or --raw, prepends vnc and postpends port 5001')
    parser.add_argument('--none', dest='none_', const=sum, nargs='?', help='Used with ip or --raw, prepends nothing')

    args = parser.parse_args()

    #print(args)

    #print(args)
    if (args.load_file != None):
        process_masscan(args.load_file, args.out_file)
    elif (args.load_file_raw != None):
        if ((args.http == None) and (args.https == None) and (args.rdp == None) and (args.vnc == None) and (args.none_ == None)):
            print("Please add arguments for http, https, rdp, or vnc.")
        process_raw_file(args.load_file_raw, args.out_file, args.http, args.https, args.rdp, args.vnc, args.none_)
    elif (args.load_file_sho != None):
        process_shodan(args.load_file_sho, args.out_file)
    elif (args.load_file_nmap != None):
        process_nmap(args.load_file_nmap, args.out_file)
    elif (args.ip != []):
        #print("Expanding IPs...")
        process_ips(args.out_file, args.http, args.https, args.rdp, args.vnc, args.none_)
        #print(args.expand(args.ip))
    else:
        parser.print_help()

#--http --https
#Discovered open port $PORT/$PROTO on $IP
