import requests
import re
import getpass
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

hostname = "firewall DNS name"

# Function for commit changes on firewall
def commitchange(apikey):
    commit_c = "https://{}/api/?type=commit&key={}&cmd=<commit></commit>".format(hostname,apikey)
    commit = requests.get(commit_c, verify=False)
    print("Changes commited \n")
    return commit


def getapikey(username,password):
    getapikey_c = "https://{}/api/?type=keygen&user={}&password={}".format(hostname,username,password)
    get_apikey_r = requests.get(getapikey_c, verify=False)
    global get_api
    get_api = get_apikey_r.text
    get_api = get_api.replace("<response status = 'success'><result><key>","")
    get_api = get_api.replace("</key></result></response>", "")
    return get_api

# find free tunnel number
def free_tun_number(apikey):
    #Get xml output form FW
    url_get_tunnel_list = "https://{}/api/?type=config&action=get&key={}&xpath=/config/devices/entry[@name='localhost.localdomain']/network/interface/tunnel".format(hostname,apikey)
    tun_list = requests.get(url_get_tunnel_list, verify=False)
    #Convert to text format
    tun_list = tun_list.text
    #Find strings where tunnel.digit numbers
    tun_regex = r'tunnel.\b\d{1,3}\b'
    find_tun_num = re.findall(tun_regex, tun_list)
    #Create new vaiable for further listing
    tun_list_1 = []
    #Create new var for search in output
    x = 1
    xsrc = 'tunnel.' + x.__str__()

    #cycle for find digits and add to list tun_list_1
    for xsrc in find_tun_num:
        b = re.sub("\D", "", xsrc)
        tun_list_1.append(b)
        x = x + 1
        xsrc = 'tunnel.' + x.__str__()
    #Convert list contained to digits for sorting and operations
    for i in range(0, len(tun_list_1)):
        tun_list_1[i] = int(tun_list_1[i])

    #Sorting digits
    tun_list_1.sort()

    #Find free tunnel numbr
    free_tun_num = next(a for a, b in enumerate(tun_list_1, tun_list_1[0]) if a != b)

    return free_tun_num


# function for get IKE Phase 1 crypto profile list
def getph1crypto(apikey):
    url_cr_pf_list = "https://{}/api/?type=config&action=get&key={}&xpath=/config/devices/entry[@name=%27localhost.localdomain%27]/network/ike/crypto-profiles/ike-crypto-profiles".format(hostname,apikey)
    cr_pf = requests.get(url_cr_pf_list, verify=False)
    # convert output to text
    cr_pf = cr_pf.text
    # find string where name pattern find
    cr_regex = r'name=.*'
    find_cr_pf = re.findall(cr_regex, cr_pf)

    # convert to string
    find_cr_pf = find_cr_pf.__str__()
    # delete unneccessary words name/>/'/=
    find_cr_pf = find_cr_pf.replace("name","")
    find_cr_pf = find_cr_pf.replace(">", "")
    find_cr_pf = find_cr_pf.replace("=", "")
    find_cr_pf = find_cr_pf.replace("'", "")
    # convert to list
    find_cr_pf_list = find_cr_pf.strip('][').split(', ')

    #cycle for printing all items in list
    x = 0
    while x < len(find_cr_pf_list):
        print(find_cr_pf_list[x])
        x = x + 1
# function for get ipsec Phase 2 crypto profile list
def getph2crypto(apikey):
    url_cr_pf_list = "https://{}/api/?type=config&action=get&key={}&xpath=/config/devices/entry[@name=%27localhost.localdomain%27]/network/ike/crypto-profiles/ipsec-crypto-profiles".format(hostname,apikey)
    cr_pf = requests.get(url_cr_pf_list, verify=False)
    # convert output to text
    cr_pf = cr_pf.text
    # find string where name pattern find
    cr_regex = r'name=.*'
    find_cr_pf = re.findall(cr_regex, cr_pf)

    # convert to string
    find_cr_pf = find_cr_pf.__str__()
    # delete unneccessary words name/>/'/=
    find_cr_pf = find_cr_pf.replace("name","")
    find_cr_pf = find_cr_pf.replace(">", "")
    find_cr_pf = find_cr_pf.replace("=", "")
    find_cr_pf = find_cr_pf.replace("'", "")
    # convert to list
    find_cr_pf_list = find_cr_pf.strip('][').split(', ')

    #cycle for printing all items in list
    x = 0
    while x < len(find_cr_pf_list):
        print(find_cr_pf_list[x])
        x = x + 1

# Create tunnel interface with IP address
def createtunint_ip(apikey,freetunnum,tun_ip,comment):
    create_tun_int_ip_com = "https://{}/api/?type=config&action=set&key={}&xpath=/config/devices/entry[@name='localhost.localdomain']/network/interface/tunnel/units/entry[@name='tunnel.{}']&element=<ip><entry name='{}'/></ip><comment>{}</comment><interface-management-profile>Allow-Ping</interface-management-profile>".format(hostname,apikey,freetunnum,tun_ip,comment)
    create_tun_int = requests.get(create_tun_int_ip_com, verify=False)
    print("Tunnel interface tunnel.{} with {} IP address was created ".format(freetunnum,tun_ip))

# Create tunnel interface without IP address
def createtunint(apikey,freetunnum,comment):
    create_tun_int_ip_com = "https://{}/api/?type=config&action=set&key={}&xpath=/config/devices/entry[@name='localhost.localdomain']/network/interface/tunnel/units/entry[@name='tunnel.{}']&element=<comment>{}</comment>".format(hostname,apikey,freetunnum,comment)
    create_tun_int = requests.get(create_tun_int_ip_com, verify=False)
    print("Tunnel interface tunnel.{} was created ".format(freetunnum))
# Create IKE Gateway (Phase 1)
def createikegateway(apikey,ike_gateway_name,key,dpd,interval,retry,ikeprofile,localaddr,localinterface,peerip):
    createikegateway_com = "https://{}/api/?type=config&action=set&key={}" \
                            "&xpath=/config/devices/entry[@name='localhost.localdomain']/network/ike/gateway/entry[@name='{}']&" \
                            "element=<authentication><pre-shared-key><key>{}</key></pre-shared-key></authentication><protocol><ikev1>" \
                            "<dpd><enable>{}</enable><interval>{}</interval><retry>{}</retry></dpd><ike-crypto-profile>{}</ike-crypto-profile></ikev1>" \
                            "<ikev2><dpd><enable>yes</enable></dpd></ikev2></protocol>" \
                            "<local-address><ip>{}</ip><interface>{}</interface></local-address><protocol-common><nat-traversal><enable>no</enable></nat-traversal>" \
                            "<fragmentation><enable>no</enable></fragmentation></protocol-common><peer-address><ip>{}</ip></peer-address><disabled>no</disabled>".\
        format(hostname,apikey,ike_gateway_name,key,dpd,interval,retry,ikeprofile,localaddr,localinterface,peerip)
    createikegateway_r = requests.get(createikegateway_com, verify=False)
    print("IKE Gateway was created")


# Function for enter and preapre command for proxy ids
def enterproxies(company):
    # Number (amount of) local proxy ids
    numlocalproxyid = input("Enter number of (AMOUNT OF) local proxy (interested traffic) IDs: \n")
    # Number (amount of) remote proxy ids
    numremoteproxyid = input("Enter number of (AMOUNT OF) remote proxy (interested traffic) IDs: \n")

    # Create new LIST type var for enter local and remote proxies
    # Global required for use remote ip in other function (static route)
    global remoteproxyid_new
    localproxyid_new = []
    remoteproxyid_new = []

    # Convert to int type for further operations
    numlocalproxyid = int(numlocalproxyid)
    numremoteproxyid = int(numremoteproxyid)


    #Enter list of local proxies
    n = 1
    while (n -1) < numlocalproxyid:
        localproxyid = input("Enter LOCAL proxy id (interested traffic) (Example: 10.45.22.2/32)    ----    "  + n.__str__() + "/" + numlocalproxyid.__str__() + ": \n")
        localproxyid_new.append(localproxyid)
        n = n + 1

    #Enter list of remote proxies
    n = 1
    while (n - 1) < numremoteproxyid:
        remoteproxyid = input("Enter REMOTE proxy id (interested traffic) (Example: 10.45.22.3/32)    ----    "  + n.__str__() + "/" + numremoteproxyid.__str__() + ": \n")
        remoteproxyid_new.append(remoteproxyid)
        n = n + 1

    # empty string for further fill proxy ids
    proxyid = ""
    proxy_id_begin = "<proxy-id>"
    proxy_id_end = "</proxy-id>"

    # c var use for name identification
    c = 0
    # fill begin for proxy id
    proxyid = proxyid + proxy_id_begin

    # double iterations for preapre command proxy id
    for i in range(len(localproxyid_new)):
        for x1 in range(len(remoteproxyid_new)):
            c = c +1
            proxyid = proxyid + "<entry name='{}-{}'><protocol><any/></protocol><local>{}</local><remote>{}</remote></entry>".format(company, c, localproxyid_new[i], remoteproxyid_new[x1])
    c = c + 1


    proxyid = proxyid + proxy_id_end

    return(proxyid)

# function for create ipsec tunnel
def createipsectun(apikey,ipsec_tun_name,ike_gateway_name,proxies,ipseccrypto,tunnum):
    createipsectun_com = "https://{}/api/?type=config&action=set&key={}&xpath=/config/devices/entry[@name='localhost.localdomain']/network/" \
                         "tunnel/ipsec/entry[@name='{}']&element=<auto-key><ike-gateway><entry name='{}'/></ike-gateway>{}<ipsec-crypto-profile>{}</ipsec-crypto-profile>" \
                         "</auto-key><tunnel-monitor><enable>no</enable></tunnel-monitor><tunnel-interface>tunnel.{}</tunnel-interface>" \
                         "<disabled>no</disabled>".format(hostname,apikey,ipsec_tun_name,ike_gateway_name,proxies,ipseccrypto,tunnum)
    createipsectun_r = requests.get(createipsectun_com, verify=False)
    print("IPSEC Tunnel interface was created")


def assigntuntovirtualrouter(apikey,tunnumvr):
    assigntuntovirtrouter_c = "https://{}/api/?type=config&action=set&key={}" \
                              "&xpath=/config/devices/entry[@name='localhost.localdomain']/network/virtual-router/entry[ @ name = 'default']/" \
                              "interface&element=<member>tunnel.{}</member>".format(hostname,apikey,tunnumvr)
    assigntuntovirtrouter = requests.get(assigntuntovirtrouter_c, verify=False)
    print("Tunnel interface was assigned to virtual router")
    return assigntuntovirtrouter


def assigntuntoseczone(apikey,tunnumsc):
    assigntuntoseczone_c = "https://{}/api/?type=config&action=set&key={}" \
                           "&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/zone/entry[@name='VPN Router']&element=<network>" \
                           "<layer3><member>tunnel.{}</member></layer3></network>".format(hostname,apikey,tunnumsc)
    assigntuntoseczone_r = requests.get(assigntuntoseczone_c, verify=False)
    print("Tunnel interface was assigned to VPN Router Security Zone")
    return assigntuntoseczone_r


def addstaticroute(apikey,statroutename,tunnum,metric,destination):
    addstaticroute_c = "https://{}/api/?type=config&action=set&key={}" \
                       "&xpath=/config/devices/entry[@name='localhost.localdomain']/network/virtual-router/entry[@name='default']/routing-table/ip/static-route" \
                       "&element=<entry name='{}'><interface>tunnel.{}</interface><metric>{}</metric><destination>{}</destination></entry>".format(hostname,apikey,statroutename,tunnum,metric,destination)
    addstaticroute_r = requests.get(addstaticroute_c, verify=False)
    print("Static route was added")


def addstaticroute_tunnel(apikey,statroutename,monitname,sourcemonit,destinationmonit,tunnum,metric,destination):
    addstaticroute_c = "https://{}/api/?type=config&action=set&key={}&xpath=/config/devices/entry[@name='localhost.localdomain']/network/virtual-router/entry[@name='default']/routing-table/ip/static-route&element=<entry name='{}'><path-monitor><monitor-destinations><entry name='{}'><enable>yes</enable><source>{}</source><destination>{}</destination><interval>3</interval><count>5</count></entry></monitor-destinations><enable>yes</enable><failure-condition>any</failure-condition><hold-time>2</hold-time></path-monitor><interface>tunnel.{}</interface><metric>{}</metric><destination>{}</destination></entry>".format(apikey,statroutename,monitname,sourcemonit,destinationmonit,tunnum,metric,destination)
    addstaticroute_r = requests.get(hostname,addstaticroute_c, verify=False)
    print("Static route was added")

# used in creating ipsec tunnel without proxy id
free_string = ""
username = getpass.getuser()
getpass.getpass(prompt='Enter the password for {}\n'.format(username), stream=None)

#Generate API key and add to var for futher use
apikey = getapikey(username,password)

# Primary metric for static routing
metric_primary = 5
# Secondary metric for static routing
metric_secondary = 15
#Company name between which VPN initialize
company = input("Enter Company name: \n")

#Primary name for use in naming IKE gateway, ipsec tunnel and etc
primary_name = company + "_Primary"
#Secondary name for use in naming IKE gateway, ipsec tunnel and etc
secondary_name = company + "_Secondary"

key = input("Enter pre-shared key: \n")
dpd = input("DPD enable or not (yes or no): \n")
interval = input("Enter DPD interval in sec: \n")
retry = input("Enter DPD retry in sec: \n")
print("List of IKE gateways (Phase 1): \n")
print(getph1crypto(apikey))
ikegateway = input("Enter (COPY) IKE Gateway Profile: \n")
print("List of IPSEC crypto profiles (Phase 2): \n")
print(getph2crypto(apikey))
ipseccryptoprofile = input("Enter (COPY) IPSEC Crypto Profile: \n")
optionpeeripnumber = input("Company has 1 or  2 peer IP address (enter 1 or 2): \n ")
optionprxyortunnel = input("Select option: 1 or 2: 1 - proxy id based rules; 2 - tunnel based VPN: \n")
proxies_input = enterproxies(company)

if optionprxyortunnel == "2":
    # Tunnel interface IP
    tunip = input("Enter IP address for Tunnel interface (Example: 10.220.22.1/30): \n")
    desttunip = input("Enter tunnel IP addess on " + company + "side (Example: 10.220.22.2): \n")

if optionpeeripnumber == "1":
    peerip = input("Enter peer IP address (Example: 81.56.65.22) of " + company + "\n")


if optionpeeripnumber == "2":
    peerip = input("Enter PRIMARY peer IP address (Example: 81.56.65.22)  of " + company + "\n")
    peerip2 = input("Enter SECONDARY peer IP address (Example: 85.22.58.49)  of " + company + "\n")



if optionprxyortunnel == "1" and optionpeeripnumber == "1":
    # Get free tunnel number
    tunnum1 = free_tun_number(apikey)
    # Create new tunnel interface
    createtunint(apikey,tunnum1,primary_name)
    # assign tun interface to virtual router
    assigntuntovirtualrouter(apikey,tunnum1)
    # assign tun interface to VPN Router security zone
    assigntuntoseczone(apikey,tunnum1)
    commitchange(apikey)
    #Create phase 1
    createikegateway(apikey,primary_name, key, dpd, interval, retry, ikegateway, "81.21.95.53/30", "ae2.138", peerip)
    #Create phase 2
    createipsectun(apikey,primary_name,primary_name,proxies_input,ipseccryptoprofile,tunnum1)
    # Add static routes. Values get from Global var (proxy ids)
    cc = 1
    for x2 in range(len(remoteproxyid_new)):
        statroutename = primary_name + "-" + cc.__str__()
        addstaticroute(apikey,statroutename, tunnum1, metric_primary, remoteproxyid_new[x2])
        cc = cc + 1


    # Create secondary tunnel/ike/ipsectunnel
    # Get free tunnel number
    tunnum2 = free_tun_number(apikey)
    # Create new tunnel interface
    createtunint(apikey,tunnum2, secondary_name)
    # Assign tunnel interface to virtual router
    assigntuntovirtualrouter(apikey,tunnum2)
    # Assign tunnel interface to VPN Route security zone
    assigntuntoseczone(apikey,tunnum2)

    commitchange(apikey)
    # Create phase 1
    createikegateway(apikey,secondary_name, key, dpd, interval, retry, ikegateway, "85.132.71.113/28", "ae2.859", peerip)
    # Create phase 2
    createipsectun(apikey,secondary_name, secondary_name, proxies_input, ipseccryptoprofile, tunnum2)

    # Add static routes. Values get from Global var (proxy ids)
    cc = 1
    for x3 in range(len(remoteproxyid_new)):
        statroutename = secondary_name + "-" + cc.__str__()
        addstaticroute(apikey,statroutename, tunnum2, metric_secondary, remoteproxyid_new[x3])
        cc = cc + 1


if optionprxyortunnel == "1" and optionpeeripnumber == "2":
    # Get free tunnel number
    tunnum1 = free_tun_number(apikey)
    # Create new tunnel interface
    createtunint(apikey,tunnum1, primary_name)
    # assign tun interface to virtual router
    assigntuntovirtualrouter(apikey,tunnum1)
    # assign tun interface to VPN Router security zone
    assigntuntoseczone(apikey,tunnum1)
    commitchange(apikey)
    # Create phase 1
    createikegateway(apikey,primary_name, key, dpd, interval, retry, ikegateway, "81.21.95.53/30", "ae2.138", peerip)
    # Create phase 2
    createipsectun(apikey,primary_name, primary_name, proxies_input, ipseccryptoprofile, tunnum1)
    # Add static routes. Values get from Global var (proxy ids)
    cc = 1
    for x2 in range(len(remoteproxyid_new)):
        statroutename = primary_name + "-" + cc.__str__()
        addstaticroute(apikey,statroutename, tunnum1, metric_primary, remoteproxyid_new[x2])
        cc = cc + 1

    # Create secondary tunnel/ike/ipsectunnel
    # Get free tunnel number
    tunnum2 = free_tun_number(apikey)
    # Create new tunnel interface
    createtunint(apikey,tunnum2, secondary_name)
    # Assign tunnel interface to virtual router
    assigntuntovirtualrouter(apikey,tunnum2)
    # Assign tunnel interface to VPN Route security zone
    assigntuntoseczone(apikey,tunnum2)

    commitchange(apikey)
    # Create phase 1
    createikegateway(apikey,secondary_name, key, dpd, interval, retry, ikegateway, "85.132.71.113/28", "ae2.859", peerip2)
    # Create phase 2
    createipsectun(apikey,secondary_name, secondary_name, proxies_input, ipseccryptoprofile, tunnum2)

    # Add static routes. Values get from Global var (proxy ids)
    cc = 1
    for x3 in range(len(remoteproxyid_new)):
        statroutename = secondary_name + "-" + cc.__str__()
        addstaticroute(apikey,statroutename, tunnum2, metric_secondary, remoteproxyid_new[x3])
        cc = cc + 1

if optionprxyortunnel == "2" and optionpeeripnumber == "1":
    # Get free tunnel number
    tunnum1 = free_tun_number(apikey)
    # Create new tunnel interface
    createtunint_ip(apikey, tunnum1, tunip, primary_name)

    # assign tun interface to virtual router
    assigntuntovirtualrouter(apikey,tunnum1)
    # assign tun interface to VPN Router security zone
    assigntuntoseczone(apikey,tunnum1)
    commitchange(apikey)
    # Create phase 1
    createikegateway(apikey,primary_name, key, dpd, interval, retry, ikegateway, "81.21.95.53/30", "ae2.138", peerip)
    # Create phase 2
    createipsectun(apikey,primary_name, primary_name, free_string , ipseccryptoprofile, tunnum1)

    # Add static routes. Values get from Global var (proxy ids)
    cc = 1
    for x2 in range(len(remoteproxyid_new)):
        statroutename = primary_name + "-" + cc.__str__()
        monitname = company + "_Path_Monit_" + cc.__str__()
        addstaticroute_tunnel(apikey,statroutename, monitname, tunip, desttunip, tunnum1, metric_primary, remoteproxyid_new[x2])
        cc = cc + 1

    # Create secondary tunnel/ike/ipsectunnel
    # Get free tunnel number
    tunnum2 = free_tun_number(apikey)
    # Create new tunnel interface
    createtunint(apikey,tunnum2, secondary_name)
    # Assign tunnel interface to virtual router
    assigntuntovirtualrouter(apikey,tunnum2)
    # Assign tunnel interface to VPN Route security zone
    assigntuntoseczone(apikey,tunnum2)

    commitchange(apikey)
    # Create phase 1
    createikegateway(apikey,secondary_name, key, dpd, interval, retry, ikegateway, "85.132.71.113/28", "ae2.859", peerip)
    # Create phase 2
    createipsectun(apikey,secondary_name, secondary_name, free_string, ipseccryptoprofile, tunnum2)
    # Add static routes. Values get from Global var (proxy ids)
    cc = 1
    for x3 in range(len(remoteproxyid_new)):
        statroutename = secondary_name + "-" + cc.__str__()
        addstaticroute(apikey, statroutename, tunnum2, metric_secondary, remoteproxyid_new[x3])
        cc = cc + 1


if optionprxyortunnel == "2" and optionpeeripnumber == "2":
    # Get free tunnel number
    tunnum1 = free_tun_number(apikey)
    # Create new tunnel interface
    createtunint_ip(apikey,tunnum1, tunip, primary_name)
    # assign tun interface to virtual router
    assigntuntovirtualrouter(apikey,tunnum1)
    # assign tun interface to VPN Router security zone
    assigntuntoseczone(apikey,tunnum1)
    commitchange(apikey)
    # Create phase 1
    createikegateway(apikey,primary_name, key, dpd, interval, retry, ikegateway, "81.21.95.53/30", "ae2.138", peerip)
    # Create phase 2
    createipsectun(apikey,primary_name, primary_name, "", ipseccryptoprofile, tunnum1)
    # Add static routes. Values get from Global var (proxy ids)
    cc = 1
    for x2 in range(len(remoteproxyid_new)):
        statroutename = primary_name + "-" + cc.__str__()
        monitname = company + "_Path_Monit_" + cc.__str__()
        addstaticroute_tunnel(apikey,statroutename, monitname, tunip, desttunip, tunnum1, metric_primary, remoteproxyid_new[x2])
        cc = cc + 1

    # Create secondary tunnel/ike/ipsectunnel
    # Get free tunnel number
    tunnum2 = free_tun_number(apikey)
    # Create new tunnel interface
    createtunint(apikey,tunnum2, secondary_name)
    # Assign tunnel interface to virtual router
    assigntuntovirtualrouter(apikey,tunnum2)
    # Assign tunnel interface to VPN Route security zone
    assigntuntoseczone(apikey,tunnum2)

    commitchange(apikey)
    # Create phase 1
    createikegateway(apikey,secondary_name, key, dpd, interval, retry, ikegateway, "85.132.71.113/28", "ae2.859", peerip2)
    # Create phase 2
    createipsectun(apikey,secondary_name, secondary_name, "", ipseccryptoprofile, tunnum2)
    # Add static routes. Values get from Global var (proxy ids)
    cc = 1
    for x3 in range(len(remoteproxyid_new)):
        statroutename = secondary_name + "-" + cc.__str__()
        addstaticroute(apikey, statroutename, tunnum2, metric_secondary, remoteproxyid_new[x3])
        cc = cc + 1

commitchange(apikey)

print("You should create NAT and Security rule manually")
input("Press Enter to exit")
