import requests
import os
from datetime import datetime
import time

# import datetime

hostname1 = "firewall1"
hostname2 = "firewall2"
apikey = "apikey"
# API Request for get XML configuration file
url_palo1 = "https://{}/api/?type=export&category=configuration&key={}".format(hostname1,apikey)
url_palo2 = "https://{}/api/?type=export&category=configuration&key={}".format(hostname2,apikey)


# Run Request

def backup(url, name):

    conf = requests.get(url, verify=False)
    # Get now date and time
    now = datetime.now()
    # Format for today date and time
    date = now.strftime("%d-%m-%Y")
    path = 'C:\\test\\'
    # Create filename with date in name
    filename = name + '_' + date + '.xml'
    # Save XML to file

    with open(path + filename, 'wb') as f:
        f.write(conf.content)

    current_time = time.time()
    print(current_time)
    
    
    for x in os.listdir(path):
        # creation_time = os.path.getctime(path + x)
        creation_time = os.path.getctime(path + x)
        # print(creation_time)
        # Check and delete backup files older than 30 days
        if (current_time - creation_time) // (24 * 3600) >= 30:
            os.remove(path + x)
           # print('{} removed'.format(x))


backup(url_palo1, 'palo1')
backup(url_palo2, 'palo2')
