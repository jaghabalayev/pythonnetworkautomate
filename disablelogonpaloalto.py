import json

import requests

getrule = "{}/api/?type=config&action=set&key={}&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules/entry[@name='{}']&element=<log-start>no</log-start>"


apikey = '#HERE-IS-API-KEY#'

#Here is rulenames in list format
rule_list = ['rule1', 'rule2']

for x in rule_list:
    conf = requests.post(getrule.format("https://hostname.local", apikey, x), verify=False)

