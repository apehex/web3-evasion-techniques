import csv
import json
import web3

# RPCs ########################################################################

with open('.env.json', 'r') as _f:
    _ENV = json.load(_f)

PROVIDERS = {
    int(_k): {
        'rpc': web3.Web3(Web3.HTTPProvider(_v['rpc'])),
        'api': _v.get('api', '')}
    for _k, _v in _ENV.items() if _v.get('rpc', '')}

# DOWNLOAD ####################################################################

with open('all.csv', 'r') as _f:
    _r = csv.reader(_f, delimiter=',')
    for _l in _r:
        int(_l[0]) in PROVIDERS

# web3.eth.get_code('0x6C8f2A135f6ed072DE4503Bd7C4999a1a17F824B')
