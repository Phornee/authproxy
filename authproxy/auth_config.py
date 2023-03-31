"""
Config file holding the mapping between the domain names and the internal hosts
"""

mapping = {'grafana.phornee.synology.me': {'host': 'http://192.168.0.16:3000', 'endpoint': '', 'method': 'GET'},
           'waterflow.phornee.synology.me': {'host': 'http://192.168.0.15:80', 'endpoint': 'waterflow', 'method': 'GET'}
          }
