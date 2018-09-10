import json

'''
===============================================================================
CLASS JsonConfigWriter
===============================================================================
Intended to create a config JSON file to start the dmprd.
It uses a given template config.json with default values for every required
field.
Set...(): methods are used to modify the default values.
method writeOutputFile(...): is used to write a new JSON config file with the
modified values at a given path
===============================================================================
'''


class JsonConfigWriter:
    def __init__(self, path):
        self.templatePath = path
        self.jsonTemplateFile = open(path)
        self.jsonTemplate = self.jsonTemplateFile.read()
        self.jsonData = json.loads(self.jsonTemplate)

    def set_id(self, id):
        self.jsonData["core"]["id"] = id

    def set_interface_name(self, name, nr=0):
        self.jsonData["core"]["interfaces"][nr]["name"] = name

    def set_interface_port(self, port, nr=0):
        self.jsonData["core"]["interfaces"][nr]["port"] = port

    def set_interface_addr_v4(self, adr, nr=0):
        self.jsonData["core"]["interfaces"][nr]["addr-v4"] = adr

    def set_interface_ttl_v4(self, ttl, nr=0):
        self.jsonData["core"]["interfaces"][nr]["ttl-v4"] = ttl

    def set_interface_addr_v6(self, adr, nr=0):
        self.jsonData["core"]["interfaces"][nr]["addr-v6"] = adr

    def set_interface_ttl_v6(self, ttl, nr=0):
        self.jsonData["core"]["interfaces"][nr]["ttl-v6"] = ttl

    def set_interface_attributes_bandwith(self, bw, nr=0):
        self.jsonData["core"]["interfaces"][nr]["link-attributes"]["bandwidth"] = bw

    def set_interface_attributes_loss(self, loss, nr=0):
        self.jsonData["core"]["interfaces"][nr]["link-attributes"]["loss"] = loss

    def set_mcast_v4_tx_adr(self, address):
        self.jsonData["core"]["mcast-v4-tx-addr"] = address

    def set_mcast_v6_tx_adr(self, address):
        self.jsonData["core"]["mcast-v6-tx-addr"] = address

    def set_network_prefix(self, prefix, len, nr=0):
        self.jsonData["core"]["networks"][nr]["prefix"] = prefix
        self.jsonData["core"]["networks"][nr]["prefix-len"] = len

    def set_network_proto(self, proto, nr=0):
        self.jsonData["core"]["networks"][nr]["proto"] = proto

    def write_output_file(self, path):
        with open(path, 'w') as outfile:
            json.dump(self.jsonData, outfile)
