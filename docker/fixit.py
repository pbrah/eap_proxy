#!/usr/bin/python
import pymongo
import pprint
import sys
import fcntl, socket, struct

try:
    if_wan = sys.argv[1]
except:
    pprint.pprint("Usage: fixit.py <interface>")
    pprint.pprint("Example: fixit.py eth8")
    sys.exit()

def getHwAddr(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', ifname[:15]))
    return ':'.join(['%02x' % ord(char) for char in info[18:24]])


#Set up the connection
client = pymongo.MongoClient("mongodb://localhost:27117/")

#Specify the database
database = client["ace"]

#Specify the collection
collection = database[ "device" ]

#Get UDM Pro system mac
udmpromac = getHwAddr('eth0')

#Find the document in the collection
document = collection.find_one( {"mac": udmpromac })

#Store the _id of the document you found
device_id = document.get('_id')


#*print original
pprint.pprint("Listing current ethernet_table:")

#update ethernet_table and print
document = collection.find_one( {"mac": udmpromac })
ethernet_table = document.get('ethernet_table')
pprint.pprint(ethernet_table)

pprint.pprint("")

#Deleting all wan interfaces
pprint.pprint("Deleting all entries for wan interface:")
pprint.pprint("")
pprint.pprint(if_wan)
pprint.pprint("")
collection.update_many(
    { "_id": device_id}, {
        '$pull': {
            "ethernet_table": { "name": if_wan } } } )

#update ethernet_table and print again
document = collection.find_one( {"mac": udmpromac })
ethernet_table = document.get('ethernet_table')
pprint.pprint(ethernet_table)

pprint.pprint("")

#insert single entry for existing eth8 mac address
pprint.pprint("Inserting single entry for wan interface")
pprint.pprint("")
pprint.pprint(if_wan)
pprint.pprint("")
mac = getHwAddr(if_wan)
collection.update_one(
    { "_id": device_id}, {
        '$push': {
            "ethernet_table": {
                "mac": mac, "name": if_wan, "num_port": 1 } } } )

#update ethernet_table and print again
document = collection.find_one( {"mac": udmpromac })
ethernet_table = document.get('ethernet_table')
pprint.pprint(ethernet_table)

pprint.pprint("")

