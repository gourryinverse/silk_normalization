#!/usr/bin/python

# RESTRICTIVE SOFTWARE LICENSE AGREEMENT
# 
# This License Agreement ("Agreement") is a legal agreement between you ("Licensee")
# and Gregory Price, the author and copyright holder of the enclosed software ("Software").
# 
# 1. GRANT OF LICENSE
# 
# Gregory Price grants you a non-transferable, non-exclusive license to use the
# the Software on a single device for the purpose of evaluation. You may not
# distribute, share, or allow any other person or entity to use the Software.
# This license does not grant you any rights to the source code of the Software,
# nor may you create derivative works based on the software.
# 
# 2. COPYRIGHT
# 
# The Software is protected by copyright laws and international treaty provisions.
# You acknowledge that no title to the intellectual property in the Software is
# transferred to you. You further acknowledge that title and full ownership rights
# to the Software will remain the exclusive property of Gregory Price, and
# you will not acquire any rights to the Software, except as expressly set forth
# above.
# 
# 3. RESTRICTIONS
# 
# You may not copy, modify, reverse engineer, decompile, disassemble, or create
# derivative works of the Software. You may not rent, lease, loan, sublicense,
# distribute, or otherwise transfer rights to the Software. Any attempt to do so
# will result in immediate termination of this license.
# 
# 4. TERMINATION
# 
# This Agreement will terminate immediately without notice if you fail to comply
# with any of its terms. Upon termination, you must destroy all copies of the
# Software.  Upon completion of evaluation, you must destroy all copies of the
# software.
# 
# 5. DISCLAIMER
# 
# The Software is provided "AS IS" without warranty of any kind, either express or
# implied, including but not limited to warranties of merchantability or fitness
# for a particular purpose.
# 
# 6. LIMITATION OF LIABILITY
# 
# In no event will Gregory Price be liable for any damages whatsoever arising out
# of the use of or inability to use this Software.
# 
# By using the Software, you acknowledge that you have read this Agreement,
# understand it, and agree to be bound by its terms and conditions.

import requests
from pymongo import MongoClient
import json

MONGO_DB_URI = 'mongodb://localhost:27017/'
DATABASE_NAME = 'mydatabase'
COLLECTION_NAME = 'hosts_data'
METADATA_COLLECTION_NAME = 'fetch_metadata'
NORMALIZED_COLLECTION_NAME = 'normalized'

with open('settings.json', 'r') as f:
    data = json.load(f)

BASE_URL = data.get('baseurl')
TOKEN = data.get('token')

client = MongoClient(MONGO_DB_URI)
db = client[DATABASE_NAME]
collection = db[COLLECTION_NAME]
metadata_collection = db[METADATA_COLLECTION_NAME]
normal_collection = db[NORMALIZED_COLLECTION_NAME]

# To reset the collections, uncomment then
#collection.delete_many({})
#metadata_collection.delete_many({})
#normal_collection.delete_many({})

collection.create_index("index_id", unique=True)
collection.create_index("source")
metadata_collection.create_index("source")
normal_collection.create_index("silk_id", unique=True)
normal_collection.create_index("ip_mac_hostname", unique=True)

def get_next_silkid():
    result = db.counters.find_one_and_update(
        {"_id": "next_silk_id"},
        {"$inc": {"value": 1}},
        return_document=True,
        upsert=True
    )
    return result["value"]

def insert_record(ipmachn, source, index_value, ip, mac, hostname, version):
    record = {
        "silk_id" : get_next_silkid(),
        "ip_mac_hostname" : ipmachn,
        "source_ids" : {source : [index_value,]},
        "ip" : ip,
        "mac" : mac,
        "hostname" : hostname,
        "version" : 1
    }
    try:
        normal_collection.insert_one(record)
        return True
    except:
        # Chances are another thread already inserted this
        # But really we probaly want real error handling here
        return False

def update_record(ipmachn, source, index_value, version, record):
    version = record["version"]
    # Could probably use defaultdict here, but lazy
    if source in record["source_ids"]:
        # Could probably use another dict here, but ignore for now
        if index_value not in record["source_ids"][source]:
            record["source_ids"].append(index_value)
    else:
        record["source_ids"][source] = [index_value,]
    updates = {
        "$set" : {
            "silk_id": record["silk_id"],
            "ip_mac_hostname": record["ip_mac_hostname"],
            "source_ids": record["source_ids"],
            "ip": record["ip"],
            "mac": record["mac"],
            "hostname": record["hostname"]
        },
        "$inc": { "version": 1 }
    }
    criteria = {
        "ip_mac_hostname": ipmachn,
        "version": version
    }
    # Return whether the documented was inserted or updated
    # False if the doc changed since start (retry later)
    result = normal_collection.update_one(criteria, updates, upsert=True)
    return result.upserted_id or result.modified_count > 0

def normalize(source, index_value, ip, mac, hostname):
    ipmachn = "_".join([ip,mac,hostname])
    criteria = {"ip_mac_hostname": ipmachn}
    record = normal_collection.find_one(criteria)

    version = 1
    if not record:
        return insert_record(ipmachn, source, index_value, ip, mac, hostname, version)
    else:
        return update_record(ipmachn, source, index_value, version, record)

def normalize_crowdstrike(source, host, index_value):
    ip = host["local_ip"]
    mac = host["mac_address"].replace("-",":").lower()
    hostname = host["hostname"].lower()
    return normalize(source, index_value, ip, mac, hostname)

def normalize_qualys(source, host, index_value):
    ip = host["address"].lower()
    hostname = host["fqdn"].lower()
    mac = ""
    for interface in host["networkInterface"]["list"]:
        if interface["HostAssetInterface"]["address"] == ip:
            mac = interface["HostAssetInterface"]["macAddress"].lower()
    if not mac:
        print("some error with interface data on record:", host["index_id"])
        return None
    return normalize(source, index_value, ip, mac, hostname)

def get_last_successful_skip(source, default=0):
    record = metadata_collection.find_one({"source": source})
    print(record)
    return record['skip'] if record else default

def update_last_successful_skip(source, skip_value):
    result = metadata_collection.update_one(
        {"source": source},
        {"$set": {"skip": skip_value}},
        upsert=True
    )
    return

def fetch_hosts(endpoint, skip=0, limit=1):
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "token": TOKEN
    }

    # Payload for the POST request
    params = {
        "skip": skip,
        "limit": limit
    }

    # Sending the POST request to the API endpoint
    response = requests.post(BASE_URL + endpoint, params=params, headers=headers)

    # Check if the response was successful
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error {response.status_code}: {response.text}")
        return []

def sanitize(data):
    if isinstance(data, dict):
        sanitized = {}
        for key, value in data.items():
            # Sanitize the key
            new_key = key.replace("$", "_")

            if isinstance(value, (dict, list)):
                sanitized[new_key] = sanitize(value)
            elif isinstance(value, str):
                sanitized[new_key] = value.replace("$", "_")
            else:
                sanitized[new_key] = value
        return sanitized

    elif isinstance(data, list):
        return [sanitize(item) for item in data]

    else:
        if isinstance(data, str):
            return data.replace("$", "_")
        return data

def store_to_mongodb(collection, host, source, index_key):
    host = sanitize(host)
    index_value = source + "_" + str(host[index_key])
    filter_criteria = {"index_id": index_value}
    update_operation = {
        "$set": {
            "source": source,
            "host": host
        }
    }
    collection.update_one(filter_criteria, update_operation, upsert=True)
    return index_value

def print_dedup_entries():
    client = MongoClient(MONGO_DB_URI)
    db = client[DATABASE_NAME]
    collection = db[COLLECTION_NAME]

    # Find all documents in the collection
    documents = normal_collection.find()

    # Print each document
    for doc in documents:
        print(doc)
        print("-" * 50)  # Optional line separator for clarity
    return

# Probably turn this into a class eventually and write proper abstraction
endpoints = {
    "qualys" : ["/api/qualys/hosts/get", "_id", normalize_qualys],
    "crowdstrike" : ["/api/crowdstrike/hosts/get", "device_id", normalize_crowdstrike]
}

if __name__ == "__main__":
    for source, endpoint_info in endpoints.items():
        endpoint = endpoint_info[0]
        index_key = endpoint_info[1]

        # To reset your parsing location, uncomment this
        # Obviously should have a more progrmatic way to do this
        #update_last_successful_skip(source, 0)
        last_skip = get_last_successful_skip(source)

        while True:  # Keep fetching until no more data is returned.
            hosts = fetch_hosts(endpoint, last_skip, 1)  # Fetching 100 entries at a time.
            if not hosts:  # Break out of the loop if no more data is returned.
                break

            for host in hosts:
                index_value = store_to_mongodb(collection, host, source, index_key)
                endpoint_info[2](source, host, index_value)
            update_last_successful_skip(source, last_skip)
            last_skip += 1
    print_dedup_entries()
