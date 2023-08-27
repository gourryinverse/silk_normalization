#!/usr/bin/python

# Copyright Gregory Price, 2023
#
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

class JSONWrapper:
    def __init__(self, data:dict):
        for key, value in data.items():
            if isinstance(value, dict):
                setattr(self, key, JSONWrapper(value))
            else:
                setattr(self, key, value)
        return

    def __getattr__(self, key:str):
        if key in self.__dict__:
            return self.__dict__[key]
        raise AttributeError(f"'{type(self).__name__}' object has no attribute '{key}'")

    def __iter__(self):
        return iter(self.__dict__.values())

    def get_dict(self):
        return self.__dict__

class NormalData():
    _data = {}

    def __init__(self, ip:str, mac:str, hostname:str):
        self._data = {"ip":ip, "mac":mac, "hostname":hostname}
        return

    def __getattr__(self, key):
        if key in self._data:
            return self._data[key]
        raise AttributeError(f"'{type(self).__name__}' object has no attribute '{key}'")

class Source():
    _data = None

    def __init__(self, data:dict):
        self._data = data

    def __getattr__(self, key):
        if key in self._data:
            return self._data[key]
        raise AttributeError(f"'{type(self).__name__}' object has no attribute '{key}'")

    def get_dict(self) -> dict:
        return self._data


class Sources():
    _sources = None

    def __init__(self, settings:JSONWrapper):
        self._sources = settings.sources.get_dict()
        return

    def __getattr__(self, key):
        if key in self._sources:
            return self._sources[key]
        raise AttributeError(f"'{type(self).__name__}' object has no attribute '{key}'")

    def __iter__(self):
        return iter(self._sources.values())

    def get_dict(self) -> dict:
        return self._sources

class DBInterface():
    settings = None
    client = None
    db = None
    raw_collection = None
    metadata_collection = None
    normal_collection = None
    sources = None

    def __init__(self, settings:JSONWrapper, sources:Sources):
        self.settings = settings.database
        self.client = MongoClient(self.settings.uri)
        self.db = self.client[self.settings.name]
        self.raw_collection = self.db[self.settings.collections.raw]
        self.metadata_collection = self.db[self.settings.collections.metadata]
        self.normal_collection = self.db[self.settings.collections.normalized]
        self.sources = sources
        self.reset_database(settings.database.reset)
        return

    def reset_database(self, delete_all:bool):
        if (delete_all):
            self.raw_collection.delete_many({})
            self.metadata_collection.delete_many({})
            self.normal_collection.delete_many({})
            for source in self.sources:
                self.update_last_successful_skip(source, 0)
        self.raw_collection.create_index("index_id", unique=True)
        self.raw_collection.create_index("source")
        self.metadata_collection.create_index("source")
        self.normal_collection.create_index("silk_id", unique=True)
        self.normal_collection.create_index("ip_mac_hostname", unique=True)
        return

    def get_last_successful_skip(self, source:Source, default:int = 0) -> int:
        record = self.metadata_collection.find_one({"source": source.get_dict()})
        return record['skip'] if record else default

    def update_last_successful_skip(self, source, skip_value):
        result = self.metadata_collection.update_one(
            {"source": source.get_dict()},
            {"$set": {"skip": skip_value}},
            upsert=True
        )
        return

    def sanitize_raw_record(self, data) -> dict:
        if isinstance(data, dict):
            sanitized = {}
            for key, value in data.items():
                # Sanitize the key
                new_key = key.replace("$", "_")

                if isinstance(value, (dict, list)):
                    sanitized[new_key] = self.sanitize_raw_record(value)
                elif isinstance(value, str):
                    sanitized[new_key] = value.replace("$", "_")
                else:
                    sanitized[new_key] = value
            return sanitized

        elif isinstance(data, list):
            return [self.sanitize_raw_record(item) for item in data]

        else:
            if isinstance(data, str):
                return data.replace("$", "_")
            return data

    def insert_raw_record(self, source:Source, host:dict) -> str:
        host = self.sanitize_raw_record(host)
        index_value = source.name + "_" + str(host[source.index_id])
        filter_criteria = {"index_id": index_value}
        update_operation = {
            "$set": {
                "source": source.name,
                "host": host
            }
        }
        self.raw_collection.update_one(filter_criteria, update_operation, upsert=True)
        return index_value

    def get_next_silkid(self) -> int:
        result = self.db.counters.find_one_and_update(
            {"_id": "next_silk_id"},
            {"$inc": {"value": 1}},
            return_document=True,
            upsert=True
        )
        return result["value"]

    def insert_normal_record(self, ipmachn:str, source:Source, index_value:str, data:NormalData) -> bool:
        record = {
            "silk_id" : self.get_next_silkid(),
            "ip_mac_hostname" : ipmachn,
            "source_ids" : {source.name : [index_value,]},
            "ip" : data.ip,
            "mac" : data.mac,
            "hostname" : data.hostname,
            "version" : 1
        }
        try:
            self.normal_collection.insert_one(record)
            return True
        except:
            # Chances are another thread already inserted this
            # But really we probaly want real error handling here
            return False

    def update_normal_record(self, ipmachn:str, source:Source, index_value:str, record:dict) -> bool:
        version = record["version"]
        # Could probably use defaultdict here, but lazy
        if source.name in record["source_ids"]:
            # Could probably use another dict here, but ignore for now
            if index_value not in record["source_ids"][source.name]:
                record["source_ids"].append(index_value)
        else:
            record["source_ids"][source.name] = [index_value,]
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
        result = self.normal_collection.update_one(criteria, updates, upsert=True)
        return result.upserted_id or result.modified_count > 0

    def add_normal_record(self, source:Source, index_value:str, data:NormalData) -> bool:
        ipmachn = "_".join([data.ip,data.mac,data.hostname])
        criteria = {"ip_mac_hostname": ipmachn}
        record = self.normal_collection.find_one(criteria)

        version = 1
        if not record:
            return self.insert_normal_record(ipmachn, source, index_value, data)
        else:
            return self.update_normal_record(ipmachn, source, index_value, record)

    def print_dedup_entries(self):
        documents = self.normal_collection.find()
        for doc in documents:
            print(doc)
            print("-" * 50) # Separater for clarity
        return


class Normalizer():
    settings = None

    def __init__(self, settings):
        self.settings = settings.normalizer
        return

    def normalize_crowdstrike(self, source:Source, host:dict, index_value:str) -> NormalData:
        ip = host["local_ip"]
        mac = host["mac_address"].replace("-",":").lower()
        hostname = host["hostname"].lower()
        return NormalData(ip, mac, hostname)

    def normalize_qualys(self, source:Source, host:dict, index_value:str) -> NormalData:
        ip = host["address"].lower()
        hostname = host["fqdn"].lower()
        mac = ""
        for interface in host["networkInterface"]["list"]:
            if interface["HostAssetInterface"]["address"] == ip:
                mac = interface["HostAssetInterface"]["macAddress"].lower()
        if not mac:
            print("some error with interface data on record:", host["index_id"])
            return None
        return NormalData(ip, mac, hostname)

    def normalize(self, source:Source, host:dict, index_value:str) -> NormalData:
        normalize_method = "normalize_"+source.name
        if hasattr(self, normalize_method):
            return getattr(self, normalize_method)(source, host, index_value)
        raise AttributeError(f"'{type(self).__name__}' object has no normalize method for Source: '{source.name}'")


class Fetcher():
    settings = None
    headers = None

    def __init__(self, settings):
        self.settings = settings
        self.headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "token": settings.fetcher.token
        }
        return

    def fetch_hosts(self, source:Source, skip:int=0, limit:int=1) -> list:
        # Payload for the POST request
        params = {
            "skip": skip,
            "limit": limit
        }

        # Sending the POST request to the API endpoint
        url = self.settings.fetcher.base_url + source.endpoint
        response = requests.post(url, params=params, headers=self.headers)

        # Check if the response was successful
        if response.status_code == 200:
            return response.json()
        else:
            print(f"Error {response.status_code}: {response.text}")
            return []


class PipeLine():
    sources = None
    fetcher = None
    normalizer = None
    database = None

    def __init__(self, settings):
        self.settings = settings
        self.sources = Sources(settings)
        self.fetcher = Fetcher(settings)
        self.database = DBInterface(settings, self.sources)
        self.normalizer = Normalizer(settings)
        return

    def ExecuteBatch(self, source:Source, start:int, limit:int) -> bool:
        hosts = self.fetcher.fetch_hosts(source, start, limit)
        if not hosts:
            return False
        for host in hosts:
            index_value = self.database.insert_raw_record(source, host)
            normal_data = self.normalizer.normalize(source, host, index_value)
            if normal_data:
                self.database.add_normal_record(source, index_value, normal_data)
        # Right now this will just end up skipping any records that were fetched
        # but not necessarily successfully inserted or normalized.  Realistically
        # I would probably fail if it failed to insert the raw data or record
        # the record number that failed in a separate database and move on.  If
        # i failed to normalize, i would place it in a deferred list and try again
        # later, and if that failed i would report an error for manual inspection.
        # Either way, we would want to continue on if at all possible, unless we
        # think the potential for poisoning the database is too high, then we should
        # fail out immediately on failure of either step.
        self.database.update_last_successful_skip(source, start+limit)
        return True

    def Execute(self):
        for source in self.sources:
            while True:
                start = self.database.get_last_successful_skip(source, 0)
                if not self.ExecuteBatch(source, start, self.settings.pipeline.fetch_interval):
                    break
        self.database.print_dedup_entries()
        return

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--reset', action='store_true', default=None,
        help='Reset the database before starting')
    args = parser.parse_args()

    with open('settings.json', 'r') as f:
        settings = JSONWrapper(json.load(f))

    if args.reset is not None:
        settings.database.reset = args.reset

    pipeline = PipeLine(settings)
    pipeline.Execute()
