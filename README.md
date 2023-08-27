# Objective

1) Collect all hosts from the following endpoints
2) Normalize the hosts collected here into a common format
3) Deduplicate top level metadata records

This could probably be split up into 3 discrete scripts if you wanted
to do these steps separately and then operate in a read-only fashion
on each subsequent step - but since the data here is limited, we will
do it all in one script.

To run:
./analyze.py

To reset the database before executing the pipeline:
./analyze.py --reset

The output will be deduplicated metadata records that maintain pointers
back to the original records so that additional information can be queried
or later normalized further.

# Settings

You will need to create the 'settings.json' file with the following json
Make sure to apply your token and baseurl to settings.fetcher

To reset the database, change settings.database.reset or use the --reset flag

{
    "pipeline" : {
        "fetch_interval" : 1
    },
    "fetcher" : {
        "base_url" : "your_base_url",
        "token" : "your_secret"
    },
    "database" : {
        "uri" : "mongodb://localhost:27017/",
        "name" : "mydatabase",
        "collections" : {
            "raw" : "hosts_data",
            "metadata" : "fetch_metadata",
            "normalized" : "normalized"
        },
        "reset" : true

    },
    "sources" : {
        "qualys" : {
            "name" : "qualys",
            "endpoint" : "/api/qualys/hosts/get",
            "index_id" : "_id"
        },
        "crowdstrike" : {
            "name" : "crowdstrike",
            "endpoint" : "/api/crowdstrike/hosts/get",
            "index_id" : "device_id"
        }
    }
}

# Collection

Simply iterate through the endpoints to collect each record.

Keep count of where we left off in case we decide to break and come back.

For now I iterate 1 at a time since the API limit is 2 records.  But
realistically this could be parallelized. 

# Normalization and Deduplication

We do these at the same time, technically.  Since we index on common
data, we can use that to simply re-use work we've already done rather than
generating duplicates from the get-go.

## Normalization

I don't know what is really important in the qualys and crowdstrike data
from a quick view, so i will focus on normalizing just common fields:

- ip address
- mac address
- hostname

Our actual normalized structure is as such:

{
    "silk_id" : int,
    "ip_mac_hostname" : str,
    "source_ids" : list,
    "ip" : str,
    "mac" : str,
    "hostname" : str,
    "version" : int
}

ip, mac, and hostname are all normalized from different named fields in the
source data, and the formatting is normalized (lowercase only, common formatting
for mac addresses - as examples)

Note: Some hosts have multiple ip addresses and mac's.  We used the field that seemed
most reasonable given the context of the data, but we would probably need additional
analysis on larger portions of data to determine what is actually reasonable (or if
different fields should be used).

## Deduplication

We will concatenate the 3 major pieces of information into an index id
and simply add references to the raw data from each source to prevent
multiple meta-data entries.

Once there is a better understanding about what data is preferred, instead
there can be a step here to do that at the same time as well. 
