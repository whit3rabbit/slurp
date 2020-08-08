# slurp
Enumerates S3 buckets manually or via certstream

## Overview
- First of all, credit to https://github.com/eth0izzle/bucket-stream for the certstream idea
- Also, credit to all the vendor packages that made this tool possible
- Not responsible for how you use this tool.

![certstream](https://i.imgur.com/6JUDNI5.png)

![manual](https://i.imgur.com/d28yX1Y.png)

### Features
- Written in Go:
    - It's faster than python
    - No dependency hell and version locks (ie python 3 and requirements.txt, etc)
    - Better concurrency
- Manual mode so that you can test individual domains.
- Certstream mode so that you can enumerate s3 buckets in real time.
- Colorized output for visual grep ;)
- Currently generates over 400 permutations per domain
- `StoreInDB` which will eventually be used to push data to a database
- Strong copyleft license

## Usage
- `slurp domain --domain google.com` will enumerate the S3 domains for a specific target.
- `slurp certstream` will follow certstream and enumerate S3 buckets from each domain.
- `permutations.json` stores the permutations that are used by the program; they are in JSON format and loaded during execution **this is required**; it assumes a specific format per permutation: `anything_you_want.%s`; the ending `.%s` is **required** otherwise the AWS S3 URL will not be attached to it, and therefore no results will come from S3 enumeration. If you need flexible permutations then you have to [edit the source](https://github.com/bbb31/slurp/blob/master/main.go#L361).
- `slurp cerstream --ext --names` will report interesting file extensions and regex name hits
- `slurp certstream --ext --names --es http://127.0.0.1:9200` will log all interesting finds of public buckets to Elasticsearch
- `slurp domain --file domain-names.txt` will read any file and go through line by line to see if buckets are open


## Elasticsearch

This requires an older version of Elasticsearch (unless someone wants to update mapping).  I use a docker VM:

```
sudo docker pull sebp/elk:612
sudo docker run -p 5601:5601 -p 9200:9200  -p 5044:5044 \
-v elk-data:/var/lib/elasticsearch --name elk sebp/elk:612
```
Also, create an index for slurp.  Replace IP with the IP address of the ElasticSearch server:
```
curl -X PUT "[IP OF ELASTICSEARCH]:9200/slurp?pretty" -H 'Content-Type: application/json' -d'
{
        "settings":{
                "number_of_shards": 1,
                "number_of_replicas": 0
        },
        "mappings":{
		    "slurp":{
                  "properties":{
                                "url":{
                                        "type":"keyword"
                                },
                                "time":{
                                        "type":"date"
                                },
                                "exthit":{
                                        "type":"keyword"
                                },
                                "regexhit":{
                                        "type":"text"
                                },
                                "fileext":{
                                        "type":"keyword"
                                },
                                "filename":{
                                        "type":"text"
                                }
                    }
		        }
         }
}
'
```

## Installation
- Download from Releases section, or build yourself with `go build` or `build.sh`.

## License
- AGPLv3
