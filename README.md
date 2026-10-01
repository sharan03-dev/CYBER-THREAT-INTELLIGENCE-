# MongoDB dump of the CTI platform (Lab 7.1)

Created by:  `python labs/lab7_1/lab_01_production_schema.py --dump`
which runs:  `mongodump --db=cti_platform --gzip --archive=dump/cti_platform.archive.gz`
(the cache collections ip_lookups, lookup_history and cache_metrics are excluded).

Restore it anywhere:
`mongorestore --gzip --archive=dump/cti_platform.archive.gz --nsFrom='cti_platform.*' --nsTo='cti_platform_from_dump.*'`
or let the lab do it: `python labs/lab7_1/lab_01_production_schema.py --from-dump`
