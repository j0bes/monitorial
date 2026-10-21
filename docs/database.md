# Database documentation
Here is the documentation explaining the functioning and logic of the **data storage** in this project.
This section concerns the [`database/`](../database/) directory, whose architecture is as follows:
|File|Functions|
|---|---|
|[`db.py`](../database/db.py)|Initializes the database structure|
|[`hosts.py`](../database/hosts.py)|Registers hosts (scan_id, ip, hostname, mac) in the `hosts` table|
|[`ports.py`](../database/ports.py)|Registers ports (host_id, port, protocol, service, product, version) in the `ports` table|
|[`scans.py`](../database/scans.py)|Performs all database operations: loading a scan, retrieving IDs, retrieving the progress of an ongoing scan, and more|

In this project, storage is a central component, allowing better access to data later on.

That is why the database is structured into three tables: `scans`, `hosts`, and `ports`. Each table is linked through foreign keys to maintain referential integrity and ensure consistent relationships between the stored data.

The `hosts` table contains a `scan_id` foreign key referencing `scans.scan_id`, allowing each host to be associated with the scan that discovered it. Similarly, the `ports` table contains a `host_id` foreign key referencing `hosts.host_id`, allowing each port to be associated with the host on which it was discovered.

**Example of the `scans` and `hosts` tables:**

|scan_id|timestamp|status|total_ips|completed_ips|
|---|---|---|---|---|
|1|2026-02-10|done|254|254|
|2|2026-03-08|done|254|254|

|scan_id|host_id|ip|hostname|mac|
|---|---|---|---|---|
|1|3|192.168.0.2|debian|D7:82:09:28:E4:67|
|1|4|192.168.0.13|windows|E5:67:A1:54:C7:32|
|2|1|192.168.0.1|livebox|5E:FF:56:A2:AF:15|

As we can clearly see here, the `hosts` table inherits the foreign key `scan_id`, allowing us to know which scan each host belongs to.

<hr>

*@j0bes* - Database documentation - 2026

[README](../README.md)