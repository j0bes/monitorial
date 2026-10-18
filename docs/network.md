# Network documentation
Here is the documentation explaining the functioning and logic of the **network scanner** in this project.
This section concerns the [`scanner/`](../scanner/) directory, whose architecture is as follows:
|File|Functions|
|---|---|
|[`network.py`](../scanner/network.py)|Detects the network and returns information about connected machines|
|[`ports.py`](../scanner/ports.py)|Analyzes the open ports of an active machine (port, service, version)|
|[`scan_service.py`](../scanner/scan_service.py)|Main module for executing the scan|

## Procedure
1. Determine the network in CIDR notation (192.168.0.1/24)
2. Retrieve all possible hosts and ping them
3. On active machines on the network, determine the open ports
4. On the open ports of each machine, analyze the open ports
5. Save each machine to the database along with additional information as it is discovered

Once these procedures are completed, a scan containing all the related information is stored in the database. This allows data access to be centralized, which will facilitate its display on the web interface later.

## Technologies used
This scanner uses several external **Python 3** packages:

|Package/Module|Purpose|
|---|---|
|[netifaces](https://pypi.org/project/netifaces/)|Retrieves network interfaces and determines the current network|
|[socket](https://docs.python.org/3/library/socket.html)|Establishes a virtual connection to test ports|
|[getmac](https://pypi.org/project/getmac/)|Retrieves the MAC address of an IP|
|[subprocess](https://docs.python.org/3/library/subprocess.html)|Executes commands (ping)|
|[ipaddress](https://docs.python.org/3/library/ipaddress.html)|Converts to CIDR notation|
|[platform](https://www.geeksforgeeks.org/python/platform-module-in-python/)|Determines the user's operating system|

## Monitoring bonus
> List of network events that could later be used to create alerts.

The `monitoring/` directory compares a scan with its previous one (if it exists) and returns a list of events.
Example events:
* NEW_HOST
* REMOVED_HOST
* NEW_PORT
* CLOSED_PORT
* NEW_SERVICE
* SERVICE_CHANGED
* VERSION_CHANGED

<hr>

*@j0bes* - Network documentation - 2026

[README](../README.md)