# Database documentation
Here is the documentation explaining the functioning and logic of the **data storage** in this project.
This section concerns [`database/`](../database/) directory, whose architecture is as follows:
|File|Functions|
|---|---|
|[`db.py`](../database/db.py)|Initialise la structure de la base de données|
|[`hosts.py`](../database/hosts.py)|Enregistre les hôtes (scan_id, ip, hostname, mac) dans la table `hosts`|
|[`ports.py`](../database/ports.py)|Enregistre les ports (host_id, port, protocol, service, product, version) dans la table `ports`|
|[`scans.py`](../database/scans.py)|Execute toutes les manipulations sur la base de données: charger un scan, récupérer les ID, récupérer la progression d'un scan en cours et +|

Dans ce projet le stockage est un point central, et permet par la suite un meilleur accès au donnée.

C'est pourquoi ici on distingue les tables: `scans`, `hosts`, `ports`. Et chaque table hérite d'une clé étrangère afin de garantir les dépendances.

**Exemple de la table `scans` et `hosts`:**

|scan_id|timestamp|status|total_ips|completed_ips|
|---|---|---|---|---|
|1|2026-02-10|done|254|254|
|2|2026-03-08|done|254|254|

|scan_id|host_id|ip|hostname|mac|
|---|---|---|---|---|
|1|3|192.168.0.2|debian|D7:82:09:28:E4:67|
|1|4|192.168.0.13|windows|E5:67:A1:54:C7:32|
|2|1|192.168.0.1|livebox|5E:FF:56:A2:AF:15|

On voit bien ici que la table `hosts` hérite de la clé étrangère `scan_id` ce qui nous permet de savoir a quel scan chaque hôte appartient.

<hr>

*@j0bes* - Database documentation - 2026

[README](../README.md)