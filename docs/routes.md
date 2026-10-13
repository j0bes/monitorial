# Routes documentation
Here is the documentation explaining the functioning and logic of the **Flask** routes in this project.
They mainly enable communication between [the database](./database.md) and the web interface (via JavaScript), as well as the display of the main page `/`.

**Flask** allows us to create a small local web server, making the scanner accessible via: `http://127.0.0.1:5000`.

> Note: Flask is not limited to local use, but in my case, I will use it this way.

## Structure & Functioning
|Route|Function|Method|Files|
|---|---|---|---|
|`/`|Main page|-|`index.html`|
|`/api/scan`|Starts a scan|POST|`scanner/` & `database/`|
|`/api/scans`|- Retrieves the list of scans (ID + TIMESTAMP)<br>- To display the history|GET|`database/`|
|`/api/scan/<scan_id>/progress`|Calculates the progress percentage of a scan|GET|`database/`|
|`/api/scan/<scan_id>/hosts`|- Retrieves data related to the machines in a scan<br>- To display the table of active machines|GET|`database/`|

<hr>

*@j0bes* - Routes documentation - 2026

[README](../README.md)