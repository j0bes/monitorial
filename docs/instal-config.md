# Installation & Configuration
## Prerequisites
The following software is required to use the network scanner:

- Python 3.12 or 3.13 (tested): [Download Python](https://www.python.org/downloads/)
- Nmap: [Windows](https://nmap.org/download), Linux (install it using your distribution's package manager).

Other Python versions have not been tested and may require additional configuration, particularly when installing netifaces.
#### Checking Nmap
```bash
nmap --version
```
## Clone the Repository
Clone the repository to your local machine:
```bash
git clone https://github.com/j0bes/monitorial.git
cd monitorial
```
## Virtual Environment
To avoid dependency conflicts and ensure a consistent development environment, it is recommended to run this project inside a virtual environment.
```bash
python3 -m venv .env

# Windows (PowerShell)
.env\Scripts\Activate.ps1

# Linux
source .env/bin/activate
```
### Install Dependencies
This project relies on several external packages, listed in the [network documentation](./network.md#technologies-used). Install them using `pip`:
```bash
python -m pip install -r requirements.txt
```
> **Note (Windows):** The `netifaces` package contains native C code and may require compilation during installation. If installation fails, make sure you are using a compatible Python version and install the required C/C++ build tools through [Visual Studio](https://visualstudio.microsoft.com/downloads/), selecting the **Desktop development with C++** workload. Then retry the installation.
## Run the Application
Once all prerequisites and dependencies have been installed, start the web application:
```bash
python app.py
```
Open the following URL in your browser to access the local web interface:<br>
http://127.0.0.1:5000
> To stop the application, press `Ctrl+C` in the terminal where the server is running.
## Configure the Target Subnet

By default, the scanner automatically detects the network to which your machine is connected.

If you want to scan a specific subnet, you can override the default behavior by setting the `SCAN_NETWORK` environment variable when starting the application.

The subnet must be specified in **CIDR notation**. If the provided value is invalid, the application will return an error.

```powershell
# Windows (PowerShell)
$env:SCAN_NETWORK="192.168.56.0/24"; python app.py
```

```bash
# Linux
SCAN_NETWORK=192.168.56.0/24 python3 app.py
```

> **Warning:** As stated in the [README](../README.md), only scan networks that you own or for which you have explicit authorization. You are responsible for ensuring that your use of this scanner complies with all applicable laws and regulations.

---

*@j0bes* — Installation & Configuration — 2026

[README](../README.md)
