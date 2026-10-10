async function startScan() {
    document.getElementById("progress-fill").style.width = `0%`
    const res = await fetch("/api/scan", {
        method: 'POST',
        headers: {"Content-Type": "application/json"}
    })
    const data = await res.json()
    console.log("Scan started: " + data.scan_id)

    progressBar(data)

}

async function progressBar(data){
    const interval = setInterval(async () => {
        const call = await fetch(`/api/scan/${data.scan_id}/progress`, {
            method: 'GET',
            headers: {"Content-Type": "application/json"}
        })
        const percentage = await call.json();
        document.getElementById("progress-fill").style.width = `${percentage.percentage}%`

        if (percentage.percentage == 100){
            clearInterval(interval)
            printMachine(data.scan_id)
        }
    }, 2000)
}

async function printMachine(scan_id){
    const dt = await fetch(`/api/scan/${scan_id}/hosts`, {
        method: 'GET',
        headers: {"Content-Type": "application/json"}
    })
    const hosts = await dt.json()
    console.log(hosts)

    const totalPorts = Object.values(hosts.hosts).reduce(
        (total, host) => total + Object.keys(host.ports).length, 0
    )

    document.getElementById("stat-date").innerHTML = new Date(hosts.timestamp).toLocaleString('fr-FR', {dateStyle: 'short', timeStyle: 'short'})
    document.getElementById("stat-machines").innerHTML = Object.keys(hosts.hosts).length
    document.getElementById("stat-ports").innerHTML = totalPorts
}