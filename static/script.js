let scanResults = [];

async function startScan() {
    let target = document.getElementById("target").value.trim();
    let numPorts = parseInt(document.getElementById("num_ports").value, 10);

    if (!target || isNaN(numPorts) || numPorts < 1 || numPorts > 65535) {
        alert("Enter a valid target and port range!");
        return;
    }

    document.getElementById("output").innerHTML = `<p>🔍 Scanning ${target}...</p>`;

    try {
        let response = await fetch("/scan", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ target: target, ports: numPorts })
        });

        let result = await response.json();
        scanResults = result; // Store results for export

        let outputDiv = document.getElementById("output");
        outputDiv.innerHTML = `<p><strong>IP:</strong> ${result.ip}</p>`;

        let geo = result.geolocation || {};
        let location = `${geo.city || 'Unknown'}, ${geo.region || 'Unknown'}, ${geo.country || 'Unknown'}`;
        outputDiv.innerHTML += `<p><strong>Location:</strong> ${location}</p>`;

        let osDetectionDiv = document.getElementById("os-detection");
        let detectedOS = result.os || "Unknown";
        osDetectionDiv.innerHTML = `🖥️ <strong>Detected OS:</strong> ${detectedOS}`;

        if (!result.results || result.results.length === 0) {
            outputDiv.innerHTML += "<p>No open ports found.</p>";
        } else {
            let firewallDetected = result.results.some(port => port.status === "filtered");
            result.results.forEach(port => {
                outputDiv.innerHTML += `<p>➡ Port ${port.port} (${port.service}) - ${port.status}</p>`;
            });

            if (firewallDetected) {
                outputDiv.innerHTML += `<p>⚠️ <strong>Firewall Detected!</strong> Some ports are filtered.</p>`;
            }
        }
    } catch (error) {
        document.getElementById("output").innerHTML = "<p>❌ Error occurred during scan.</p>";
    }
}

function exportToCSV() {
    if (!scanResults || !scanResults.results || scanResults.results.length === 0) {
        alert("No scan results to export!");
        return;
    }

    let csvContent = "data:text/csv;charset=utf-8,";
    csvContent += "IP Address,Location,Detected OS,Port,Service,Status\n"; // CSV Header

    let ip = scanResults.ip || "Unknown";
    let geo = scanResults.geolocation || {};
    let location = `${geo.city || 'Unknown'}, ${geo.region || 'Unknown'}, ${geo.country || 'Unknown'}`;
    let detectedOS = scanResults.os || "Unknown";

    scanResults.results.forEach(port => {
        csvContent += `${ip},"${location}",${detectedOS},${port.port},${port.service},${port.status}\n`;
    });

    let encodedUri = encodeURI(csvContent);
    let link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute("download", "port_scan_results.csv");
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
}
