document.addEventListener("DOMContentLoaded", function () {
    const scanBtn = document.getElementById("scan-btn");
    const subnetInput = document.getElementById("subnet-input");
    const statusDiv = document.getElementById("scan-status");
    const resultsDiv = document.getElementById("scan-results");

    scanBtn.addEventListener("click", function () {
        const subnet = subnetInput.value.trim();
        if (!subnet) {
            alert("Please enter a subnet address.");
            return;
        }

        statusDiv.innerHTML = "<b>Scanning...</b> Please wait.";
        resultsDiv.innerHTML = "";

        fetch("/start-scan", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ subnet: subnet })
        })
        .then(response => response.json())
        .then(data => {
            statusDiv.innerHTML = "<b>Scan Completed.</b>";
            resultsDiv.innerHTML = buildTable(data.results);
        })
        .catch(err => {
            statusDiv.innerHTML = "<span style='color:red'>Error occurred.</span>";
            console.error(err);
        });
    });

    function buildTable(results) {
        if (!results || results.length === 0) {
            return "<p>No assets detected.</p>";
        }

        let html = '<table border="1" style="width: 100%; border-collapse: collapse;">';
        html += "<tr><th>IP</th><th>MAC</th><th>Device</th><th>Status</th></tr>";
        results.forEach(item => {
            html += `<tr>
                        <td>${item.ip || "-"}</td>
                        <td>${item.mac || "-"}</td>
                        <td>${item.device || "-"}</td>
                        <td>${item.status || "-"}</td>
                     </tr>`;
        });
        html += "</table>";
        return html;
    }
});
