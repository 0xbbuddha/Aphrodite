function(task, responses) {
    if (task.status.includes("error")) {
        return {'plaintext': responses.reduce((p, c) => p + c, "")};
    } else if (responses.length > 0) {
        const headers = [
            {"plaintext": "Interface", "type": "string", "cellStyle": {}},
            {"plaintext": "IPv4",      "type": "string", "cellStyle": {"fillWidth": true}},
            {"plaintext": "IPv6",      "type": "string", "cellStyle": {"fillWidth": true}},
            {"plaintext": "MAC",       "type": "string", "cellStyle": {}},
        ];
        let rows = [];
        for (let i = 0; i < responses.length; i++) {
            let data;
            try { data = JSON.parse(responses[i]); }
            catch (e) { return {'plaintext': responses.reduce((p, c) => p + c, "")}; }
            const ifaces = data["interfaces"] || [];
            for (const iface of ifaces) {
                rows.push({
                    "rowStyle": {},
                    "Interface": {"plaintext": iface["name"] || "", "cellStyle": {}},
                    "IPv4":      {"plaintext": iface["ipv4"] || "", "cellStyle": {}},
                    "IPv6":      {"plaintext": iface["ipv6"] || "", "cellStyle": {}},
                    "MAC":       {"plaintext": iface["mac"]  || "", "cellStyle": {}},
                });
            }
        }
        return {"table": [{"headers": headers, "rows": rows, "title": "Network Interfaces"}]};
    } else {
        return {"plaintext": "No output."};
    }
}
