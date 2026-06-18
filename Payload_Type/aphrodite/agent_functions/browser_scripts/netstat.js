function(task, responses) {
    if (task.status.includes("error")) {
        return {'plaintext': responses.reduce((p, c) => p + c, "")};
    } else if (responses.length > 0) {
        const headers = [
            {"plaintext": "Proto",  "type": "string", "cellStyle": {}},
            {"plaintext": "Local",  "type": "string", "cellStyle": {"fillWidth": true}},
            {"plaintext": "Remote", "type": "string", "cellStyle": {"fillWidth": true}},
            {"plaintext": "State",  "type": "string", "cellStyle": {}},
            {"plaintext": "PID",    "type": "string", "cellStyle": {}},
        ];
        let rows = [];
        for (let i = 0; i < responses.length; i++) {
            let data;
            try { data = JSON.parse(responses[i]); }
            catch (e) { return {'plaintext': responses.reduce((p, c) => p + c, "")}; }
            const conns = data["connections"] || [];
            for (const c of conns) {
                const state = c["state"] || "";
                let rowStyle = {};
                if (state === "ESTABLISHED" || state === "ESTAB") {
                    rowStyle = {"backgroundColor": "#1a3a1a"};
                } else if (state === "LISTEN" || state === "LISTENING") {
                    rowStyle = {"backgroundColor": "#1a1a3a"};
                }
                rows.push({
                    "rowStyle": rowStyle,
                    "Proto":  {"plaintext": c["proto"]  || "", "cellStyle": {}},
                    "Local":  {"plaintext": c["local"]  || "", "cellStyle": {}},
                    "Remote": {"plaintext": c["remote"] || "", "cellStyle": {}},
                    "State":  {"plaintext": state,             "cellStyle": {}},
                    "PID":    {"plaintext": c["pid"]    || "", "cellStyle": {}},
                });
            }
        }
        return {"table": [{"headers": headers, "rows": rows, "title": "Network Connections"}]};
    } else {
        return {"plaintext": "No output."};
    }
}
