function(task, responses) {
    if (task.status.includes("error")) {
        return {'plaintext': responses.reduce((p, c) => p + c, "")};
    } else if (responses.length > 0) {
        let data;
        try { data = JSON.parse(responses[0]); }
        catch(e) { return {'plaintext': responses[0]}; }

        if (data.error) {
            return {'plaintext': 'Error: ' + data.error};
        }

        const action = data.action || "";

        if (action === "query") {
            return {'plaintext': '[' + (data.type || '?') + ']  ' + (data.value || '') + '  =  ' + (data.data || '')};
        }

        if (action === "add" || action === "delete") {
            return {'plaintext': action + ': ' + (data.status || data.error || 'done')};
        }

        if (action === "enum") {
            let tables = [];

            if (data.subkeys && data.subkeys.length > 0) {
                const headers = [
                    {"plaintext": "Subkey", "type": "string", "cellStyle": {"fillWidth": true}},
                ];
                const rows = data.subkeys.map(k => ({
                    "rowStyle": {},
                    "Subkey": {"plaintext": k, "cellStyle": {}},
                }));
                tables.push({"headers": headers, "rows": rows, "title": "Subkeys"});
            }

            if (data.values && data.values.length > 0) {
                const headers = [
                    {"plaintext": "Name", "type": "string", "cellStyle": {}},
                    {"plaintext": "Type", "type": "string", "cellStyle": {}},
                    {"plaintext": "Data", "type": "string", "cellStyle": {"fillWidth": true}},
                ];
                const rows = data.values.map(v => ({
                    "rowStyle": {},
                    "Name": {"plaintext": v.name || "(Default)", "cellStyle": {}},
                    "Type": {"plaintext": v.type  || "",          "cellStyle": {}},
                    "Data": {"plaintext": v.data  || "",          "cellStyle": {}},
                }));
                tables.push({"headers": headers, "rows": rows, "title": "Values"});
            }

            if (tables.length > 0) return {"table": tables};
            return {'plaintext': '(empty key)'};
        }

        return {'plaintext': JSON.stringify(data, null, 2)};
    }
    return {'plaintext': 'No output.'};
}
