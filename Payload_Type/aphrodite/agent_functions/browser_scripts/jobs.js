function(task, responses) {
    if (task.status.includes("error")) {
        return {'plaintext': responses.reduce((p, c) => p + c, "")};
    } else if (responses.length > 0) {
        const headers = [
            {"plaintext": "Task ID", "type": "string", "cellStyle": {}},
            {"plaintext": "PID",     "type": "number", "cellStyle": {}},
        ];
        let rows = [];
        for (let i = 0; i < responses.length; i++) {
            let data;
            try { data = JSON.parse(responses[i]); }
            catch (e) { return {'plaintext': responses.reduce((p, c) => p + c, "")}; }
            const jobs = data["jobs"] || [];
            if (jobs.length === 0) return {"plaintext": "No active jobs."};
            for (const j of jobs) {
                rows.push({
                    "rowStyle": {},
                    "Task ID": {"plaintext": j["task_id"] || "", "cellStyle": {}},
                    "PID":     {"plaintext": String(j["pid"] ?? ""), "cellStyle": {}},
                });
            }
        }
        if (rows.length === 0) return {"plaintext": "No active jobs."};
        return {"table": [{"headers": headers, "rows": rows, "title": "Active Jobs"}]};
    } else {
        return {"plaintext": "No output."};
    }
}
