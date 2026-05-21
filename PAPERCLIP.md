# Paperclip Orchestrator for miTch

This dashboard provides a visual overview of your AI agents, their tasks, and costs.

## Access
- **URL:** [http://127.0.0.1:3101](http://127.0.0.1:3101)
- **API Health:** [http://127.0.0.1:3101/api/health](http://127.0.0.1:3101/api/health)

## Infrastructure
- **Source:** `paperclip-orchestrator/`
- **Home Directory:** `paperclip-home/` (contains configs, db, and backups)
- **Database:** Embedded PostgreSQL on port `54329`

## Managing the Server
The server is currently running as a background process (PID 14516).

### Restart Server
```bash
# From the root directory
$env:PAPERCLIP_HOME="D:\Mensch\miTch\paperclip-home"; cd paperclip-orchestrator; pnpm dev
```

### View Logs
```bash
# See what Paperclip is doing
gemini read_background_output --pid 14516
```

## Connecting Agents
To add the **Gemini CLI** to Paperclip:
1. Open the Dashboard.
2. Go to **Agents** > **New Agent**.
3. Select **CLI Adapter**.
4. Set Command to `gemini`.
5. Enable **Heartbeats** to keep the agent checking for new tickets.

## Visualizing Gemma (Port 9379)
To see routing activity:
1. Add a **Log Observer** to your agent configuration.
2. Link it to the command `gemini gemma logs`.
3. The routing decisions (Flash vs Pro) will appear in the Paperclip activity stream.
