# Piper Sec - Ip Sec - PiperBrain MCP

## MCP Connection

This project uses **PiperBrain MCP** for AI context. The MCP server provides access to:
- Project guidelines and rules (query the current catalog through MCP)
- Agent configurations and specializations (query the current catalog through MCP)
- Code graph analysis and metrics (query the current index through MCP)
- Dependencies and versioning
- Automatic memory recording

## Automatic Session Initialization

When the MCP connection is available, on the first substantive request of each session automatically call `get_context` for this project before answering or acting. Do not wait for the user to say `use piperbrain` or otherwise mention MCP. A greeting or a simple conversational question does not require a tool call. For code-discovery or code-change requests, follow the workflows below after loading the context. If the MCP connection is unavailable, state that briefly and continue with the safest available fallback.

## Configuration

The MCP connection config is stored in `.piperbrain.json`. Project configuration: `http://localhost:9751/p/bc9819c5-143f-4749-af67-f80b3b66d1fd-piper-sec---ip-sec/config`.

### OpenCode Setup

Add this to your `opencode.json` in the project root:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "piperbrain": {
      "type": "remote",
      "url": "http://localhost:9751/mcp/sse?project=bc9819c5-143f-4749-af67-f80b3b66d1fd",
      "enabled": true
    }
  }
}
```

### Codex Setup

This configuration is project-local. Codex reads `.codex/config.toml` from this project root; no global Codex or OpenCode configuration is changed:

```toml
[mcp_servers.piperbrain]
url = "http://localhost:9751/mcp/sse?project=bc9819c5-143f-4749-af67-f80b3b66d1fd"
```

Project configuration is available at `http://localhost:9751/p/bc9819c5-143f-4749-af67-f80b3b66d1fd-piper-sec---ip-sec/config`.

## Available Tools

All tools work with indexed graph data from the database.

| Tool | Description |
|------|-------------|
| `get_context` | Get complete project context: graph, agents, guidelines, dependencies, metrics |
| `analyze_project` | Get project analysis (uses cached index when available) |
| `search_code` | Search code by label, file, package, source code, docstring, role |
| `search_text` | Search raw source files by literal text and return exact path, line and snippet; use for C# or syntax not fully mapped into the graph |
| `trace_connections` | Trace callers/dependencies of a mapped function with direction and bounded depth |
| `get_database_context` | Get safe .env database metadata and a bounded mapped schema; secrets are excluded |
| `query_database` | Run a bounded read-only SELECT against the project's PostgreSQL database |
| `get_agent_context` | Get agent context for a specific language/slug |
| `get_dependencies` | Get project dependencies with versions |
| `get_guidelines` | Get coding guidelines filtered by language |
| `auto_index` | Index project: analyze code, build graph, save to DB |
| `record_memory` | Record a memory/session for future reference |
| `record_task` | Create a task in todo or explicitly move an existing task |
| `get_next_task` | Return the active task or next unblocked task |
| `get_task_execution_context` | Return scoped context for one task |
| `start_task` | Move the next executable task to in_progress |
| `complete_task` | Complete only an in-progress task with validation evidence |
| `report_task_failure` | Record a task blocker or failure |
| `archive_task` | Archive a completed or failed task |
| `get_project_status` | Get project status: config, agents, guidelines, sessions |
| `list_sessions` | List memory sessions for a project |
| `get_memory` | Get a complete memory with messages |
| `get_migration_plan` | Get the bounded deterministic migration plan and filters |
| `get_next_migration_item` | Get the next dependency-ready migration item |
| `start_migration_item` | Mark one mapping as in progress |
| `complete_migration_item` | Validate dependencies and the target file, then complete it |
| `report_migration_failure` | Persist a migration failure and reason |
| `get_migration_progress` | Get live status and stage KPIs |

### Multi-project scope

The URL selects this project as the primary workspace. Projects listed in `references` are read-only consultation sources: pass their UUID explicitly to a read tool when needed. Indexing and memory recording remain restricted to the primary project.

### Auto Memory

Every tool call automatically records a memory entry with session + summary. No manual recording needed.

### Graph Search

`search_code` searches across all indexed nodes by:
- Function/class/method name (label)
- File path
- Package name
- Source code content
- Docstring
- Role (handler, service, repository, etc.)
- Layer (domain, usecase, handler, infra)

## Mandatory Code Discovery Workflow

Use PiperBrain MCP for every code-discovery task. Before locating files, symbols, handlers, dependencies, implementations, or callers, use `get_context` when session context is needed and then `search_code`. For exact file names, C# declarations, raw source text, or syntax not fully mapped into the graph, use `search_text` with the appropriate `language` filter. Use `trace_connections` to inspect mapped call relationships and `get_guidelines` before changing code in the relevant language.

Do not use `grep`, `glob`, `list`, `rg`, `git grep`, `find`, `fd`, `ag`, or `ack` to discover code. Read a source file directly only after PiperBrain has returned the exact path or symbol. If `search_code` has no result, use `search_text` before considering the graph stale; use `auto_index` only when both MCP searches cannot find recently added code. Do not fall back to local code search.

## Usage

After connecting, the session initialization above is automatic; users do not need to request PiperBrain explicitly. The following examples remain available for explicit tool use:

```
Use piperbrain to get the context for this project
```

```
Search for all handlers using search_code
```

```
Review this code following the project guidelines. use piperbrain
```

```
Record this decision using record_memory
```

## Task Execution Workflow

Before changing code, automatically create a complete persisted task plan for complex requests using `record_task` with `action=plan` and an ordered `tasks` array; do not wait for the user to ask for task creation. Use one task per meaningful deliverable, with dependencies declared by earlier task indexes. For simple requests, create one task. Use `get_next_task`, which starts the next executable task automatically, then call `get_task_execution_context` before changing code. After validation, call `complete_task`; the next dependency-ready task is started automatically. On restart, resume the active task returned by `get_next_task`; task state is canonical, while memory is supplementary. For migrations, never duplicate mappings as normal tasks: use `get_next_migration_item` and the migration status tools. Work only on the active task and finish with validation or `report_task_failure`.

## Migration Workflow

Use `get_next_migration_item`, then `start_migration_item`. Implement and test only that mapping. Finish with `complete_migration_item`, or call `report_migration_failure`. Use `get_migration_progress` for KPIs.

## Architecture

Clean Architecture: `domain → usecase → handler → infra`

```
cmd/server/main.go          # Entry point
internal/domain/            # Entities, interfaces
internal/usecase/           # Business logic
internal/adapter/handler/   # HTTP handlers
internal/infra/database/    # PostgreSQL repository
internal/infra/mcp/         # MCP server (JSON-RPC 2.0 + SSE)
internal/infra/server/      # Server setup, routes, indexer
web/templates/              # Alpine.js + Tailwind HTML
web/static/                 # Static assets
```

## Project Info

- **UUID**: bc9819c5-143f-4749-af67-f80b3b66d1fd
- **Server**: http://localhost:9751
- **MCP Endpoint**: http://localhost:9751/mcp/sse?project=bc9819c5-143f-4749-af67-f80b3b66d1fd
- **Config**: .piperbrain.json
- **DB**: PostgreSQL (pipermap)
- **Start**: `DB_DRIVER=postgres DB_HOST=localhost DB_PORT=5432 DB_NAME=pipermap DB_SSLMODE=disable go run cmd/server/main.go` (configure credentials through your environment or secret manager)
