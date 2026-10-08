# evilkit Companion API

The companion exposes a small HTTP API for the iOS app. All endpoints are JSON.
Authorization uses a Bearer token supplied at server startup.

## Base URL and authentication

```
http://<companion-ip>:8787/api/v1
Authorization: Bearer <token>
```

`GET /health` and `GET /tools` are public; every mutating endpoint requires the
token.

## Endpoints

### `GET /health`

Public. Returns server status.

```json
{
  "status": "ok",
  "version": "0.1.0",
  "sessions": 1,
  "jobs": 3
}
```

### `GET /tools`

Public. Lists available tools and their JSON schemas.

```json
{
  "tools": [
    {
      "name": "verify_http",
      "description": "Make an HTTP/HTTPS request to a target URL using curl.",
      "schema": { ... }
    }
  ]
}
```

### `POST /sessions`

Create an authorised testing session. Returns `201 Created`.

Request:

```json
{
  "scope": "10.0.0.0/24",
  "deny": "10.0.0.1"
}
```

Response:

```json
{
  "id": "abc123",
  "scope": "10.0.0.0/24",
  "deny": "10.0.0.1",
  "created_at": 1790672377.8
}
```

Scope syntax matches desktop evilkit: comma-separated IPs, CIDRs, hostnames, and
range forms. Invalid scopes return `400 Bad Request`.

### `GET /sessions/{id}`

Fetch session details.

### `POST /sessions/{id}/run`

Run a tool. Returns `200 OK` synchronously by default, or streams Server-Sent
Events when `Accept: text/event-stream` is requested.

Request:

```json
{
  "tool": "verify_http",
  "args": {
    "url": "http://10.0.0.5/",
    "method": "GET",
    "timeout": 30
  }
}
```

Synchronous response:

```json
{
  "id": "job-123",
  "state": "done",
  "returncode": 0,
  "output": ["HTTP/1.1 200 OK", "..."]
}
```

If the target is outside the session scope, returns `403 Forbidden`.

### `GET /sessions/{id}/jobs/{job_id}`

Fetch a job and its complete output.

## Scope enforcement

Before any tool executes, its target is checked against the session's allowed
and denied lists using the same parser and CIDR containment logic as desktop
evilkit. If the target is outside scope, the job is marked `error` with
`returncode: 403` and no network packet is sent.

## Streaming output

For long-running tools (nmap, nuclei), request streaming:

```bash
curl -sN -H 'Authorization: Bearer <token>' \
  -H 'Accept: text/event-stream' \
  -X POST -d '{"tool":"port_scan","args":{"target":"10.0.0.5"}}' \
  http://<companion>:8787/api/v1/sessions/<id>/run
```

Events:

- `event: job` — job metadata (`id`, `state`).
- `event: output` — one line of tool output.
- `event: done` — final state and return code.

## Audit log

Every session creation and tool call is appended to a JSONL file under the
server's `--data-dir`. The format matches desktop evilkit's `launches.jsonl`.
