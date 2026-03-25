# strait

Policy proxy for AI agent sandboxing. Cedar policies, credential injection, structured audit logging.

Sits upstream of [nono](https://github.com/nicholasgasior/nono) via `--upstream-proxy`. All agent network traffic flows through the strait — Cedar policy determines what gets through.

## Status

Early development. See [ninthwave-sh/ninthwave](https://github.com/ninthwave-sh/ninthwave) for orchestration context.

## Architecture

```
Agent (sandboxed by nono)
  │  Kernel: only 127.0.0.1:<nono-port> allowed
  ▼
nono proxy (127.0.0.1:<nono-port>)
  │  --upstream-proxy 127.0.0.1:<strait-port>
  ▼
strait (127.0.0.1:<strait-port>)
  │  Cedar policy eval → ALLOW/DENY
  │  Credential injection on ALLOW
  │  Structured audit log for every decision
  ▼
Internet
```

## Usage

```bash
strait --port 9999 --policy ./rules.cedar --credentials ./creds.toml
nono run --upstream-proxy 127.0.0.1:9999 -- claude
```

## License

MIT
