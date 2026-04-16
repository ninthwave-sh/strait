# Strait Desktop

Electron shell for the first desktop control plane.

## Scripts

```bash
npm test
npm run build
npm run shell
```

The shell connects to the local gRPC control service over the default Unix socket path used by `strait service start`. Override the path with `STRAIT_CONTROL_SOCKET` when needed.
