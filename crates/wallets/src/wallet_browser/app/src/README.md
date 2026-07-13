# Browser wallet

Interface for interacting with Foundry from the browser. The application source lives inside the
`foundry-wallets` crate, and its production bundle is embedded in the crate at compile time.

## Development

```sh
pnpm install --frozen-lockfile
pnpm dev
```

When running Foundry, pass the `--browser-disable-open` and `--browser-development` flags.

The `--browser-development` flag disables certain security policies, allowing the Rust server to
accept connections from Vite at `localhost:5173`.

## Production bundle

```sh
pnpm build
```

The build writes directly to `../assets`. Commit those generated assets
alongside every source change; CI rebuilds the application and rejects stale output.
