# Contributing

[Back to the README](README.md) · [Report a vulnerability privately](SECURITY.md#reporting-a-vulnerability)

Use the Go version specified in
[go.mod](https://github.com/niklas-schmidt-dev/secure-setup/blob/main/go.mod).
For ordinary changes, run `go test ./...` and `go vet ./...`. Changes to the
rules or remote scripts should also exercise real nftables and the relevant
end-to-end setup path.

## Test commands

```sh
# Unit tests: ruleset generator, parsers, plans and sessions
go test ./...

# Rulesets and scripts against a real nft binary (Docker)
scripts/validate-ruleset.sh

# Remote setup against a throwaway systemd server (Docker)
test/e2e/run.sh

# Local setup: login, confirmation, self-checks, rollback, TUI and undo
test/e2e/run-here.sh
```

The end-to-end tests build a Debian container with systemd and sshd on two
networks (a "public" and a "private" one standing in for the tailnet), lock
it down, prove the public port is closed, force a lockout to watch the
rollback fire, and run `undo`. Docker commands use `DOCKER_CONTEXT` (default
`nas-docker`). CI runs all three on every pull request, on the runner's own
Docker (`DOCKER_CONTEXT=default`). The e2e networks use `10.250.100.0/24` and
`10.250.101.0/24`; override with `E2E_SUBNET_PUBLIC` and `E2E_SUBNET_PRIVATE`.
They need Docker 28 or newer. The commands below use this project's MacBook
Docker target, `nas-docker`; Docker Desktop is not used. If that daemon is
unreachable, resolve the NAS connection rather than switching contexts.
On another development machine, use its intended context explicitly.

Build the images first:

```sh
docker --context nas-docker build -t secure-setup-e2e-server -f test/e2e/Dockerfile.server test/e2e
docker --context nas-docker build -t secure-setup-e2e-client -f test/e2e/Dockerfile.client test/e2e
```

Layout:

```
main.go                 commands: wizard, here, confirm, apply, render, undo
internal/tui            the wizard (bubbletea + huh)
internal/textui         plain-text reporter and prompts for apply/undo
internal/runner         the steps: over SSH (runner.go) and on the machine itself (here.go)
internal/remote         what runs on the server, with the embedded scripts and units
internal/localhost      runs those steps on this machine (`here`)
internal/sshx           SSH client: keys, agent, password, known_hosts
internal/nftgen         nftables ruleset template and renderer
internal/cloudflare     fetches and validates Cloudflare's ranges
internal/plan           the plan file
```

## Isolate test runs

The e2e scripts create disposable containers and networks and remove those
resources on exit. They run privileged systemd containers, so use only a
Docker daemon intended for development or CI. On this MacBook all Docker
operations use `docker --context nas-docker ...`.

On the maintainer's MacBook, evaluate the checkout's scope before a local
stack or test run:

```sh
eval "$(~/.local/bin/dev-scope)"
```

Use a separate working directory for concurrent changes. Set `E2E_BINARY`
to a checkout-specific output file and choose non-overlapping
`E2E_SUBNET_PUBLIC` and `E2E_SUBNET_PRIVATE` ranges before concurrent runs on
the same daemon. These names do not provision a database or network by
themselves.

The current scripts still write some logs at fixed `/tmp/e2e-*` paths and
share their test-image tags. Run the two e2e scripts sequentially on a given
development client; do not rebuild those image tags during another run.
CI runs the scripts on separate runners. The test images use copied files,
not a bind mount of a Mac path on the remote NAS.

## Documentation assets

The README's header and network diagram live in [docs/assets](docs/assets/README.md).
The wizard image is a capture of the running CLI; keep it consistent with
the real prompts. Inspect light and dark rendering after changing assets,
and check relative documentation links. Release archives include the docs
and assets so the README's local references remain usable after extraction.
