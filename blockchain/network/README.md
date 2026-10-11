# blockchain/network

A native-binary (no Docker) Hyperledger Fabric network for provenance
storage: two peer organizations (Hospital, SecurityOps) plus one orderer,
Raft (`etcdraft`) consensus, one channel (`pacr-channel`). This replaces
the architecture spec's literal "run Fabric's own `test-network` sample via
Docker Compose" with a from-scratch equivalent topology run from downloaded
Fabric binaries, for the environmental reasons below. The two-org shape and
Raft consensus are unchanged from the spec.

## Why not Docker / the sample `test-network`

Docker Hub is blocked by egress policy in the environment this was built
in, so `docker-compose`/Fabric's `test-network.sh` (which pulls Fabric's
peer/orderer/ccenv images) cannot run. This network instead runs the
`peer`, `orderer`, `cryptogen`, `configtxgen`, and `osnadmin` binaries from
a Fabric GitHub binary release directly, and deploys chaincode via Fabric's
*external builder* mechanism (the standard non-Docker alternative to a
chaincode Docker image) instead of a chaincode image. The Go module proxy
is also blocked, so the chaincode and client SDK are Node.js
(`fabric-contract-api`/`fabric-shim`, installed from the npm registry,
which is reachable) rather than Go.

Set `FABRIC_BIN_DIR` (default `/home/claude/fabric-dist`) to wherever your
Fabric binary release is extracted; it must contain `bin/{peer,orderer,
cryptogen,configtxgen,osnadmin}` and a `config/` directory with Fabric's
stock sample configs.

## Layout

- `crypto-config.yaml` / `configtx.yaml` -- `cryptogen`/`configtxgen` input.
- `peercfg/core.yaml.template` -- Fabric's stock sample `core.yaml` with one
  line parameterized (the external builder's path, which isn't known until
  `NETWORK_DIR` is). `scripts/generate.sh` renders this into
  `peercfg/core.yaml` (gitignored, environment-specific).
- `builders/ccaas/bin/{detect,build,release,run}` -- the external builder
  Fabric uses to launch this network's Node.js chaincode without Docker.
  Despite the directory name (`ccaas`, kept for continuity with the spike
  that proved this out), it does **not** use CCaaS's peer-dials-chaincode
  model -- see Adaptation 3 below.
- `scripts/` -- `common.sh` (shared paths/addresses, sourced by the rest),
  `generate.sh`, `start-network.sh`, `stop-network.sh`, `reset.sh`,
  `package-chaincode.sh`, `deploy-chaincode.sh`, `invoke.sh`, `query.sh`.
- `crypto-config/`, `channel-artifacts/`, `run/`, `logs/` -- all generated,
  all gitignored. Nothing under them is committed.

## Quick start

```bash
cd blockchain/network/scripts
./generate.sh                     # crypto material + genesis block + core.yaml
./start-network.sh                # orderer + both peers up, both joined to the channel
./package-chaincode.sh ../../chaincode provenance_1.0 /tmp/provenance.tgz
./deploy-chaincode.sh /tmp/provenance.tgz provenance 1.0 1
./invoke.sh provenance '{"Args":["recordIncident","INC-1","dev-1","ddos","<hash>","2026-10-12T00:00:00Z"]}'
./query.sh provenance '{"Args":["verifyEvidence","<hash>"]}'
```

`./reset.sh` stops everything and wipes all ledger state for a clean
re-run of `generate.sh`.

## Adaptations made, and why (carried forward from a throwaway proof-of-concept spike)

Before any of the committed scripts above were written, a scratch spike
(never part of this repository) proved that a chaincode could actually be
installed, approved, committed, and invoked on this native-binary topology
at all. It surfaced four fixes that are not obvious from Fabric's own docs
and are easy to silently regress, so they're recorded here in full:

### Adaptation 1 -- TLS SAN validation vs. the sandbox's outbound proxy

`cryptogen`'s default certs carry only a hostname SAN
(e.g. `orderer1.orderer.pacr.local`). Addressing a node by literal
`127.0.0.1` then fails TLS validation (`x509: cannot validate certificate
for 127.0.0.1 because it doesn't contain any IP SANs`). The seemingly
obvious fix -- add a custom hostname via `/etc/hosts` and address nodes by
that instead -- creates a *different* failure in a sandboxed environment
with an outbound agent-proxy: the proxy's `noProxy` list is literal-pattern
based and doesn't recognize a custom hostname as local, so it intercepts
the connection and breaks it a different way.

**Fix:** add `SANS: ["127.0.0.1", "localhost"]` to the orderer's and each
peer org's `cryptogen` spec (`crypto-config.yaml`), which bakes an IP SAN
into every generated cert, and then address every node everywhere by
literal `127.0.0.1` (`configtx.yaml`'s `OrdererEndpoints`/`Addresses`/
`Consenters.Host`, and every `CORE_PEER_ADDRESS`/`-o`/`--peerAddresses`
flag in the scripts). This satisfies TLS SAN validation and stays inside
the proxy's `noProxy` list at the same time. If you see a bad-certificate
or TLS handshake failure anywhere in this network, check for a hostname
that crept back into an address before anything else.

### Adaptation 2 -- the etcdraft WAL ignores `ORDERER_FILELEDGER_LOCATION`

The Raft WAL/snapshot data lives at the hardcoded path
`/var/hyperledger/production/orderer/etcdraft/wal/<channel>`, regardless of
where `ORDERER_FILELEDGER_LOCATION` points the rest of the ledger. A
"clean reset" that only wipes the redirected `run/` directory and
regenerates a fresh genesis block leaves stale Raft state behind, and the
orderer panics on restart (`Could not append block: unexpected Previous
block hash`). `scripts/reset.sh` wipes `/var/hyperledger/production`
explicitly for this reason -- don't remove that line to make reset "more
surgical."

Separately: `pkill -f <pattern>` was observed to repeatedly report success
(or fail silently) without the targeted process actually dying, in the
sandbox this was built in. `scripts/stop-network.sh` finds PIDs via
`pgrep` and `kill -9`s them explicitly, then re-checks with another
`pgrep`, rather than trusting `pkill`'s own exit status.

### Adaptation 3 -- CCaaS abandoned in favor of the traditional direction

Fabric offers two directions for an external-builder-launched chaincode:
CCaaS (`fabric-chaincode-node server` mode), where the chaincode binds a
port and the *peer* dials out to it; and the traditional direction, where
the *chaincode* dials the peer's own chaincode listen address and
registers (the same mechanism Fabric's system chaincodes --
`_lifecycle`/`qscc`/`cscc`/`lscc` -- already use).

CCaaS was tried first and abandoned, not fixed: with a confirmed-correct
`connection.json`, a confirmed-correct, matching `--chaincode-id`, and a
confirmed-reachable chaincode server (verified via `curl`/`openssl`), the
peer never even attempted a TCP connection to it -- confirmed via live
`/proc/net/tcp` polling across multiple full invoke attempts, with zero
diagnostic signal on either side despite debug-level logging and `strings`
confirming the relevant CCaaS code paths exist in the peer binary. Rather
than continue debugging a silent failure with no error message to chase,
this network uses the traditional direction instead, via `builders/ccaas/
bin/run` launching `fabric-chaincode-node start` (not `server`). The
directory is still named `ccaas` only because that's what Fabric calls the
generic "external builder for a chaincode launched as a service rather
than a Docker image" pattern -- it is not using CCaaS's wire protocol.

### Adaptation 4 -- external builder `run` launch config, and the mTLS encoding gotcha

Two things about `run`'s contract are not obvious from Fabric's docs:

1. **`run` does not receive `CORE_PEER_ADDRESS`/`CORE_CHAINCODE_ID_NAME` as
   environment variables.** Those only apply to a Docker-launched
   container. For an external-builder `run`, Fabric instead writes a
   `chaincode.json` file into `run`'s second positional argument (the "run
   metadata directory"), containing `chaincode_id`, `peer_address` (this
   peer's own chaincode listen address, e.g. `127.0.0.1:7052`), and mTLS
   material (`client_cert`, `client_key`, `root_cert`, `mspid`) -- because
   the peer enforces mutual TLS on its chaincode listener. `run` must read
   this file (see `builders/ccaas/bin/run`).
2. **The client cert/key files need double-base64 encoding, not plain
   PEM.** `fabric-shim`'s `Endpoint` class
   (`node_modules/fabric-shim/lib/handler.js`) does
   `Buffer.from(opts.key, 'base64')` / `Buffer.from(opts.cert, 'base64')` on
   the *contents* of the files at `CORE_TLS_CLIENT_KEY_PATH` /
   `CORE_TLS_CLIENT_CERT_PATH`, then hands the decoded bytes straight to
   Node's TLS layer, which requires those bytes to already be PEM text. So
   the files must contain `base64(whole armored PEM text)` -- the base64
   *encoding* of the complete `-----BEGIN ... -----END-----` block,
   headers and newlines included -- not the raw PEM text itself, and not
   base64 of the bare DER body with the PEM armor stripped (both of those
   were tried first and both produce
   `error:0480006C:PEM routines::no start line`). The root CA cert
   (`CORE_PEER_TLS_ROOTCERT_FILE`, i.e. `opts.pem`) is read without this
   decoding step, so it stays as plain PEM text. `builders/ccaas/bin/run`
   does this conversion with `jq ... | base64 -w0` for the client cert/key
   and leaves the root cert alone -- if you ever rewrite this script, this
   is the single easiest thing to get wrong, with the least informative
   error message (`no start line`, not "wrong encoding").

Both the real network bootstrap above and this builder have been run
end-to-end (install → approve → commit → invoke → query, both peers
launching the chaincode and agreeing on committed state) as real commands
against this real code, not just claimed from the spike.
