# Attestation-Gated WireGuard Mesh on AMD SEV-SNP

Three AMD SEV-SNP confidential VMs on AWS form a full WireGuard mesh, but only
after each node proves its integrity to an external verification service. The
verifier appraises each node's hardware-signed attestation report, and only
once all nodes pass does it hand out the WireGuard credentials that let the mesh
come up. The result is a network whose members are cryptographically known to be
genuine, unmodified confidential VMs.

*Systemsicherheit · Hochschule Flensburg · SS 2026 · Prof. Dr. Sebastian Gajek*

Source: <https://github.com/luboben/attestation-wireguard-sev-snp>

---

## 1. Motivation — why attest before meshing

A normal VPN trusts whoever holds the right key. That says nothing about the
*state* of the machine holding it: a node could be running tampered software, a
debug build, or an outdated firmware and still present a valid key. For a
confidential workload that is exactly the gap we want to close.

AMD SEV-SNP lets a VM produce a hardware-signed **attestation report**: a
measurement of its initial memory and CPU state, signed by a key that chains
back to an AMD root of trust. Verifying that report before admitting a node to
the mesh means the network is built only from nodes that are (a) genuine SEV-SNP
hardware and (b) running the exact image we expect. Binding each node's WireGuard
key into its report ties the encrypted channel to the attested machine, so the
tunnel inherits the trust established by attestation.

## 2. Roles (RATS / RFC 9334)

This system is symmetric: every node is an Attester. The verifier combines two
RATS roles in one service — it both appraises evidence (Verifier) and decides to
release the credentials (Relying Party). That combined service is essentially a
minimal, single-purpose Key Broker.

| RATS role             | Filled by                                  | Note |
|-----------------------|--------------------------------------------|------|
| Attester              | each of the 3 SEV-SNP nodes                | mutual attestation; all three prove themselves |
| Verifier              | verification service (own hardware)        | appraises every report |
| Relying Party         | same service              | releases WireGuard credentials |
| Endorser              | AMD (ARK → ASVK → VLEK)                     | hardware authenticity |
| Reference Value Provider | self-supplied                              | golden measurement, TCB minimums, policy flags |
| Verifier Owner        | the operator                    | no separate appraisal authority |

<!--
  Mutual attestation is what removed the earlier asymmetry: there is no longer a
  statically trusted peer key — every node's WG key is learned via its own report.
-->

## 3. Architecture

- **3 nodes** — SEV-SNP-enabled EC2 instances (c6a.large, Ubuntu 24.04+) in
  eu-west-1 (Ireland; one of the two AWS regions offering SEV-SNP). Each is both
  a confidential workload and an Attester.
- **Verifier** — runs on own hardware **outside** AWS, in a VM. This removes the
  AWS hypervisor from the verifier's TCB. It is not itself attested (see §6).
- **Control plane** — nodes initiate outbound HTTPS to the verifier (pinned
  self-signed certificate). Carries the attestation dialog and credential release.
- **Data plane** — the WireGuard full mesh between the three nodes. The verifier
  is not part of the mesh.

![Architecture: three SEV-SNP nodes in a WireGuard mesh, attested by an external verifier.](figures/architecture.svg)

Full mesh = 3 tunnels (A–B, A–C, B–C). Each tunnel has its own preshared key.

## 4. Protocol flow

Because every node must attest before *any* tunnel can come up, the verifier acts
as a barrier: it collects all three reports, verifies them, and only then releases
each node's peer set.

![Attestation Sequence: parallel node attestation, a verifier barrier, then credential release and full mesh bring-up.](figures/sequence.svg)

Key binding uses a split REPORT_DATA layout: upper 32 bytes carry the verifier
nonce (freshness), lower 32 bytes carry the raw X25519 WireGuard public key
(binding). Both halves sit under the same ECDSA signature.

---

## 5. Configuration

### 5.1 Attestation interface (REST contract)

Both the node-side attestation client (§5.3) and the verifier service (§5.5)
implement this contract. REST over HTTPS, JSON bodies, the verifier's TLS
certificate pinned by every node. Three endpoints.

**1. Request a challenge** — `POST /v1/challenge`

```json
// request
{ "node_id": "A" }
// response
{ "session_id": "9f2c…", "nonce": "<base64, 32 bytes>" }
```

The `nonce` is fresh and random per request. `node_id` selects the node's mesh
slot/address from the verifier's config — convenience, not a trust anchor (see
notes).

**2. Submit evidence** — `POST /v1/attest`

```json
// request
{
  "session_id":    "9f2c…",
  "report":        "<base64 of the raw SEV-SNP attestation report>",
  "cert_chain":    "<base64 of the VLEK leaf cert (PEM); verifier fetches ARK+ASVK from the AMD KDS>",
  "wg_public_key": "<base64, 32 bytes, raw X25519>",
  "endpoint":      "203.0.113.10:51820"
}
// success
{ "status": "verified" }
// failure (HTTP 4xx)
{ "status": "rejected", "reason": "measurement_mismatch" }
```

The node builds `REPORT_DATA` as `nonce (32 B) || wg_public_key (32 B)`, so the
verifier cross-checks both halves against the issued nonce and the
`wg_public_key` field. Per-node appraisal is decided here and fails fast;
`reason` is one of `signature_invalid`, `measurement_mismatch`,
`tcb_below_minimum`, `policy_violation`, `nonce_mismatch`, `binding_mismatch`.

**3. Fetch credentials** — `GET /v1/credentials?session_id=9f2c…`

```json
// barrier not yet satisfied (HTTP 202)
{ "status": "pending", "verified": 2, "expected": 3 }
// ready (HTTP 200)
{
  "status": "ready",
  "self_address": "10.0.0.1/24",
  "listen_port": 51820,
  "peers": [
    { "public_key": "<wg_pub_B>", "endpoint": "203.0.113.11:51820",
      "allowed_ips": "10.0.0.2/32", "preshared_key": "<PSK_AB>" },
    { "public_key": "<wg_pub_C>", "endpoint": "203.0.113.12:51820",
      "allowed_ips": "10.0.0.3/32", "preshared_key": "<PSK_AC>" }
  ]
}
```

The barrier lives here: `/attest` returns as soon as *this* node is appraised,
but credentials are withheld until every expected node has passed. Nodes poll
this endpoint until it returns `ready`. Because nodes initiate outbound (the
verifier is behind NAT, §3), polling fits the connection direction.

Three points worth stating explicitly:

- **Endorsements are validated, not trusted on supply.** The node may include the
  `cert_chain` it fetched via snpguest, but the verifier validates it up to the
  AMD root it already trusts — trust comes from that known root, not from the
  node's submission. The verifier may equally fetch the chain from the AMD KDS
  itself.
- **`node_id` / slot is configuration, not attested.** Which mesh address a node
  receives is assignment, not a trust decision. In this symmetric design every
  node that passes appraisal is an equal member — membership *is* passing the
  appraisal.
- **`session_id` is a secret capability.** It is the handle to fetch credentials,
  so it is random and stays on the pinned-TLS channel. The deeper protection
  remains the key binding: released credentials are only usable by the holder of
  the attested WG private key.

### 5.2 Prerequisites

Concrete values from the reference run (eu-west-1):

- **Region:** eu-west-1 (one of two AWS regions offering SEV-SNP).
- **Instance type:** c6a.large (3rd-gen EPYC "Milan"; any SEV-SNP-capable
  c6a/m6a/r6a type works).
- **Base AMI:** Ubuntu 24.04, UEFI boot, `ami-07dcad2e028cc44c9`. After the
  one-time node setup (§5.3) it pays to bake a **custom AMI** with snpguest
  pre-built, so further nodes start in seconds instead of rebuilding (§7).
- **Security group:** SSH (TCP 22) inbound from the operator; WireGuard
  (UDP 51820) inbound **from the nodes' public IPs**; outbound to the verifier's
  HTTPS port. The mesh uses the nodes' *public* IPs as WireGuard endpoints, so a
  self-referencing (VPC-internal) rule is not sufficient (§7).
- **Tunnel address plan:** 10.0.0.1 / .2 / .3 within 10.0.0.0/24.

### 5.3 Node setup (per SEV-SNP VM)

Every node runs the same steps. They are the client side of the §5.1 contract:
generate a WireGuard key, bind it into the attestation report, submit the
evidence, then apply the returned peer set. Steps 1–3 are one-time host setup;
steps 4–8 are what the attestation client automates.

**1. Launch with SEV-SNP enabled.** It can only be turned on at launch and cannot
be disabled afterwards. Use a supported type (c6a/m6a/r6a) in a supported region
(e.g. `eu-west-1`) with a UEFI-boot Ubuntu 24.04 AMI.

```bash
aws ec2 run-instances \
  --image-id <ubuntu-24.04-ami> \        # Ubuntu 24.04 UEFI AMI, e.g. ami-07dcad2e028cc44c9 (§5.2)
  --instance-type c6a.large \
  --key-name <key-pair> \               # your EC2 key pair
  --subnet-id <subnet-id> \             # optional; omit to use the default subnet
  --security-group-ids <sg-id> \        # UDP 51820 between node public IPs; outbound to verifier (§5.2)
  --cpu-options AmdSevSnp=enabled

# confirm it took effect (AmdSevSnp should read "enabled"):
aws ec2 describe-instances --instance-ids <id> \
  --query 'Reservations[].Instances[].CpuOptions'
```

**2. Install WireGuard and build snpguest.** On a small instance (c6a.large has
4 GB RAM, no swap, and an 8 GB root disk) set `OPENSSL_NO_VENDOR=1` so snpguest
links the system OpenSSL instead of compiling a vendored copy — the vendored
build is what otherwise exhausts memory and disk (§7).

```bash
sudo apt update && sudo apt install -y wireguard build-essential pkg-config libssl-dev
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
git clone https://github.com/virtee/snpguest.git && cd snpguest
OPENSSL_NO_VENDOR=1 cargo build -r     # ~3 min; binary at target/release/snpguest
```

**3. Generate the WireGuard keypair** inside the VM. The private key never leaves
it; the public key (base64 of 32 raw bytes) is what gets bound and submitted.

```bash
umask 077
wg genkey | tee wg_private.key | wg pubkey > wg_public.key
```

**4. Request a challenge** (§5.1, endpoint 1):

```text
POST /v1/challenge  {"node_id":"A"}  ->  {"session_id": ..., "nonce": <base64 32B>}
```

**5. Build REPORT_DATA and request the report.** The 64-byte request file is the
split layout: nonce in bytes 0–31, raw X25519 public key in bytes 32–63. Decode
both from base64 to raw bytes, concatenate to exactly 64 bytes, then pass the file
to snpguest **without** `--random` — we supply our own REPORT_DATA, not a random
value (which is the only deviation from the stock Ubuntu/AWS guide).

```bash
# nonce_raw = base64-decode(nonce from step 4)          # 32 bytes
# wgpub_raw = base64-decode(contents of wg_public.key)  # 32 bytes
# cat nonce_raw wgpub_raw > request-data.bin            # exactly 64 bytes
#   (verify the expected request-data format/size with: snpguest report --help)

cd target/release
sudo ./snpguest report report.bin /path/to/request-data.bin   # no --random
sudo ./snpguest certificates pem ./                           # extracts host-provided vlek.pem
```

The node submits only this host-provided **VLEK leaf** (`vlek.pem`). It does not
fetch ARK/ASVK itself — the verifier pulls them from the AMD KDS and validates the
chain to the AMD root it trusts (§5.1). `Milan` is the 3rd-gen EPYC codename c6a
uses; a Genoa-based type would report a different one.

Optional local sanity check (the real appraisal is the verifier's job):

```bash
sudo ./snpguest verify attestation ./ report.bin
```

**6. Submit evidence** (§5.1, endpoint 2). Base64-encode `report.bin` and the VLEK
leaf `vlek.pem`, send them with the public key and this node's WireGuard endpoint
(public IP:port):

```text
POST /v1/attest  {session_id, report(b64), cert_chain(b64), wg_public_key(b64), endpoint}
  ->  {"status":"verified"}   or 4xx {"status":"rejected","reason": ...}
```

**7. Poll for credentials** (§5.1, endpoint 3) until the barrier releases:

```text
GET /v1/credentials?session_id=...   ->  202 pending ...  then  200 ready {self_address, peers[...]}
```

**8. Render the WireGuard config and bring up the interface.** Write the returned
peer set into `/etc/wireguard/wg0.conf` (template in §5.4), using the local
private key from step 3, then:

```bash
sudo wg-quick up wg0
sudo wg show          # confirm handshakes with both peers
```

Steps 4–8 are implemented by `attest_client.py`. Run it on each node (it pins the
verifier certificate as its sole trusted CA). Use `sudo`: the client shells out to
`sudo snpguest`, writes `/etc/wireguard/wg0.conf`, and runs `wg-quick up`. Under
sudo `~` is root's home, so pass an absolute `--snpguest-dir`.

```bash
sudo python3 attest_client.py \
  --verifier https://<verifier-hostname>:8443 --verifier-cert verifier.crt \
  --node-id A --endpoint <public-ip>:51820 \
  --snpguest-dir /home/ubuntu/snpguest/target/release --bring-up
```

### 5.4 WireGuard config (template, Node A shown)

Assembled **after** attestation from the verifier's response. Private keys and
PSKs are generated/received at runtime and are **never committed to the repo**.

```ini
[Interface]
PrivateKey = <generated inside the VM, never leaves it>
Address    = 10.0.0.1/24
ListenPort = 51820        # must match the security-group UDP port

[Peer]   # Node B
PublicKey    = <wg_pub_B from verifier>
Endpoint     = <public_ip_B>:51820
AllowedIPs   = 10.0.0.2/32
PresharedKey = <PSK_AB from verifier>

[Peer]   # Node C
PublicKey    = <wg_pub_C from verifier>
Endpoint     = <public_ip_C>:51820
AllowedIPs   = 10.0.0.3/32
PresharedKey = <PSK_AC from verifier>
```

<!-- Nodes B and C are analogous with their own two peers and the matching PSKs. -->

### 5.5 Verifier setup (own hardware)

The verifier is a Python web service on the UTM VM and the only place appraisal
happens. It implements the server side of the §5.1 contract. It is not itself
attested (see §6); on own hardware it is anchored by physical control.

**Responsibilities per endpoint.**

- `/v1/challenge` — issue a fresh 32-byte random nonce, open a session keyed by
  `node_id`, store `{nonce, status: awaiting_evidence}`.
- `/v1/attest` — parse and check the submitted report, then mark the session
  `verified` or reject with a reason.
- `/v1/credentials` — withhold until the barrier is satisfied, then return the
  node's peer set.

**Report parsing.** Parse `report.bin` along the AMD ABI attestation-report layout
(Table 23) with Python `struct`, little-endian, accounting for reserved/padding.
Extract at minimum `version`, `policy`, `current_tcb` / `reported_tcb`,
`report_data` (64 B), `measurement` (48 B), and the signature. Validate the parser
once against `snpguest display report report.bin` so the offsets are known-good
before anything depends on them.

**Cryptographic verification — delegate, do not hand-roll.** Two checks: the report
is signed by the VLEK leaf (ECDSA P-384), and the VLEK chains to the AMD root (ARK)
the verifier trusts. Both are error-prone by hand (P-384 r/s endianness, chain
handling), so delegate them to a vetted implementation. Simplest is to run
snpguest on the verifier over the submitted report and certs
(`snpguest verify attestation <certs-dir> report.bin`, plus chain validation
against the cached AMD root); the virtee `sev` crate is the library alternative.
The verifier caches the AMD root once and does not trust node-supplied certs
beyond validating them to that root.

**Appraisal (your Python logic), fail-fast at `/v1/attest`,** each failure mapped
to a contract `reason`:

- `measurement` equals the golden measurement (§5.6) — else `measurement_mismatch`
- `reported_tcb` >= the four TCB minimums (§5.6) — else `tcb_below_minimum`
- `policy` flags as expected, e.g. debug disabled — else `policy_violation`
- `report_data[0:32]` equals this session's nonce — else `nonce_mismatch`
- `report_data[32:64]` equals the submitted `wg_public_key` — else `binding_mismatch`
- signature or chain invalid — `signature_invalid`

**Barrier and credential assembly.** Hold every passing session until all expected
nodes (here 3) are `verified`. Then assign tunnel addresses by `node_id`
(A -> 10.0.0.1, B -> 10.0.0.2, C -> 10.0.0.3), mint one preshared key per mesh
edge, and build each node's peer set. `/v1/credentials` returns `pending` with a
count until then, `ready` afterwards.

```bash
wg genpsk     # one per edge: PSK_AB, PSK_AC, PSK_BC  (or secrets.token_bytes(32) in Python)
```

**TLS (pinned self-signed).** Generate the certificate with the verifier's public
hostname in the SAN, serve HTTPS with it, and ship the certificate to every node
as their sole trusted CA — nodes pin it (`requests ... verify=verifier.crt`) and
reject anything else. This authenticates the verifier to the nodes; it does not
authenticate the report (the AMD signature does that).

```bash
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout verifier.key -out verifier.crt -days 365 \
  -subj "/CN=<verifier-hostname>" -addext "subjectAltName=DNS:<verifier-hostname>"
```

**Reachability.** The verifier is outside AWS, behind NAT (§3). Give it a stable
name (dynamic DNS, or a manual A-record for a single session) and forward its
HTTPS port through the router to the VM; nodes connect outbound to
`https://<verifier-hostname>:<port>/v1/...`. The verifier is never a WireGuard
peer — that would be a chicken-and-egg with the mesh it gates. The reference run
used port 8443 so the service binds without root, with the router forwarding the
public 8443 to it.

Implemented by `verifier.py` (Flask). Fill the reference values in its `CONFIG`
(§5.6), then run it on the VM:

```bash
pip install -r requirements.txt
python3 verifier.py     # serves HTTPS on CONFIG["bind"] using verifier.crt / verifier.key
```

### 5.6 Reference values

These are what `/v1/attest` appraises against (§5.5). They live in the verifier's
config and must come from a trusted source separate from the evidence — a node
must not be able to supply its own expected values.

**Golden measurement (48 bytes)** — the expected launch measurement, derived in
two steps:

1. *Stability baseline:* launch a node twice with identical configuration and
   compare the `measurement` field. A stable value is a candidate golden
   measurement.
2. *Independent reconstruction:* try to recompute it with `sev-snp-measure` from
   the OVMF firmware (plus kernel/initrd/cmdline for direct boot) and the vCPU
   setup. On AWS this is the hard part — the measured early-boot OVMF runs before
   the AMI and is AWS-provided, so the exact inputs may be unavailable. If it
   matches, the value is strongly grounded; if it cannot be reproduced, document
   it honestly as a **trust-on-first-use (TOFU) baseline** from observed stable
   launches.

On this lab's AWS platform the second step is **not achievable**: `sev-snp-measure`
runs, but the OVMF firmware that the launch measurement covers is AWS-provided and
not exposed to the guest, so the input needed for an exact recomputation is
unavailable. The golden measurement is therefore a **trust-on-first-use (TOFU)
baseline** — but a well-supported one: the same 48-byte value
(`507e82d2…a15f`) was observed across two launches five weeks apart (with two
stop/start cycles in between) and again from a custom AMI — confirming the
measurement is bound to the AWS-provided OVMF, not to the AMI's disk contents.
The honest consequence is recorded in §6: a TOFU
baseline detects drift from that baseline (a changed image or firmware) but does
not by itself prove the baseline corresponds to known-good source. Expect it to
change legitimately when AWS updates the underlying OVMF, so treat a mismatch as
"investigate", not automatically "attack".

The values appraised against, captured on a c6a.large (Milan, ABI 1.58.1) in
eu-west-1 and pinned in the verifier's `CONFIG`:

- **Golden measurement:** `507e82d27ea5b951dd765a3eb31ba5f582673b301d6983ded482d3feb066cb68979f1f11fede97687374d3a25002a15f`
- **Report version:** 5
- **TCB minimums (anti-rollback floor):** bootloader 4, TEE 0, SNP 29, microcode 222
- **Policy:** `0x2030000` (debug disabled, SMT allowed, page-swap-disable set)

**TCB minimums** — the reported TCB has four components (bootloader, TEE, SNP
firmware, microcode). Each is a minimum acceptable version and any report with a
component below it is rejected; this is anti-rollback against known-vulnerable
firmware. The floor above is the platform's current TCB; it should track upward
as AWS patches the platform.

**Policy flags** — the report's `policy` field encodes the guest policy fixed at
launch. The verifier pins the exact value `0x2030000`; the security-relevant bit
is debug disabled, alongside SMT allowed, migration-agent association off, and
page-swap-disable set. Anything that does not match is rejected.

## 6. Trust assumptions and limitations

- **Verifier is not self-attested.** It is trusted by physical control of the
  hardware, which removes the AWS hypervisor from its TCB but does not protect
  against a remote compromise of the verifier process. Managed solutions (Azure
  MAA in an SGX enclave) attest the verifier itself; this lab does not.
- **Launch-time, not runtime.** Attestation proves the state at launch. It does
  not detect later in-memory compromise.
- **Golden measurement is a TOFU baseline.** On AWS the launch measurement cannot
  be independently reconstructed (the measured OVMF is AWS-provided and not
  exposed), so the expected value is trusted on first use — here, a value stable
  across two launches. This detects drift from that baseline but does not prove
  the baseline itself corresponds to known-good source (see §5.6).
- **CSP in the TCB.** AWS reports are VLEK-signed, so AWS is trusted for key
  provisioning.
- **All node identities are attested.** With mutual attestation there is no
  statically trusted peer key — an improvement over an asymmetric design.
- **Bootstrap.** Reference values and the verifier's reachability are
  pre-provisioned/assumed. Availability and DoS are out of scope.

## 7. Lessons learned

These came up from actually building and running the system. The kind of problems that are invisible in planning but become problems during the practice.

- **Building snpguest on a small instance.** c6a.large has 4 GB RAM and no swap,
  and the stock Ubuntu root disk is 8 GB. snpguest's dependency tree vendors and
  compiles OpenSSL from C source, which exhausted first memory (the instance shut
  *itself* down — `Client.InstanceInitiatedShutdown`, an OOM, not an AWS action)
  and then disk (`No space left on device`). `OPENSSL_NO_VENDOR=1` links the
  system OpenSSL and sidesteps both; adding swap fixes the memory side alone.
  Building once and capturing a custom AMI removes the problem for further nodes.
- **The measurement is OVMF-bound, not AMI-bound.** A node launched from the
  custom AMI produced the same launch measurement as one from the stock AMI —
  consistent with AWS measuring its own early-boot OVMF before the AMI loads, and
  the reason the golden measurement stays stable across images (§5.6, §6).
- **Mesh endpoints are public IPs.** The verifier hands each node its *public* IP
  as the WireGuard endpoint, so peer traffic leaves and re-enters through the
  internet gateway. A self-referencing security-group rule matches only
  VPC-internal source IPs and is therefore not enough; UDP 51820 must be allowed
  from the nodes' public IPs. Until that rule existed, every config was correct
  but no handshake completed.

## 8. References

- RFC 9334 — Remote ATtestation procedureS (RATS) Architecture
- AMD — SEV Secure Nested Paging Firmware ABI Specification (Pub. 56860)
- J. A. Donenfeld — WireGuard: Next Generation Kernel Network Tunnel (NDSS 2017)
- AWS — Attest an Amazon EC2 instance with AMD SEV-SNP (EC2 User Guide)