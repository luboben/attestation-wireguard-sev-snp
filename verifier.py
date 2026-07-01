#!/usr/bin/env python3
"""
Attestation verifier + relying party for the SEV-SNP WireGuard mesh.

Server side of the REST contract in README section 5.1. This is a lab service:
in-memory state, single process, no persistence. It does three things:

  1. /v1/challenge  -> issue a fresh nonce, open a session
  2. /v1/attest     -> verify + appraise one node's report (fail-fast)
  3. /v1/credentials-> withhold until all nodes pass (barrier), then hand out peers

Cryptographic verification (report signature + AMD cert chain) is DELEGATED to
snpguest, not hand-rolled. This service parses the report only for the fields it
appraises, and enforces freshness (nonce) and key binding (WireGuard pubkey).

Fill the TODO config values from a known-good launch (see README section 5.6).
"""

import base64
import os
import secrets
import struct
import subprocess
import tempfile
import threading

from flask import Flask, jsonify, request

# --------------------------------------------------------------------------- #
# Configuration. Empirical values are TODO until the first real launch.        #
# --------------------------------------------------------------------------- #
CONFIG = {
    # node_id -> tunnel address inside the mesh
    "nodes": {"A": "10.0.0.1", "B": "10.0.0.2", "C": "10.0.0.3"},
    "tunnel_prefix": 24,
    "listen_port": 51820,

    # Reference values (README 5.6) -- capture these from a known-good report.
    # 48-byte launch measurement; stable across launches on 2026-05-28 and 2026-06-29 (5.6).
    "golden_measurement_hex": "507e82d27ea5b951dd765a3eb31ba5f582673b301d6983ded482d3feb066cb68979f1f11fede97687374d3a25002a15f",
    # Observed on AWS c6a.large (Milan, ABI 1.58.1); stable across two launches.
    "min_tcb": {"bootloader": 4, "tee": 0, "snp": 29, "microcode": 222},  # anti-rollback floor
    "expected_policy": 0x2030000,   # debug off, SMT on, page-swap-disable on; exact match
    "expected_version": 5,          # observed report version on this platform (was assumed 2)

    # snpguest delegation
    "snpguest": "snpguest",         # path to the binary on the verifier VM
    "processor_model": "milan",     # c6a == 3rd-gen EPYC (Milan)

    # TLS (pinned self-signed; see README 5.5)
    "tls_cert": "verifier.crt",
    "tls_key": "verifier.key",
    "bind": ("0.0.0.0", 443),
}

# --------------------------------------------------------------------------- #
# Report parsing -- AMD ABI attestation-report offsets (little-endian).        #
# Validate these once against `snpguest display report report.bin` before      #
# trusting them; offsets are ABI-stable but worth confirming on your version.  #
# --------------------------------------------------------------------------- #
OFF_VERSION = 0x000      # u32
OFF_POLICY = 0x008       # u64
OFF_CURRENT_TCB = 0x038  # u64
OFF_REPORT_DATA = 0x050  # 64 bytes
OFF_MEASUREMENT = 0x090  # 48 bytes
OFF_REPORTED_TCB = 0x180  # u64
REPORT_MIN_LEN = 0x2A0   # signature starts here; report is at least this long


def parse_report(buf: bytes) -> dict:
    if len(buf) < REPORT_MIN_LEN:
        raise ValueError("attestation report too short: %d bytes" % len(buf))
    return {
        "version": struct.unpack_from("<I", buf, OFF_VERSION)[0],
        "policy": struct.unpack_from("<Q", buf, OFF_POLICY)[0],
        "current_tcb": struct.unpack_from("<Q", buf, OFF_CURRENT_TCB)[0],
        "reported_tcb": struct.unpack_from("<Q", buf, OFF_REPORTED_TCB)[0],
        "report_data": buf[OFF_REPORT_DATA:OFF_REPORT_DATA + 64],
        "measurement": buf[OFF_MEASUREMENT:OFF_MEASUREMENT + 48],
    }


def tcb_components(tcb: int) -> dict:
    # TCB_VERSION packing for Milan: bootloader=b0, tee=b1, snp=b6, microcode=b7.
    # Confirm against the AMD ABI for your platform before relying on it.
    b = tcb.to_bytes(8, "little")
    return {"bootloader": b[0], "tee": b[1], "snp": b[6], "microcode": b[7]}


# --------------------------------------------------------------------------- #
# Cryptographic verification -- delegated to snpguest.                         #
# The node supplies its host-provided VLEK leaf; we fetch ARK+ASVK from the     #
# AMD KDS ourselves (we trust the AMD root, not the node's submission).        #
# --------------------------------------------------------------------------- #
def verify_crypto(report_bin: bytes, vlek_leaf_pem: bytes) -> tuple[bool, str]:
    sg = CONFIG["snpguest"]
    with tempfile.TemporaryDirectory() as d:
        report_path = os.path.join(d, "report.bin")
        with open(report_path, "wb") as f:
            f.write(report_bin)
        with open(os.path.join(d, "vlek.pem"), "wb") as f:
            f.write(vlek_leaf_pem)
        try:
            # Fetch ARK + ASVK for the VLEK endorser into the same dir.
            subprocess.run(
                [sg, "fetch", "ca", "pem", d, CONFIG["processor_model"],
                 "--endorser", "vlek"],
                check=True, capture_output=True, timeout=30,
            )
            # Validate the chain (ARK -> ASVK -> VLEK) ...
            subprocess.run([sg, "verify", "certs", d],
                           check=True, capture_output=True, timeout=30)
            # ... and that the VLEK signed this report.
            subprocess.run([sg, "verify", "attestation", d, report_path],
                           check=True, capture_output=True, timeout=30)
        except subprocess.CalledProcessError as e:
            return False, (e.stderr or e.stdout or b"").decode("utf-8", "replace")
        except Exception as e:  # noqa: BLE001 - lab service, surface anything
            return False, str(e)
    return True, "ok"


# --------------------------------------------------------------------------- #
# Appraisal -- our own logic. Returns None on success or a contract reason.    #
# --------------------------------------------------------------------------- #
def appraise(fields: dict, nonce: bytes, wg_pubkey: bytes) -> str | None:
    if fields["version"] != CONFIG["expected_version"]:
        return "policy_violation"
    if fields["report_data"][:32] != nonce:
        return "nonce_mismatch"
    if fields["report_data"][32:64] != wg_pubkey:
        return "binding_mismatch"

    golden = CONFIG["golden_measurement_hex"]
    if not golden.startswith("TODO"):
        if fields["measurement"] != bytes.fromhex(golden):
            return "measurement_mismatch"

    have = tcb_components(fields["reported_tcb"])
    for part, minimum in CONFIG["min_tcb"].items():
        if have[part] < minimum:
            return "tcb_below_minimum"

    if CONFIG["expected_policy"] is not None:
        if fields["policy"] != CONFIG["expected_policy"]:
            return "policy_violation"

    return None


# --------------------------------------------------------------------------- #
# In-memory session + barrier state.                                           #
# --------------------------------------------------------------------------- #
_lock = threading.Lock()
_sessions: dict[str, dict] = {}   # session_id -> session
_edge_psks: dict[frozenset, str] = {}   # {a,b} -> base64 PSK


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


def _barrier_ready() -> bool:
    verified = {s["node_id"] for s in _sessions.values() if s["status"] == "verified"}
    return verified >= set(CONFIG["nodes"].keys())


def _edge_psk(a: str, b: str) -> str:
    key = frozenset((a, b))
    if key not in _edge_psks:
        _edge_psks[key] = _b64(secrets.token_bytes(32))  # WireGuard PSK = 32 bytes
    return _edge_psks[key]


def _peer_set_for(node_id: str) -> list:
    by_node = {s["node_id"]: s for s in _sessions.values() if s["status"] == "verified"}
    peers = []
    for other_id, sess in by_node.items():
        if other_id == node_id:
            continue
        peers.append({
            "public_key": _b64(sess["wg_pubkey"]),
            "endpoint": sess["endpoint"],
            "allowed_ips": "%s/32" % CONFIG["nodes"][other_id],
            "preshared_key": _edge_psk(node_id, other_id),
        })
    return peers


# --------------------------------------------------------------------------- #
# REST endpoints (README 5.1).                                                 #
# --------------------------------------------------------------------------- #
app = Flask(__name__)


@app.post("/v1/challenge")
def challenge():
    body = request.get_json(force=True, silent=True) or {}
    node_id = body.get("node_id")
    if node_id not in CONFIG["nodes"]:
        return jsonify(error="unknown node_id"), 400
    session_id = secrets.token_urlsafe(24)
    nonce = secrets.token_bytes(32)
    with _lock:
        _sessions[session_id] = {
            "node_id": node_id, "nonce": nonce, "status": "awaiting_evidence",
            "wg_pubkey": None, "endpoint": None,
        }
    return jsonify(session_id=session_id, nonce=_b64(nonce))


@app.post("/v1/attest")
def attest():
    body = request.get_json(force=True, silent=True) or {}
    try:
        session_id = body["session_id"]
        report_bin = base64.b64decode(body["report"])
        vlek_leaf = base64.b64decode(body["cert_chain"])   # VLEK leaf PEM
        wg_pubkey = base64.b64decode(body["wg_public_key"])  # 32 raw bytes
        endpoint = body["endpoint"]
    except (KeyError, ValueError):
        return jsonify(status="rejected", reason="malformed_request"), 400

    with _lock:
        sess = _sessions.get(session_id)
    if sess is None:
        return jsonify(status="rejected", reason="unknown_session"), 404
    if len(wg_pubkey) != 32:
        return jsonify(status="rejected", reason="binding_mismatch"), 400

    ok, detail = verify_crypto(report_bin, vlek_leaf)
    if not ok:
        return jsonify(status="rejected", reason="signature_invalid", detail=detail), 400

    try:
        fields = parse_report(report_bin)
    except ValueError as e:
        return jsonify(status="rejected", reason="signature_invalid", detail=str(e)), 400

    reason = appraise(fields, sess["nonce"], wg_pubkey)
    if reason is not None:
        return jsonify(status="rejected", reason=reason), 400

    with _lock:
        sess["wg_pubkey"] = wg_pubkey
        sess["endpoint"] = endpoint
        sess["status"] = "verified"
    return jsonify(status="verified")


@app.get("/v1/credentials")
def credentials():
    session_id = request.args.get("session_id", "")
    with _lock:
        sess = _sessions.get(session_id)
        if sess is None:
            return jsonify(error="unknown_session"), 404
        if sess["status"] != "verified":
            return jsonify(status="rejected", reason="not_verified"), 409
        if not _barrier_ready():
            # Count DISTINCT verified slots, not sessions -- otherwise three nodes
            # all claiming slot "A" would misleadingly report 3/3 while the barrier
            # (which keys on node_id) never releases. See README section 7.
            verified = len({s["node_id"] for s in _sessions.values()
                            if s["status"] == "verified"})
            return jsonify(status="pending", verified=verified,
                           expected=len(CONFIG["nodes"])), 202
        node_id = sess["node_id"]
        payload = {
            "status": "ready",
            "self_address": "%s/%d" % (CONFIG["nodes"][node_id], CONFIG["tunnel_prefix"]),
            "listen_port": CONFIG["listen_port"],
            "peers": _peer_set_for(node_id),
        }
    return jsonify(payload)


if __name__ == "__main__":
    app.run(host=CONFIG["bind"][0], port=CONFIG["bind"][1], threaded=True,
            ssl_context=(CONFIG["tls_cert"], CONFIG["tls_key"]))
