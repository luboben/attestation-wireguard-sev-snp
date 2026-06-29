#!/usr/bin/env python3
"""
Node attestation client for the SEV-SNP WireGuard mesh.

Client side of the REST contract in README section 5.1; automates steps 4-8 of
README section 5.3 on each SEV-SNP node:

  1. request a challenge (nonce) from the verifier
  2. generate a WireGuard keypair (private key never leaves this VM)
  3. build REPORT_DATA = nonce(32) || wg_public_key(32) and request a report
  4. gather the VLEK leaf certificate
  5. submit the evidence
  6. poll for credentials until the barrier releases
  7. render /etc/wireguard/wg0.conf and (optionally) bring the tunnel up

Run with --bring-up to invoke `wg-quick up` at the end (needs root). The verifier
certificate is PINNED via --verifier-cert (used as the sole trusted CA).
"""

import argparse
import base64
import os
import subprocess
import sys
import tempfile
import time

import requests


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


def gen_wireguard_keypair() -> tuple[str, str]:
    priv = subprocess.run(["wg", "genkey"], check=True,
                          capture_output=True, text=True).stdout.strip()
    pub = subprocess.run(["wg", "pubkey"], input=priv, check=True,
                         capture_output=True, text=True).stdout.strip()
    return priv, pub


def request_report(snpguest: str, snpguest_dir: str, report_data: bytes,
                   workdir: str) -> tuple[bytes, bytes]:
    """Return (report_bin, vlek_leaf_pem). report_data must be exactly 64 bytes."""
    assert len(report_data) == 64, "REPORT_DATA must be 64 bytes"
    req_path = os.path.join(workdir, "request-data.bin")
    report_path = os.path.join(workdir, "report.bin")
    with open(req_path, "wb") as f:
        f.write(report_data)

    # No --random: we supply our own REPORT_DATA (nonce || wg_pub).
    subprocess.run(["sudo", snpguest, "report", report_path, req_path],
                   check=True, cwd=snpguest_dir)
    # Extract the host-provided VLEK leaf certificate into workdir.
    subprocess.run(["sudo", snpguest, "certificates", "pem", workdir],
                   check=True, cwd=snpguest_dir)

    with open(report_path, "rb") as f:
        report_bin = f.read()
    vlek_path = os.path.join(workdir, "vlek.pem")
    if not os.path.exists(vlek_path):
        sys.exit("vlek.pem not found in %s (check `snpguest certificates` output)" % workdir)
    with open(vlek_path, "rb") as f:
        vlek_leaf = f.read()
    return report_bin, vlek_leaf


def render_wg_config(creds: dict, private_key: str) -> str:
    lines = [
        "[Interface]",
        "PrivateKey = %s" % private_key,
        "Address    = %s" % creds["self_address"],
        "ListenPort = %d" % creds["listen_port"],
    ]
    for p in creds["peers"]:
        lines += [
            "",
            "[Peer]",
            "PublicKey    = %s" % p["public_key"],
            "Endpoint     = %s" % p["endpoint"],
            "AllowedIPs   = %s" % p["allowed_ips"],
            "PresharedKey = %s" % p["preshared_key"],
        ]
    return "\n".join(lines) + "\n"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--verifier", required=True, help="https://<verifier-host>")
    ap.add_argument("--verifier-cert", required=True, help="pinned verifier cert (PEM)")
    ap.add_argument("--node-id", required=True, help="this node's mesh slot, e.g. A")
    ap.add_argument("--endpoint", required=True, help="this node's public ip:port")
    ap.add_argument("--snpguest-dir", required=True,
                    help="dir containing the snpguest binary (target/release)")
    ap.add_argument("--wg-conf", default="/etc/wireguard/wg0.conf")
    ap.add_argument("--poll-interval", type=float, default=3.0)
    ap.add_argument("--poll-timeout", type=float, default=300.0)
    ap.add_argument("--bring-up", action="store_true",
                    help="run `wg-quick up` after writing the config (needs root)")
    args = ap.parse_args()

    snpguest = os.path.join(args.snpguest_dir, "snpguest")
    verify = args.verifier_cert  # requests uses this PEM as the only trusted CA
    base = args.verifier.rstrip("/")

    # 1. challenge
    r = requests.post("%s/v1/challenge" % base, json={"node_id": args.node_id},
                      verify=verify, timeout=30)
    r.raise_for_status()
    session_id = r.json()["session_id"]
    nonce = base64.b64decode(r.json()["nonce"])
    assert len(nonce) == 32, "verifier nonce must be 32 bytes"

    # 2. WireGuard keypair (private key stays on this VM)
    wg_priv, wg_pub = gen_wireguard_keypair()
    wg_pub_raw = base64.b64decode(wg_pub)
    assert len(wg_pub_raw) == 32, "WireGuard public key must be 32 bytes"

    # 3.+4. REPORT_DATA = nonce || wg_pub, request report + VLEK leaf
    report_data = nonce + wg_pub_raw
    with tempfile.TemporaryDirectory() as workdir:
        report_bin, vlek_leaf = request_report(snpguest, args.snpguest_dir,
                                                report_data, workdir)

    # 5. submit evidence
    r = requests.post("%s/v1/attest" % base, verify=verify, timeout=60, json={
        "session_id": session_id,
        "report": b64(report_bin),
        "cert_chain": b64(vlek_leaf),
        "wg_public_key": wg_pub,
        "endpoint": args.endpoint,
    })
    if r.status_code != 200:
        sys.exit("attestation rejected: %s" % r.text)

    # 6. poll for credentials until the barrier releases
    deadline = time.time() + args.poll_timeout
    creds = None
    while time.time() < deadline:
        r = requests.get("%s/v1/credentials" % base, params={"session_id": session_id},
                         verify=verify, timeout=30)
        if r.status_code == 200:
            creds = r.json()
            break
        if r.status_code == 202:
            st = r.json()
            print("waiting for barrier: %s/%s verified" %
                  (st.get("verified"), st.get("expected")))
            time.sleep(args.poll_interval)
            continue
        sys.exit("unexpected credentials response %d: %s" % (r.status_code, r.text))
    if creds is None:
        sys.exit("timed out waiting for the barrier")

    # 7. render config and optionally bring the tunnel up
    conf = render_wg_config(creds, wg_priv)
    old = os.umask(0o077)
    try:
        with open(args.wg_conf, "w") as f:
            f.write(conf)
    finally:
        os.umask(old)
    print("wrote %s (%d peers)" % (args.wg_conf, len(creds["peers"])))

    if args.bring_up:
        iface = os.path.splitext(os.path.basename(args.wg_conf))[0]
        subprocess.run(["sudo", "wg-quick", "up", iface], check=True)
        subprocess.run(["sudo", "wg", "show", iface], check=False)


if __name__ == "__main__":
    main()
