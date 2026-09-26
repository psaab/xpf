# Management HTTPS certificates and rotation

The management HTTPS endpoint accepts either the persisted system-generated certificate or an operator-installed certificate/key pair. Custom PEM files must be readable by the `xpf` process; the certificate chain is leaf-first. Protect the private key (for example, mode `0600`).

## Install a custom certificate

Install the chain and matching private key on the firewall, then commit both paths together:

```text
set system services web-management https certificate /etc/xpf/tls/management-chain.pem
set system services web-management https private-key /etc/xpf/tls/management-key.pem
commit
```

Use a certificate issued by a CA trusted by the management clients and covering the HTTPS management address. The leaf must be currently valid. The `certificate` and `private-key` settings must be configured as a pair; a partial pair is rejected and HTTPS fails closed. To use the generated certificate instead, select `set system services web-management https system-generated-certificate` and remove the custom paths.

## Validity checks and monitoring

The server checks `NotBefore` and `NotAfter` when it loads a pair, on every TLS handshake, and on a periodic one-hour monitor. An out-of-window custom certificate is logged at error level, increments `xpf_management_tls_certificate_invalid_total`, and is not served. If an already-running custom certificate expires or becomes not-yet-valid, TLS handshakes are refused until a valid pair is installed. The monitor reloads the configured files, so a valid replacement written to the same paths is picked up without restarting the daemon.

An expired or not-yet-valid system-generated pair is logged at error level, increments the same counter, and is re-minted. If minting or loading a usable custom pair fails, the HTTPS certificate selector refuses the handshake rather than falling back to a stale certificate. HTTP remains available for recovery.

## Rotate a certificate (including compromise response)

For a deterministic rotation, install the new chain and key at new versioned paths, then update both configuration paths and commit. The running server loads and validates the new pair during reconciliation; new TLS handshakes use it without a daemon restart. Confirm the commit succeeded and make a strict-verifying client reconnect to the HTTPS management address. Replacing the selected certificate/key is the server-side revocation action: the old identity is no longer selected for new TLS handshakes. Existing TLS connections remain established until they close or drain; for a compromised key, terminate any affected client sessions as part of the incident response.

For a self-signed system-generated certificate, rotation creates a new trust anchor. Clients that pin the old self-signed certificate must update their pin. For a CA-issued certificate, also revoke the old certificate through the issuing CA when required; this service does not implement CRL or OCSP checks.

The system-generated pair is persisted at `/etc/xpf/tls/cert.pem` and `/etc/xpf/tls/key.pem`. Expiry or not-yet-valid status causes automatic re-minting; deleting those files is not needed for ordinary renewal.
