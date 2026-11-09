# Performance

Parsing uses one `tshark -T fields` pass per handler instead of pyshark
decoding every matching packet. Quick wins are a single pass (previously a
regex over `str(packet)` for every packet).

## Measured

Synthetic 20,000-packet capture, same machine (baseline with the then-14-handler
registry):

| Operation | Before | After | Speed-up |
|---|---|---|---|
| Full parse (all handlers) | 54.6 s | 8.1 s | 6.7x |
| Quick-win scan | 95.4 s | 0.6 s | 159x |

Small provided captures: 4.1–5.1 s with the 14-handler registry; most of that
is tshark startup per handler. The current registry has **31 handlers**, and a
2026-11-09 benchmark on a synthetic 20,000-packet mixed DNS/HTTP capture
(`python scripts/benchmark.py --packets 20000`) measured **16.5 s for 33 tshark
passes** (some detectors need two passes; the shared Kerberos pass serves
`kerberos`, `kerberoast`, `asrepcatcher` and `kerberosdepth` in one). Use
`--only` when you do not need everything.

The loading screen shows `handler 3/31 ftp | elapsed 00:12 | ETA 00:41`; the
same line is logged at INFO so long runs are predictable.

## Big captures

- Use `--only` for the protocols you care about; each handler is one pass.
  `--only services,ips,dns` is the cheap first map.
- `-q` alone scans only the quick-win protocols and is now cheap.
- `--credentials-only` runs 18 handlers (identity/credential/hash protocols,
  including tokens and database auth).
- Avoid running all handlers on multi-hundred-MB captures when you only need
  credentials: `pufferrelay -f big.pcapng --credentials-only --dump out`.

## Known limits

- TCP reassembly for very large file objects depends on tshark; carving caps
  objects at 1 MiB (HTTP/FTP) or 8 MiB (SMB) and 16 MiB per capture.
- The database grows with findings, not capture size.
- `tcp.reassembled.data` is required for Kerberos DER parsing; captures without
  reassembly produce Kerberoast candidates instead of hashes.
