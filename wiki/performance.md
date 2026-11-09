# Performance

Parsing uses one `tshark -T fields` pass per handler instead of pyshark
decoding every matching packet. Quick wins are a single pass (previously a
regex over `str(packet)` for every packet).

## Measured

Synthetic 20,000-packet capture, same machine:

| Operation | Before | After | Speed-up |
|---|---|---|---|
| Full parse (all handlers) | 54.6 s | 8.1 s | 6.7x |
| Quick-win scan | 95.4 s | 0.6 s | 159x |

Small provided captures: full parse 4.1–5.1 s (most of that is tshark startup
per handler).

The loading screen shows `handler 3/14 ftp | elapsed 00:12 | ETA 00:41`; the
same line is logged at INFO so long runs are predictable.

## Big captures

- Use `--only` for the protocols you care about; each handler is one pass.
- `-q` alone scans only the quick-win protocols and is now cheap.
- `--credentials-only` runs 8 handlers (identity/credential protocols).
- Avoid running all 14 handlers on multi-hundred-MB captures when you only need
  credentials: `pufferrelay -f big.pcapng --credentials-only --dump out`.

## Known limits

- TCP reassembly for very large file objects depends on tshark; carving caps
  objects at 1 MiB and 16 MiB per capture.
- The database grows with findings, not capture size.
