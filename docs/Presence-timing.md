# Polling and presence timing

Prepared locally after 3.12.0; not released yet.

Timing remains configurable. When saving a tracked entry, the form requires:

**Presence grace period ≥ scan interval + request timeout.**

This is a configuration floor, not a guarantee or a bound on a complete poll.
Sequential requests, retries and clients reported through a parent can take
longer. In a mesh, consider the slowest reporting node and increase the grace
period as needed. Longer grace periods delay real departure detection.

- Scan interval schedules polling; requests add duration and shorter intervals increase router load.
- Presence grace period ages the last observation; the state changes on a subsequent evaluation, not at an exact wall-clock deadline.
- Request timeout limits a request, with shorter endpoint-specific limits on some reads. It does not cap a complete update.
- Activity days governs old client retention and can remove entities when no other node retains them. This is independent of scheduled auto-purge; disabling that schedule with 0 does not disable activity retention.

For scan/timeout 20/20, the minimum is 40 seconds; for 30/20 it is 50 seconds.
Start with 60 seconds in those examples. With scan/timeout 60/20, at least
80 seconds are required. Slow meshes may need more than the minimum.

New entries suggest 60 seconds of presence grace. Existing settings are not
changed automatically at startup or when opening the form. Unsafe saves show
an inline minimum and preserve submitted values without authentication or
persistence. The check does not block entries with tracking disabled.

The maintainer's trial uses main/node scans of 20/30 seconds, timeout 20 seconds
and presence grace 60 seconds on both. Auto-purge stays disabled during testing.
Observe a continuously connected client for 10 minutes, then test a deliberate
disconnect/reconnect. This checks the timing hypothesis; it does not prove every
future presence fluctuation has the same cause.
