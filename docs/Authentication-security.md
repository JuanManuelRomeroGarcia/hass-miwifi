# Authentication security and CodeQL findings

MiWiFi uses the router firmware's LuCI login protocol. The firmware login page
constructs `H(nonce + H(password + public_key))`, where `H` is SHA-1 or SHA-256,
depending on the firmware mode. The public constant is part of the protocol;
it is not a secret or a unique per-user password salt. This formula was checked
against the local RC01 login page during the security review on 14 October 2026.
Both modes are covered by synthetic login request tests, including UTF-8 input.

CodeQL flags both hashes as unsuitable for password hashing. This is a real
protocol limitation: a captured login exchange permits offline password
guessing with fast hashes. The integration does not use these hashes to store
its own password verifier, but that does not remove the network risk. Replacing
the hashes with Argon2, bcrypt or PBKDF2 in the client alone would produce a
different response and fail authentication; a stronger protocol requires
support in the router firmware.

The SHA-1 and SHA-256 findings remain visible in CodeQL. They are not suppressed,
dismissed as false positives, or presented as fixed by this review.

## Reduce exposure

- Use a strong, unique router administrator password.
- Prefer HTTPS where the router supports it. Automatic protocol detection tries
  HTTPS first, then HTTP; `auto` therefore does not guarantee encrypted transport.
- Keep Home Assistant and the router management interface on a trusted network
  and restrict management access. HTTP does not protect login exchanges or
  subsequent authenticated traffic from observers on the network.
- Treat Home Assistant configuration and backups as sensitive: the integration
  needs the configured router credential to authenticate again.

Client roaming now logs only that ownership changed and the number of empty
device rows removed. That message no longer includes a client MAC or config entry
identifier. The regression test checks both formatted messages and raw log
arguments. This change addresses the specific clear-text logging finding; it is
not a claim that every diagnostic or debug message contains no private data.

References: [CodeQL password hashing rule](https://codeql.github.com/codeql-query-help/python/py-weak-sensitive-data-hashing/)
and [CodeQL sensitive logging rule](https://codeql.github.com/codeql-query-help/python/py-clear-text-logging-sensitive-data/).
