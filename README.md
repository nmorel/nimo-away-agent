# away agent

Takes signed course messages on `POST /course` (HMAC-SHA256 of `<timestamp>.<raw body>`), does free acts alone, and holds gated acts: it pings the owner's phone through ntfy with a link to a page where the owner approves with a code. Policy lives in `policy.mjs`.

Env: `OWNER_SECRET` (admin endpoints), `NTFY_TOPIC`, optional `SIGNING_KEY` (or set it at runtime via `POST /admin/signing-key`).
