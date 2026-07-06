# Caching & Compression

## Cache-Control

The `Cache-Control` on a served file is resolved in this order:

1. A matching **header rule** in the deploy config (`project.cfg` `routing`) —
   always wins.
2. The deploy's blanket **`cache.default`**, if set.
3. Otherwise, **smart per-file defaults**:
   - a content-hashed filename (`app.4f3a2b2c.js`, `index-a1b2c3d4.css`) →
     `public, max-age=31536000, immutable` (the name changes when the content
     does, so it's safe to cache forever);
   - HTML → `public, max-age=0, must-revalidate` (so a new deploy is picked up).

Fingerprint detection is conservative: the token before the extension must be ≥8
characters and contain both a letter and a digit, so plain words
(`application.js`) and bare dates (`report-20240115.pdf`) are not cached for a
year.

## Conditional requests

Every response carries a strong **ETag** (the content hash). `If-None-Match`
yields a `304`. This is optimal revalidation, so `If-Modified-Since` is
intentionally not implemented (there is no per-file mtime to compare, and the
date validator is strictly weaker).

## Compression

boatramp serves **precompressed variants** by default: at `sync`, compressible
files get `br` and `gzip` blobs (kept only when smaller than identity), and the
server negotiates `Accept-Encoding` (br > gzip, honoring `;q=0` and `*`), sets
`Content-Encoding` + a per-representation `ETag` + `Vary: Accept-Encoding`. A
variant that isn't smaller than identity is never served (a decompression-bomb
guard; boatramp itself never decompresses).

### On-the-fly compression

For responses that have **no** precompressed variant — dynamic handler/proxy
output, and static files the bundler never compressed — enable per-site
on-the-fly compression (the `compression` build feature):

```jsonc
// SiteConfig.compression
{ "enabled": true, "min_size": 1024 }
```

It streams a gzip/brotli encoder over `200` responses of a compressible type
that are at least `min_size` bytes, and **skips `Set-Cookie` responses**
(BREACH safety). Precompressed variants still win where present.

`Range` requests always serve identity.
