# Enable compression

boatramp negotiates compression per request from the client's `Accept-Encoding`.
Precompressed sibling variants are preferred over on-the-fly compression because
they cost no per-request CPU. This page covers both. For how compression
interacts with `Cache-Control` and `ETag`, see [Control caching](./caching.md).

## Ship precompressed variants

At `sync`, boatramp compresses compressible files and stores `br` and `gzip`
blobs next to the identity blob — an `app.js` gets `app.js.br` and `app.js.gz`
siblings. A variant is kept only when it is smaller than identity.

At serve time boatramp negotiates `Accept-Encoding` (brotli over gzip, honoring
`;q=0` and `*`), returns the best variant the client accepts, and sets
`Content-Encoding`, a per-representation `ETag`, and `Vary: Accept-Encoding`.

Request the brotli variant:

```sh
curl -sI -H 'Accept-Encoding: br' https://my-site.example/app.js
```

```text
HTTP/2 200
content-type: text/javascript
content-encoding: br
vary: accept-encoding
```

A client sending no `Accept-Encoding` — or `identity` — gets the uncompressed
blob and the same `Vary` header.

## Compress on the fly

Responses with no precompressed variant — dynamic handler and proxy output —
can be compressed per request. Build with the `compression` feature and enable
it in the site's config:

```ron
// site access/compression config
compression: ( enabled: true, min_size: 1024 ),
```

boatramp streams a gzip or brotli encoder over compressible responses at least
`min_size` bytes. It skips `Set-Cookie` responses for BREACH safety, and `Range`
requests always serve identity. Where a precompressed variant exists it still
wins — on-the-fly compression only fills the gap.
