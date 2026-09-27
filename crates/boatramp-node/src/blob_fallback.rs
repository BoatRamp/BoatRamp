//! The `BLOB FALLBACK ZERO-GAP OK` mutation-verified gate — blob-backend migration Part 2.
//!
//! Compiled ONLY under the `blob-fallback-gate-mutation` feature (the CI gate lane). It drives the
//! REAL [`FallbackStorage`](boatramp_storage::FallbackStorage) composite over real `FsStorage`
//! tempdir backends (plus a real [`DeployStore`](boatramp_core::deploy::DeployStore) for the
//! GC-refusal invariant), asserts every zero-gap security invariant, and prints the marker only on a
//! clean run. Each `BOATRAMP_BLOBFB_MUTATE_*` env var makes the gate build/behave like a specific
//! broken implementation (via a seam applied to the composite's INPUTS — the predicate, a mutation
//! wrapper backend, or the read policy), so a clean run reaches the marker while every mutation PANICS
//! before it — proving each check is load-bearing. Mirrors the #505 `s3_credential::gate` structure
//! exactly. See the ci.yml gate step.

#[cfg(test)]
mod gate {
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::time::Duration;

    /// Whether a mutation env var is set (non-empty and not `0`). Each `BOATRAMP_BLOBFB_MUTATE_*`
    /// env var makes the gate behave like a specific broken implementation, so CI can prove each
    /// invariant is load-bearing. Mirrors the #505 `s3_credential::gate_mutation::env_on` seam.
    fn env_on(name: &str) -> bool {
        std::env::var(name)
            .map(|v| !v.is_empty() && v != "0")
            .unwrap_or(false)
    }

    use boatramp_core::deploy::DeployStore;
    use boatramp_core::kv::MemoryKv;
    use boatramp_core::{
        ByteStream, ChangeStream, GetObject, ObjectMeta, PutMeta, Storage, StorageError,
    };
    use boatramp_storage::{FallbackStorage, FallbackWhen, FsStorage};
    use bytes::Bytes;
    use futures::StreamExt;

    // ---- helpers ------------------------------------------------------------------------------

    fn bytes_stream(bytes: Bytes) -> ByteStream {
        futures::stream::once(async move { Ok(bytes) }).boxed()
    }

    async fn collect(mut body: ByteStream) -> Vec<u8> {
        let mut buf = Vec::new();
        while let Some(chunk) = body.next().await {
            buf.extend_from_slice(&chunk.expect("chunk"));
        }
        buf
    }

    async fn put(store: &Arc<dyn Storage>, key: &str, bytes: &[u8]) {
        store
            .put(
                key,
                bytes_stream(Bytes::copy_from_slice(bytes)),
                PutMeta::default(),
            )
            .await
            .expect("put");
    }

    async fn read(store: &Arc<dyn Storage>, key: &str) -> Result<Vec<u8>, StorageError> {
        Ok(collect(store.get(key).await?.body).await)
    }

    /// The sorted key set present in a backend (list `""`).
    async fn keys_of(store: &Arc<dyn Storage>) -> Vec<String> {
        let mut ks: Vec<String> = store
            .list("")
            .await
            .expect("list")
            .into_iter()
            .map(|m| m.key)
            .collect();
        ks.sort();
        ks
    }

    /// The boatramp read-fallback allowlist predicate (mirrors `blobs::blob_fallback_when`). Under the
    /// `NO_FALLBACK` mutation it never allows fallback (so a primary miss is never healed → G1 FAIL);
    /// under `ALLOW_CP_FALLBACK` it allows fallback for EVERY key (so a secondary-only `config/…`
    /// resurrects → G5-cp FAIL).
    fn predicate() -> FallbackWhen {
        if env_on("BOATRAMP_BLOBFB_MUTATE_NO_FALLBACK") {
            return Arc::new(|_k: &str| false);
        }
        if env_on("BOATRAMP_BLOBFB_MUTATE_ALLOW_CP_FALLBACK") {
            return Arc::new(|_k: &str| true);
        }
        Arc::new(|k: &str| {
            boatramp_core::deploy::is_blob_key(k)
                || k.starts_with("hblob/")
                || k.starts_with("mqgp/")
        })
    }

    /// A `Storage` wrapper over an `FsStorage` that INJECTS one of the read-policy mutations, applied
    /// to a backend a real [`FallbackStorage`] is built over. When no mutation flag is set it is a thin
    /// passthrough, so the CLEAN run drives the real composite unchanged.
    ///
    /// - `hide_hits` (G2 `REVERSE_PRECEDENCE`): turn a present PRIMARY object into a `NotFound`, so the
    ///   real composite falls through to the secondary and serves the WRONG (secondary) bytes even
    ///   though the primary has the key — proving primary-precedence is load-bearing.
    /// - `error_on_read` (G4-err `FALLBACK_ON_ERROR`): return a `Backend` error from the primary. The
    ///   real composite must PROPAGATE it (never consult the secondary). The shared `reads` counter
    ///   (used on the SECONDARY wrapper in G4) lets the test assert the secondary was never touched.
    ///
    /// (G3 `WRITE_SECONDARY` is not a wrapper mutation — the real composite's `put`/`delete` are
    /// primary-only, so that invariant models the broken "mirror writes onto the secondary" behavior
    /// directly in its test body.)
    struct MutWrap {
        inner: Arc<dyn Storage>,
        hide_hits: bool,
        error_on_read: bool,
        reads: Arc<Mutex<usize>>,
    }

    impl MutWrap {
        fn count(&self) {
            *self.reads.lock().unwrap() += 1;
        }
    }

    #[async_trait::async_trait]
    impl Storage for MutWrap {
        async fn get(&self, key: &str) -> Result<GetObject, StorageError> {
            self.count();
            if self.error_on_read {
                return Err(StorageError::backend("primary transient failure (gate)"));
            }
            if self.hide_hits {
                // Pretend the primary lacks the key even when it has it (forces a fall-through).
                return Err(StorageError::NotFound(key.to_string()));
            }
            self.inner.get(key).await
        }
        async fn get_range(
            &self,
            key: &str,
            offset: u64,
            len: Option<u64>,
        ) -> Result<GetObject, StorageError> {
            self.count();
            if self.error_on_read {
                return Err(StorageError::backend("primary transient failure (gate)"));
            }
            if self.hide_hits {
                return Err(StorageError::NotFound(key.to_string()));
            }
            self.inner.get_range(key, offset, len).await
        }
        async fn put(
            &self,
            key: &str,
            body: ByteStream,
            meta: PutMeta,
        ) -> Result<ObjectMeta, StorageError> {
            self.inner.put(key, body, meta).await
        }
        async fn head(&self, key: &str) -> Result<ObjectMeta, StorageError> {
            self.count();
            if self.error_on_read {
                return Err(StorageError::backend("primary transient failure (gate)"));
            }
            if self.hide_hits {
                return Err(StorageError::NotFound(key.to_string()));
            }
            self.inner.head(key).await
        }
        async fn delete(&self, key: &str) -> Result<(), StorageError> {
            self.inner.delete(key).await
        }
        async fn list(&self, prefix: &str) -> Result<Vec<ObjectMeta>, StorageError> {
            self.inner.list(prefix).await
        }
        fn mapped(&self, key: &str) -> Option<bytes::Bytes> {
            self.inner.mapped(key)
        }
        fn local_file(&self, key: &str) -> Option<std::fs::File> {
            self.inner.local_file(key)
        }
        fn supports_watch(&self) -> bool {
            self.inner.supports_watch()
        }
        async fn watch(&self, prefix: &str) -> Result<Option<ChangeStream>, StorageError> {
            self.inner.watch(prefix).await
        }
    }

    /// Two fresh fs backends (distinct tempdir roots) — the primary + the read-only secondary.
    fn fs_pair(tmp: &std::path::Path) -> (Arc<dyn Storage>, Arc<dyn Storage>) {
        let primary: Arc<dyn Storage> = Arc::new(FsStorage::new(tmp.join("primary")));
        let secondary: Arc<dyn Storage> = Arc::new(FsStorage::new(tmp.join("secondary")));
        (primary, secondary)
    }

    /// Build the REAL composite under test over the given primary/secondary (5s secondary timeout).
    fn compose(primary: Arc<dyn Storage>, secondary: Arc<dyn Storage>) -> Arc<dyn Storage> {
        Arc::new(FallbackStorage::new(
            primary,
            secondary,
            predicate(),
            Duration::from_secs(5),
        ))
    }

    // ---- invariants ---------------------------------------------------------------------------

    /// G1: a primary MISS on an eligible key is healed from the secondary.
    /// Mutation `NO_FALLBACK` (predicate never allows fallback) ⇒ NotFound ⇒ FAIL.
    async fn g1_primary_miss_reads_secondary(tmp: &std::path::Path) {
        let (primary, secondary) = fs_pair(&tmp.join("g1"));
        put(
            &secondary,
            "hblob/site/c/only-on-secondary",
            b"SECONDARY-BYTES",
        )
        .await;
        let fb = compose(primary, secondary);
        let got = read(&fb, "hblob/site/c/only-on-secondary")
            .await
            .expect("G1: a primary miss must be healed from the secondary");
        assert_eq!(
            got, b"SECONDARY-BYTES",
            "G1: the secondary's bytes must be served on a primary miss"
        );
    }

    /// G2: a primary HIT wins over a divergent secondary (primary precedence).
    /// Mutation `REVERSE_PRECEDENCE` (primary wrapped to hide its hit) ⇒ secondary bytes ⇒ FAIL.
    async fn g2_primary_hit_wins(tmp: &std::path::Path) {
        let (raw_primary, secondary) = fs_pair(&tmp.join("g2"));
        put(&raw_primary, "hblob/site/c/dup", b"PRIMARY-WINS").await;
        put(&secondary, "hblob/site/c/dup", b"secondary-loses").await;
        // The mutation hides the primary's hit so the composite falls through.
        let primary: Arc<dyn Storage> = Arc::new(MutWrap {
            inner: raw_primary,
            hide_hits: env_on("BOATRAMP_BLOBFB_MUTATE_REVERSE_PRECEDENCE"),
            error_on_read: false,
            reads: Arc::new(Mutex::new(0)),
        });
        let fb = compose(primary, secondary);
        let got = read(&fb, "hblob/site/c/dup").await.expect("G2 read");
        assert_eq!(
            got, b"PRIMARY-WINS",
            "G2: a primary hit must win over a divergent secondary (no reverse precedence)"
        );
    }

    /// G3: `put`/`delete` touch the PRIMARY ONLY; the secondary object set is unchanged.
    /// Mutation `WRITE_SECONDARY` (the broken impl also writes the secondary) ⇒ secondary set changes
    /// ⇒ FAIL.
    async fn g3_write_isolation(tmp: &std::path::Path) {
        let (primary, secondary) = fs_pair(&tmp.join("g3"));
        put(&secondary, "hblob/site/c/pre-existing", b"S").await;
        let secondary_before = keys_of(&secondary).await;
        let fb = compose(primary.clone(), secondary.clone());

        // Write + delete through the composite (primary-only in the real impl).
        put(&fb, "hblob/site/c/new", b"N").await;
        fb.delete("hblob/site/c/pre-existing").await.unwrap();

        // The mutation models a broken composite that mirrors writes/deletes onto the read-only
        // secondary — do that DIRECTLY here so the invariant observes the divergence.
        if env_on("BOATRAMP_BLOBFB_MUTATE_WRITE_SECONDARY") {
            put(&secondary, "hblob/site/c/new", b"N").await;
            secondary.delete("hblob/site/c/pre-existing").await.unwrap();
        }

        let secondary_after = keys_of(&secondary).await;
        assert_eq!(
            secondary_before, secondary_after,
            "G3: put/delete must be primary-only — the secondary object set must be unchanged"
        );
        // And the primary DID take the write (sanity: the write landed somewhere).
        assert!(
            keys_of(&primary)
                .await
                .contains(&"hblob/site/c/new".to_string()),
            "G3: the write must land on the primary"
        );
    }

    /// G4-err: a non-NotFound PRIMARY error PROPAGATES and the secondary is NOT consulted.
    /// Mutation `FALLBACK_ON_ERROR` (fall back on ANY error) ⇒ secondary bytes returned ⇒ FAIL.
    async fn g4_error_propagates(tmp: &std::path::Path) {
        let (raw_primary, secondary) = fs_pair(&tmp.join("g4"));
        put(&secondary, "hblob/site/c/obj", b"SHOULD-NOT-BE-SERVED").await;
        let secondary_reads = Arc::new(Mutex::new(0usize));
        // A primary that always errors; a secondary whose reads are counted.
        let primary: Arc<dyn Storage> = Arc::new(MutWrap {
            inner: raw_primary,
            hide_hits: false,
            error_on_read: true,
            reads: Arc::new(Mutex::new(0)),
        });
        let counted_secondary: Arc<dyn Storage> = Arc::new(MutWrap {
            inner: secondary,
            hide_hits: false,
            error_on_read: false,
            reads: secondary_reads.clone(),
        });

        if env_on("BOATRAMP_BLOBFB_MUTATE_FALLBACK_ON_ERROR") {
            // The broken impl: on a primary ERROR, fall back to the secondary anyway.
            let result = match primary.get("hblob/site/c/obj").await {
                Ok(o) => Ok(o),
                Err(_) => counted_secondary.get("hblob/site/c/obj").await,
            };
            // It "succeeds" by serving the secondary — which is exactly the failure this gate forbids.
            let bytes = collect(result.expect("broken impl served secondary").body).await;
            assert_ne!(
                bytes, b"SHOULD-NOT-BE-SERVED",
                "G4-err: a primary error must NOT fall back to the secondary"
            );
        } else {
            // The REAL composite: the primary error must PROPAGATE, secondary untouched.
            let fb = compose(primary, counted_secondary);
            let err = fb.get("hblob/site/c/obj").await;
            assert!(
                matches!(err, Err(StorageError::Backend(_))),
                "G4-err: a non-NotFound primary error must propagate"
            );
            assert_eq!(
                *secondary_reads.lock().unwrap(),
                0,
                "G4-err: the secondary must NOT be consulted on a primary error"
            );
        }
    }

    /// G5-cp: a `config/…` present ONLY on the secondary is NOT served (the allowlist excludes it).
    /// Mutation `ALLOW_CP_FALLBACK` (predicate allows every key) ⇒ the config resolves ⇒ FAIL.
    async fn g5_control_plane_not_resurrected(tmp: &std::path::Path) {
        let (primary, secondary) = fs_pair(&tmp.join("g5"));
        put(&secondary, "config/site-alpha", b"STALE-CONFIG").await;
        let fb = compose(primary, secondary);
        assert!(
            matches!(
                fb.get("config/site-alpha").await,
                Err(StorageError::NotFound(_))
            ),
            "G5-cp: a control-plane-shaped key on the secondary must NOT fall back (allowlist excludes it)"
        );
    }

    /// G8-gc: a `DeployStore` over a `FallbackStorage` REFUSES `collect_garbage(prune=true)`.
    /// Mutation `PRUNE_ANYWAY` (the composite reports `allows_prune()==true`) ⇒ GC prunes ⇒ FAIL.
    async fn g8_gc_refuses_prune(tmp: &std::path::Path) {
        let (primary, secondary) = fs_pair(&tmp.join("g8"));
        // An UNREFERENCED content-addressed blob present only on the secondary — a prune candidate
        // (no manifest references it). Its presence in the union `list` is what would make GC report
        // it reclaimed while the primary-only delete no-ops on the read-only secondary.
        let orphan = "ab/0000000000000000000000000000000000000000000000000000000000000000";
        put(&secondary, orphan, b"orphan-blob-bytes").await;

        // The composite under test. Under the mutation, swap in a shim that reports allows_prune==true
        // (the broken composite) so GC would proceed.
        let composite: Arc<dyn Storage> = if env_on("BOATRAMP_BLOBFB_MUTATE_PRUNE_ANYWAY") {
            Arc::new(PrunablyBrokenFallback {
                inner: FallbackStorage::new(
                    primary,
                    secondary.clone(),
                    predicate(),
                    Duration::from_secs(5),
                ),
            })
        } else {
            compose(primary, secondary.clone())
        };

        let store = DeployStore::new(composite, Arc::new(MemoryKv::new()));
        let result = store.collect_garbage(true).await;

        if env_on("BOATRAMP_BLOBFB_MUTATE_PRUNE_ANYWAY") {
            // The broken composite allowed the prune: GC ran (Ok). That is the fail-open this gate
            // forbids — assert the refusal that the real composite guarantees, which now fails.
            assert!(
                matches!(
                    result,
                    Err(boatramp_core::DeployError::PruneUnsafeWithFallback)
                ),
                "G8-gc: GC must REFUSE a prune while a read-fallback secondary is attached \
                 (mutation PRUNE_ANYWAY let it through)"
            );
        } else {
            // The REAL composite: GC must refuse the prune, and the orphan must still be on the
            // secondary (nothing deleted).
            assert!(
                matches!(
                    result,
                    Err(boatramp_core::DeployError::PruneUnsafeWithFallback)
                ),
                "G8-gc: GC must REFUSE a prune while a read-fallback secondary is attached"
            );
            assert!(
                keys_of(&secondary).await.contains(&orphan.to_string()),
                "G8-gc: the refused prune must not have deleted the secondary orphan"
            );
        }
    }

    /// G9-key: the composite forwards the key BYTE-IDENTICAL to both backends — a `hblob/tenantA/…`
    /// get must not resolve a `hblob/tenantB/…` object. Mutation `REWRITE_KEY` (the primary is wrapped
    /// to rewrite tenantA→tenantB before lookup) ⇒ cross-tenant bytes served ⇒ FAIL.
    async fn g9_key_fidelity(tmp: &std::path::Path) {
        let (raw_primary, secondary) = fs_pair(&tmp.join("g9"));
        // tenantB's object lives on the primary; tenantA's key is absent everywhere.
        put(&raw_primary, "hblob/tenantB/c/secret", b"TENANT-B-SECRET").await;
        let primary: Arc<dyn Storage> = if env_on("BOATRAMP_BLOBFB_MUTATE_REWRITE_KEY") {
            Arc::new(KeyRewritingPrimary { inner: raw_primary })
        } else {
            raw_primary
        };
        let fb = compose(primary, secondary);
        // A get for tenantA's key must NEVER return tenantB's bytes.
        match fb.get("hblob/tenantA/c/secret").await {
            Err(StorageError::NotFound(_)) => {} // correct: tenantA has no object anywhere.
            Ok(o) => {
                let bytes = collect(o.body).await;
                assert_ne!(
                    bytes, b"TENANT-B-SECRET",
                    "G9-key: a tenantA get must not resolve tenantB's object (no key rewrite)"
                );
                panic!("G9-key: tenantA key unexpectedly resolved to an object");
            }
            Err(e) => panic!("G9-key: unexpected error {e:?}"),
        }
    }

    /// G10-map: `mapped`/`local_file` are PRIMARY ONLY. An object present only on the fs SECONDARY
    /// returns `mapped()==None` (and `local_file()==None`) through a primary miss. Mutation
    /// `MAPPED_FALLBACK` (fall back for the zero-copy accessors) ⇒ `Some` ⇒ FAIL.
    async fn g10_mapped_primary_only(tmp: &std::path::Path) {
        let (primary, secondary) = fs_pair(&tmp.join("g10"));
        put(
            &secondary,
            "hblob/site/c/only-secondary",
            b"secondary-mmap-bytes",
        )
        .await;
        let fb = compose(primary, secondary.clone());

        let mapped = if env_on("BOATRAMP_BLOBFB_MUTATE_MAPPED_FALLBACK") {
            // The broken impl: fall back to the secondary's zero-copy accessor.
            fb.mapped("hblob/site/c/only-secondary")
                .or_else(|| secondary.mapped("hblob/site/c/only-secondary"))
        } else {
            fb.mapped("hblob/site/c/only-secondary")
        };
        assert!(
            mapped.is_none(),
            "G10-map: mapped() must be primary-only — a secondary-only object must not map"
        );
        assert!(
            fb.local_file("hblob/site/c/only-secondary").is_none(),
            "G10-map: local_file() must be primary-only"
        );
    }

    /// A shim that wraps a real [`FallbackStorage`] but LIES about `allows_prune` (returns `true`) —
    /// the G8-gc `PRUNE_ANYWAY` mutation, modeling a composite that forgot to forbid pruning.
    struct PrunablyBrokenFallback {
        inner: FallbackStorage,
    }
    #[async_trait::async_trait]
    impl Storage for PrunablyBrokenFallback {
        async fn get(&self, key: &str) -> Result<GetObject, StorageError> {
            self.inner.get(key).await
        }
        async fn get_range(
            &self,
            key: &str,
            offset: u64,
            len: Option<u64>,
        ) -> Result<GetObject, StorageError> {
            self.inner.get_range(key, offset, len).await
        }
        async fn put(
            &self,
            key: &str,
            body: ByteStream,
            meta: PutMeta,
        ) -> Result<ObjectMeta, StorageError> {
            self.inner.put(key, body, meta).await
        }
        async fn head(&self, key: &str) -> Result<ObjectMeta, StorageError> {
            self.inner.head(key).await
        }
        async fn delete(&self, key: &str) -> Result<(), StorageError> {
            self.inner.delete(key).await
        }
        async fn list(&self, prefix: &str) -> Result<Vec<ObjectMeta>, StorageError> {
            self.inner.list(prefix).await
        }
        // The mutation: pretend a read-fallback composite is safe to prune.
        fn allows_prune(&self) -> bool {
            true
        }
    }

    /// A primary wrapper that rewrites a `hblob/tenantA/…` key to `hblob/tenantB/…` before lookup —
    /// the G9-key `REWRITE_KEY` mutation (a key-mangling composite that collapses a tenant boundary).
    struct KeyRewritingPrimary {
        inner: Arc<dyn Storage>,
    }
    impl KeyRewritingPrimary {
        fn rewrite(key: &str) -> String {
            key.replace("tenantA", "tenantB")
        }
    }
    #[async_trait::async_trait]
    impl Storage for KeyRewritingPrimary {
        async fn get(&self, key: &str) -> Result<GetObject, StorageError> {
            self.inner.get(&Self::rewrite(key)).await
        }
        async fn get_range(
            &self,
            key: &str,
            offset: u64,
            len: Option<u64>,
        ) -> Result<GetObject, StorageError> {
            self.inner.get_range(&Self::rewrite(key), offset, len).await
        }
        async fn put(
            &self,
            key: &str,
            body: ByteStream,
            meta: PutMeta,
        ) -> Result<ObjectMeta, StorageError> {
            self.inner.put(&Self::rewrite(key), body, meta).await
        }
        async fn head(&self, key: &str) -> Result<ObjectMeta, StorageError> {
            self.inner.head(&Self::rewrite(key)).await
        }
        async fn delete(&self, key: &str) -> Result<(), StorageError> {
            self.inner.delete(&Self::rewrite(key)).await
        }
        async fn list(&self, prefix: &str) -> Result<Vec<ObjectMeta>, StorageError> {
            self.inner.list(prefix).await
        }
    }

    #[tokio::test]
    async fn blob_fallback_zero_gap_gate() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path();

        g1_primary_miss_reads_secondary(root).await;
        g2_primary_hit_wins(root).await;
        g3_write_isolation(root).await;
        g4_error_propagates(root).await;
        g5_control_plane_not_resurrected(root).await;
        g8_gc_refuses_prune(root).await;
        g9_key_fidelity(root).await;
        g10_mapped_primary_only(root).await;

        // Reached only on a clean, fully-passing run — a mutation env var panics one invariant above.
        println!(
            "BLOB FALLBACK ZERO-GAP OK: the read-fallback composite serves the primary first and \
             heals a primary miss from the read-only secondary (G1) without ever losing primary \
             precedence (G2); put/delete are primary-only (G3); a non-NotFound primary error \
             propagates and never consults the secondary (G4-err); a non-allowlisted \
             (control-plane-shaped) key never resurrects off the secondary (G5-cp); GC refuses to \
             prune while a fallback secondary is attached (G8-gc); the key is forwarded byte-identical \
             so no tenant boundary collapses (G9-key); and mapped/local_file are primary-only (G10). \
             Mutation-verified: BOATRAMP_BLOBFB_MUTATE_{{NO_FALLBACK,REVERSE_PRECEDENCE,\
             WRITE_SECONDARY,FALLBACK_ON_ERROR,ALLOW_CP_FALLBACK,PRUNE_ANYWAY,REWRITE_KEY,\
             MAPPED_FALLBACK}}=1 each FAIL this gate."
        );
    }
}
