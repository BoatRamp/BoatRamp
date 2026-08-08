//! Managed credentials for a boatramp-run SQL database (PLAN-managed-compute-sql,
//! Phase 2). boatramp generates a strong password on first use, seals it with the
//! secrets [`KeyEnvelope`], and persists it in the control-plane KV — **stable
//! across restarts** (the DB server was initialized with it) and **never stored in
//! cleartext**. The same password configures the DB workload's server env at launch
//! and connects the handler `sql` binding, so an operator sets no DB secret at all.

use std::sync::Arc;

use boatramp_core::envelope::KeyEnvelope;
use boatramp_core::kv::KvStore;
use boatramp_storage::ExternalSqlKind;

/// The env vars a managed DB server image reads to **initialize on first boot** with
/// boatramp's managed credential — so the handler can then connect as `user`/`password`
/// to `database`. (Postgres: `POSTGRES_*`; MySQL: `MYSQL_*`, incl. a root password —
/// unused by handlers but required by the image to init.) Injected into the DB
/// workload's env at launch (P2-b); the values come from [`ManagedSqlCredentials`].
#[cfg_attr(not(feature = "handlers"), allow(dead_code))]
pub fn managed_db_server_env(
    kind: ExternalSqlKind,
    database: &str,
    user: &str,
    password: &str,
) -> Vec<(String, String)> {
    match kind {
        ExternalSqlKind::Postgres => vec![
            ("POSTGRES_USER".into(), user.into()),
            ("POSTGRES_PASSWORD".into(), password.into()),
            ("POSTGRES_DB".into(), database.into()),
        ],
        ExternalSqlKind::Mysql => vec![
            ("MYSQL_USER".into(), user.into()),
            ("MYSQL_PASSWORD".into(), password.into()),
            ("MYSQL_DATABASE".into(), database.into()),
            // The image requires a root password to initialize; reuse the managed
            // secret (root is not exposed to handlers, which connect as `user`).
            ("MYSQL_ROOT_PASSWORD".into(), password.into()),
        ],
    }
}

/// Generates + seals + persists a stable password per managed-DB workload.
#[cfg_attr(not(feature = "handlers"), allow(dead_code))]
pub struct ManagedSqlCredentials {
    kv: Arc<dyn KvStore>,
    envelope: Arc<dyn KeyEnvelope>,
}

impl ManagedSqlCredentials {
    /// Build over the control-plane KV and the secrets envelope. A managed DB
    /// requires an envelope (`[secrets]`) so the password is never stored in clear.
    #[cfg_attr(not(feature = "handlers"), allow(dead_code))]
    pub fn new(kv: Arc<dyn KvStore>, envelope: Arc<dyn KeyEnvelope>) -> Self {
        Self { kv, envelope }
    }

    /// KV key holding a workload's sealed password.
    fn key(project: &str, workload: &str) -> String {
        format!("managed-sql-cred/{project}/{workload}")
    }

    /// The stable password for managed DB `workload` in `project`: unsealed from the
    /// store if present, else generated (32 random bytes → hex), sealed, and stored.
    /// Idempotent + stable across restarts, so the DB (initialized with it on first
    /// boot) keeps accepting the same credential.
    ///
    /// Single-node correct (get-then-put). A cluster where two nodes generate
    /// concurrently would race to a mismatch; that needs a put-if-absent (tracked in
    /// the plan) — not yet implemented here.
    #[cfg_attr(not(feature = "handlers"), allow(dead_code))]
    pub async fn password(&self, project: &str, workload: &str) -> Result<String, String> {
        let key = Self::key(project, workload);
        if let Some(sealed) = self.kv.get(&key).await.map_err(|e| e.to_string())? {
            let plain = self
                .envelope
                .unwrap(&sealed)
                .await
                .map_err(|e| e.to_string())?;
            return String::from_utf8(plain).map_err(|_| {
                format!("managed sql credential for {workload:?} is not valid UTF-8")
            });
        }
        let mut bytes = [0u8; 32];
        getrandom::getrandom(&mut bytes).map_err(|e| format!("rng: {e}"))?;
        let password: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        let sealed = self
            .envelope
            .wrap(password.as_bytes())
            .await
            .map_err(|e| e.to_string())?;
        self.kv.put(&key, sealed).await.map_err(|e| e.to_string())?;
        Ok(password)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use boatramp_core::envelope::EnvelopeError;
    use boatramp_core::kv::MemoryKv;

    /// A trivial reversible "envelope" for tests — NOT encryption; it just proves the
    /// stored blob is transformed (sealed) and round-trips (cf. cert.rs's test double).
    struct ReverseEnvelope;
    #[async_trait]
    impl KeyEnvelope for ReverseEnvelope {
        async fn wrap(&self, plaintext: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
            Ok(plaintext.iter().rev().copied().collect())
        }
        async fn unwrap(&self, wrapped: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
            Ok(wrapped.iter().rev().copied().collect())
        }
    }

    #[tokio::test]
    async fn password_is_generated_once_sealed_and_stable() {
        let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let creds = ManagedSqlCredentials::new(kv.clone(), Arc::new(ReverseEnvelope));

        let pw = creds.password("default", "pg").await.unwrap();
        assert_eq!(pw.len(), 64, "32 random bytes, hex-encoded");

        // Stable: a second call unseals the stored value, it is not regenerated.
        assert_eq!(creds.password("default", "pg").await.unwrap(), pw);

        // Stored SEALED, never in cleartext.
        let raw = kv
            .get("managed-sql-cred/default/pg")
            .await
            .unwrap()
            .unwrap();
        assert_ne!(
            raw,
            pw.as_bytes(),
            "the stored blob is sealed, not the password"
        );
        assert_eq!(
            raw.iter().rev().copied().collect::<Vec<u8>>(),
            pw.as_bytes()
        );

        // A fresh store instance (a restart) unseals the SAME password.
        let after_restart = ManagedSqlCredentials::new(kv, Arc::new(ReverseEnvelope));
        assert_eq!(after_restart.password("default", "pg").await.unwrap(), pw);

        // A different workload gets a different password.
        assert_ne!(creds.password("default", "other").await.unwrap(), pw);
    }

    #[test]
    fn server_env_recipe_per_engine() {
        let pg = managed_db_server_env(ExternalSqlKind::Postgres, "analytics", "app", "pw");
        assert_eq!(
            pg,
            vec![
                ("POSTGRES_USER".into(), "app".into()),
                ("POSTGRES_PASSWORD".into(), "pw".into()),
                ("POSTGRES_DB".into(), "analytics".into()),
            ]
        );
        let my = managed_db_server_env(ExternalSqlKind::Mysql, "shop", "app", "pw");
        // MySQL needs a root password to initialize, plus the app user/db.
        assert!(my.contains(&("MYSQL_USER".into(), "app".into())));
        assert!(my.contains(&("MYSQL_DATABASE".into(), "shop".into())));
        assert!(my.contains(&("MYSQL_ROOT_PASSWORD".into(), "pw".into())));
    }
}
