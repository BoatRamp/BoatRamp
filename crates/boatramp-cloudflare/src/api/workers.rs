//! The Cloudflare **Workers script-upload** API — `PUT /accounts/{id}/workers/
//! scripts/{name}` (multipart: a JSON `metadata` part + the wasm module part).
//! This is documented public REST (the Terraform `workers_script` resource), so
//! only the metadata shape is boatramp-specific.
//!
//! boatramp uploads the edge Worker wasm with its bindings (R2/D1/KV +
//! `durable_object_namespace` for the container node DO + the CacheCoordinator)
//! and the Durable-Object **migration** that creates those DO namespaces.

use serde::Serialize;

use super::{parse_envelope, ApiError, CfApi};

/// One binding attached to the Worker. Serializes with the `type` discriminant
/// the script-upload metadata expects (`r2_bucket`, `d1`, `kv_namespace`,
/// `durable_object_namespace`, `plain_text`, `secret_text`).
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Binding {
    /// An R2 bucket binding (blobs).
    R2Bucket {
        /// The JS variable name the Worker sees.
        name: String,
        /// The bucket name.
        bucket_name: String,
    },
    /// A D1 database binding (the `sql` handler store).
    D1 {
        /// The JS variable name.
        name: String,
        /// The database id (uuid).
        id: String,
    },
    /// A Workers KV namespace binding.
    KvNamespace {
        /// The JS variable name.
        name: String,
        /// The namespace id.
        namespace_id: String,
    },
    /// A Durable Object namespace binding (a DO class in this Worker).
    DurableObjectNamespace {
        /// The JS variable name.
        name: String,
        /// The exported DO class name.
        class_name: String,
    },
    /// A plaintext variable (non-secret config).
    PlainText {
        /// The JS variable name.
        name: String,
        /// The literal value.
        text: String,
    },
}

/// The Durable-Object migration applied with an upload — creates/renames/deletes
/// DO namespaces. boatramp creates its DO classes with `new_sqlite_classes`.
#[derive(Debug, Clone, Serialize, PartialEq, Default)]
pub struct Migrations {
    /// The previously-applied migration tag to verify against (first upload: none).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_tag: Option<String>,
    /// The tag this migration sets as latest.
    pub new_tag: String,
    /// Classes to create (non-SQLite DO storage).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub new_classes: Vec<String>,
    /// Classes to create with SQLite-in-DO storage (the modern default).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub new_sqlite_classes: Vec<String>,
    /// Classes whose DO namespaces should be deleted.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub deleted_classes: Vec<String>,
}

/// The `metadata` part of a Worker script upload (the fields boatramp sets).
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ScriptMetadata {
    /// The module part name that is the Worker entrypoint (must match the uploaded
    /// module part's name, e.g. `"worker.wasm"`).
    pub main_module: String,
    /// The bindings attached to the Worker.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub bindings: Vec<Binding>,
    /// The DO migration to apply (first upload creates the DO namespaces).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub migrations: Option<Migrations>,
    /// The Workers runtime compatibility date.
    pub compatibility_date: String,
    /// Optional compatibility flags.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub compatibility_flags: Vec<String>,
}

/// One module part of a Worker upload — the ESM entrypoint plus any wasm/JS it
/// imports (a `worker-build` output is a JS shim + the wasm module + JS glue).
/// The part name is the module's filename, referenced by other modules and by
/// [`ScriptMetadata::main_module`].
#[derive(Debug, Clone, PartialEq)]
pub struct WorkerModule {
    /// The module filename / part name (e.g. `"shim.mjs"`, `"index_bg.wasm"`).
    pub name: String,
    /// The module MIME (`application/javascript+module` or `application/wasm`).
    pub content_type: String,
    /// The module bytes.
    pub bytes: Vec<u8>,
}

impl WorkerModule {
    /// An ES-module JavaScript part.
    pub fn js(name: impl Into<String>, bytes: Vec<u8>) -> Self {
        Self {
            name: name.into(),
            content_type: "application/javascript+module".into(),
            bytes,
        }
    }

    /// A WebAssembly module part.
    pub fn wasm(name: impl Into<String>, bytes: Vec<u8>) -> Self {
        Self {
            name: name.into(),
            content_type: "application/wasm".into(),
            bytes,
        }
    }
}

impl CfApi {
    /// Upload (create or replace) a Worker script: its `modules` (the ESM
    /// entrypoint + any wasm/JS it imports) plus the `metadata` (bindings + DO
    /// migration). [`ScriptMetadata::main_module`] must name one of the modules.
    pub async fn upload_worker(
        &self,
        script_name: &str,
        metadata: &ScriptMetadata,
        modules: Vec<WorkerModule>,
    ) -> Result<serde_json::Value, ApiError> {
        let url = format!("{}/workers/scripts/{script_name}", self.account_base());
        let meta_json =
            serde_json::to_vec(metadata).map_err(|e| ApiError::Decode(e.to_string()))?;
        let metadata_part = reqwest::multipart::Part::bytes(meta_json)
            .mime_str("application/json")
            .map_err(|e| ApiError::Network(e.to_string()))?;
        let mut form = reqwest::multipart::Form::new().part("metadata", metadata_part);
        for module in modules {
            let part = reqwest::multipart::Part::bytes(module.bytes)
                .file_name(module.name.clone())
                .mime_str(&module.content_type)
                .map_err(|e| ApiError::Network(e.to_string()))?;
            form = form.part(module.name, part);
        }
        let resp = self
            .client
            .put(&url)
            .bearer_auth(&self.token)
            .multipart(form)
            .send()
            .await
            .map_err(|e| ApiError::Network(e.to_string()))?;
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| ApiError::Network(e.to_string()))?;
        parse_envelope(&bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_serializes_to_the_upload_shape() {
        let meta = ScriptMetadata {
            main_module: "worker.wasm".into(),
            bindings: vec![
                Binding::R2Bucket {
                    name: "BLOBS".into(),
                    bucket_name: "boatramp-blobs".into(),
                },
                Binding::DurableObjectNamespace {
                    name: "NODE".into(),
                    class_name: "BoatrampNode".into(),
                },
                Binding::PlainText {
                    name: "BOATRAMP_PRIMARY".into(),
                    text: "enam".into(),
                },
            ],
            migrations: Some(Migrations {
                new_tag: "v1".into(),
                new_sqlite_classes: vec!["BoatrampNode".into(), "CacheCoordinator".into()],
                ..Default::default()
            }),
            compatibility_date: "2025-01-01".into(),
            compatibility_flags: vec![],
        };
        let json = serde_json::to_value(&meta).unwrap();
        assert_eq!(json["main_module"], "worker.wasm");
        // Binding `type` discriminants match the documented metadata vocabulary.
        assert_eq!(json["bindings"][0]["type"], "r2_bucket");
        assert_eq!(json["bindings"][0]["bucket_name"], "boatramp-blobs");
        assert_eq!(json["bindings"][1]["type"], "durable_object_namespace");
        assert_eq!(json["bindings"][1]["class_name"], "BoatrampNode");
        assert_eq!(json["bindings"][2]["type"], "plain_text");
        // First upload: no old_tag; SQLite DO classes created under the new tag.
        assert!(json["migrations"].get("old_tag").is_none());
        assert_eq!(json["migrations"]["new_tag"], "v1");
        assert_eq!(json["migrations"]["new_sqlite_classes"][0], "BoatrampNode");
        // Empty vecs are omitted (compatibility_flags, new_classes).
        assert!(json.get("compatibility_flags").is_none());
        assert!(json["migrations"].get("new_classes").is_none());
    }
}
