use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};

use anyhow::{Result, anyhow};
use credibil_vc::oid4vci::types::Dataset;
use serde::Deserialize;
use serde_json::{Map, Value};

use super::kms::Keyring;

static OWNER: LazyLock<Keyring> = LazyLock::new(Keyring::new);

#[derive(Default, Clone, Debug, Deserialize)]
#[serde(default)]
struct Credential {
    configuration_id: String,
    claims: Map<String, Value>,
    pending: bool,
}

#[derive(Default, Clone, Debug)]
pub struct DatasetStore {
    datasets: Arc<Mutex<HashMap<String, HashMap<String, Credential>>>>,
}

impl DatasetStore {
    #[must_use]
    pub fn new() -> Self {
        let json = include_bytes!("../data/datasets.json");
        let datasets: HashMap<String, HashMap<String, Credential>> =
            serde_json::from_slice(json).expect("should serialize");

        Self {
            datasets: Arc::new(Mutex::new(datasets)),
        }
    }

    pub fn authorize(
        &self, subject_id: &str, credential_configuration_id: &str,
    ) -> Result<Vec<String>> {
        let subj_datasets =
            self.datasets.lock().expect("should lock").get(subject_id).unwrap().clone();

        // preset dataset identifiers for subject/credential
        let mut identifiers = vec![];
        for (k, credential) in &subj_datasets {
            if credential.configuration_id != credential_configuration_id {
                continue;
            }
            identifiers.push(k.clone());
        }

        if identifiers.is_empty() {
            return Err(anyhow!("no matching dataset for subject/credential"));
        }

        Ok(identifiers)
    }

    pub fn dataset(&self, subject_id: &str, credential_identifier: &str) -> Result<Dataset> {
        // get claims for the given `subject_id` and `credential_identifier`
        let mut subj_datasets =
            self.datasets.lock().expect("should lock").get(subject_id).unwrap().clone();
        let mut credential = subj_datasets.get(credential_identifier).unwrap().clone();

        // update subject's pending state to make Deferred Issuance work
        let pending = credential.pending;
        credential.pending = false;
        subj_datasets.insert(credential_identifier.to_string(), credential.clone());
        self.datasets.lock().expect("should lock").insert(subject_id.to_string(), subj_datasets);

        Ok(Dataset {
            claims: credential.claims,
            pending,
        })
    }
}
