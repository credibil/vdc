//! #! Querying credentials

use std::collections::HashMap;

use anyhow::Result;
use credibil_did::SignerExt;

use crate::format::mso_mdoc::DeviceResponseBuilder;
use crate::format::sd_jwt::SdJwtVpBuilder;
use crate::oid4vp::ResponseMode;
use crate::oid4vp::types::{QueryResult, RequestObject, RequestedFormat};

/// Generate a Verifiable Presentation (VP) token.
///
/// # Errors
///
/// Returns an error when building a presentation from a `QueryResult` fails.
pub async fn generate(
    request_object: &RequestObject, results: &[QueryResult<'_>], signer: &impl SignerExt,
) -> Result<HashMap<String, Vec<String>>> {
    let mut token = HashMap::<String, Vec<String>>::new();

    // create an entry for each credential query
    for result in results {
        let mut presentations = vec![];

        // create presentation for each query result
        match result.query.format {
            RequestedFormat::DcSdJwt => {
                for matched in &result.matches {
                    let vp = SdJwtVpBuilder::new()
                        .client_id(request_object.client_id.to_string())
                        .nonce(request_object.nonce.clone())
                        .matched(matched)
                        .signer(signer)
                        .build()
                        .await?;
                    presentations.push(vp);
                }
            }
            RequestedFormat::MsoMdoc => {
                let response_uri = match &request_object.response_mode {
                    ResponseMode::DirectPost { response_uri }
                    | ResponseMode::DirectPostJwt { response_uri } => response_uri,
                    ResponseMode::Fragment { .. } => {
                        return Err(anyhow::anyhow!("response_uri not found"));
                    }
                };

                for matched in &result.matches {
                    let vp = DeviceResponseBuilder::new()
                        .client_id(request_object.client_id.to_string())
                        .nonce(request_object.nonce.clone())
                        .response_uri(response_uri.to_string())
                        .matched(matched)
                        .signer(signer)
                        .build()
                        .await?;
                    presentations.push(vp);
                }
            }
            RequestedFormat::JwtVcJson | RequestedFormat::JwtVcJsonLd | RequestedFormat::LdpVc => {
                todo!()
            }
        }

        token.insert(result.query.id.clone(), presentations);
    }

    Ok(token)
}
