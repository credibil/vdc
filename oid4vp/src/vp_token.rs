//! #! Querying credentials

use std::collections::HashMap;

use anyhow::Result;
use credibil_proof::Signature;
use credibil_vdc::dcql::{QueryResult, RequestedFormat};
use credibil_vdc::mso_mdoc::DeviceResponseBuilder;
use credibil_vdc::sd_jwt::SdJwtVpBuilder;
use credibil_vdc::w3c_vc::W3cVpBuilder;

use crate::ResponseMode;
use crate::types::RequestObject;

/// Generate a Verifiable Presentation (VP) token.
///
/// # Errors
///
/// Returns an error when building a presentation from a `QueryResult` fails.
pub async fn generate(
    request_object: &RequestObject, results: &[QueryResult<'_>], signer: &impl Signature,
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
            RequestedFormat::JwtVcJson => {
                for matched in &result.matches {
                    let vp = W3cVpBuilder::new()
                        .client_id(request_object.client_id.to_string())
                        .nonce(request_object.nonce.clone())
                        .matched(matched)
                        .signer(signer)
                        .build()
                        .await?;
                    presentations.push(vp);
                }
            }
            RequestedFormat::JwtVcJsonLd | RequestedFormat::LdpVc => {
                todo!()
            }
        }

        token.insert(result.query.id.clone(), presentations);
    }

    Ok(token)
}
