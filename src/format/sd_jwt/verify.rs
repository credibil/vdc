use anyhow::Result;

/// Verifies an SD-JWT presentation (KB-JWT, and associated disclosures).
///
/// # Errors
///
/// Returns an error if the SD-JWT presentation is invalid or if verification
/// fails.
pub async fn verify() -> Result<()> {
    // unpack the kb-jwt and verify
    // unpack the sd-jwt and verify
    // unpack disclosures and verify against  sd-jwt `_sd` & `_sd_alg`
    // return the disclosures and metadata

    Ok(())
}
