# Credibil VC

Issuance and Verification libraries for use in `OpenID` Verifiable Credentials solutions.

> [!CAUTION]
>
> The code in this repository is under active development.
> 
> We still have much to do and welcome feedback and contributions.

## OpenID for Verifiable Credentials

This repository provides (rudimentary) implementations of [OpenID for Verifiable 
Credential Issuance] and [OpenID for Verifiable Presentations] specifications with an
initial focus on meeting requirements in the [JWT VC Issuance] and [JWT VC Presentation]
Profiles.

You will find a more complete set of documentation on the 
[Credibil website](https://credibil.io).

## Getting Started

There is no default feature for this crate. To use the Issuer API include the `issuer` feature flag; to include the Verifier API use `verifier`. You can include both if building a single service that both issues and verifies credentials or if you are building, say, a holder agent application (like a wallet) that might need the types necessary to interact with both types of service.

Example impementations for Credential issuance and presentation can be found in the [examples](./examples) directory

Additionally, end-to-end client examples can be found in the `/tests` directory.

## WASM

One of the goals of this project is to allow WASM services to be built using this API. While the bulk of the library is compatible with WASM without special consideration, some dependencies require a feature flag. So if compiling for WASM, regardless of the WASM runtime, include the `wasm` feature.

## Specification Conformance

### OpenID for Verifiable Credential Issuance

The following table shows the current status of the implementation of the OpenID for 
Verifiable Credential Issuance specification:

|                   | Alpha<sup>1</sup>                  | In-progress     | Planned                          |
| ----------------- | ---------------------------------- | --------------- | -------------------------------- |
| **Initiated**     | Issuer, Wallet                     |                 |                                  |
| **Flow**          | Pre-Authorized, Authorization Code |                 |                                  |
| **Origin**        | Cross-device, Same-device          |                 |                                  |
| **Issuance**      | Immediate, Deferred                |                 |                                  |
| **FormatProfile** | jwt_vc_json                        |                 | ldp_vc, jwt_vc_json-ld, mso-mdoc |
| **Signature**     | ES256K, EdDSA                      |                 |                                  |
| **Binding**       | did:web, did:key                   |                 | did:dht, did:keri                |
| **Encryption**    |                                    | ECDH-ES/A128GCM | ECDH-ES/A256GCM                  |

1. Working code, but not yet rigorously verified.

### OpenID for Verifiable Presentations

TODO

## Additional

[![ci](https://github.com/credibil/vc/actions/workflows/ci.yaml/badge.svg)](https://github.com/credibil/vc/actions/workflows/ci.yaml)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE-MIT)
[![License](https://img.shields.io/badge/license-Apache-blue.svg)](./LICENSE-APACHE)

<!-- The [changelog][CHANGES] is used to record a summary of changes between releases. A more granular
record of changes can be found in the commit history. -->

More information about [contributing][CONTRIBUTING]. Please respect we maintain this project on a
part-time basis. While we welcome suggestions and technical input, it may take time to respond.

The artefacts in this repository are dual licensed under either:

- MIT license ([LICENSE-MIT] or <http://opensource.org/licenses/MIT>)
- Apache License, Version 2.0 ([LICENSE-APACHE] or <http://www.apache.org/licenses/LICENSE-2.0>)

The license applies to all parts of the source code, its documentation and supplementary files
unless otherwise indicated.

[OpenID for Verifiable Credential Issuance]: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html
[OpenID for Verifiable Presentations]: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html
[JWT VC Issuance]: https://identity.foundation/jwt-vc-issuance-profile
[JWT VC Presentation]: https://identity.foundation/jwt-vc-presentation-profile
<!-- [CHANGES]: CHANGELOG.md -->
[CONTRIBUTING]: CONTRIBUTING.md
[LICENSE-MIT]: LICENSE-MIT
[LICENSE-APACHE]: LICENSE-APACHE

<!-- > [!NOTE]  
> Highlights information that users should take into account, even when skimming.
> [!TIP]
> Optional information to help a user be more successful.
> [!IMPORTANT]  
> Crucial information necessary for users to succeed.
> [!WARNING]  
> Critical content demanding immediate user attention due to potential risks.
> [!CAUTION]
> Negative potential consequences of an action.
-->
