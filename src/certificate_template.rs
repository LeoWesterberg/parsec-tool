// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

//! Utility code that is shared by multiple subcommands;

use picky_asn1::wrapper::IntegerAsn1;
use serde::{Deserialize, Serialize};
use crate::error::{Result, ToolErrorKind, Error};
use log::error;
use parsec_client::core::interface::operations::psa_algorithm::{
    Algorithm, AsymmetricSignature, Hash, SignHash,
};
use parsec_client::core::interface::operations::psa_key_attributes::{EccFamily, Type};
use parsec_client::BasicClient;

use crate::util::sign_message_with_policy;
use rcgen::{
    Certificate, CertificateParams, DistinguishedName, DnType, KeyPair,
    SignatureAlgorithm, PKCS_ECDSA_P256_SHA256, PKCS_ECDSA_P384_SHA384, PKCS_RSA_SHA256,
    PKCS_RSA_SHA384, PKCS_RSA_SHA512, RcgenError, RemoteKeyPair
};
use time::OffsetDateTime;


#[derive(Serialize, Deserialize)]
struct EccSignature {
    r: IntegerAsn1,
    s: IntegerAsn1,
}


/// Short-lived structure to encapsulate the key name and the client, so that we can implement the
/// RemoteKeyPair trait for rcgen.
#[derive(Debug)]
struct ParsecRemoteKeyPair {
    key_name: String,
    public_key_der: Vec<u8>,
    parsec_client: BasicClient,
    rcgen_algorithm: &'static SignatureAlgorithm,
}

impl ParsecRemoteKeyPair {

    /// Creates a new ParsecRemoteKeyPair
    pub fn new(key_name: String, public_key_der: Vec<u8>, parsec_client: BasicClient, rcgen_algorithm: &'static SignatureAlgorithm) -> ParsecRemoteKeyPair {
        ParsecRemoteKeyPair {
            key_name: key_name,
            public_key_der: public_key_der,
            parsec_client: parsec_client,
            rcgen_algorithm: rcgen_algorithm
        }
    }
}

impl RemoteKeyPair for ParsecRemoteKeyPair {
    fn public_key(&self) -> &[u8] {
        &self.public_key_der
    }

    fn sign(&self, msg: &[u8]) -> std::result::Result<Vec<u8>, RcgenError> {
        let signature =
            sign_message_with_policy(&self.parsec_client, &self.key_name, msg, Some(Hash::Sha256))
                .map_err(RcgenError::from)?;
        Ok(signature)
    }

    fn algorithm(&self) -> &'static SignatureAlgorithm {
        self.rcgen_algorithm
    }
}

impl From<Error> for RcgenError {
    fn from(_e: Error) -> Self {
        // There isn't a suitable mapping, because RcgenError does not have a variant for the
        // case where RemoteKeyPair failed for third-party reasons.
        // See: https://github.com/est31/rcgen/issues/67
        // The crate will publish a new enum variant. When this change is released, we can rework this to be a
        // more suitable error.
        RcgenError::KeyGenerationUnavailable
    }
}
///Template
#[derive(Debug)]
pub struct Template{
    /// The name of the key to use for signing. This must be an existing key that is accessible
    /// to the user, and it must be a signing key (either an RSA key or an elliptic curve key).
    ///
    /// Elliptic curve keys must use the NIST P256 or P384 curves.
    key_name: String,

    /// The common name to be used within the Distinguished Name (DN) specification of
    /// the CSR.
    common_name: Option<String>,

    /// The locality name to be used within the Distinguished Name (DN) specification of
    /// the CSR.
    locality: Option<String>,

    /// The organization name to be used within the Distinguished Name (DN) specification of
    /// the CSR.
    organization: Option<String>,

    /// The organizational unit name to be used within the Distinguished Name (DN) specification
    /// of the CSR.
    organizational_unit: Option<String>,

    /// The state name to be used within the Distinguished Name (DN) specification of the CSR.
    state: Option<String>,

    /// The country name to be used within the Distinguished Name (DN) specification of the CSR.
    country: Option<String>,

    /// A Subject Alternative Name (SAN) for the domain of the CSR.
    subject_alternative_name: Option<Vec<String>>,

    /// Certificate starting date
    not_before: Option<OffsetDateTime>,

    /// Certificate end date
    not_after: Option<OffsetDateTime>

}

///Template
impl Template {
    /// Creates a new template
    pub fn new(key_name: String, common_name: Option<String>, locality: Option<String>,
        organization: Option<String>, organizational_unit: Option<String>, state: Option<String>,
        country: Option<String>, subject_alternative_name: Option<Vec<String>>, not_before: Option<OffsetDateTime>,
        not_after: Option<OffsetDateTime>
    ) -> Template {
        Template {
            key_name: key_name,
            common_name: common_name,
            locality: locality,
            organization: organization,
            organizational_unit: organizational_unit,
            state: state,
            country: country,
            subject_alternative_name: subject_alternative_name,
            not_before: not_before,
            not_after: not_after
        }

    }
    // Inspect the attributes of the signing key and map them down to one of rcgen's supported hash-and-sign
    // schemes (throwing an error if there isn't a suitable mapping).
    //
    // There's rather a lot of complexity here, because we need to map down lots of nested PSA properties onto a small number
    // of hash-and-sign schemes that RCGEN supports.
    fn get_rcgen_algorithm(
        &self,
        basic_client: &BasicClient,
    ) -> Result<&'static SignatureAlgorithm> {
        let attributes = basic_client.key_attributes(&self.key_name)?;

        if let Algorithm::AsymmetricSignature(alg) = attributes.policy.permitted_algorithms {
            match alg {
                AsymmetricSignature::RsaPkcs1v15Sign { hash_alg } => match hash_alg {
                    SignHash::Specific(Hash::Sha256) => Ok(&PKCS_RSA_SHA256),
                    SignHash::Specific(Hash::Sha384) => Ok(&PKCS_RSA_SHA384),
                    SignHash::Specific(Hash::Sha512) => Ok(&PKCS_RSA_SHA512),
                    SignHash::Any => Ok(&PKCS_RSA_SHA256), // Default hash algorithm for the tool.
                    _ => {
                        // The algorithm is specific, but not one that RCGEN can use, so fail the operation.
                        error!("Signing key requires use of hashing algorithm ({:?}), which is not supported for certificate requests.", alg);
                        Err(ToolErrorKind::NotSupported.into())
                    }
                },
                AsymmetricSignature::RsaPkcs1v15SignRaw => {
                    // Key policy specifies raw RSA signatures. RCGEN will always hash-and-sign, so fail.
                    error!("Signing key specifies raw signing only, which is not supported for certificate requests.");
                    Err(ToolErrorKind::NotSupported.into())
                }
                AsymmetricSignature::RsaPss { .. } => {
                    error!("Signing key specifies RSA PSS scheme, which is not supported for certificate requests.");
                    Err(ToolErrorKind::NotSupported.into())
                }
                AsymmetricSignature::Ecdsa { hash_alg } => {
                    if !matches!(
                        attributes.key_type,
                        Type::EccKeyPair {
                            curve_family: EccFamily::SecpR1
                        }
                    ) {
                        error!(
                            "Signing key must use curve family SecpR1 for certificate requests."
                        );
                        return Err(ToolErrorKind::NotSupported.into());
                    };

                    match hash_alg {
                        SignHash::Specific(Hash::Sha256) => {
                            if attributes.bits == 256 {
                                Ok(&PKCS_ECDSA_P256_SHA256)
                            } else {
                                error!("Signing key should have strength 256, but actually has strength {}.", attributes.bits);
                                Err(ToolErrorKind::NotSupported.into())
                            }
                        }
                        SignHash::Specific(Hash::Sha384) => {
                            if attributes.bits == 384 {
                                Ok(&PKCS_ECDSA_P384_SHA384)
                            } else {
                                error!("Signing key should have strength 384, but actually has strength {}.", attributes.bits);
                                Err(ToolErrorKind::NotSupported.into())
                            }
                        }
                        SignHash::Any => {
                            match attributes.bits {
                                256 => Ok(&PKCS_ECDSA_P256_SHA256),
                                _ => {
                                    // We have to fail this, because ParsecRemoteKeyPair::sign() defaults the hash to SHA-256, and RCGEN
                                    // doesn't support a hash algorithm that is different from the key strength.
                                    error!("Signing keys of strength other than 256-bit not supported without specific hash algorithm.");
                                    Err(ToolErrorKind::NotSupported.into())
                                }
                            }
                        }
                        _ => {
                            // The algorithm is specific, but not one that RCGEN can use, so fail the operation.
                            error!("Signing key requires use of hashing algorithm ({:?}), which is not supported for certificate requests.", alg);
                            Err(ToolErrorKind::NotSupported.into())
                        }
                    }
                }
                _ => {
                    // Unsupported algorithm.
                    error!("The specified key is not supported for certificate requests.");
                    Err(ToolErrorKind::NotSupported.into())
                }
            }
        } else {
            error!("Specified key is not an asymmetric signing key, which is needed for certificate requests.");
            Err(ToolErrorKind::WrongKeyAlgorithm.into())
        }
    }
    ///Creates a new certificate
    pub fn create_cert(&self, basic_client: BasicClient) -> Result<Certificate>{
        let public_key = basic_client.psa_export_public_key(&self.key_name)?;

        let rcgen_algorithm = self.get_rcgen_algorithm(&basic_client)?;

        let parsec_key_pair = ParsecRemoteKeyPair::new(self.key_name.clone(), public_key, basic_client, rcgen_algorithm);

        // let parsec_key_pair = ParsecRemoteKeyPair {
        //     key_name: self.key_name.clone(),
        //     public_key_der: public_key,
        //     // "Move" the client into the struct here.
        //     parsec_client: basic_client,
        //     rcgen_algorithm,
        // };

        let remote_key_pair = KeyPair::from_remote(Box::new(parsec_key_pair))?;

        let subject_alt_names = match &self.subject_alternative_name {
            Some(san) => san.to_owned(),
            None => Vec::new(),
        };

        let mut dn = DistinguishedName::new();

        if let Some(common_name) = &self.common_name {
            dn.push(DnType::CommonName, common_name.clone());
        }

        if let Some(organizational_unit) = &self.organizational_unit {
            // NOTE: X509 permits multiple OUs, but the RCGEN crate only preserves one entry, so for now the
            // parsec-tool also only accepts one entry on the command-line. If this changes in the future, it
            // will be possible to evolve the command-line parser to accept multiple values without it being
            // a breaking change.
            dn.push(DnType::OrganizationalUnitName, organizational_unit.clone());
        }

        if let Some(organization) = &self.organization {
            dn.push(DnType::OrganizationName, organization.clone());
        }

        if let Some(locality) = &self.locality {
            dn.push(DnType::LocalityName, locality.clone());
        }

        if let Some(state) = &self.state {
            dn.push(DnType::StateOrProvinceName, state.clone());
        }

        if let Some(country) = &self.country {
            dn.push(DnType::CountryName, country.clone());
        }

        let mut params = CertificateParams::new(subject_alt_names);
        params.alg = rcgen_algorithm;
        params.key_pair = Some(remote_key_pair);
        params.distinguished_name = dn;

        if let Some(not_before) = &self.not_before {
            params.not_before = not_before.clone();
        }

        if let Some(not_after) = &self.not_after {
            params.not_after = not_after.clone();
        }

        Ok(Certificate::from_params(params)?)
        
    }

}

