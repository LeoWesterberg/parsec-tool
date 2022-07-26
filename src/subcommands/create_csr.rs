// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

//! Creates a Certificate Signing Request (CSR) from a keypair.

use crate::error::Result;
use crate::certificate_template::Template;
use parsec_client::BasicClient;
use structopt::StructOpt;


/// Creates an X509 Certificate Signing Request (CSR) from a keypair, using the signing algorithm
/// that is associated with the key.
///
/// The CSR is written to the standard output in PEM format by default.
#[derive(Debug, StructOpt)]
pub struct CreateCsr {
    //wrapper: Template,
    /// The name of the key to use for signing. This must be an existing key that is accessible
    /// to the user, and it must be a signing key (either an RSA key or an elliptic curve key).
    ///
    /// Elliptic curve keys must use the NIST P256 or P384 curves.
    #[structopt(short = "k", long = "key-name")]
    key_name: String,

    /// The common name to be used within the Distinguished Name (DN) specification of
    /// the CSR.
    #[structopt(long = "cn")]
    common_name: Option<String>,

    /// The locality name to be used within the Distinguished Name (DN) specification of
    /// the CSR.
    #[structopt(long = "l")]
    locality: Option<String>,

    /// The organization name to be used within the Distinguished Name (DN) specification of
    /// the CSR.
    #[structopt(long = "o")]
    organization: Option<String>,

    /// The organizational unit name to be used within the Distinguished Name (DN) specification
    /// of the CSR.
    #[structopt(long = "ou")]
    organizational_unit: Option<String>,

    /// The state name to be used within the Distinguished Name (DN) specification of the CSR.
    #[structopt(long = "st")]
    state: Option<String>,

    /// The country name to be used within the Distinguished Name (DN) specification of the CSR.
    #[structopt(long = "c")]
    country: Option<String>,

    /// A Subject Alternative Name (SAN) for the domain of the CSR.
    #[structopt(long = "san")]
    subject_alternative_name: Option<Vec<String>>,
}

impl CreateCsr {
    /// Creates a Certificate Signing Request (CSR) from a keypair.
    pub fn run(&self, basic_client: BasicClient) -> Result<()> {
        let cert_wrapper = Template::new(self.key_name.clone(), self.common_name.clone(), self.locality.clone(), self.organization.clone(), 
                                         self.organizational_unit.clone(), self.state.clone(), self.country.clone(),
                                         self.subject_alternative_name.clone(), None, None);
        let cert = cert_wrapper.create_cert(basic_client)?;
        let pem_string = cert.serialize_request_pem()?;

        println!("{}", pem_string);

        Ok(())
    }
}
