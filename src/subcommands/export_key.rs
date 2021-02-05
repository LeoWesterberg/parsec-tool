// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

//! Exports a key.

pub use crate::cli::ParsecToolApp;
use crate::error::ParsecToolError;
use crate::subcommands::common::{OutputFileOpts, ProviderOpts};
use crate::subcommands::ParsecToolSubcommand;
use parsec_client::core::interface::operations::psa_export_key;
use parsec_client::core::interface::operations::{NativeOperation, NativeResult};
use parsec_client::core::interface::secrecy::ExposeSecret;
use parsec_client::core::operation_client::OperationClient;
use parsec_client::BasicClient;
use std::convert::TryFrom;
use std::fs::File;
use std::io::Write;
use structopt::StructOpt;

/// Exports a key.
#[derive(Debug, StructOpt)]
pub struct ExportKey {
    #[structopt(short = "k", long = "key-name")]
    key_name: String,

    #[structopt(flatten)]
    provider_opts: ProviderOpts,

    #[structopt(flatten)]
    output_file_opts: OutputFileOpts,
}

impl TryFrom<&ExportKey> for NativeOperation {
    type Error = ParsecToolError;

    fn try_from(psa_export_key_subcommand: &ExportKey) -> Result<NativeOperation, Self::Error> {
        // Trivially converted to a `NativeOperation`.
        Ok(NativeOperation::PsaExportKey(psa_export_key::Operation {
            key_name: psa_export_key_subcommand.key_name.clone(),
        }))
    }
}

impl ParsecToolSubcommand<'_> for ExportKey {
    /// Exports a key.
    fn run(
        &self,
        _matches: &ParsecToolApp,
        basic_client: BasicClient,
    ) -> Result<(), ParsecToolError> {
        info!("Exporting key...");

        let client = OperationClient::new();
        let native_result = client.process_operation(
            NativeOperation::try_from(self)?,
            self.provider_opts.provider()?,
            &basic_client.auth_data(),
        )?;

        let result = match native_result {
            NativeResult::PsaExportKey(result) => result,
            _ => {
                return Err(ParsecToolError::UnexpectedNativeResult(native_result));
            }
        };

        if let Some(output_file_path) = &self.output_file_opts.output_file_path {
            success!("Exported the key to {:?}.", output_file_path);
            let mut file = File::create(output_file_path)?;
            file.write_all(&result.data.expose_secret())?;
        } else {
            success!("Key:");
            for byte in &*result.data.expose_secret() {
                print!("{:02X} ", byte);
            }
            println!();
        }
        Ok(())
    }
}
