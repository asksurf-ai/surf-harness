//! Validate one promoted contract bundle directory.

use std::process::ExitCode;

use nano_types::contract::ContractBundle;

fn main() -> ExitCode {
    let mut arguments = std::env::args_os();
    let _program = arguments.next();
    let Some(bundle_root) = arguments.next() else {
        eprintln!("usage: load_contract_bundle <promoted-root>");
        return ExitCode::FAILURE;
    };
    if arguments.next().is_some() {
        eprintln!("usage: load_contract_bundle <promoted-root>");
        return ExitCode::FAILURE;
    }

    match ContractBundle::from_directory(bundle_root) {
        Ok(_) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("contract bundle validation failed: {error}");
            ExitCode::FAILURE
        }
    }
}
