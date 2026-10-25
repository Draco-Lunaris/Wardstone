//! Test-support binary: establishes the production protections and reports the
//! verdict.
//!
//! It takes no arguments and has no alternate path — it runs exactly the
//! `init(PRODUCTION_POOL)` that every `wardstone` binary mode runs, so the
//! refusal tests observe the real boot behaviour of the real code.

use std::process::ExitCode;

fn main() -> ExitCode {
    match ws_secmem::init(ws_secmem::PRODUCTION_POOL) {
        Ok(_) => {
            println!("protections ok");
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("{err}");
            ExitCode::FAILURE
        }
    }
}
