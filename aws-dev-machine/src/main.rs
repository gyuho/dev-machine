mod apply;
mod default_spec;
mod delete;

use clap::{crate_version, Command};

const APP_NAME: &str = "dev-machine";

/// Should be able to run with idempotency
/// (e.g., multiple restarts should not recreate the same CloudFormation stacks)
fn main() {
    let matches = Command::new(APP_NAME)
        .version(crate_version!())
        .about("Development machine provisioner")
        .subcommands(vec![
            default_spec::command(),
            apply::command(),
            delete::command(),
        ])
        .get_matches();

    match matches.subcommand() {
        Some((default_spec::NAME, sub_matches)) => {
            let opt = default_spec::Options {
                log_level: sub_matches
                    .get_one::<String>("LOG_LEVEL")
                    .unwrap_or(&String::from("info"))
                    .clone(),
                region: sub_matches.get_one::<String>("REGION").unwrap().clone(),
                instance_mode: sub_matches
                    .get_one::<String>("INSTANCE_MODE")
                    .unwrap()
                    .clone(),
                instance_size: sub_matches
                    .get_one::<String>("INSTANCE_SIZE")
                    .unwrap_or(&String::from("2xlarge"))
                    .clone(),
                ip_mode: sub_matches.get_one::<String>("IP_MODE").unwrap().clone(),
                aad_tag: sub_matches.get_one::<String>("AAD_TAG").unwrap().clone(),
                arch_type: sub_matches.get_one::<String>("ARCH_TYPE").unwrap().clone(),
                rust_os_type: sub_matches
                    .get_one::<String>("RUST_OS_TYPE")
                    .unwrap()
                    .clone(),
                spec_file_path: sub_matches
                    .get_one::<String>("SPEC_FILE_PATH")
                    .unwrap()
                    .clone(),
            };
            default_spec::execute(opt).unwrap();
        }

        Some((apply::NAME, sub_matches)) => {
            apply::execute(
                &sub_matches
                    .get_one::<String>("LOG_LEVEL")
                    .unwrap_or(&String::from("info"))
                    .clone(),
                &sub_matches
                    .get_one::<String>("SPEC_FILE_PATH")
                    .unwrap_or(&String::new())
                    .clone(),
                sub_matches.get_flag("SKIP_PROMPT"),
            )
            .unwrap();
        }

        Some((delete::NAME, sub_matches)) => {
            delete::execute(
                &sub_matches
                    .get_one::<String>("LOG_LEVEL")
                    .unwrap_or(&String::from("info"))
                    .clone(),
                &sub_matches
                    .get_one::<String>("SPEC_FILE_PATH")
                    .unwrap_or(&String::new())
                    .clone(),
                sub_matches.get_flag("DELETE_ALL"),
                sub_matches.get_flag("SKIP_PROMPT"),
            )
            .unwrap();
        }

        _ => unreachable!("unknown subcommand"),
    }
}
