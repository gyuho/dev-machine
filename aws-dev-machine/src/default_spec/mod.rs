use std::io::{self, stdout};

use clap::{Arg, Command};
use crossterm::{
    execute,
    style::{Color, Print, ResetColor, SetForegroundColor},
};

pub const NAME: &str = "default-spec";

pub fn command() -> Command {
    Command::new(NAME)
        .about("Writes a default configuration")
        .arg(
            Arg::new("LOG_LEVEL")
                .long("log-level")
                .short('l')
                .help("Sets the log level")
                .required(false)
                .num_args(1)
                .value_parser(["debug", "info"])
                .default_value("info"),
        )
        .arg(
            Arg::new("REGION")
                .long("region")
                .short('r')
                .help("Sets the AWS region for API calls/endpoints")
                .required(true)
                .num_args(1)
                .default_value("us-west-2"),
        )
        .arg(
            Arg::new("ARCH")
                .long("arch")
                .short('a')
                .help("Sets the machine architecture")
                .required(true)
                .num_args(1)
                .value_parser([aws_dev_machine::ARCH_AMD64, aws_dev_machine::ARCH_ARM64])
                .default_value(aws_dev_machine::ARCH_AMD64),
        )
        .arg(
            Arg::new("OS")
                .long("os")
                .short('o')
                .help("Sets the machine OS")
                .required(true)
                .num_args(1)
                .value_parser([aws_dev_machine::OS_UBUNTU, aws_dev_machine::OS_AL2])
                .default_value(aws_dev_machine::OS_UBUNTU),
        )
        .arg(
            Arg::new("INSTANCE_MODE")
                .long("instance-mode")
                .help("Sets instance mode")
                .required(false)
                .num_args(1)
                .value_parser(["spot", "on-demand"])
                .default_value("spot"),
        )
        .arg(
            Arg::new("IP_MODE")
                .long("ip-mode")
                .help("Sets IP mode to provision EC2 elastic IPs for all nodes")
                .required(false)
                .num_args(1)
                .value_parser(["elastic", "ephemeral"])
                .default_value("elastic"),
        )
        .arg(
            Arg::new("AAD_TAG")
                .long("aad-tag")
                .short('a')
                .help("Sets the AAD tag for envelope encryption with KMS")
                .required(false)
                .num_args(1)
                .default_value("aws-dev-machine-aad-tag"),
        )
        .arg(
            Arg::new("SPEC_FILE_PATH")
                .long("spec-file-path")
                .short('s')
                .help("The spec file to load and update")
                .required(true)
                .num_args(1),
        )
}

pub struct Options {
    pub log_level: String,
    pub region: String,
    pub arch: String,
    pub os: String,
    pub instance_mode: String,
    pub ip_mode: String,
    pub aad_tag: String,
    pub spec_file_path: String,
}

pub fn execute(opts: Options) -> io::Result<()> {
    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, opts.log_level),
    );

    let spec = aws_dev_machine::Spec::default(
        &opts.region,
        &opts.arch,
        &opts.os,
        &opts.aad_tag,
        opts.instance_mode,
        opts.ip_mode,
    )
    .unwrap();
    spec.validate()?;
    spec.sync(&opts.spec_file_path)?;

    execute!(
        stdout(),
        SetForegroundColor(Color::Blue),
        Print(format!("\nSaved spec: '{}'\n", opts.spec_file_path)),
        ResetColor
    )?;
    let spec_contents = spec.encode_yaml().unwrap();
    println!("{}\n", spec_contents);

    execute!(
        stdout(),
        SetForegroundColor(Color::Magenta),
        Print(format!("\ncat {}\n", opts.spec_file_path)),
        ResetColor
    )?;
    println!();
    println!("# run the following to create resources");
    execute!(
        stdout(),
        SetForegroundColor(Color::Green),
        Print(format!(
            "{} apply \\\n--spec-file-path {}\n",
            std::env::current_exe()
                .expect("unexpected None current_exe")
                .display(),
            opts.spec_file_path
        )),
        ResetColor
    )?;

    println!();
    println!("# run the following to delete resources");
    execute!(
        stdout(),
        SetForegroundColor(Color::Red),
        Print(format!(
            "{} delete \\\n--spec-file-path {}\n",
            std::env::current_exe()
                .expect("unexpected None current_exe")
                .display(),
            opts.spec_file_path
        )),
        ResetColor
    )?;

    Ok(())
}
