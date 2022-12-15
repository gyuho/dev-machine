use std::{
    collections::HashMap,
    fs::File,
    io::{self, stdout, Error, ErrorKind},
    os::unix::fs::PermissionsExt,
    path::Path,
    sync::Arc,
    thread,
    time::Duration,
};

use aws_manager::{
    self, cloudformation, ec2,
    kms::{self, envelope},
    s3, sts,
};
use aws_sdk_cloudformation::model::{Capability, OnFailure, Parameter, StackStatus, Tag};
use clap::{Arg, Command};
use crossterm::{
    execute,
    style::{Color, Print, ResetColor, SetForegroundColor},
};
use dialoguer::{theme::ColorfulTheme, Select};
use rust_embed::RustEmbed;
use tokio::runtime::Runtime;

pub const NAME: &str = "apply";

pub fn command() -> Command {
    Command::new(NAME)
        .about("Applies/creates resources based on configuration")
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
            Arg::new("SPEC_FILE_PATH")
                .long("spec-file-path")
                .short('s')
                .help("The spec file to load and update")
                .required(true)
                .num_args(1),
        )
        .arg(
            Arg::new("SKIP_PROMPT")
                .long("skip-prompt")
                .short('s')
                .help("Skips prompt mode")
                .required(false)
                .num_args(0),
        )
}

// 50-minute
const MAX_WAIT_SECONDS: u64 = 50 * 60;

pub fn execute(log_level: &str, spec_file_path: &str, skip_prompt: bool) -> io::Result<()> {
    #[derive(RustEmbed)]
    #[folder = "cfn-templates/"]
    #[prefix = "cfn-templates/"]
    struct Asset;

    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, log_level),
    );

    let mut spec = aws_dev_machine::Spec::load(spec_file_path).unwrap();
    spec.validate()?;

    let rt = Runtime::new().unwrap();

    let mut aws_resources = spec.aws_resources.clone().unwrap();
    let shared_config = rt
        .block_on(aws_manager::load_config(Some(aws_resources.region.clone())))
        .unwrap();

    let sts_manager = sts::Manager::new(&shared_config);
    let current_identity = rt.block_on(sts_manager.get_identity()).unwrap();

    // validate identity
    match aws_resources.clone().identity {
        Some(identity) => {
            // AWS calls must be made from the same caller
            if identity != current_identity {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!(
                        "config identity {:?} != currently loaded identity {:?}",
                        identity, current_identity
                    ),
                ));
            }
        }
        None => {
            aws_resources.identity = Some(current_identity);
        }
    }

    // set defaults based on ID
    if aws_resources.ec2_key_name.is_none() {
        aws_resources.ec2_key_name = Some(format!("{}-ec2-key", spec.id));
    }
    if aws_resources.cloudformation_ec2_instance_role.is_none() {
        aws_resources.cloudformation_ec2_instance_role =
            Some(aws_dev_machine::StackName::Ec2InstanceRole(spec.id.clone()).encode());
    }
    if aws_resources.cloudformation_vpc.is_none() {
        aws_resources.cloudformation_vpc =
            Some(aws_dev_machine::StackName::Vpc(spec.id.clone()).encode());
    }
    if aws_resources.cloudformation_asg.is_none() {
        aws_resources.cloudformation_asg =
            Some(aws_dev_machine::StackName::Asg(spec.id.clone()).encode());
    }
    spec.aws_resources = Some(aws_resources.clone());
    spec.sync(spec_file_path)?;

    execute!(
        stdout(),
        SetForegroundColor(Color::Blue),
        Print(format!("\nLoaded Spec: '{}'\n", spec_file_path)),
        ResetColor
    )?;
    let spec_contents = spec.encode_yaml()?;
    println!("{}\n", spec_contents);

    if !skip_prompt {
        let options = &[
            "No, I am not ready to create resources!",
            "Yes, let's create resources!",
        ];
        let selected = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Select your 'apply' option")
            .items(&options[..])
            .default(0)
            .interact()
            .unwrap();
        if selected == 0 {
            return Ok(());
        }
    }

    log::info!("creating resources (with spec path {})", spec_file_path);
    let s3_manager = s3::Manager::new(&shared_config);
    let kms_manager = kms::Manager::new(&shared_config);
    let ec2_manager = ec2::Manager::new(&shared_config);
    let cloudformation_manager = cloudformation::Manager::new(&shared_config);

    thread::sleep(Duration::from_secs(2));
    execute!(
        stdout(),
        SetForegroundColor(Color::Green),
        Print("\n\n\nSTEP: create S3 bucket\n"),
        ResetColor
    )?;
    rt.block_on(s3_manager.create_bucket(&aws_resources.bucket))
        .unwrap();

    thread::sleep(Duration::from_secs(2));
    rt.block_on(s3_manager.put_object(
        Arc::new(spec_file_path.to_string()),
        Arc::new(aws_resources.bucket.clone()),
        Arc::new(aws_dev_machine::StorageNamespace::DevMachineConfigFile(spec.id.clone()).encode()),
    ))
    .unwrap();

    if aws_resources.kms_cmk_id.is_none() && aws_resources.kms_cmk_arn.is_none() {
        thread::sleep(Duration::from_secs(2));
        execute!(
            stdout(),
            SetForegroundColor(Color::Green),
            Print("\n\n\nSTEP: create KMS key\n"),
            ResetColor
        )?;
        let key = rt
            .block_on(kms_manager.create_symmetric_default_key(format!("{}-cmk", spec.id).as_str()))
            .unwrap();

        aws_resources.kms_cmk_id = Some(key.id);
        aws_resources.kms_cmk_arn = Some(key.arn);
        spec.aws_resources = Some(aws_resources.clone());
        spec.sync(spec_file_path)?;

        thread::sleep(Duration::from_secs(1));
        rt.block_on(s3_manager.put_object(
            Arc::new(spec_file_path.to_string()),
            Arc::new(aws_resources.bucket.clone()),
            Arc::new(
                aws_dev_machine::StorageNamespace::DevMachineConfigFile(spec.id.clone()).encode(),
            ),
        ))
        .unwrap();
    }
    let envelope_manager = envelope::Manager::new(
        kms_manager,
        aws_resources.kms_cmk_id.clone().unwrap(),
        "dev-machine".to_string(),
    );

    if aws_resources.ec2_key_path.is_none() {
        thread::sleep(Duration::from_secs(2));
        execute!(
            stdout(),
            SetForegroundColor(Color::Green),
            Print("\n\n\nSTEP: create EC2 key pair\n"),
            ResetColor
        )
        .unwrap();
        let ec2_key_path = get_ec2_key_path(spec_file_path);
        rt.block_on(ec2_manager.create_key_pair(
            aws_resources.ec2_key_name.clone().unwrap().as_str(),
            ec2_key_path.as_str(),
        ))
        .unwrap();

        let tmp_compressed_path = random_manager::tmp_path(15, Some(".zstd")).unwrap();
        compress_manager::pack_file(
            ec2_key_path.as_str(),
            &tmp_compressed_path,
            compress_manager::Encoder::Zstd(3),
        )
        .unwrap();

        let tmp_encrypted_path = random_manager::tmp_path(15, Some(".encrypted")).unwrap();
        rt.block_on(envelope_manager.seal_aes_256_file(
            Arc::new(tmp_compressed_path),
            Arc::new(tmp_encrypted_path.clone()),
        ))
        .unwrap();

        rt.block_on(
            s3_manager.put_object(
                Arc::new(tmp_encrypted_path),
                Arc::new(aws_resources.bucket.clone()),
                Arc::new(
                    aws_dev_machine::StorageNamespace::Ec2AccessKeyCompressedEncrypted(
                        spec.id.clone(),
                    )
                    .encode(),
                ),
            ),
        )
        .unwrap();

        aws_resources.ec2_key_path = Some(ec2_key_path);
        spec.aws_resources = Some(aws_resources.clone());
        spec.sync(spec_file_path)?;

        thread::sleep(Duration::from_secs(1));
        rt.block_on(s3_manager.put_object(
            Arc::new(spec_file_path.to_string()),
            Arc::new(aws_resources.bucket.clone()),
            Arc::new(
                aws_dev_machine::StorageNamespace::DevMachineConfigFile(spec.id.clone()).encode(),
            ),
        ))
        .unwrap();
    }

    if aws_resources
        .cloudformation_ec2_instance_profile_arn
        .is_none()
    {
        thread::sleep(Duration::from_secs(2));
        execute!(
            stdout(),
            SetForegroundColor(Color::Green),
            Print("\n\n\nSTEP: create EC2 instance role\n"),
            ResetColor
        )?;

        let ec2_instance_role_yaml = Asset::get("cfn-templates/ec2_instance_role.yaml").unwrap();
        let ec2_instance_role_tmpl =
            std::str::from_utf8(ec2_instance_role_yaml.data.as_ref()).unwrap();
        let ec2_instance_role_stack_name = aws_resources
            .cloudformation_ec2_instance_role
            .clone()
            .unwrap();

        rt.block_on(cloudformation_manager.create_stack(
            ec2_instance_role_stack_name.as_str(),
            Some(vec![Capability::CapabilityNamedIam]),
            OnFailure::Delete,
            ec2_instance_role_tmpl,
            Some(Vec::from([
                Tag::builder().key("KIND").value("dev-machine").build(),
            ])),
            Some(Vec::from([
                build_param("Id", &spec.id),
                build_param("KmsCmkArn", &aws_resources.kms_cmk_arn.clone().unwrap()),
                build_param("S3BucketName", &aws_resources.bucket),
            ])),
        ))
        .unwrap();

        thread::sleep(Duration::from_secs(10));
        let stack = rt
            .block_on(cloudformation_manager.poll_stack(
                ec2_instance_role_stack_name.as_str(),
                StackStatus::CreateComplete,
                Duration::from_secs(500),
                Duration::from_secs(30),
            ))
            .unwrap();

        for o in stack.outputs.unwrap() {
            let k = o.output_key.unwrap();
            let v = o.output_value.unwrap();
            log::info!("stack output key=[{}], value=[{}]", k, v,);
            if k.eq("InstanceProfileArn") {
                aws_resources.cloudformation_ec2_instance_profile_arn = Some(v)
            }
        }
        spec.aws_resources = Some(aws_resources.clone());
        spec.sync(spec_file_path)?;

        thread::sleep(Duration::from_secs(1));
        rt.block_on(s3_manager.put_object(
            Arc::new(spec_file_path.to_string()),
            Arc::new(aws_resources.bucket.clone()),
            Arc::new(
                aws_dev_machine::StorageNamespace::DevMachineConfigFile(spec.id.clone()).encode(),
            ),
        ))
        .unwrap();
    }

    if aws_resources.cloudformation_vpc_id.is_none()
        && aws_resources.cloudformation_vpc_security_group_id.is_none()
        && aws_resources.cloudformation_vpc_public_subnet_ids.is_none()
    {
        thread::sleep(Duration::from_secs(2));
        execute!(
            stdout(),
            SetForegroundColor(Color::Green),
            Print("\n\n\nSTEP: create VPC\n"),
            ResetColor
        )?;

        let vpc_yaml = Asset::get("cfn-templates/vpc.yaml").unwrap();
        let vpc_tmpl = std::str::from_utf8(vpc_yaml.data.as_ref()).unwrap();
        let vpc_stack_name = aws_resources.cloudformation_vpc.clone().unwrap();

        let parameters = Vec::from([
            build_param("Id", &spec.id),
            build_param("VpcCidr", "10.0.0.0/16"),
            build_param("PublicSubnetCidr1", "10.0.64.0/19"),
            build_param("PublicSubnetCidr2", "10.0.128.0/19"),
            build_param("PublicSubnetCidr3", "10.0.192.0/19"),
            build_param("IngressIpv4Range", "0.0.0.0/0"),
        ]);
        rt.block_on(cloudformation_manager.create_stack(
            vpc_stack_name.as_str(),
            None,
            OnFailure::Delete,
            vpc_tmpl,
            Some(Vec::from([
                Tag::builder().key("KIND").value("dev-machine").build(),
            ])),
            Some(parameters),
        ))
        .unwrap();

        thread::sleep(Duration::from_secs(10));
        let stack = rt
            .block_on(cloudformation_manager.poll_stack(
                vpc_stack_name.as_str(),
                StackStatus::CreateComplete,
                Duration::from_secs(300),
                Duration::from_secs(30),
            ))
            .unwrap();

        for o in stack.outputs.unwrap() {
            let k = o.output_key.unwrap();
            let v = o.output_value.unwrap();
            log::info!("stack output key=[{}], value=[{}]", k, v,);
            if k.eq("VpcId") {
                aws_resources.cloudformation_vpc_id = Some(v);
                continue;
            }
            if k.eq("SecurityGroupId") {
                aws_resources.cloudformation_vpc_security_group_id = Some(v);
                continue;
            }
            if k.eq("PublicSubnetIds") {
                let splits: Vec<&str> = v.split(',').collect();
                let mut pub_subnets: Vec<String> = vec![];
                for s in splits {
                    log::info!("public subnet {}", s);
                    pub_subnets.push(String::from(s));
                }
                aws_resources.cloudformation_vpc_public_subnet_ids = Some(pub_subnets);
            }
        }
        spec.aws_resources = Some(aws_resources.clone());
        spec.sync(spec_file_path)?;

        thread::sleep(Duration::from_secs(1));
        rt.block_on(s3_manager.put_object(
            Arc::new(spec_file_path.to_string()),
            Arc::new(aws_resources.bucket.clone()),
            Arc::new(
                aws_dev_machine::StorageNamespace::DevMachineConfigFile(spec.id.clone()).encode(),
            ),
        ))
        .unwrap();
    }

    let is_spot_instance = spec.machine.instance_mode == String::from("spot");
    let on_demand_pct = if is_spot_instance { 0 } else { 100 };
    let mut asg_parameters = Vec::from([
        build_param("Id", &spec.id),
        build_param("KmsCmkArn", &aws_resources.kms_cmk_arn.clone().unwrap()),
        build_param("AadTag", &spec.aad_tag),
        build_param("S3BucketName", &aws_resources.bucket),
        build_param(
            "Ec2KeyPairName",
            &aws_resources.ec2_key_name.clone().unwrap(),
        ),
        build_param(
            "InstanceProfileArn",
            &aws_resources
                .cloudformation_ec2_instance_profile_arn
                .clone()
                .unwrap(),
        ),
        build_param(
            "PublicSubnetIds",
            &aws_resources
                .cloudformation_vpc_public_subnet_ids
                .clone()
                .unwrap()[0], // always use a single AZ, use join(",") for multi-AZ
        ),
        build_param(
            "SecurityGroupId",
            &aws_resources
                .cloudformation_vpc_security_group_id
                .clone()
                .unwrap(),
        ),
        build_param("AsgSpotInstance", format!("{}", is_spot_instance).as_str()),
        build_param("IpMode", &spec.machine.ip_mode),
        build_param(
            "OnDemandPercentageAboveBaseCapacity",
            format!("{}", on_demand_pct).as_str(),
        ),
    ]);

    asg_parameters.push(build_param("Arch", &spec.machine.arch));
    if !spec.machine.instance_types.is_empty() {
        let instance_types = spec.machine.instance_types.clone();
        asg_parameters.push(build_param("InstanceTypes", &instance_types.join(",")));
        asg_parameters.push(build_param(
            "InstanceTypesCount",
            format!("{}", instance_types.len()).as_str(),
        ));
    }

    if spec.machine.machines > 0 && aws_resources.cloudformation_asg_logical_id.is_none() {
        thread::sleep(Duration::from_secs(2));
        execute!(
            stdout(),
            SetForegroundColor(Color::Green),
            Print("\n\n\nSTEP: create ASG\n"),
            ResetColor
        )?;

        let cloudformation_asg_yaml = Asset::get(&format!(
            "cfn-templates/asg_{}_{}.yaml",
            spec.machine.arch, spec.machine.os
        ))
        .unwrap();
        let cloudformation_asg_tmpl =
            std::str::from_utf8(cloudformation_asg_yaml.data.as_ref()).unwrap();
        let cloudformation_asg_stack_name = aws_resources.cloudformation_asg.clone().unwrap();

        let desired_capacity = spec.machine.machines;

        // must deep-copy as shared with other machine kind
        let mut parameters = asg_parameters.clone();

        // TODO: remove this... doesn't work for amd64 and other regions
        if aws_resources.region == "us-west-2" && spec.machine.os == "al2" {
            // manually overwrite to use latest kernel
            if spec.machine.arch == "amd64" {
                // 64-bit AMD with Kernel 5.10
                // "/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2" returns Kernel 4.14
                parameters.push(build_param("ImageId", "ami-02b92c281a4d3dc79"));
            } else if spec.machine.arch == "arm64" {
                // 64-bit Arm with Kernel 5.10
                // "/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-arm64-gp2" returns Kernel 4.14
                parameters.push(build_param("ImageId", "ami-0100e0d6026a6c58d"));
            }
        }

        parameters.push(build_param(
            "AsgDesiredCapacity",
            format!("{}", desired_capacity).as_str(),
        ));

        rt.block_on(cloudformation_manager.create_stack(
            cloudformation_asg_stack_name.as_str(),
            None,
            OnFailure::Delete,
            cloudformation_asg_tmpl,
            Some(Vec::from([
                Tag::builder().key("KIND").value("dev-machine").build(),
            ])),
            Some(parameters),
        ))
        .unwrap();

        // add 5-minute for ELB creation
        let mut wait_secs = 300 + 60 * desired_capacity as u64;
        if wait_secs > MAX_WAIT_SECONDS {
            wait_secs = MAX_WAIT_SECONDS;
        }
        thread::sleep(Duration::from_secs(30));
        let stack = rt
            .block_on(cloudformation_manager.poll_stack(
                cloudformation_asg_stack_name.as_str(),
                StackStatus::CreateComplete,
                Duration::from_secs(wait_secs),
                Duration::from_secs(30),
            ))
            .unwrap();

        for o in stack.outputs.unwrap() {
            let k = o.output_key.unwrap();
            let v = o.output_value.unwrap();
            log::info!("stack output key=[{}], value=[{}]", k, v,);
            if k.eq("AsgLogicalId") {
                aws_resources.cloudformation_asg_logical_id = Some(v);
                continue;
            }
        }
        if aws_resources.cloudformation_asg_logical_id.is_none() {
            return Err(Error::new(
                ErrorKind::Other,
                "aws_resources.cloudformation_asg_logical_id not found",
            ));
        }

        let asg_name = aws_resources.cloudformation_asg_logical_id.clone().unwrap();

        let mut droplets: Vec<ec2::Droplet> = Vec::new();
        let target_nodes = spec.machine.machines;
        for _ in 0..10 {
            // TODO: better retries
            log::info!(
                "fetching all droplets for dev-machine SSH access (target nodes {})",
                target_nodes
            );
            droplets = rt.block_on(ec2_manager.list_asg(&asg_name)).unwrap();
            if (droplets.len() as u32) >= target_nodes {
                break;
            }
            log::info!(
                "retrying fetching all droplets (only got {})",
                droplets.len()
            );
            thread::sleep(Duration::from_secs(30));
        }

        let mut eips = Vec::new();
        if spec.machine.ip_mode == String::from("elastic") {
            log::info!("using elastic IPs... wait more");
            loop {
                eips = rt
                    .block_on(ec2_manager.describe_eips_by_tags(HashMap::from([(
                        String::from("Id"),
                        spec.id.clone(),
                    )])))
                    .unwrap();

                log::info!("got {} EIP addresses", eips.len());

                let mut ready = true;
                for eip_addr in eips.iter() {
                    ready = ready && eip_addr.instance_id.is_some();
                }
                if ready && eips.len() == target_nodes as usize {
                    break;
                }

                thread::sleep(Duration::from_secs(30));
            }
        }

        let mut instance_id_to_public_ip = HashMap::new();
        for eip_addr in eips.iter() {
            let allocation_id = eip_addr.allocation_id.to_owned().unwrap();
            let instance_id = eip_addr.instance_id.to_owned().unwrap();
            let public_ip = eip_addr.public_ip.to_owned().unwrap();
            log::info!("EIP found {allocation_id} for {instance_id} and {public_ip}");
            instance_id_to_public_ip.insert(instance_id, public_ip);
        }

        let ec2_key_path = aws_resources.ec2_key_path.clone().unwrap();
        let f = File::open(&ec2_key_path).unwrap();
        f.set_permissions(PermissionsExt::from_mode(0o444)).unwrap();

        let user_name = {
            if spec.machine.os == aws_dev_machine::OS_AL2 {
                aws_dev_machine::OS_AL2_USER_NAME
            } else {
                aws_dev_machine::OS_UBUNTU_USER_NAME
            }
        };

        for d in droplets {
            // ssh -o "StrictHostKeyChecking no" -i [ec2_key_path] [user name]@[public IPv4/DNS name]
            // aws ssm start-session --region [region] --target [instance ID]
            // TODO: support other user name?
            let public_ip = if let Some(public_ip) = instance_id_to_public_ip.get(&d.instance_id) {
                public_ip.clone()
            } else {
                d.public_ipv4.clone()
            };

            println!(
                "
# change SSH key permission
chmod 400 {}
# instance '{}' ({}, {}) -- ip mode '{}'
ssh -o \"StrictHostKeyChecking no\" -i {} {}@{}
# download to local machine
scp -i {} {}@{}:REMOTE_FILE_PATH LOCAL_FILE_PATH
scp -i {} -r {}@{}:REMOTE_DIRECTORY_PATH LOCAL_DIRECTORY_PATH
# upload to remote machine
scp -i {} LOCAL_FILE_PATH {}@{}:REMOTE_FILE_PATH
scp -i {} -r LOCAL_DIRECTORY_PATH {}@{}:REMOTE_DIRECTORY_PATH
# SSM session (requires SSM agent)
aws ssm start-session --region {} --target {}
",
                ec2_key_path,
                //
                d.instance_id,
                d.instance_state_name,
                d.availability_zone,
                spec.machine.ip_mode,
                //
                ec2_key_path,
                user_name,
                public_ip,
                //
                ec2_key_path,
                user_name,
                public_ip,
                //
                ec2_key_path,
                user_name,
                public_ip,
                //
                ec2_key_path,
                user_name,
                public_ip,
                //
                ec2_key_path,
                user_name,
                public_ip,
                //
                aws_resources.region,
                d.instance_id,
            );
        }
        println!();

        spec.aws_resources = Some(aws_resources.clone());
        spec.sync(spec_file_path)?;

        thread::sleep(Duration::from_secs(1));
        rt.block_on(s3_manager.put_object(
            Arc::new(spec_file_path.to_string()),
            Arc::new(aws_resources.bucket),
            Arc::new(aws_dev_machine::StorageNamespace::DevMachineConfigFile(spec.id).encode()),
        ))
        .unwrap();

        log::info!("waiting for bootstrap and ready (to be safe)");
        thread::sleep(Duration::from_secs(20));
    }

    println!();
    log::info!("apply all success!");
    println!();
    println!("# run the following to delete resources");
    execute!(
        stdout(),
        SetForegroundColor(Color::Red),
        Print(format!(
            "{} delete \\\n--delete-all \\\n--spec-file-path {}\n",
            std::env::current_exe()
                .expect("unexpected None current_exe")
                .display(),
            spec_file_path
        )),
        ResetColor
    )?;

    Ok(())
}

fn build_param(k: &str, v: &str) -> Parameter {
    Parameter::builder()
        .parameter_key(k)
        .parameter_value(v)
        .build()
}

fn get_ec2_key_path(spec_file_path: &str) -> String {
    let path = Path::new(spec_file_path);
    let parent_dir = path.parent().unwrap();
    let name = path.file_stem().unwrap();
    let new_name = format!("{}-ec2-access.key", name.to_str().unwrap(),);
    String::from(
        parent_dir
            .join(Path::new(new_name.as_str()))
            .as_path()
            .to_str()
            .unwrap(),
    )
}
