use std::{
    fs::{self, File},
    io::{self, Error, ErrorKind, Write},
    path::Path,
    string::String,
};

use aws_manager::{ec2, sts};
use log::info;
use serde::{Deserialize, Serialize};

pub const MIN_MACHINES: u32 = 1;
pub const MAX_MACHINES: u32 = 2;

pub const ARCH_AMD64: &str = "amd64";
pub const ARCH_ARM64: &str = "arm64";

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub struct Spec {
    #[serde(default)]
    pub id: String,

    #[serde(default)]
    pub aad_tag: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub aws_resources: Option<AWSResources>,
    pub machine: Machine,
}

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub struct Machine {
    #[serde(default)]
    pub machines: u32,
    #[serde(default)]
    pub arch_type: String,
    #[serde(default)]
    pub rust_os_type: String,
    #[serde(default)]
    pub instance_types: Vec<String>,
    #[serde(default)]
    pub instance_mode: String,
    #[serde(default)]
    pub ip_mode: String,
}

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub struct AWSResources {
    #[serde(default)]
    pub region: String,

    #[serde(default)]
    pub bucket: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<sts::Identity>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub kms_cmk_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kms_cmk_arn: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub ec2_key_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ec2_key_path: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloudformation_ec2_instance_role: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloudformation_ec2_instance_profile_arn: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloudformation_vpc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloudformation_vpc_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloudformation_vpc_security_group_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloudformation_vpc_public_subnet_ids: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloudformation_asg: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloudformation_asg_logical_id: Option<String>,
}

impl Default for AWSResources {
    fn default() -> Self {
        Self::default()
    }
}

impl AWSResources {
    pub fn default() -> Self {
        Self {
            region: String::from("us-west-2"),
            bucket: String::from(""),

            identity: None,

            kms_cmk_id: None,
            kms_cmk_arn: None,

            ec2_key_name: None,
            ec2_key_path: None,

            cloudformation_ec2_instance_role: None,
            cloudformation_ec2_instance_profile_arn: None,

            cloudformation_vpc: None,
            cloudformation_vpc_id: None,
            cloudformation_vpc_security_group_id: None,
            cloudformation_vpc_public_subnet_ids: None,

            cloudformation_asg: None,
            cloudformation_asg_logical_id: None,
        }
    }
}

/// Represents the CloudFormation stack name.
pub enum StackName {
    Ec2InstanceRole(String),
    Vpc(String),
    Asg(String),
}

impl StackName {
    pub fn encode(&self) -> String {
        match self {
            StackName::Ec2InstanceRole(id) => format!("{}-ec2-instance-role", id),
            StackName::Vpc(id) => format!("{}-vpc", id),
            StackName::Asg(id) => format!("{}-asg", id),
        }
    }
}

impl Spec {
    pub fn default(
        region: &str,
        arch_type: &str,
        rust_os_type: &str,
        aad_tag: &str,
        instance_mode: &str,
        instance_size: &str,
        ip_mode: &str,
    ) -> io::Result<Self> {
        Ok(Self {
            id: id_manager::time::with_prefix("dev-machine"),
            aad_tag: aad_tag.to_string(),

            aws_resources: Some(AWSResources {
                region: region.to_string(),
                bucket: format!(
                    "dev-machine-{}-{}-{region}",
                    id_manager::time::timestamp(6),
                    id_manager::system::string(7)
                ), // [year][month][date]-[system host-based id]
                ..AWSResources::default()
            }),

            machine: Machine {
                machines: 1,
                arch_type: arch_type.to_string(),
                rust_os_type: rust_os_type.to_string(),
                instance_types: ec2::default_instance_types(region, arch_type, instance_size)
                    .unwrap(),
                instance_mode: instance_mode.to_string(),
                ip_mode: ip_mode.to_string(),
            },
        })
    }

    /// Converts to string in YAML format.
    pub fn encode_yaml(&self) -> io::Result<String> {
        match serde_yaml::to_string(&self) {
            Ok(s) => Ok(s),
            Err(e) => Err(Error::new(
                ErrorKind::Other,
                format!("failed to serialize Spec to YAML {}", e),
            )),
        }
    }

    /// Saves the current spec to disk
    /// and overwrites the file.
    pub fn sync(&self, file_path: &str) -> io::Result<()> {
        info!("syncing Spec to '{}'", file_path);
        let path = Path::new(file_path);
        let parent_dir = path.parent().unwrap();
        fs::create_dir_all(parent_dir)?;

        let ret = serde_yaml::to_string(self);
        let d = match ret {
            Ok(d) => d,
            Err(e) => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("failed to serialize Spec to YAML {}", e),
                ));
            }
        };
        let mut f = File::create(file_path)?;
        f.write_all(d.as_bytes())?;

        Ok(())
    }

    pub fn load(file_path: &str) -> io::Result<Self> {
        info!("loading Spec from {}", file_path);

        if !Path::new(file_path).exists() {
            return Err(Error::new(
                ErrorKind::NotFound,
                format!("file {} does not exists", file_path),
            ));
        }

        let f = File::open(&file_path).map_err(|e| {
            Error::new(
                ErrorKind::Other,
                format!("failed to open {} ({})", file_path, e),
            )
        })?;
        serde_yaml::from_reader(f)
            .map_err(|e| Error::new(ErrorKind::InvalidInput, format!("invalid YAML: {}", e)))
    }

    /// Validates the spec.
    pub fn validate(&self) -> io::Result<()> {
        info!("validating Spec");

        if self.id.is_empty() {
            return Err(Error::new(ErrorKind::InvalidInput, "'id' cannot be empty"));
        }

        // some AWS resources have tag limit of 32-character
        if self.id.len() > 28 {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("'id' length cannot be >28 (got {})", self.id.len()),
            ));
        }

        match &self.aws_resources {
            Some(v) => {
                if v.region.is_empty() {
                    return Err(Error::new(
                        ErrorKind::InvalidInput,
                        "'machine.region' cannot be empty",
                    ));
                }
            }
            None => {}
        }

        if self.machine.machines < MIN_MACHINES {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "'machine.machines' {} <minimum {}",
                    self.machine.machines, MIN_MACHINES
                ),
            ));
        }
        if self.machine.machines > MAX_MACHINES {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "'machine.machines' {} >maximum {}",
                    self.machine.machines, MAX_MACHINES
                ),
            ));
        }

        Ok(())
    }
}

/// RUST_LOG=debug cargo test --package aws-dev-machine --lib -- test_spec --exact --show-output
#[test]
fn test_spec() {
    let _ = env_logger::builder().is_test(true).try_init();

    let id = random_manager::secure_string(10);
    let bucket = format!("test-{}", id_manager::time::timestamp(8));

    let contents = format!(
        r#"

id: {}

aad_tag: hi

aws_resources:
  region: us-west-2
  bucket: {}

machine:
  machines: 1
  arch_type: arm64
  rust_os_type: al2
  instance_types:
  - c6g.large
  instance_mode: spot
  ip_mode: elastic


"#,
        id, bucket,
    );
    let mut f = tempfile::NamedTempFile::new().unwrap();
    let ret = f.write_all(contents.as_bytes());
    assert!(ret.is_ok());
    let config_path = f.path().to_str().unwrap();

    let ret = Spec::load(config_path);
    assert!(ret.is_ok());
    let cfg = ret.unwrap();

    let ret = cfg.sync(config_path);
    assert!(ret.is_ok());

    let orig = Spec {
        id: id.clone(),
        aad_tag: String::from("hi"),

        aws_resources: Some(AWSResources {
            region: String::from("us-west-2"),
            bucket: bucket.clone(),
            ..AWSResources::default()
        }),

        machine: Machine {
            arch_type: ARCH_ARM64.to_string(),
            rust_os_type: "al2".to_string(),
            machines: 1,
            instance_types: vec![String::from("c6g.large")],
            instance_mode: String::from("spot"),
            ip_mode: String::from("elastic"),
        },
    };

    assert_eq!(cfg, orig);
    assert!(cfg.validate().is_ok());
    assert!(orig.validate().is_ok());

    // manually check to make sure the serde deserializer works
    assert_eq!(cfg.id, id);
    assert_eq!(cfg.aad_tag, "hi");

    assert!(cfg.aws_resources.is_some());
    let aws_reesources = cfg.aws_resources.unwrap();
    assert_eq!(aws_reesources.region, "us-west-2");
    assert_eq!(aws_reesources.bucket, bucket);

    assert_eq!(cfg.machine.machines, 1);
    assert_eq!(cfg.machine.arch_type, "arm64");
    assert_eq!(cfg.machine.rust_os_type, "al2");
    let instance_types = cfg.machine.instance_types;
    assert_eq!(instance_types[0], "c6g.large");
}

/// Represents the S3/storage key path.
/// MUST be kept in sync with "cfn-templates/ec2_instance_role.yaml".
pub enum StorageNamespace {
    DevMachineConfigFile(String),
    Ec2AccessKeyCompressedEncrypted(String),
}

impl StorageNamespace {
    pub fn encode(&self) -> String {
        match self {
            StorageNamespace::DevMachineConfigFile(id) => format!("{}/dev-machine.config.yaml", id),
            StorageNamespace::Ec2AccessKeyCompressedEncrypted(id) => {
                format!("{}/ec2-access-key.zstd.seal_aes_256.encrypted", id)
            }
        }
    }
}
