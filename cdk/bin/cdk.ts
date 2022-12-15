#!/usr/bin/env node
import 'source-map-support/register';
import * as path from 'path';
import * as cdk from 'aws-cdk-lib';
import * as cfn_include from 'aws-cdk-lib/cloudformation-include';
// import * as cfn_ec2 from 'aws-cdk-lib/aws-ec2';

export class DevMachineInstanceRoleStack extends cdk.Stack {
  public readonly instanceRoleArn: cdk.CfnOutput;
  public readonly instanceProfileArn: cdk.CfnOutput;

  constructor(scope: cdk.App, id: string, props: cdk.StackProps) {
    super(scope, id, props);
    console.log("CDK_ACCOUNT:", process.env.CDK_ACCOUNT);
    console.log("CDK_REGION:", process.env.CDK_REGION);

    // ref. https://docs.aws.amazon.com/cdk/api/v1/docs/cloudformation-include-readme.html#non-resource-template-elements
    const tmplAsg = new cfn_include.CfnInclude(this, `included-template-instance-role-${process.env.CLUSTER_ID || ''}`, {
      templateFile: path.join('..', 'aws-dev-machine', 'cfn-templates', 'ec2_instance_role.yaml'),
    });

    // mutate default parameters
    const paramId: cdk.CfnParameter = tmplAsg.getParameter('Id');
    paramId.default = process.env.ID;

    const paramKmsCmkArn: cdk.CfnParameter = tmplAsg.getParameter('KmsCmkArn');
    paramKmsCmkArn.default = process.env.KMS_CMK_ARN;

    const paramS3BucketName: cdk.CfnParameter = tmplAsg.getParameter('S3BucketName');
    paramS3BucketName.default = process.env.S3_BUCKET_NAME;

    this.instanceRoleArn = tmplAsg.getOutput('InstanceRoleArn');
    this.instanceProfileArn = tmplAsg.getOutput('InstanceProfileArn');
  }
}

export class DevMachineInstanceVpcStack extends cdk.Stack {
  public readonly vpcId: cdk.CfnOutput;
  public readonly securityGroupId: cdk.CfnOutput;
  public readonly publicSubnetIds: cdk.CfnOutput;

  constructor(scope: cdk.App, id: string, props: cdk.StackProps) {
    super(scope, id, props);

    // ref. https://docs.aws.amazon.com/cdk/api/v1/docs/cloudformation-include-readme.html#non-resource-template-elements
    const tmplVpc = new cfn_include.CfnInclude(this, `included-template-vpc-${process.env.CLUSTER_ID || ''}`, {
      templateFile: path.join('..', 'aws-dev-machine', 'cfn-templates', 'vpc.yaml'),
    });

    // mutate default parameters
    const paramId: cdk.CfnParameter = tmplVpc.getParameter('Id');
    paramId.default = process.env.ID;

    this.vpcId = tmplVpc.getOutput('VpcId');
    this.securityGroupId = tmplVpc.getOutput('SecurityGroupId');
    this.publicSubnetIds = tmplVpc.getOutput('PublicSubnetIds');
  }
}

interface DevMachineAsgProps extends cdk.StackProps {
  instanceRoleArn: String;
  instanceProfileArn: String;
  vpcId: String;
  securityGroupId: String;
  publicSubnetIds: String;
}

export class DevMachineInstanceAsgStack extends cdk.Stack {
  public readonly asgLogicalId: cdk.CfnOutput;

  constructor(scope: cdk.App, id: string, props: DevMachineAsgProps) {
    super(scope, id, props);

    // ref. https://docs.aws.amazon.com/cdk/api/v1/docs/cloudformation-include-readme.html#non-resource-template-elements
    const tmplAsg = new cfn_include.CfnInclude(this, `included-template-asg-${process.env.CLUSTER_ID || ''}`, {
      templateFile: path.join('..', 'aws-dev-machine', 'cfn-templates', 'asg_amd64_ubuntu.yaml'),
    });

    // mutate default parameters
    const paramId: cdk.CfnParameter = tmplAsg.getParameter('Id');
    paramId.default = process.env.ID;

    const paramKmsCmkArn: cdk.CfnParameter = tmplAsg.getParameter('KmsCmkArn');
    paramKmsCmkArn.default = process.env.KMS_CMK_ARN;

    const paramS3BucketName: cdk.CfnParameter = tmplAsg.getParameter('S3BucketName');
    paramS3BucketName.default = process.env.S3_BUCKET_NAME;

    const paramEc2KeyPairName: cdk.CfnParameter = tmplAsg.getParameter('Ec2KeyPairName');
    paramEc2KeyPairName.default = process.env.EC2_KEY_PAIR_NAME;

    const paramAadTag: cdk.CfnParameter = tmplAsg.getParameter('AadTag');
    paramAadTag.default = process.env.AAD_TAG;

    const paramInstanceProfileArn: cdk.CfnParameter = tmplAsg.getParameter('InstanceProfileArn');
    paramInstanceProfileArn.default = process.env.INSTANCE_PROFILE_ARN;
    // TODO: not working...
    // paramInstanceProfileArn.default = props.instanceProfileArn.toString();

    const paramPublicSubnetIds: cdk.CfnParameter = tmplAsg.getParameter('PublicSubnetIds');
    paramPublicSubnetIds.default = process.env.PUBLIC_SUBNET_IDS;
    // TODO: not working...
    // paramPublicSubnetIds.default = props.publicSubnetIds.toString();

    const paramSecurityGroupId: cdk.CfnParameter = tmplAsg.getParameter('SecurityGroupId');
    paramSecurityGroupId.default = process.env.SECURITY_GROUP_ID;
    // TODO: not working...
    // paramSecurityGroupId.default = props.securityGroupId.toString();

    this.asgLogicalId = tmplAsg.getOutput('AsgLogicalId');
  }
}

const app = new cdk.App();

const instanceRoleStack = new DevMachineInstanceRoleStack(app, 'dev-machine-instance-role-stack',
  {
    stackName: 'dev-machine-instance-role-stack',
    env: {
      account: process.env.CDK_ACCOUNT || process.env.CDK_DEFAULT_ACCOUNT,
      region: process.env.CDK_REGION || process.env.CDK_DEFAULT_REGION
    },
  }
);

const vpcStack = new DevMachineInstanceVpcStack(app, 'dev-machine-vpc-stack',
  {
    stackName: 'dev-machine-vpc-stack',
    env: {
      account: process.env.CDK_ACCOUNT || process.env.CDK_DEFAULT_ACCOUNT,
      region: process.env.CDK_REGION || process.env.CDK_DEFAULT_REGION
    },
  }
);

const asgStack = new DevMachineInstanceAsgStack(app, 'dev-machine-asg-stack',
  {
    stackName: 'dev-machine-asg-stack',
    env: {
      account: process.env.CDK_ACCOUNT || process.env.CDK_DEFAULT_ACCOUNT,
      region: process.env.CDK_REGION || process.env.CDK_DEFAULT_REGION
    },
    instanceRoleArn: instanceRoleStack.instanceRoleArn.value.toString(),
    instanceProfileArn: instanceRoleStack.instanceProfileArn.value.toString(),
    vpcId: vpcStack.vpcId.value.toString(),
    securityGroupId: vpcStack.securityGroupId.value.toString(),
    publicSubnetIds: vpcStack.publicSubnetIds.value.toString(),
  }
);
// asgStack.node.addDependency([instanceRoleStack, vpcStack]);

app.synth();
