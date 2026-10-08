# hou.kuaipao.us 商户 API 签名备忘 (对接文档捕获)

**来源**: 报告包内捕获 (MAPI-HMAC-SHA256)
## 要点
- 签名: HMAC-SHA256; 规范串=method/path/body 摘要/timestamp/nonce 按规则拼装
- IP 白名单: 未配置 → 403; 下单/回调双通道
- 全文: 已撤出仓库（原文留本机案卷）
## 教训
- 支付平台"对接文档"= 签名复现捷径; 遇签名报错先找这份文档
- 商户 ID 进 URL / 签名密钥可从回显推导 — 复算验证通过即可建单 (参见 epusdt 案)
