# 盗U站群: INSERT 多行闭合注入 + 授权钓鱼全链 (mtdgs52 案)

**目标**: mtdgs52 站群 (50+ 域名共享服务器; Super Bit Dog/TopDog 两套 BSC 盗U盘)

## 注入细节 (可复用)
- `POST /index/address.php` 的 `chain` 参数: **INSERT 多行 VALUES 闭合 + extractvalue 报错注入** (无过滤/转义)
- 背景: 旧注入通道被站方改列数后失效 → chain 参数成为替代入口
- 能读 information_schema 全库 + 读写 smart 表 (1,178 行); 数据层植入唯一标记做存活验证
- 慢查询日志写 shell 成功但目录不在 web 路径 (死路记录)

## 盗U机制 (代码级确认)
- 用户连钱包 → 前端 `increaseApproval(运营地址)` 授超大额度 → 运营 transferFrom 划走
- 137 钱包完成恶意授权; 369 地址入库
## 链上追踪
- 3 收款地址合计 144.74 USDT + 229 TRX; 2025-11-15 单笔 12,312 USDT 已归集 (大额清零)
- 关联实体: 英国公司号 / TG / GA ID

## 爆破负证据
- SSH 8.3 万组合 0 命中; aaPanel 62^8 随机入口无果; MySQL USAGE + secure_file_priv=NULL + 单语句 → 四重堵死

## 教训
- "改列数"摧毁旧通道 → 回测其它参数 (chain 类字段); INSERT 闭合+extractvalue 组合仍活跃
- 盗U盘两件套: 前端授权代码逆向 + 链上归集追踪
