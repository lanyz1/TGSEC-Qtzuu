# 案例课: web 根目录泄露产品本体 + 中文业务词后台发现 (zhangduozhe.net)

## 场景
CF 前置的卡密/挂机软件销售站 (zhangduozhe.net)。三套后台口令硬 (35 万+组合全灭),
源站 IP 藏死, 无 RCE 链。**但通过两个非爆破解法拿到产品本体与第四套后台。**

## 教训 1: 备份/泄露文件猎捕 —— 排在前列, 不要最后做
**做了 8 小时蓝奏云验证码绕过后, 发现安装包就摆在 `/uploads/zhangduozhe.zip` (218MB, 无鉴权)。**

无效努力路径 (应避免):
- 蓝奏分享页 → `/fn` → `apifile.woozooo.com` 换直链 → Aliyun WAF `acw_sc__v2` 挑战 (可解, 见下) → **末跳 `ajax.php` 的 `sign` 由浏览器验证流程现场签发, 脚本无法构造** → 死路
- 本地 Chromium CDP 驱动 → 人机验证码 (数据中心 IP 必挂)
- 美国跳板重跑 → 同样死在人机验证

**正确做法**: 拿到"软件下载"需求后, **第一件事**是:
```
1. 拉 /download/ 页, 找所有外链 (本次: 只有蓝奏, 但页脚有站内 /uploads 线索)
2. 按"产品名/域名/拼音/日期" × 归档后缀 (zip/rar/7z/tar.gz/sql/gz)
   × 全部常见目录 (/uploads//download//backup//static//assets//files//data/...) 扫一遍
3. 命中 200 且 size>1MB 的就是产品本体
```
本次 28 目录 × 63 名 = 2028 路径, 只 1 个命中, 但那 1 个价值最大。
**判据**: `content-length` 与本地字节数一致 + `zipfile.testzip() is None` 才算完整。

## 教训 2: 后台目录枚举必须加"中文业务词/拼音"
通用英文词表 (SecLists 16k) **完全漏掉 `/buy/admin/`**; 换成业务词
(`kefu/dingdan/kami/zhangdan/fahuo/huiyuan/chongzhi/tixian/gonggao/lunbo/...`) 后立刻命中。

**词表构造**: 站点自身的导航/菜单文本 + 行业词 + 拼音 (不要只用英文)。

**判据**: 302→login.php = 受保护页面存在 (有价值); 200 = 未授权页面。

## 教训 3: 上传接口的"字段名"是独立于扩展名的坎
`/api/upload.php` 三态错误: `请先登录`(无会话) → `没有收到图片文件`(字段名错) → `上传成功`。
**字段名 = `image`** (不是 file/upload/files)。正确姿势:
- 会话 × 字段名 (file/image/img/photo/pic/upload/upfile/files/files[]/avatar/thumb) × 附加字段 (action=upload/type=image) 矩阵化
- 有效扩展名要按**返回的 url 扩展名**判定, 不能只看 `success:true`

## 教训 4: 强制扩展名 = RCE 死路, 但仍要试全族
50 种扩展名变体 (`php/php5/phtml/pht/phar/phps/inc/asp/jsp/exe/htaccess/.user.ini` +
`::$DATA/%00/;/:/尾空格/尾点/双扩展/大小写/`/`) **全部强制落为 `.jpg`** →
nginx 静态返回源码不执行 → 无 RCE。
**但顺手确认了**: 任意字节可落地 + 可公开读取 = 内容投递面 (可作 XSS 载体若 MIME 可绕)。

## 教训 5: dotfile 403 是盲规则, 不是"文件存在"证据
`/.env` 403, 但 `/.env_nonexistent_xyz123` **也是 403** (nginx 全局 `location ~ /\.` deny)
→ 该 403 **无信息量**, 不构成"文件存在"的判断依据。**必须做对照组测试。**

## 教训 6: 易语言 (E-language) 客户端逆向要点
- 标志: `*.sp.exe` (大体积) + `V8Core.dll`/`V8Engine.dll` (V8 支持库) + `SkinH_EL.dll`
- 字符串**私有加密**: GBK 扫描只得 UI 碎片; UTF-16 扫描全是噪声; **无 zlib/gzip 流**
- 依赖 `ocr.dll` (打码) + `HPSocket4C.dll`/libcurl (通信)
- **下载包内往往无 JS 脚本** → 策略/配置为运行时从服务器拉取
- 价值: 产品结构、真实牌桌 ID (路单)、运营者自身盈亏 (方案.txt)、依赖能力判断

## 演练脚本清单 (本次可复用)
- 文件泄露猎捕: 名 × 后缀 × 目录 三维笛卡尔积 + 并发 + 200&size>阈值 过滤
- 中文业务词后台枚举: 词表 + 对 `/admin//forum/admin//api//buy//agent/` 同时打
- 上传矩阵: 会话 × 字段名 × 附加字段 × 扩展名族, 以返回 url 的扩展名为准
- 报文注入清扫: 时间盲注必须**受控复测 3 次** (本次 `id=1 AND SLEEP(5)` 曾出现 25s/7s 假阳性, 复测后基线本身 14s → 纯网络噪声)
