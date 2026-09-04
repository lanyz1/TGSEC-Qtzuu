# Rust Security Audit

> Rust 代码安全审计模块
> 适用于: Actix-web, Axum, Rocket, Tonic (gRPC), Tauri, 系统编程

## 识别特征

```rust
// Rust 项目识别
Cargo.toml, Cargo.lock
*.rs

// Web 项目结构
├── src/
│   ├── main.rs
│   ├── routes/
│   ├── handlers/
│   ├── models/
│   └── middleware/
├── Cargo.toml
└── .env
```

---

## 一键检测命令

### unsafe 代码块

```bash
# unsafe 关键字
grep -rn "unsafe\s*{" --include="*.rs"
grep -rn "unsafe\s*fn" --include="*.rs"
grep -rn "unsafe\s*impl" --include="*.rs"

# 裸指针操作
grep -rn "\*const\s\|\*mut\s" --include="*.rs"
grep -rn "\.as_ptr\|\.as_mut_ptr" --include="*.rs"
```

### FFI 边界

```bash
# extern 块
grep -rn "extern\s*\"C\"" --include="*.rs"
grep -rn "#\[no_mangle\]" --include="*.rs"

# libc 调用
grep -rn "libc::" --include="*.rs"
```

### 反序列化

```bash
# serde 危险用法
grep -rn "deserialize_any\|#\[serde(tag\|typetag" --include="*.rs"
grep -rn "serde_json::from_\|bincode::deserialize\|rmp_serde" --include="*.rs"
```

### 命令执行

```bash
grep -rn "Command::new\|process::Command\|std::process" --include="*.rs"
grep -rn "\.arg\s*(\|\.args\s*(" --include="*.rs"
```

### SQL/数据库

```bash
grep -rn "query!\|sqlx::query\|diesel::" --include="*.rs"
grep -rn "raw_sql\|execute\s*(" --include="*.rs"
grep -rn "format!.*SELECT\|format!.*INSERT\|format!.*UPDATE" --include="*.rs"
```

### 路径操作

```bash
grep -rn "PathBuf::from\|Path::new\|\.join\s*(" --include="*.rs"
grep -rn "std::fs::\|tokio::fs::" --include="*.rs"
```

---

## Rust 特定漏洞

### 1. unsafe 代码块漏洞

```rust
// 🔴 未验证的裸指针解引用
unsafe {
    let ptr = user_input as *const u8;
    let value = *ptr;  // 未验证指针有效性!
}

// 🔴 缓冲区越界
unsafe {
    let slice = std::slice::from_raw_parts(ptr, len);  // len 可能越界
}

// 🔴 类型双关 (type punning)
unsafe {
    let data: u64 = std::mem::transmute(user_bytes);  // 未验证对齐和大小
}

// 🔴 use-after-free
unsafe {
    let ptr = Box::into_raw(boxed);
    drop(Box::from_raw(ptr));
    *ptr = 42;  // Use-after-free!
}

// 🟢 安全: 验证并封装
pub fn safe_slice<T>(ptr: *const T, len: usize) -> Option<&[T]> {
    if ptr.is_null() || len == 0 {
        return None;
    }
    // 验证对齐
    if (ptr as usize) % std::mem::align_of::<T>() != 0 {
        return None;
    }
    Some(unsafe { std::slice::from_raw_parts(ptr, len) })
}

// 搜索模式
unsafe\s*\{|unsafe\s+fn|std::mem::transmute|\*ptr|from_raw_parts
```

### 2. Send/Sync Trait 伪造

```rust
// 🔴 危险: 错误实现 Send/Sync 导致数据竞争
struct UnsafeCell<T>(*mut T);

unsafe impl<T> Send for UnsafeCell<T> {}  // 危险!
unsafe impl<T> Sync for UnsafeCell<T> {}  // 危险!

// 🔴 内部可变性误用
use std::cell::RefCell;
// RefCell 不是 Sync，在多线程中使用会 panic 或更糟

// 🟢 安全: 使用正确的同步原语
use std::sync::{Arc, Mutex, RwLock};
use parking_lot::Mutex;

// 搜索模式
unsafe\s+impl.*Send|unsafe\s+impl.*Sync
```

### 3. FFI 边界安全

```rust
// 🔴 未验证 C 字符串
extern "C" {
    fn c_function(s: *const c_char);
}

unsafe {
    let ptr = user_input.as_ptr() as *const c_char;
    c_function(ptr);  // 可能不是以 null 结尾!
}

// 🔴 回调函数中的 panic
#[no_mangle]
pub extern "C" fn callback() {
    panic!("oops");  // 跨 FFI 边界 panic 是 UB!
}

// 🟢 安全: 使用 CString 并处理 panic
use std::ffi::CString;
use std::panic::catch_unwind;

let c_string = CString::new(user_input)?;
unsafe { c_function(c_string.as_ptr()) };

#[no_mangle]
pub extern "C" fn safe_callback() -> i32 {
    match catch_unwind(|| {
        // 实际逻辑
        0
    }) {
        Ok(result) => result,
        Err(_) => -1,  // 错误码
    }
}

// 搜索模式
extern\s*"C"|#\[no_mangle\]|as\s*\*const\s*c_char
```

### 4. 整数溢出

```rust
// 🔴 Release 模式下整数溢出不 panic (wraparound)
let user_size: u32 = get_user_input();
let total = user_size * 4;  // 可能溢出!
let buf = vec![0u8; total as usize];

// 🔴 类型转换溢出
let big: u64 = get_big_number();
let small: u32 = big as u32;  // 截断!

// 🟢 安全: 使用 checked/saturating 操作
let total = user_size.checked_mul(4).ok_or("overflow")?;
let small: u32 = big.try_into().map_err(|_| "overflow")?;

// 搜索模式
as\s+u(8|16|32|64|size)|as\s+i(8|16|32|64|size)
```

### 5. 命令执行

```rust
// 🔴 危险: 用户输入直接作为命令
use std::process::Command;

let output = Command::new(user_program)
    .arg(user_arg)
    .output()?;

// 🔴 shell 执行
Command::new("sh")
    .arg("-c")
    .arg(format!("ls {}", user_path))  // 命令注入!
    .output()?;

// 🟢 安全: 白名单 + 参数分离
let allowed = ["ls", "cat", "grep"];
if !allowed.contains(&user_program.as_str()) {
    return Err("Command not allowed");
}

Command::new("ls")
    .arg("-la")
    .arg(&user_path)  // 作为单独参数，不会被 shell 解析
    .output()?;

// 搜索模式
Command::new\s*\(.*用户输入|\.arg\s*\(.*format!
```

### 6. SQL 注入

```rust
// 🔴 SQLx 字符串格式化
let query = format!("SELECT * FROM users WHERE name = '{}'", user_name);
sqlx::query(&query).fetch_all(&pool).await?;

// 🔴 Diesel raw SQL
diesel::sql_query(format!("SELECT * FROM users WHERE id = {}", user_id))
    .load::<User>(&conn)?;

// 🟢 安全: 使用参数化查询
// SQLx
sqlx::query("SELECT * FROM users WHERE name = $1")
    .bind(&user_name)
    .fetch_all(&pool)
    .await?;

// SQLx 宏 (编译时检查)
sqlx::query!("SELECT * FROM users WHERE name = $1", user_name)
    .fetch_all(&pool)
    .await?;

// Diesel
users.filter(name.eq(&user_name)).load::<User>(&conn)?;

// 搜索模式
format!.*SELECT|format!.*INSERT|format!.*UPDATE|format!.*DELETE
sql_query\s*\(.*format!
```

### 7. 路径遍历

```rust
// 🔴 危险: 路径拼接
use std::path::PathBuf;

let mut path = PathBuf::from("/data/uploads");
path.push(user_filename);  // "../../../etc/passwd" !
let content = std::fs::read(&path)?;

// 🔴 join 同样危险
let path = base_dir.join(user_filename);

// 🟢 安全: 规范化并验证
let full_path = base_dir.join(&user_filename).canonicalize()?;
if !full_path.starts_with(&base_dir) {
    return Err("Path traversal detected");
}

// 🟢 或只取文件名
let safe_name = Path::new(&user_filename)
    .file_name()
    .ok_or("Invalid filename")?;
let path = base_dir.join(safe_name);

// 搜索模式
PathBuf::from.*用户输入|\.push\s*\(.*用户输入|\.join\s*\(.*用户输入
```

### 8. 反序列化

```rust
// 🔴 serde deserialize_any (类型混淆)
#[derive(Deserialize)]
#[serde(tag = "type")]
enum Message {
    Admin(AdminCommand),  // 攻击者可指定 type = "Admin"
    User(UserCommand),
}

// 🔴 typetag (多态反序列化)
#[typetag::serde]
trait Command: Send + Sync {
    fn execute(&self);
}
// 攻击者可以反序列化任意实现了 Command 的类型

// 🔴 bincode 从不可信来源
let data: UntrustedData = bincode::deserialize(&user_bytes)?;

// 🟢 安全: 限制类型
#[derive(Deserialize)]
struct SafeMessage {
    content: String,
    // 只有简单类型，没有 enum/trait object
}

// 🟢 安全: 验证反序列化后的数据
let data: UserInput = serde_json::from_str(&input)?;
validate_user_input(&data)?;

// 搜索模式
deserialize_any|#\[serde\(tag|typetag::serde|bincode::deserialize
```

### 9. 正则表达式 DoS (ReDoS)

```rust
// 🔴 危险: 灾难性回溯
use regex::Regex;

let re = Regex::new(&user_pattern)?;  // 用户可构造恶意正则

// 默认 regex crate 有保护，但可被禁用
let re = RegexBuilder::new(pattern)
    .size_limit(0)  // 禁用限制!
    .build()?;

// 🟢 安全: 使用默认限制 + 超时
let re = Regex::new(pattern)?;  // 有默认大小限制

// 或使用 fancy-regex 的 Regex::set_size_limit

// 搜索模式
Regex::new.*用户输入|RegexBuilder.*size_limit\s*\(\s*0
```

---

## Web 框架特定漏洞

### Actix-web

```rust
// 🔴 CORS 过宽
use actix_cors::Cors;

let cors = Cors::permissive();  // 允许所有!

// 🔴 未启用 CSRF 保护
// Actix 默认不启用 CSRF

// 🟢 安全: 限制 CORS
let cors = Cors::default()
    .allowed_origin("https://myapp.com")
    .allowed_methods(vec!["GET", "POST"])
    .allowed_headers(vec![header::AUTHORIZATION, header::ACCEPT])
    .max_age(3600);

// 搜索模式
Cors::permissive|allow_any_origin
```

### Axum

```rust
// 🔴 路由未保护
Router::new()
    .route("/admin", get(admin_handler))  // 无中间件!

// 🔴 提取器未验证
async fn handler(Path(id): Path<String>) -> impl IntoResponse {
    // id 未验证
}

// 🟢 安全: 使用中间件和验证
use axum::middleware;
use validator::Validate;

#[derive(Deserialize, Validate)]
struct Input {
    #[validate(length(min = 1, max = 100))]
    name: String,
}

Router::new()
    .route("/admin", get(admin_handler))
    .layer(middleware::from_fn(auth_middleware))

// 搜索模式
Router::new\(\)(?!.*layer)|Path\(.*\):\s*Path<String>
```

### Rocket

```rust
// 🔴 数据保护未启用
#[get("/secret")]
fn secret() -> &'static str { "secret" }  // 无认证!

// 🟢 安全: 使用请求守卫
#[get("/secret")]
fn secret(user: AuthenticatedUser) -> &'static str { "secret" }

// 搜索模式
#\[get\(|#\[post\(.*(?!.*Guard|.*Request)
```

### Tonic (gRPC)

```rust
// 🔴 未启用 TLS
Server::builder()
    .add_service(my_service)
    .serve("[::]:50051".parse()?);  // 明文!

// 🔴 反射服务暴露
tonic_reflection::server::Builder::configure()
    .register_encoded_file_descriptor_set(DESCRIPTOR)
    .build()?;

// 🔴 消息大小无限制
// 默认 4MB，但可能不够安全

// 🟢 安全: 启用 TLS + 限制消息大小
Server::builder()
    .tls_config(tls_config)?
    .max_frame_size(1024 * 1024)  // 1MB
    .add_service(my_service)
    .serve_with_shutdown(addr, signal);

// 搜索模式
tonic.*Server::builder(?!.*tls_config)|tonic_reflection
```

---

## Tauri (桌面应用) 安全

```rust
// 🔴 命令暴露过多
#[tauri::command]
fn read_file(path: String) -> String {
    std::fs::read_to_string(path).unwrap()  // 任意文件读取!
}

// 🔴 IPC 未验证
#[tauri::command]
fn execute(cmd: String) -> String {
    // ...
}

// 🟢 安全: 最小权限 + 白名单
#[tauri::command]
fn read_allowed_file(name: String) -> Result<String, String> {
    let allowed = ["config.json", "data.txt"];
    if !allowed.contains(&name.as_str()) {
        return Err("Not allowed".into());
    }
    let path = app_dir.join(name);
    std::fs::read_to_string(path).map_err(|e| e.to_string())
}

// tauri.conf.json 权限限制
{
  "tauri": {
    "allowlist": {
      "fs": {
        "all": false,
        "readFile": true,
        "scope": ["$APP/*"]
      }
    }
  }
}

// 搜索模式
#\[tauri::command\]|allowlist.*all.*true
```

---

## 常见 Crate 安全问题

### 不安全的 Crate

| Crate | 问题 | 替代方案 |
|-------|------|----------|
| `chrono` | 历史 UB 问题 | `time` |
| `yaml-rust` | 未维护 | `serde_yaml` |
| `openssl` | 复杂性 | `rustls` |
| `ring` (旧版) | 需更新 | 最新版 `ring` |

### 依赖审计

```bash
# cargo-audit
cargo install cargo-audit
cargo audit

# cargo-deny
cargo install cargo-deny
cargo deny check

# cargo-geiger (unsafe 统计)
cargo install cargo-geiger
cargo geiger
```

---

## 审计清单

```
unsafe 代码:
- [ ] 搜索所有 unsafe 块
- [ ] 验证裸指针使用
- [ ] 检查 transmute
- [ ] 验证 Send/Sync 实现

FFI:
- [ ] 检查 extern "C" 边界
- [ ] 验证 C 字符串处理
- [ ] 检查 panic 跨 FFI

Web 框架:
- [ ] 检查 CORS 配置
- [ ] 验证认证中间件
- [ ] 检查路径处理
- [ ] 验证输入验证

数据处理:
- [ ] 检查 SQL 查询构造
- [ ] 验证反序列化用法
- [ ] 检查整数转换
- [ ] 验证正则表达式
```

---

## 审计正则

```regex
# unsafe
unsafe\s*\{|unsafe\s+fn|unsafe\s+impl

# FFI
extern\s*"C"|#\[no_mangle\]|as\s*\*const\s*c_char

# 内存操作
std::mem::transmute|from_raw_parts|Box::from_raw

# SQL 注入
format!.*(SELECT|INSERT|UPDATE|DELETE)

# 命令执行
Command::new.*变量|\.arg.*format!

# 路径遍历
PathBuf::from.*变量|\.join\s*\(.*变量

# 反序列化
deserialize_any|typetag|bincode::deserialize

# Web 安全
Cors::permissive|allow_any_origin
```

---

## 工具推荐

```bash
# cargo-audit (CVE 检查)
cargo audit

# cargo-deny (依赖策略)
cargo deny check

# cargo-geiger (unsafe 统计)
cargo geiger

# Clippy (lint)
cargo clippy -- -W clippy::all -W clippy::pedantic

# Miri (UB 检测，仅测试)
cargo +nightly miri test

# rust-analyzer (IDE 集成)
```

---

## CSRF 安全 (CWE-352)

### 危险模式

```rust
// 🔴 Actix-web - 无 CSRF 保护
#[post("/api/transfer")]
async fn transfer(req: web::Json<TransferRequest>) -> impl Responder {
    // 状态变更操作无 CSRF 保护
    do_transfer(&req.to, req.amount).await
}
```

### 安全配置

```rust
// Actix-web + actix-csrf
use actix_csrf::CsrfMiddleware;
use actix_web::{web, App, HttpServer};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .wrap(CsrfMiddleware::new(
                b"32-byte-long-secret-key-here!!!!"
            ))
            .route("/api/transfer", web::post().to(transfer))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}

// Axum - 使用 tower 中间件
use axum_csrf::{CsrfConfig, CsrfLayer, CsrfToken};

let config = CsrfConfig::default();
let app = Router::new()
    .route("/api/transfer", post(transfer))
    .layer(CsrfLayer::new(config));

async fn transfer(token: CsrfToken, Json(req): Json<TransferRequest>) -> impl IntoResponse {
    // token 自动验证
    do_transfer(&req.to, req.amount).await
}
```

### 检测命令

```bash
# 查找 POST/PUT/DELETE 路由
rg -n "#\[post\]|#\[put\]|#\[delete\]|\.post\(|\.put\(|\.delete\(" --glob "*.rs"

# 查找 CSRF 相关
rg -n "csrf|CsrfMiddleware|CsrfLayer" --glob "*.rs" --glob "Cargo.toml"
```

---

## 文件上传安全 (CWE-434)

### 危险模式

```rust
// 🔴 无验证的文件上传
#[post("/upload")]
async fn upload(mut payload: Multipart) -> impl Responder {
    while let Some(field) = payload.try_next().await.unwrap() {
        let filename = field.content_disposition().get_filename().unwrap();
        let filepath = format!("./uploads/{}", filename);  // 🔴 路径遍历
        let mut f = File::create(filepath).await.unwrap();
        while let Some(chunk) = field.try_next().await.unwrap() {
            f.write_all(&chunk).await.unwrap();
        }
    }
    HttpResponse::Ok()
}
```

### 安全配置

```rust
use actix_multipart::Multipart;
use sanitize_filename::sanitize;
use infer;

const ALLOWED_TYPES: &[&str] = &["image/jpeg", "image/png", "image/gif"];
const MAX_SIZE: usize = 5 * 1024 * 1024;  // 5MB

#[post("/upload")]
async fn upload(mut payload: Multipart) -> Result<HttpResponse, Error> {
    while let Some(field) = payload.try_next().await? {
        // 1. 获取安全文件名
        let original_name = field.content_disposition()
            .get_filename()
            .unwrap_or("unknown");
        let safe_name = sanitize(original_name);

        // 2. 验证扩展名
        let ext = std::path::Path::new(&safe_name)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("");
        if !["jpg", "jpeg", "png", "gif"].contains(&ext.to_lowercase().as_str()) {
            return Ok(HttpResponse::BadRequest().body("Invalid extension"));
        }

        // 3. 读取内容并验证大小
        let mut data = Vec::new();
        while let Some(chunk) = field.try_next().await? {
            if data.len() + chunk.len() > MAX_SIZE {
                return Ok(HttpResponse::BadRequest().body("File too large"));
            }
            data.extend_from_slice(&chunk);
        }

        // 4. 验证实际文件类型
        let kind = infer::get(&data);
        match kind {
            Some(t) if ALLOWED_TYPES.contains(&t.mime_type()) => {},
            _ => return Ok(HttpResponse::BadRequest().body("Invalid file type")),
        }

        // 5. 生成安全路径
        let unique_name = format!("{}_{}", Uuid::new_v4(), safe_name);
        let filepath = std::path::Path::new("./uploads").join(&unique_name);

        // 6. 保存文件
        let mut f = File::create(filepath).await?;
        f.write_all(&data).await?;
    }

    Ok(HttpResponse::Ok().body("Uploaded"))
}
```

---

## 硬编码凭据 (CWE-798)

### 危险模式

```rust
// 🔴 硬编码密钥
const API_KEY: &str = "[REDACTED]";
const DB_PASSWORD: &str = "admin123";

fn connect_db() -> Connection {
    let url = format!("postgres://user:{}@localhost/db", DB_PASSWORD);  // 🔴
    Connection::connect(&url).unwrap()
}

// 🔴 JWT 密钥硬编码
let encoding_key = EncodingKey::from_secret(b"my-secret-key");  // 🔴
```

### 安全配置

```rust
use std::env;
use secrecy::{Secret, ExposeSecret};

struct Config {
    api_key: Secret<String>,
    db_password: Secret<String>,
}

impl Config {
    fn from_env() -> Result<Self, env::VarError> {
        Ok(Self {
            api_key: Secret::new(env::var("API_KEY")?),
            db_password: Secret::new(env::var("DB_PASSWORD")?),
        })
    }
}

fn connect_db(config: &Config) -> Connection {
    let url = format!(
        "postgres://user:{}@localhost/db",
        config.db_password.expose_secret()
    );
    Connection::connect(&url).unwrap()
}
```

### 检测命令

```bash
# 查找硬编码密钥
rg -n "password\s*[:=]|secret\s*[:=]|api_key\s*[:=]|token\s*[:=]" --glob "*.rs" | grep -v "env::\|std::env"

# 查找硬编码字符串
rg -n 'const.*:.*&str.*=.*"[^"]{8,}"' --glob "*.rs"

# 查找不安全的 JWT
rg -n "from_secret\(b\"" --glob "*.rs"
```

---

**版本**: 1.1
**更新日期**: 2026-02-04
**覆盖漏洞类型**: 17+
