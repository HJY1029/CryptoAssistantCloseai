import requests
import json
import subprocess
import os
import re
import sys
import getpass
from retrying import retry

# 修复类名拼写错误：DESECBheler → DESECBHelper
class DESECBHelper:
    def __init__(self, api_key):
        self.api_key = api_key
        self.mode = "ECB"
        self.supported_mode = "ECB"
        
        self.mode_config = {
            "encrypt_func": "DES_ecb_encrypt",
            "needs_iv": False,
            "key_length": 8,
            "block_size": 8
        }
        
        self.api_url = "https://api.openai-proxy.org/v1/chat/completions"
        self.work_dir = os.path.join(os.getcwd(), f"des_ecb_workdir")
        os.makedirs(self.work_dir, exist_ok=True)
        
        self.generated_code = None
        self.retry_count = 0
        self.max_retry = 5
        self.last_error = ""

    @retry(stop_max_attempt_number=3, wait_fixed=2000)
    def _generate_c_code(self):
        """生成支持用户输入的 DES-ECB 加密代码"""
        base_prompt = """仅输出纯C代码，实现 DES-ECB 加密，必须严格遵循以下标准：
1. 头文件必须包含：<stdio.h>、<stdlib.h>、<string.h>、<stddef.h>、<openssl/des.h>
2. 实现十六进制字符串转字节数组的函数：
   int hex_to_bytes(const char* hex, unsigned char* bytes, size_t len)
   功能：将十六进制字符串转换为字节数组，失败返回0，成功返回1
3. 用户输入流程（ECB 不需要 IV）：
   - 提示用户输入16字符的十六进制密钥（8字节）
   - 提示用户输入明文（字符串）
4. 加密流程：
   - 验证输入的密钥长度是否正确（16个十六进制字符）
   - 对明文进行 PKCS#7 填充（块大小8字节）
   - 使用 DES_ecb_encrypt 进行加密（ECB 模式专用函数）
5. 输出：
   - 输入的密钥（十六进制）
   - 原始明文
   - 填充后的明文（十六进制）
   - 加密后的密文（十六进制）

只输出C代码，无任何多余文本！"""

        error_feedback = "必须修复：1) 移除所有 IV 相关逻辑（ECB 不需要 IV）；2) 使用 DES_ecb_encrypt 函数；3) 加密函数参数不需要 IV；4) 确保填充后长度为8字节的整数倍。"

        messages = [{"role": "system", "content": base_prompt}]
        user_content = "生成支持用户输入密钥和明文的 DES-ECB 加密代码，移除所有 IV 相关逻辑"
        messages.append({"role": "user", "content": f"{user_content}。错误修复：{error_feedback}"})

        payload = {
            "model": "gpt-3.5-turbo",
            "messages": messages,
            "temperature": 0.0
        }

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}"
        }

        try:
            response = requests.post(
                self.api_url,
                headers=headers,
                json=payload,
                timeout=60
            )
            response.raise_for_status()
            raw_code = response.json()["choices"][0]["message"]["content"]
            
            # 代码净化与修复
            clean_code = re.sub(
                r'//.*?\n|/\*.*?\*/|```c|```|[\u4e00-\u9fa5]',
                '', 
                raw_code, 
                flags=re.DOTALL
            )
            clean_code = clean_code.strip()
            
            # 确保必要头文件
            required_headers = [
                "#include <stdio.h>",
                "#include <stdlib.h>",
                "#include <string.h>",
                "#include <stddef.h>",
                "#include <openssl/des.h>"
            ]
            for header in required_headers:
                if header not in clean_code:
                    clean_code = header + "\n" + clean_code

            # 确保 hex_to_bytes 函数存在
            if 'hex_to_bytes' not in clean_code:
                hex_func = """int hex_to_bytes(const char* hex, unsigned char* bytes, size_t len) {
    if (strlen(hex) != 2 * len) return 0;
    for (size_t i = 0; i < len; i++) {
        if (sscanf(hex + 2*i, "%2hhx", &bytes[i]) != 1) return 0;
    }
    return 1;
}
"""
                clean_code = hex_func + "\n" + clean_code

            # 确保 PKCS#7 填充函数存在
            if 'pkcs7_pad' not in clean_code:
                pad_func = """void pkcs7_pad(unsigned char* data, size_t len, size_t block_size) {
    unsigned char pad_len = block_size - (len % block_size);
    for (size_t i = len; i < len + pad_len; i++) {
        data[i] = pad_len;
    }
}
"""
                clean_code = clean_code + "\n" + pad_func

            # 移除所有 IV 相关代码
            clean_code = re.sub(r'char iv_hex.*?\n', '', clean_code)
            clean_code = re.sub(r'unsigned char iv.*?\n', '', clean_code)
            clean_code = re.sub(r'printf\("Enter .*?IV.*?"\);.*?\n', '', clean_code)
            clean_code = re.sub(r'scanf\("%16s", iv_hex\);.*?\n', '', clean_code)
            clean_code = re.sub(r'if \(.*?iv.*?\)\n', '', clean_code)

            # 确保使用 ECB 加密函数
            clean_code = clean_code.replace("DES_cbc_encrypt", "DES_ecb_encrypt")

            self.generated_code = clean_code
            return self.generated_code, "代码生成成功（DES-ECB 模式，支持用户输入）"
        except Exception as e:
            return "", f"API错误: {str(e)}"

    def _compile_and_run(self, code=None):
        c_code = code or self.generated_code
        if not c_code:
            return "无代码可编译"

        # 写入代码文件
        code_path = os.path.join(self.work_dir, "des_ecb_encrypt.c")
        with open(code_path, "w") as f:
            f.write(c_code)

        # 编译代码
        exec_path = os.path.join(self.work_dir, "des_ecb_encrypt")
        compile_cmd = f"gcc {code_path} -o {exec_path} -lcrypto -Wall"
        compile_result = subprocess.run(
            compile_cmd,
            shell=True,
            capture_output=True,
            text=True
        )
        if compile_result.returncode != 0:
            self.last_error = compile_result.stderr
            return f"编译失败: {self.last_error}"

        # 运行加密程序
        os.chmod(exec_path, 0o755)
        print("\n===== 加密程序 - 请输入以下信息 =====")
        try:
            subprocess.run(
                [exec_path],
                stdin=sys.stdin,
                stdout=sys.stdout,
                stderr=sys.stderr,
                text=True
            )
            return "运行成功"
        except Exception as e:
            return f"运行错误: {str(e)}"

    def process(self):
        while self.retry_count < self.max_retry:
            self.retry_count += 1
            print(f"\n===== 第 {self.retry_count}/{self.max_retry} 次尝试 (DES-ECB) =====")

            code, msg = self._generate_c_code()
            if not code:
                print(f"生成失败: {msg}")
                if input("是否重试？(y/n): ").lower() != 'y':
                    return
                continue

            print("\n生成的代码：")
            print("-" * 70)
            print(code)
            print("-" * 70)

            result = self._compile_and_run(code)
            if result == "运行成功":
                print("✅ 加密成功")
                return

            print(f"❌ 失败: {result}")
            if self.retry_count < self.max_retry:
                if input("是否重试？(y/n): ").lower() != 'y':
                    return

        print("⚠️ 已达最大重试次数")

if __name__ == "__main__":
    api_key = getpass.getpass("请输入OpenAI API Key（输入时不显示）: ")
    confirm_key = getpass.getpass("请再次确认API Key: ")
    
    if api_key != confirm_key:
        print("❌ 两次输入的API Key不一致")
        sys.exit(1)
        
    # 确保类名调用正确
    helper = DESECBHelper(api_key)
    helper.process()
