import requests
import json
import subprocess
import os
import re
import sys
from retrying import retry

class AESOFBHelper:
    def __init__(self, api_key):  
        self.api_key = api_key
        self.mode = "OFB"
        self.supported_mode = "OFB"
       
        self.mode_config = {
            "encrypt_func": "AES_ofb128_encrypt",
            "needs_iv": True,
            "key_length": 16  # 128位密钥
        }
        
        self.api_url = f"https://api.openai-proxy.org/v1/chat/completions"
        self.work_dir = os.path.join(os.getcwd(), f"aes_ofb_workdir")
        os.makedirs(self.work_dir, exist_ok=True)
        
        self.generated_code = None
        self.retry_count = 0
        self.max_retry = 5
        self.last_error = ""
        self.compilation_errors = []
        self.code_history = []

    @retry(stop_max_attempt_number=3, wait_fixed=2000)
    def _generate_c_code(self):
        """生成正确的AES-OFB-128加密代码"""
        base_prompt = """仅输出纯C代码，实现AES-OFB-128加密：

1. 头文件：
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

2. 核心函数：
void hex_to_bytes(const char* hex_str, unsigned char* bytes, size_t len) {
    for (size_t i = 0; i < len; i++) {
        sscanf(hex_str + 2*i, "%2hhx", &bytes[i]);
    }
}

3. 主流程（必须严格执行）：
int main() {
    // 变量定义
    unsigned char key[16];
    unsigned char iv[16];
    char key_hex[33], iv_hex[33];  // 密钥和IV的字符串缓冲区
    char plaintext_hex[1024];      // 明文字符串缓冲区
    AES_KEY aes_key;

    // 输入密钥
    printf("请输入16字节十六进制密钥（32字符）: ");
    scanf("%32s", key_hex);
    while(getchar() != '\\n');  // 清理缓冲区
    hex_to_bytes(key_hex, key, 16);  // 转换为字节

    // 输入IV
    printf("请输入16字节十六进制IV（32字符）: ");
    scanf("%32s", iv_hex);
    while(getchar() != '\\n');  // 清理缓冲区
    hex_to_bytes(iv_hex, iv, 16);    // 转换为字节

    // 初始化加密密钥
    AES_set_encrypt_key(key, 128, &aes_key);

    // 输入明文
    printf("请输入要加密的明文（十六进制）: ");
    fgets(plaintext_hex, sizeof(plaintext_hex), stdin);
    if (plaintext_hex[strlen(plaintext_hex)-1] == '\\n')
        plaintext_hex[strlen(plaintext_hex)-1] = '\\0';  // 移除换行

    // 处理明文
    size_t plaintext_len = strlen(plaintext_hex) / 2;
    unsigned char plaintext[plaintext_len];
    hex_to_bytes(plaintext_hex, plaintext, plaintext_len);  // 转换为字节

    // 加密
    unsigned char ciphertext[plaintext_len];
    unsigned char iv_copy[16];
    memcpy(iv_copy, iv, 16);  // 使用IV副本
    AES_ofb128_encrypt(plaintext, ciphertext, plaintext_len, &aes_key, iv_copy);

    // 输出密文
    printf("密文: ");
    for (size_t i = 0; i < plaintext_len; i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\\n");

    return 0;
}

4. 禁止：
- 任何注释
- 缺少缓冲区清理
- 直接使用密钥/IV数组作为字符串缓冲区
- 省略十六进制到字节的转换
- 填充操作

只输出C代码！"""

        # 错误反馈
        error_feedback = "必须修复：1) 添加scanf后的缓冲区清理；2) 使用单独的字符串缓冲区存储输入；3) 正确转换十六进制到字节；4) 标准化提示文本。"

        messages = [{"role": "system", "content": base_prompt}]
        user_content = "生成符合标准的AES-OFB加密代码"
        if error_feedback:
            user_content += f"。错误修复：{error_feedback}"
        messages.append({"role": "user", "content": user_content})

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
            
            response_data = response.json()
            raw_code = response_data["choices"][0]["message"]["content"]
            
            # 代码净化与强制修复
            clean_code = re.sub(
                r'//.*?\n|/\*.*?\*/|```c|```|[\u4e00-\u9fa5]',
                '', 
                raw_code, 
                flags=re.DOTALL
            )
            
            # 强制修复缓冲区清理
            if 'while(getchar() != \'\\n\');' not in clean_code:
                clean_code = re.sub(
                    r'(scanf\("%32s", key_hex\);)',
                    r'\1\n    while(getchar() != \'\\n\');',
                    clean_code
                )
                clean_code = re.sub(
                    r'(scanf\("%32s", iv_hex\);)',
                    r'\1\n    while(getchar() != \'\\n\');',
                    clean_code
                )
            
            # 强制使用单独的字符串缓冲区
            clean_code = re.sub(r'scanf\("%32s", key\);', 'scanf("%32s", key_hex);', clean_code)
            clean_code = re.sub(r'scanf\("%32s", iv\);', 'scanf("%32s", iv_hex);', clean_code)
            
            # 标准化提示文本
            clean_code = re.sub(r'printf\("16（32）: "\);', 
                               'printf("请输入16字节十六进制密钥（32字符）: ");', clean_code)
            clean_code = re.sub(r'printf\("（）: "\);', 
                               'printf("请输入要加密的明文（十六进制）: ");', clean_code)
            clean_code = re.sub(r'printf\(": "\);', 'printf("密文: ");', clean_code)

            self.generated_code = clean_code.strip()
            return self.generated_code, "代码生成成功"
        except Exception as e:
            return "", f"API错误: {str(e)}"

    def _compile_and_run(self, code=None):
        c_code = code or self.generated_code
        if not c_code:
            return "无代码可编译"

        # 最终修复
        c_code = re.sub(r'key\[16\]作为字符串', 'key_hex作为字符串缓冲区', c_code)
        c_code = re.sub(r'AES_ofb128_encrypt(.*?), NULL', 'AES_ofb128_encrypt\\1', c_code)

        code_path = os.path.join(self.work_dir, "aes_ofb_encrypt.c")
        with open(code_path, "w") as f:
            f.write(c_code)

        exec_path = os.path.join(self.work_dir, "aes_ofb_encrypt")
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

        os.chmod(exec_path, 0o755)
        print("\n请输入加密信息：")
        try:
            subprocess.run([exec_path], stdin=sys.stdin, stdout=sys.stdout, stderr=sys.stderr)
            return "运行成功"
        except Exception as e:
            return f"运行错误: {str(e)}"

    def process(self):
        while self.retry_count < self.max_retry:
            self.retry_count += 1
            print(f"\n===== 第 {self.retry_count}/{self.max_retry} 次尝试 (AES-OFB) =====")

            code, msg = self._generate_c_code()
            if not code:
                print(f"生成失败: {msg}")
                if input("重试？(y/n): ").lower() != 'y':
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
            if self.retry_count < self.max_retry and input("重试？(y/n): ").lower() != 'y':
                return

        print("⚠️ 已达最大重试次数")

if __name__ == "__main__":
    api_key = input("请输入OpenAI API Key: ")
    helper = AESOFBHelper(api_key)
    helper.process()
