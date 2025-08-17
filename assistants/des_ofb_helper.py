import requests
import json
import subprocess
import os
import re
import sys
from retrying import retry

class DESOFBHelper:
    def __init__(self, api_key):  
        self.api_key = api_key
        self.mode = "OFB"
        self.supported_mode = "OFB"
       
        self.mode_config = {
            "encrypt_func": "DES_ofb64_encrypt",
            "needs_iv": True,
            "key_length": 8  # 64位密钥（含8位奇偶校验）
        }
        
        self.api_url = f"https://api.openai-proxy.org/v1/chat/completions"
        self.work_dir = os.path.join(os.getcwd(), f"des_ofb_workdir")
        os.makedirs(self.work_dir, exist_ok=True)
        
        self.generated_code = None
        self.retry_count = 0
        self.max_retry = 5
        self.last_error = ""
        self.compilation_errors = []
        self.code_history = []

    @retry(stop_max_attempt_number=3, wait_fixed=2000)
    def _generate_c_code(self):
        """生成正确的DES-OFB加密代码，修复密钥校验问题"""
        base_prompt = """仅输出纯C代码，实现DES-OFB加密：

1. 头文件：
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/des.h>
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

2. 核心函数：
void hex_to_bytes(const char* hex_str, unsigned char* bytes, size_t len) {
    for (size_t i = 0; i < len; i++) {
        sscanf(hex_str + 2*i, "%2hhx", &bytes[i]);
    }
}

// 自动调整DES密钥的奇偶校验位
void adjust_des_key_parity(unsigned char *key) {
    for (int i = 0; i < 8; i++) {
        // 计算当前字节的奇偶性
        int parity = 0;
        for (int j = 0; j < 7; j++) {
            parity ^= (key[i] >> (j + 1)) & 1;
        }
        // 设置奇偶校验位（最低位）
        key[i] = (key[i] & 0xfe) | parity;
    }
}

3. 主流程（必须严格执行）：
int main() {
    // 变量定义
    unsigned char key[8];
    unsigned char iv[8];
    char key_hex[17], iv_hex[17];  // 密钥和IV的字符串缓冲区
    char plaintext_hex[1024];      // 明文字符串缓冲区
    DES_cblock des_key;
    DES_key_schedule key_schedule;
    int num = 0;  // DES_ofb64_encrypt需要的计数器

    // 输入密钥
    printf("请输入8字节十六进制密钥（16字符）: ");
    scanf("%16s", key_hex);
    while(getchar() != '\\n');  // 清理缓冲区
    hex_to_bytes(key_hex, key, 8);  // 转换为字节
    adjust_des_key_parity(key);  // 自动调整奇偶校验位
    memcpy(des_key, key, 8);

    // 设置密钥（不检查奇偶校验）
    DES_set_key_unchecked(&des_key, &key_schedule);

    // 输入IV
    printf("请输入8字节十六进制IV（16字符）: ");
    scanf("%16s", iv_hex);
    while(getchar() != '\\n');  // 清理缓冲区
    hex_to_bytes(iv_hex, iv, 8);    // 转换为字节

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
    DES_ofb64_encrypt(plaintext, ciphertext, plaintext_len, &key_schedule, 
                     (DES_cblock*)iv, &num);

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
        error_feedback = "必须修复：1) 使用DES_set_key_unchecked替代DES_set_key_checked；2) 添加自动调整奇偶校验位的函数；3) 确保中文提示正常显示。"

        messages = [{"role": "system", "content": base_prompt}]
        user_content = "生成符合标准的DES-OFB加密代码，避免密钥校验错误"
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
                    r'(scanf\("%16s", key_hex\);)',
                    r'\1\n    while(getchar() != \'\\n\');',
                    clean_code
                )
                clean_code = re.sub(
                    r'(scanf\("%16s", iv_hex\);)',
                    r'\1\n    while(getchar() != \'\\n\');',
                    clean_code
                )
            
            # 强制使用不检查奇偶校验的函数
            clean_code = re.sub(r'DES_set_key_checked', 'DES_set_key_unchecked', clean_code)
            
            # 确保添加了奇偶校验调整函数
            if 'adjust_des_key_parity' not in clean_code:
                parity_func = """void adjust_des_key_parity(unsigned char *key) {
    for (int i = 0; i < 8; i++) {
        int parity = 0;
        for (int j = 0; j < 7; j++) {
            parity ^= (key[i] >> (j + 1)) & 1;
        }
        key[i] = (key[i] & 0xfe) | parity;
    }
}
"""
                clean_code = re.sub(r'(#pragma GCC diagnostic ignored "-Wdeprecated-declarations"\n)', 
                                   r'\1\n' + parity_func, clean_code)
            
            # 强制使用中文提示
            clean_code = re.sub(r'Enter 16 characters \(8 bytes\) hexadecimal key: ', 
                               '请输入8字节十六进制密钥（16字符）: ', clean_code)
            clean_code = re.sub(r'Enter 16 characters \(8 bytes\) hexadecimal IV: ', 
                               '请输入8字节十六进制IV（16字符）: ', clean_code)
            clean_code = re.sub(r'Enter the plaintext to encrypt \(in hexadecimal\): ', 
                               '请输入要加密的明文（十六进制）: ', clean_code)
            clean_code = re.sub(r'Ciphertext: ', '密文: ', clean_code)

            self.generated_code = clean_code.strip()
            return self.generated_code, "代码生成成功"
        except Exception as e:
            return "", f"API错误: {str(e)}"

    def _compile_and_run(self, code=None):
        c_code = code or self.generated_code
        if not c_code:
            return "无代码可编译"

        code_path = os.path.join(self.work_dir, "des_ofb_encrypt.c")
        with open(code_path, "w") as f:
            f.write(c_code)

        exec_path = os.path.join(self.work_dir, "des_ofb_encrypt")
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
            print(f"\n===== 第 {self.retry_count}/{self.max_retry} 次尝试 (DES-OFB) =====")

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
    helper = DESOFBHelper(api_key)
    helper.process()
