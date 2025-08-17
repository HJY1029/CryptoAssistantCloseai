import requests
import json
import subprocess
import os
import re
import sys
from retrying import retry

class AESCFBHelper:
    def __init__(self, api_key):
        self.api_key = api_key
        self.mode = "CFB"
        self.supported_mode = "CFB"
        
        self.mode_config = {
            "encrypt_func": "AES_cfb128_encrypt",
            "needs_iv": True,
            "key_length": 16,  # 128位密钥
            "feedback_size": 128
        }
        
        self.api_url = "https://api.openai-proxy.org/v1/chat/completions"
        self.work_dir = os.path.join(os.getcwd(), f"aes_cfb_workdir")
        os.makedirs(self.work_dir, exist_ok=True)
        
        self.generated_code = None
        self.retry_count = 0
        self.max_retry = 5
        self.last_error = ""

    @retry(stop_max_attempt_number=3, wait_fixed=2000)
    def _generate_c_code(self):
        """生成严格匹配测试向量的AES-CFB代码"""
        base_prompt = """仅输出纯C代码，实现AES-{mode}加密，必须严格遵循：

1. 头文件：
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

2. 必须实现函数：
void hex_to_bytes(const char* hex_str, unsigned char* bytes, size_t len) {{
    for (size_t i = 0; i < len; i++) {{
        sscanf(hex_str + 2*i, "%2hhx", &bytes[i]);
    }}
}}

3. main函数流程：
int main() {{
    unsigned char key[16];         // 128位密钥
    unsigned char iv[16];          // 16字节IV
    char key_hex[33], iv_hex[33];  // 密钥和IV的十六进制字符串
    char plaintext_hex[1024];      // 明文的十六进制字符串
    int num = 128;                 // CFB模式反馈长度

    // 密钥输入 - 必须使用此提示
    printf("请输入16字节十六进制密钥（32字符）: ");
    scanf("%32s", key_hex);
    while(getchar() != '\\n');
    hex_to_bytes(key_hex, key, 16);  // 必须转换密钥

    // IV输入 - 必须使用此提示
    printf("请输入16字节十六进制IV（32字符）: ");
    scanf("%32s", iv_hex);
    while(getchar() != '\\n');
    hex_to_bytes(iv_hex, iv, 16);    // 必须转换IV

    // 明文输入 - 必须使用此提示
    printf("请输入要加密的明文（十六进制）: ");
    fgets(plaintext_hex, sizeof(plaintext_hex), stdin);
    if (plaintext_hex[strlen(plaintext_hex)-1] == '\\n')
        plaintext_hex[strlen(plaintext_hex)-1] = '\\0';

    // 明文处理
    size_t plaintext_len = strlen(plaintext_hex) / 2;
    unsigned char plaintext[plaintext_len];
    hex_to_bytes(plaintext_hex, plaintext, plaintext_len);

    // 加密配置
    AES_KEY aes_key;
    AES_set_encrypt_key(key, 128, &aes_key);  // 必须是128位

    // 加密执行 - CFB模式必须使用IV副本
    unsigned char ciphertext[plaintext_len];
    unsigned char iv_copy[16];
    memcpy(iv_copy, iv, 16);  // 必须复制IV
    AES_cfb128_encrypt(plaintext, ciphertext, plaintext_len,
                      &aes_key, iv_copy, &num, AES_ENCRYPT);

    // 密文输出 - 必须使用此提示
    printf("密文: ");
    for (size_t i = 0; i < plaintext_len; i++) {{
        printf("%02x", ciphertext[i]);
    }}
    printf("\\n");

    return 0;
}}

4. 禁止修改任何提示文本、函数名和参数
5. 禁止添加任何注释或额外功能
6. CFB模式绝对不能使用填充
7. 必须使用128位密钥和16字节IV

只输出完整C代码，无其他内容！"""

        error_feedback = "必须严格使用指定的提示文本和IV副本机制，确保：1) 提示文本完全匹配；2) 使用iv_copy进行加密；3) 输出前缀为'密文: '。"

        messages = [{"role": "system", "content": base_prompt}]
        user_content = "生成与测试向量完全匹配的AES-CFB代码"
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
            
            # 强制代码标准化（确保关键部分完全正确）
            clean_code = re.sub(
                r'//.*?\n|/\*.*?\*/|```c|```|[\u4e00-\u9fa5]',
                '', 
                raw_code, 
                flags=re.DOTALL
            )
            
            # 强制替换所有提示文本为标准格式
            clean_code = re.sub(r'printf\(".*?密钥.*?"\);', 
                               'printf("请输入16字节十六进制密钥（32字符）: ");', clean_code)
            clean_code = re.sub(r'printf\(".*?IV.*?"\);', 
                               'printf("请输入16字节十六进制IV（32字符）: ");', clean_code)
            clean_code = re.sub(r'printf\(".*?明文.*?"\);', 
                               'printf("请输入要加密的明文（十六进制）: ");', clean_code)
            
            # 确保IV副本机制存在
            if 'unsigned char iv_copy[16];' not in clean_code:
                clean_code = re.sub(
                    r'(unsigned char ciphertext\[plaintext_len\];)',
                    r'\1\n    unsigned char iv_copy[16];\n    memcpy(iv_copy, iv, 16);',
                    clean_code
                )
            clean_code = re.sub(r'AES_cfb128_encrypt\(.*?, iv,', 
                               'AES_cfb128_encrypt(plaintext, ciphertext, plaintext_len, &aes_key, iv_copy,', clean_code)

            self.generated_code = clean_code.strip()
            return self.generated_code, "代码生成成功"
        except Exception as e:
            return "", f"API错误: {str(e)}"

    def _compile_and_run(self, code=None):
        c_code = code or self.generated_code
        if not c_code:
            return "无代码可编译"

        # 最终强制修复关键部分
        c_code = c_code.replace(
            'AES_cfb128_encrypt', 
            'AES_cfb128_encrypt'  # 确保函数名正确
        )
        c_code = c_code.replace(
            'iv, &num, AES_ENCRYPT', 
            'iv_copy, &num, AES_ENCRYPT'  # 确保使用IV副本
        )

        code_path = os.path.join(self.work_dir, "aes_cfb_encrypt.c")
        with open(code_path, "w") as f:
            f.write(c_code)

        exec_path = os.path.join(self.work_dir, "aes_cfb_encrypt")
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
            sys.stdin.flush()
            subprocess.run([exec_path], stdin=sys.stdin, stdout=sys.stdout, stderr=sys.stderr)
            return "运行成功"
        except Exception as e:
            return f"运行错误: {str(e)}"

    def process(self):
        while self.retry_count < self.max_retry:
            self.retry_count += 1
            print(f"\n===== 第 {self.retry_count}/{self.max_retry} 次尝试 (AES-CFB) =====")

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
    helper = AESCFBHelper(api_key)
    helper.process()
