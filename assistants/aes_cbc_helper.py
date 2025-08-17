import requests
import json
import subprocess
import os
import re
import sys
from retrying import retry

class AESCBCHelper:
    def __init__(self, api_key):
        self.api_key = api_key
        self.mode = "CBC"
        self.supported_mode = "CBC"
        
        self.mode_config = {
            "encrypt_func": "AES_cbc_encrypt",
            "needs_iv": True,
            "key_length": 16,  # 128位密钥
            "block_size": 16
        }
        
        self.api_url = "https://api.openai-proxy.org/v1/chat/completions"
        self.work_dir = os.path.join(os.getcwd(), f"aes_cbc_workdir")
        os.makedirs(self.work_dir, exist_ok=True)
        
        self.generated_code = None
        self.retry_count = 0
        self.max_retry = 5
        self.last_error = ""

    @retry(stop_max_attempt_number=3, wait_fixed=2000)
    def _generate_c_code(self):
        """生成精确符合标准的AES-CBC加密代码"""
        base_prompt = """仅输出纯C代码，实现AES-CBC加密，必须严格遵循以下标准：

1. 头文件：
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

2. 函数定义：
- hex_to_bytes：将十六进制字符串转换为字节数组
  原型：void hex_to_bytes(const char* hex_str, unsigned char* bytes, size_t len);

- pkcs7_pad：仅当需要时进行PKCS#7填充
  原型：void pkcs7_pad(unsigned char* data, size_t len, size_t block_size);

3. 主流程（必须严格按顺序）：
   a. 定义：
      - unsigned char key[16];        // 128位密钥
      - unsigned char iv[16];         // 16字节IV
      - char key_hex[33], iv_hex[33]; // 密钥和IV的十六进制字符串
      - char plaintext_hex[1024];     // 明文的十六进制字符串

   b. 输入密钥：
      printf("请输入16字节十六进制密钥（32字符）: ");
      scanf("%32s", key_hex);
      while(getchar() != '\n');
      hex_to_bytes(key_hex, key, 16);  // 必须转换密钥

   c. 输入IV：
      printf("请输入16字节十六进制IV（32字符）: ");
      scanf("%32s", iv_hex);
      while(getchar() != '\n');
      hex_to_bytes(iv_hex, iv, 16);    // 必须转换IV

   d. 输入明文：
      printf("请输入要加密的明文（十六进制）: ");
      fgets(plaintext_hex, sizeof(plaintext_hex), stdin);
      if (plaintext_hex[strlen(plaintext_hex)-1] == '\n')
          plaintext_hex[strlen(plaintext_hex)-1] = '\0';

   e. 计算长度：
      size_t plaintext_len = strlen(plaintext_hex) / 2;
      size_t encrypted_len = ((plaintext_len + 15) / 16) * 16;  // 16字节块对齐

   f. 准备缓冲区：
      unsigned char plaintext[encrypted_len];
      unsigned char ciphertext[encrypted_len];
      hex_to_bytes(plaintext_hex, plaintext, plaintext_len);

   g. 填充（仅当需要时）：
      if (plaintext_len % 16 != 0)
          pkcs7_pad(plaintext, plaintext_len, 16);

   h. 加密：
      AES_KEY aes_key;
      AES_set_encrypt_key(key, 128, &aes_key);  // 明确128位
      AES_cbc_encrypt(plaintext, ciphertext, encrypted_len, &aes_key, iv, AES_ENCRYPT);

   i. 输出密文：
      printf("密文: ");
      for (size_t i = 0; i < encrypted_len; i++)
          printf("%02x", ciphertext[i]);
      printf("\n");

4. 禁止：
   - 任何注释
   - 模糊的提示文本（如"16（32）: "）
   - 省略密钥/IV的hex_to_bytes转换
   - 错误的输出提示

只输出C代码，无其他内容！"""

        error_feedback = "必须严格修复：1) 密钥和IV必须通过hex_to_bytes转换；2) 提示文本必须完全匹配要求；3) 密文输出前缀必须是'密文: '；4) 确保所有长度计算正确。"

        messages = [{"role": "system", "content": base_prompt}]
        user_content = "生成符合标准的AES-CBC加密代码，确保与提供的测试向量匹配"
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
            
            # 代码净化与强制修复
            clean_code = re.sub(
                r'//.*?\n|/\*.*?\*/|```c|```|[\u4e00-\u9fa5]',
                '', 
                raw_code, 
                flags=re.DOTALL
            )
            
            # 强制修正所有提示文本
            clean_code = re.sub(
                r'printf\("16（32）: "\);',
                'printf("请输入16字节十六进制密钥（32字符）: ");',
                clean_code
            )
            clean_code = re.sub(
                r'printf\("16IV（32）: "\);',
                'printf("请输入16字节十六进制IV（32字符）: ");',
                clean_code
            )
           
            
            # 确保密钥和IV被正确转换
            if 'hex_to_bytes(key_hex, key, 16);' not in clean_code:
                clean_code = re.sub(
                    r'(scanf\("%32s", key_hex\);\n.*?while\(getchar\(\) != \'\n\'\);)',
                    r'\1\n    hex_to_bytes(key_hex, key, 16);',
                    clean_code,
                    flags=re.DOTALL
                )
            if 'hex_to_bytes(iv_hex, iv, 16);' not in clean_code:
                clean_code = re.sub(
                    r'(scanf\("%32s", iv_hex\);\n.*?while\(getchar\(\) != \'\n\'\);)',
                    r'\1\n    hex_to_bytes(iv_hex, iv, 16);',
                    clean_code,
                    flags=re.DOTALL
                )
            
            # 确保密文输出提示正确
            clean_code = re.sub(
                r'printf\("请输入要加密的明文（十六进制）: "\);',
                'printf("明文: ");',
                clean_code
            )
            
            # 确保加密长度正确
            clean_code = re.sub(
                r'AES_cbc_encrypt\((.*?), (.*?), \d+, (.*?), (.*?), (.*?)\);',
                r'AES_cbc_encrypt(\1, \2, encrypted_len, \3, \4, \5);',
                clean_code
            )

            self.generated_code = clean_code.strip()
            return self.generated_code, "代码生成成功"
        except Exception as e:
            return "", f"API错误: {str(e)}"

    def _compile_and_run(self, code=None):
        c_code = code or self.generated_code
        if not c_code:
            return "无代码可编译"

        # 最终检查确保所有转换步骤存在
        if 'hex_to_bytes(key_hex, key, 16);' not in c_code:
            c_code = c_code.replace(
                'while(getchar() != \'\\n\');',
                'while(getchar() != \'\\n\');\n    hex_to_bytes(key_hex, key, 16);',
                1
            )
        if 'hex_to_bytes(iv_hex, iv, 16);' not in c_code:
            c_code = c_code.replace(
                'while(getchar() != \'\\n\');',
                'while(getchar() != \'\\n\');\n    hex_to_bytes(iv_hex, iv, 16);',
                1
            )

        code_path = os.path.join(self.work_dir, "aes_cbc_encrypt.c")
        with open(code_path, "w") as f:
            f.write(c_code)

        exec_path = os.path.join(self.work_dir, "aes_cbc_encrypt")
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
            print(f"\n===== 第 {self.retry_count}/{self.max_retry} 次尝试 (AES-CBC) =====")

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
    helper = AESCBCHelper(api_key)
    helper.process()
    
