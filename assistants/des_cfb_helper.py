import requests
import json
import subprocess
import os
import re
import sys
from retrying import retry

class DESCFBHelper:
    def __init__(self, api_key):
        self.api_key = api_key
        self.mode = "CFB"
        self.supported_mode = "CFB"
        
        self.mode_config = {
            "encrypt_func": "DES_cfb_encrypt",
            "needs_iv": True,
            "key_length": 8,  # 64位密钥(8字节)
            "feedback_size": 64  # DES块大小为64位
        }
        
        self.api_url = "https://api.openai-proxy.org/v1/chat/completions"
        self.work_dir = os.path.join(os.getcwd(), f"des_cfb_workdir")
        os.makedirs(self.work_dir, exist_ok=True)
        
        self.generated_code = None
        self.retry_count = 0
        self.max_retry = 5
        self.last_error = ""

    @retry(stop_max_attempt_number=3, wait_fixed=2000)
    def _generate_c_code(self):
        """生成严格匹配测试向量的DES-CFB代码"""
        base_prompt = """仅输出纯C代码，实现DES-CFB加密，必须严格遵循：

1. 头文件：
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/des.h>
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

2. 必须实现函数：
void hex_to_bytes(const char* hex_str, unsigned char* bytes, size_t len) {
    for (size_t i = 0; i < len; i++) {
        sscanf(hex_str + 2*i, "%2hhx", &bytes[i]);
    }
}

3. main函数流程：
int main() {
    unsigned char key[8];          // 64位密钥(8字节)
    unsigned char iv[8];           // 8字节IV
    char key_hex[17], iv_hex[17];  // 密钥和IV的十六进制字符串
    char plaintext_hex[1024];      // 明文的十六进制字符串
    int num = 64;                  // CFB反馈大小

    // 密钥输入
    printf("请输入8字节十六进制密钥（16字符）: ");
    scanf("%16s", key_hex);
    while(getchar() != '\\n');
    hex_to_bytes(key_hex, key, 8);

    // IV输入
    printf("请输入8字节十六进制IV（16字符）: ");
    scanf("%16s", iv_hex);
    while(getchar() != '\\n');
    hex_to_bytes(iv_hex, iv, 8);

    // 明文输入
    printf("请输入要加密的明文（十六进制）: ");
    fgets(plaintext_hex, sizeof(plaintext_hex), stdin);
    if (plaintext_hex[strlen(plaintext_hex)-1] == '\\n')
        plaintext_hex[strlen(plaintext_hex)-1] = '\\0';

    // 明文处理
    size_t plaintext_len = strlen(plaintext_hex) / 2;
    unsigned char plaintext[plaintext_len];
    hex_to_bytes(plaintext_hex, plaintext, plaintext_len);

    // 加密配置
    DES_cblock des_key;
    DES_key_schedule key_schedule;
    memcpy(des_key, key, 8);
    DES_set_key_checked(&des_key, &key_schedule);

    // 加密执行
    unsigned char ciphertext[plaintext_len];
    DES_cblock iv_copy;
    memcpy(iv_copy, iv, 8);
    DES_cfb_encrypt(plaintext, ciphertext, num, plaintext_len,
                   &key_schedule, &iv_copy, DES_ENCRYPT);

    // 密文输出
    printf("密文: ");
    for (size_t i = 0; i < plaintext_len; i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\\n");

    return 0;
}

4. 强制要求：
- 所有printf提示文本必须完全匹配上述内容
- DES_cfb_encrypt只能有7个参数，顺序严格为：输入,输出,反馈位数,长度,密钥调度,&IV,加密标志
- 禁止任何多余参数和重复传递
- 代码中不能出现中文和多余注释"""

        error_feedback = "修复：1) 提示文本必须区分密钥/IV/明文；2) DES_cfb_encrypt只能有7个参数；3) 移除所有重复参数；4) 确保参数类型正确。"

        messages = [{"role": "system", "content": base_prompt}]
        messages.append({"role": "user", "content": f"生成可编译的DES-CFB代码。错误修复：{error_feedback}"})

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
            
            # 强制清理和标准化代码
            clean_code = re.sub(r'//.*?\n|/\*.*?\*/|```c|```|[\u4e00-\u9fa5]', '', raw_code, flags=re.DOTALL)
            
            # 强制替换所有提示文本为正确内容
            clean_code = re.sub(r'printf\("密文: "\);', 'printf("请输入8字节十六进制密钥（16字符）: ");', clean_code, count=1)
            clean_code = re.sub(r'printf\("密文: "\);', 'printf("请输入8字节十六进制IV（16字符）: ");', clean_code, count=1)
            clean_code = re.sub(r'printf\("密文: "\);', 'printf("请输入要加密的明文（十六进制）: ");', clean_code, count=1)
            
            # 强制修复DES_cfb_encrypt参数（确保仅7个参数）
            clean_code = re.sub(
                r'DES_cfb_encrypt\(.*?\);',
                'DES_cfb_encrypt(plaintext, ciphertext, num, plaintext_len, &key_schedule, &iv_copy, DES_ENCRYPT);',
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

        # 最终强制修复关键问题
        # 1. 确保所有提示文本正确
        c_code = c_code.replace('printf("密文: ");', 'printf("请输入8字节十六进制密钥（16字符）: ");', 1)
        c_code = c_code.replace('printf("密文: ");', 'printf("请输入8字节十六进制IV（16字符）: ");', 1)
        c_code = c_code.replace('printf("密文: ");', 'printf("请输入要加密的明文（十六进制）: ");', 1)
        
        # 2. 确保加密函数参数正确
        c_code = re.sub(
            r'DES_cfb_encrypt\(.*?\);',
            'DES_cfb_encrypt(plaintext, ciphertext, num, plaintext_len, &key_schedule, &iv_copy, DES_ENCRYPT);',
            c_code
        )

        # 3. 写入代码文件
        code_path = os.path.join(self.work_dir, "des_cfb_encrypt.c")
        with open(code_path, "w") as f:
            f.write(c_code)

        # 4. 编译并运行
        exec_path = os.path.join(self.work_dir, "des_cfb_encrypt")
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
            print(f"\n===== 第 {self.retry_count}/{self.max_retry} 次尝试 (DES-CFB) =====")

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
    helper = DESCFBHelper(api_key)
    helper.process()
