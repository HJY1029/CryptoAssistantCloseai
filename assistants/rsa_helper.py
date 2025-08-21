import requests
import json
import subprocess
import os
import re
import sys
import getpass
from retrying import retry

class RSAHelper:
    def __init__(self, api_key):
        self.api_key = api_key
        self.algorithm = "RSA"
        self.api_url = "https://api.openai-proxy.org/v1/chat/completions"
        self.work_dir = os.path.join(os.getcwd(), "rsa_workdir")
        os.makedirs(self.work_dir, exist_ok=True)
        
        self.generated_code = None
        self.retry_count = 0
        self.max_retry = 5
        self.last_error = ""

    @retry(stop_max_attempt_number=3, wait_fixed=2000)
    def _generate_c_code(self):
        """生成修复头文件格式和参数错误的RSA加密代码"""
        system_prompt = f"""仅输出纯C++代码，无任何其他内容！
基于OpenSSL 3.0+实现RSA加密，严格遵循以下要求：

1. 头文件必须单独成行（每个#include一行）：
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <iomanip>
#include <cstring>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>
#include <openssl/provider.h>

2. 输入：命令行参数（3个）
   - argv[1]：明文（十六进制）
   - argv[2]：公钥n（十六进制）
   - argv[3]：公钥e（十六进制）

3. 核心流程：
   a. 检查参数数量（argc == 4）
   b. 十六进制明文转二进制（vector<unsigned char>）
   c. 解析n和e为BIGNUM（BN_hex2bn）
   d. 用OSSL_PARAM_BLD构建公钥参数
   e. 正确调用EVP_PKEY_fromdata：
      EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params)
   f. 设置填充：RSA_PKCS1_OAEP_PADDING
   g. 加密并输出十六进制密文到控制台和文件

4. 输出文件：{self.work_dir}/rsa_cipher.txt

只输出完整可编译的C++代码，无注释、无多余内容！"""

        error_feedback = """必须修复：
1. 每个#include单独成行，禁止连写
2. EVP_PKEY_fromdata参数顺序：ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params
3. 确保main函数正确定义：int main(int argc, char* argv[])"""

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": error_feedback}
        ]

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
            
            # 强制修复头文件连写问题（核心修复）
            clean_code = re.sub(
                r'#include <(.*?)>(#include <.*?>)',
                r'#include <\1>\n\2',
                raw_code
            )
            # 确保所有头文件单独成行
            clean_code = re.sub(
                r'#include <(.*?)>(?!\n)',
                r'#include <\1>\n',
                clean_code
            )
            
            # 移除中文和无效字符
            clean_code = re.sub(r'//.*?\n|/\*.*?\*/|```cpp|```|[\u4e00-\u9fa5]|[\x00-\x1F]', '', clean_code, flags=re.DOTALL)
            
            # 修复EVP_PKEY_fromdata参数顺序
            clean_code = re.sub(
                r'EVP_PKEY_fromdata\(ctx, EVP_PKEY_PUBLIC_KEY, (.*?), &pkey\)',
                r'EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, \1)',
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

        # 最终检查头文件格式
        code_path = os.path.join(self.work_dir, "rsa_encrypt.cpp")
        with open(code_path, "w") as f:
            f.write(c_code)

        exec_path = os.path.join(self.work_dir, "rsa_encrypt")
        compile_cmd = (
            f"g++ {code_path} -o {exec_path} "
            f"-I/usr/include/openssl -L/usr/lib/x86_64-linux-gnu "
            f"-lcrypto -Wl,-rpath=/usr/lib/x86_64-linux-gnu -Wall"
        )
        compile_result = subprocess.run(
            compile_cmd,
            shell=True,
            capture_output=True,
            text=True
        )
        if compile_result.returncode != 0:
            self.last_error = compile_result.stderr
            return f"编译失败:\n{self.last_error}"

        os.chmod(exec_path, 0o755)
        print("\n📌 请输入测试参数（格式：明文  n  e）:")
        try:
            params = input("参数: ").strip().split()
            if len(params) != 3:
                return "需要3个参数：明文(hex)、n(hex)、e(hex)"
            
            result = subprocess.run(
                [exec_path] + params,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            if result.stdout:
                print("\n加密结果:")
                print(result.stdout)
            if result.stderr:
                print("\n错误信息:")
                print(result.stderr)
                
            return "运行成功" if result.returncode == 0 else "运行失败"
        except Exception as e:
            return f"运行错误: {str(e)}"

    def process(self):
        while self.retry_count < self.max_retry:
            self.retry_count += 1
            print(f"\n===== 第 {self.retry_count}/{self.max_retry} 次尝试 (RSA) =====")

            code, msg = self._generate_c_code()
            if not code:
                print(f"代码生成失败: {msg}")
                if input("重试？(y/n): ").lower() != 'y':
                    return
                continue

            print("\n📝 生成的加密代码：")
            print("-" * 70)
            print(code)
            print("-" * 70)

            result = self._compile_and_run(code)
            if result == "运行成功":
                print("✅ 加密成功")
                return

            print(f"❌ 操作失败: {result}")
            if input("重试？(y/n): ").lower() != 'y':
                return

        print(f"⚠️ 已达最大重试次数({self.max_retry})")

if __name__ == "__main__":
    try:
        api_key = getpass.getpass("请输入OpenAI API Key（输入时不显示）: ")
        api_key_confirm = getpass.getpass("请再次确认API Key: ")
        if api_key != api_key_confirm:
            print("❌ 两次输入的API Key不一致")
            sys.exit(1)
        helper = RSAHelper(api_key)
        helper.process()
    except KeyboardInterrupt:
        print("\n⚠️ 用户中断操作")
        sys.exit(0)
    except Exception as e:
        print(f"❌ 发生错误: {str(e)}")
        sys.exit(1)
