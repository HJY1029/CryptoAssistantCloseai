import requests
import json
import subprocess
import os
import re
import sys
from retrying import retry

class SM4Helper:
    def __init__(self, api_key):
        self.api_key = api_key
        self.algorithm = "SM4-CBC"
        self.api_url = "https://api.openai-proxy.org/v1/chat/completions"
        self.work_dir = os.path.join(os.getcwd(), "sm4_workdir")
        os.makedirs(self.work_dir, exist_ok=True)
        
        self.generated_code = None
        self.retry_count = 0
        self.max_retry = 5
        self.last_error = ""

    @retry(stop_max_attempt_number=3, wait_fixed=2000)
    def _generate_c_code(self):
        # 系统提示（保持不变）
        system_prompt = """仅输出纯C代码，无任何其他内容！
基于GMSSL库的SM4-CBC加密必须严格遵循：
1. 核心组件：
   - 密钥类型：SM4_KEY key;
   - 密钥初始化：sm4_set_encrypt_key(&key, raw_key);
   - 加密函数：sm4_encrypt(&key, in_block, out_block);
2. CBC模式强制要求：
   - 必须使用16字节IV（初始向量），通过32个十六进制字符输入
   - 加密流程：明文块与前一个密文块（首块与IV）异或后加密
   - IV输入提示：printf("请输入IV(32个十六进制字符): ");
3. PKCS#7填充规则：
   - 块大小固定为16字节
   - 当明文长度为16的整数倍时，填充16字节（值为0x10）
   - 否则填充 (16 - 余数) 字节，值为填充长度
   - 填充后长度计算：padded_len = input_len + pad_len
4. 输入输出：
   - 密钥输入：printf("请输入密钥(32个十六进制字符): ");
   - 明文输入：printf("请输入明文: ");
   - 密文输出：printf("加密结果(十六进制): "); 格式为%02x
5. 禁止：密文重复、填充长度计算错误、缺少IV处理

只输出C代码，无注释、无标记、无多余内容！"""

        error_feedback = ""
        if self.last_error:
            error_feedback = f"之前错误: {self.last_error}\n修复要求：1.正确实现PKCS#7填充（整数倍补16字节） 2.密文长度=填充后长度×2 3.确保CBC块异或逻辑正确"
        else:
            error_feedback = "生成符合SM4-CBC标准的代码，重点处理IV和填充逻辑"

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": error_feedback}
        ]

        payload = {
            "model": "gpt-4o-mini",
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
            
            # 代码清理（保持不变）
            clean_code = re.sub(r'```c?', '', raw_code)
            clean_code = re.sub(r'```', '', clean_code)
            clean_code = re.sub(r'//.*?\n', '\n', clean_code)
            clean_code = re.sub(r'\n+', '\n', clean_code).strip()
            
            clean_code = re.sub(r'#include.*?sm4.h>', '#include <gmssl/sm4.h>', clean_code)
            clean_code = re.sub(r'sm4_set_key', 'sm4_set_encrypt_key', clean_code)
            
            required_includes = [
                '#include <stdio.h>',
                '#include <stdlib.h>',
                '#include <string.h>',
                '#include <gmssl/sm4.h>',
                '#pragma GCC diagnostic ignored "-Wdeprecated-declarations"'
            ]
            for inc in required_includes:
                if inc not in clean_code:
                    clean_code = inc + '\n' + clean_code
            
            if 'pkcs7_pad' in clean_code:
                clean_code = re.sub(
                    r'size_t pad_len = block_size - \(input_len % block_size\);',
                    r'size_t pad_len = (input_len % block_size == 0) ? block_size : (block_size - (input_len % block_size));',
                    clean_code
                )
            
            self.generated_code = clean_code
            return self.generated_code, "代码生成成功"
        except Exception as e:
            return "", f"API错误: {str(e)}"

    def _compile_and_run(self, code=None):
        c_code = code or self.generated_code
        if not c_code:
            return "无代码可编译"

        # 修复填充长度计算（保持不变）
        c_code = re.sub(
            r'size_t padded_len = plaintext_len \+ \(16 - \(plaintext_len % 16\)\);',
            r'size_t pad_len = (plaintext_len % 16 == 0) ? 16 : (16 - (plaintext_len % 16));\n    size_t padded_len = plaintext_len + pad_len;',
            c_code
        )

        if 'unsigned char iv[16];' not in c_code:
            c_code = re.sub(
                r'unsigned char raw_key\[16\];',
                r'unsigned char raw_key[16];\n    unsigned char iv[16];',
                c_code
            )

        code_path = os.path.join(self.work_dir, "sm4_encrypt.c")
        with open(code_path, "w") as f:
            f.write(c_code)

        exec_path = os.path.join(self.work_dir, "sm4_encrypt")
        compile_cmd = f"gcc {code_path} -o {exec_path} -I/usr/local/include -L/usr/local/lib -lgmssl -Wl,-rpath=/usr/local/lib"
        compile_result = subprocess.run(
            compile_cmd,
            shell=True,
            capture_output=True,
            text=True
        )
        
        if compile_result.returncode != 0:
            error_lines = [line for line in compile_result.stderr.split('\n') if "error:" in line]
            self.last_error = "\n".join(error_lines)
            return f"编译失败:\n{self.last_error}"

        os.chmod(exec_path, 0o755)
        print("\n📌 请输入以下信息：")
        try:
            # 关键修复：删除自动输入的test_input，改为从终端读取手动输入
            subprocess.run(
                [exec_path],
                stdin=sys.stdin,  # 读取终端输入
                stdout=sys.stdout,
                stderr=sys.stderr
            )
            return "运行成功"
        except Exception as e:
            return f"运行失败: {str(e)}"

    def process(self):
        while self.retry_count < self.max_retry:
            self.retry_count += 1
            print(f"\n===== 第 {self.retry_count}/{self.max_retry} 次尝试 ({self.algorithm}) =====")

            code, msg = self._generate_c_code()
            if not code:
                print(f"❌ 代码生成失败: {msg}")
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
