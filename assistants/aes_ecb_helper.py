import requests
import json
import subprocess
import os
import re
import sys
from retrying import retry

class AESECBHelper:
    def __init__(self, api_key):
        self.api_key = api_key
        self.mode = "ECB"
        self.supported_mode = "ECB"
        
        self.mode_config = {
            "encrypt_func": "AES_ecb_encrypt",
            "needs_iv": False,
            "key_length": 32  # 256位密钥
        }
        
        self.api_url = "https://api.openai-proxy.org/v1/chat/completions"
        self.work_dir = os.path.join(os.getcwd(), f"aes_ecb_workdir")
        os.makedirs(self.work_dir, exist_ok=True)
        
        self.generated_code = None
        self.retry_count = 0
        self.max_retry = 5
        self.last_error = ""
        self.compilation_errors = []
        self.code_history = []

    # 预定义正确的十六进制转换函数（直接嵌入，不依赖AI生成）
    @property
    def fixed_hex_functions(self):
        return """
// 十六进制字符转数值
static unsigned char hex_char_to_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + c - 'a';
    if (c >= 'A' && c <= 'F') return 10 + c - 'A';
    return 0xFF; // 无效字符
}

// 强化版十六进制转字节数组（确保正确转换）
int hex_to_bytes(const char *hex, unsigned char *bytes, size_t max_len) {
    if (!hex || !bytes) return -1;
    
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0) return -1; // 长度必须为偶数
    
    size_t byte_len = hex_len / 2;
    if (byte_len > max_len) return -1; // 超出最大长度
    
    for (size_t i = 0; i < hex_len; i += 2) {
        unsigned char high = hex_char_to_val(hex[i]);
        unsigned char low = hex_char_to_val(hex[i+1]);
        
        if (high == 0xFF || low == 0xFF) return -1; // 无效字符
        
        bytes[i/2] = (high << 4) | low;
    }
    
    return byte_len;
}

// 字节数组转十六进制
void bytes_to_hex(const unsigned char *bytes, size_t len, char *hex) {
    const char *hex_chars = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        hex[2*i] = hex_chars[(bytes[i] >> 4) & 0x0F];
        hex[2*i + 1] = hex_chars[bytes[i] & 0x0F];
    }
    hex[2*len] = '\\0';
}
"""

    @property
    def openssl_test_code(self):
        return f"""
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <ctype.h>
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

{self.fixed_hex_functions}

// PKCS#7填充实现
void pkcs7_pad(const unsigned char *data, size_t data_len, unsigned char *padded, size_t *padded_len) {{
    *padded_len = data_len + (AES_BLOCK_SIZE - (data_len % AES_BLOCK_SIZE));
    memcpy(padded, data, data_len);
    unsigned char pad_value = AES_BLOCK_SIZE - (data_len % AES_BLOCK_SIZE);
    for (size_t i = data_len; i < *padded_len; i++) {{
        padded[i] = pad_value;
    }}
}}

// 测试向量结构体
typedef struct {{
    const char *key_hex;
    const char *plaintext_hex;
    const char *expected_ciphertext_hex;
    size_t key_len;       // 预期密钥字节长度
    size_t text_len;      // 预期明文/密文字节长度
}} AES_TestVector;

// 测试向量（验证长度正确性）
AES_TestVector openssl_test_vectors[] = {{
    {{
        "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff46ddc1832731015ead891cc3cf1c9d34b49264b510751b1ff9e537937bc46b5d6ff4ecc8",
        "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
        "f3eed1bdb5d2a031b362c18fb610967a3cbb140b8c52bcb119a565b4551758d2604f450853ffd2dda2eecc44c2e32cf7ba0675c2e6c007c1a96178cb778d6429b6c55a06d552cb75",
        32, 64
    }},
    {{
        "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
        "88d4266fd4e6338d13b845554bb7b5b6d037e072d39b4e76d80084de11e7897e7c452f2353d1cc6465b872a6ac5a6d27d8e92273c82c7c33f8991e71460c63",
        32, 32
    }}
}};

#define TEST_VECTOR_COUNT (sizeof(openssl_test_vectors) / sizeof(AES_TestVector))

// 测试执行函数
int run_openssl_tests() {{
    int tests_passed = 0;
    AES_KEY aes_key;
    unsigned char key[32];
    unsigned char plaintext[128];
    unsigned char ciphertext[128];
    unsigned char expected_ciphertext[128];
    unsigned char padded_plaintext[128];
    size_t padded_len;
    char ciphertext_hex[257];
    
    printf("===== 运行OpenSSL测试向量验证 =====\\n");
    
    for (size_t i = 0; i < TEST_VECTOR_COUNT; i++) {{
        AES_TestVector *test = &openssl_test_vectors[i];
        printf("测试向量 %zu: ", i + 1);
        
        // 验证密钥转换
        int key_result = hex_to_bytes(test->key_hex, key, test->key_len);
        if (key_result != (int)test->key_len) {{
            printf("密钥转换失败 (实际=%d, 预期=%zu) ❌\\n", key_result, test->key_len);
            continue;
        }}
        
        // 验证明文转换
        int plaintext_result = hex_to_bytes(test->plaintext_hex, plaintext, test->text_len);
        if (plaintext_result != (int)test->text_len) {{
            printf("明文转换失败 (实际=%d, 预期=%zu) ❌\\n", plaintext_result, test->text_len);
            continue;
        }}
        
        // 验证预期密文转换
        int ciphertext_result = hex_to_bytes(test->expected_ciphertext_hex, expected_ciphertext, test->text_len);
        if (ciphertext_result != (int)test->text_len) {{
            printf("预期密文转换失败 (实际=%d, 预期=%zu) ❌\\n", ciphertext_result, test->text_len);
            continue;
        }}
        
        // 初始化加密密钥
        if (AES_set_encrypt_key(key, test->key_len * 8, &aes_key) != 0) {{
            printf("密钥设置失败 ❌\\n");
            continue;
        }}
        
        // 明文填充
        pkcs7_pad(plaintext, test->text_len, padded_plaintext, &padded_len);
        
        // 分块加密
        for (size_t j = 0; j < padded_len; j += AES_BLOCK_SIZE) {{
            AES_ecb_encrypt(padded_plaintext + j, ciphertext + j, &aes_key, AES_ENCRYPT);
        }}
        
        // 验证结果
        if (memcmp(ciphertext, expected_ciphertext, test->text_len) == 0) {{
            printf("通过 ✅\\n");
            tests_passed++;
        }} else {{
            printf("失败 ❌\\n");
            bytes_to_hex(ciphertext, test->text_len, ciphertext_hex);
            printf("  实际密文: %s\\n", ciphertext_hex);
            printf("  预期密文: %s\\n", test->expected_ciphertext_hex);
        }}
    }}
    
    printf("===== 测试完成: %d/%zu 通过 =====\\n", tests_passed, TEST_VECTOR_COUNT);
    return tests_passed == TEST_VECTOR_COUNT ? 0 : 1;
}}
"""

    @retry(stop_max_attempt_number=3, wait_fixed=2000)
    def _generate_c_code(self):
        """生成代码，强制使用预定义的正确转换函数"""
        forced_instructions = """
        必须严格遵守以下要求，否则代码无效：
        1. 必须使用提供的hex_to_bytes和bytes_to_hex函数，不得修改
        2. 测试向量中的key_hex长度必须是key_len的2倍（每个字节2个十六进制字符）
        3. main函数中必须先读取十六进制字符串到char数组，再转换为unsigned char密钥
        4. 禁止直接使用unsigned char数组接收用户输入的十六进制密钥
        """
        
        base_prompt = f"""仅输出纯C代码，实现AES-ECB加密功能，必须包含：

1. 头文件：
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <ctype.h>
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

2. 必须使用提供的十六进制转换函数（已包含在测试代码中）
3. 必须包含的函数：
- pkcs7_pad：PKCS#7填充（块大小16字节）
- main：程序入口，支持--test参数和交互模式

4. 交互模式要求：
- 读取密钥：char hex_key[65]; fgets(hex_key, sizeof(hex_key), stdin);
- 转换密钥：hex_to_bytes(hex_key, key, 32);
- 所有提示信息必须是中文

5. 必须完整包含以下测试代码：
{self.openssl_test_code}

{forced_instructions}

只输出完整可编译的C代码，不要任何注释和多余内容！"""

        # 错误反馈：明确指出转换函数问题
        error_feedback = "hex_to_bytes函数实现错误，必须使用提供的版本，通过位运算而非sscanf进行转换！"

        messages = [
            {"role": "system", "content": base_prompt},
            {"role": "user", "content": f"生成代码，修复错误：{error_feedback}。必须使用提供的十六进制转换函数！"}
        ]

        payload = {
            "model": "gpt-4o-mini",
            "messages": messages,
            "temperature": 0.0,
            "max_tokens": 2000,
            "n": 1
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
            
            if response.status_code != 200:
                return "", f"API请求失败 (状态码: {response.status_code})"
            
            response_data = response.json()
            
            if "error" in response_data:
                return "", f"API错误: {response_data['error']['message']}"
                
            raw_code = response_data["choices"][0]["message"]["content"]
             # 1. 彻底移除所有Markdown格式标记
            raw_code = re.sub(r'^```c\n', '', raw_code)  # 移除开头的```c
            raw_code = re.sub(r'\n```$', '', raw_code)   # 移除结尾的```
            raw_code = re.sub(r'^```\n', '', raw_code)   # 处理可能的其他格式
            raw_code = re.sub(r'```$', '', raw_code)
            
            # 2. 移除AI可能生成的不完整函数定义
            raw_code = re.sub(r'static unsigned char hex_char_to_val.*?\n}\n', '', raw_code, flags=re.DOTALL)
            raw_code = re.sub(r'int hex_to_bytes.*?\{.*?\}', '', raw_code, flags=re.DOTALL)
            raw_code = re.sub(r'void bytes_to_hex.*?\{.*?\}', '', raw_code, flags=re.DOTALL)
            
            # 3. 强制插入完整的转换函数（放在代码最前面）
            clean_code = self.fixed_hex_functions + "\n" + raw_code
            
            # 4. 确保没有重复定义
            clean_code = re.sub(r'(static unsigned char hex_char_to_val.*?)\1', r'\1', clean_code, flags=re.DOTALL)
            
            # 强制替换为预定义的转换函数（彻底避免AI生成错误）
            clean_code = re.sub(
                r'int hex_to_bytes.*?\{.*?\}',  # 移除AI可能生成的错误函数
                '',
                raw_code,
                flags=re.DOTALL
            )
            clean_code = re.sub(
                r'void bytes_to_hex.*?\{.*?\}',  # 移除AI可能生成的错误函数
                '',
                clean_code,
                flags=re.DOTALL
            )
            #  确保main函数中密钥长度检查正确
            clean_code = clean_code.replace(
                'if (hex_to_bytes(hex_key, key, sizeof(key)) != sizeof(key)) {',
                'if (hex_to_bytes(hex_key, key, 32) != 32) {'
            )
            # 确保预定义的转换函数被正确包含
            if 'hex_char_to_val' not in clean_code:
                clean_code = self.fixed_hex_functions + clean_code

            # 确保main函数正确处理密钥输入
            if 'char hex_key[65];' not in clean_code:
                clean_code = clean_code.replace(
                    'unsigned char key[32];',
                    'unsigned char key[32];\nchar hex_key[65];'
                )
            
            # 确保使用正确的密钥转换流程
            clean_code = clean_code.replace(
                'fgets((char *)key, sizeof(key), stdin);',
                'fgets(hex_key, sizeof(hex_key), stdin);\nhex_key[strcspn(hex_key, "\\n")] = 0;'
            )
            
            # 确保调用hex_to_bytes转换密钥
            if 'hex_to_bytes(hex_key, key, 32);' not in clean_code:
                clean_code = clean_code.replace(
                    'AES_set_encrypt_key(key, 256, &aes_key);',
                    'if (hex_to_bytes(hex_key, key, 32) != 32) {\n'
                    '    fprintf(stderr, "错误：密钥格式无效\\n");\n'
                    '    return 1;\n'
                    '}\n'
                    'AES_set_encrypt_key(key, 256, &aes_key);'
                )

            self.generated_code = clean_code.strip()
            return self.generated_code, "代码生成成功"
        except Exception as e:
            return "", f"API错误: {str(e)}"

    def _run_tests(self, code=None):
        """运行测试验证"""
        c_code = code or self.generated_code
        if not c_code:
            return False, "无代码可测试"

        test_code_path = os.path.join(self.work_dir, "aes_ecb_test.c")
        with open(test_code_path, "w") as f:
            f.write(c_code)

        test_exec_path = os.path.join(self.work_dir, "aes_ecb_test")
        compile_cmd = f"gcc {test_code_path} -o {test_exec_path} -lcrypto -Wall"
        compile_result = subprocess.run(
            compile_cmd,
            shell=True,
            capture_output=True,
            text=True
        )
        if compile_result.returncode != 0:
            error_msg = f"编译失败: {compile_result.stderr}"
            self.last_error = error_msg
            return False, error_msg

        try:
            test_result = subprocess.run(
                [test_exec_path, "--test"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            output = test_result.stdout
            if "测试完成: 2/2 通过" in output:
                return True, "所有测试通过"
            else:
                return False, f"测试未通过: {output}\n错误: {test_result.stderr}"
                
        except Exception as e:
            return False, f"测试运行错误: {str(e)}"

    def _compile_and_run(self, code=None):
        c_code = code or self.generated_code
        if not c_code:
            return "无代码可编译"

        code_path = os.path.join(self.work_dir, "aes_ecb_encrypt.c")
        with open(code_path, "w") as f:
            f.write(c_code)

        exec_path = os.path.join(self.work_dir, "aes_ecb_encrypt")
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
        """主流程控制"""
        while self.retry_count < self.max_retry:
            self.retry_count += 1
            print(f"\n===== 第 {self.retry_count}/{self.max_retry} 次尝试 (AES-ECB) =====")

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

            print("\n正在运行测试验证...")
            test_passed, test_msg = self._run_tests(code)
            if not test_passed:
                print(f"❌ 测试失败: {test_msg}")
                if self.retry_count < self.max_retry and input("重试生成代码？(y/n): ").lower() != 'y':
                    return
                continue

            print(f"✅ {test_msg}")
            result = self._compile_and_run(code)
            if result == "运行成功":
                print("✅ 加密成功")
                return

            print(f"❌ 失败: {result}")
            if self.retry_count < self.max_retry and input("重试？(y/n): ").lower() != 'y':
                return

        print("⚠️ 已达最大重试次数")
    
