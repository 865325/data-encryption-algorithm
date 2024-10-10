#include <iostream>
#include <stdlib.h>
#include <bitset>
#include <string.h>
#include <iomanip>

using namespace std;

// 调用des方法，加密或者解密
enum des_method
{
	des_encode,
	des_decode
};

/**
 * @brief des算法进行加密及解密
 * @param secret_key_str		密钥
 * @param secret_key_str_len	密钥长度
 * @param plain_text_str		明文
 * @param plain_text_str_len	明文长度
 * @param cipher_text_str		密文
 * @param cipher_text_str_len	密文长度
 * @param method				加密，或者解密
 * @return 无
 */
void data_encryption_standard(const char *secret_key_str, const size_t secret_key_str_len, const char *plain_text_str,
							  const size_t plain_text_str_len, char *cipher_text_str, const size_t cipher_text_str_len,
							  const des_method method);
