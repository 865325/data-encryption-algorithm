#include <iostream>
#include <stdlib.h>
#include <bitset>
#include <string.h>

using namespace std;

#define ENCRYPTION_ITERATION 16							  // DES算法迭代加密轮次
#define SECRET_KEY_LEN 64								  // 密钥长度，同时也是一次加密的数据长度
#define TEMP_SECRET_KEY_LEN 56							  // 生成子密钥过程中的中间密钥长度
#define SUB_SECRET_KEY_LEN 48							  // 子密钥的长度
#define array_len(array) sizeof(array) / sizeof(array[0]) // 获取数组的长度

/**
 * @brief 输出 bitset 到屏幕
 * @param bitset_data 需要被输出的bitset，长度为模板
 * @return 无
 */
template <size_t N>
void show_bitset(const bitset<N> &bitset_data)
{
	for (size_t i = 0; i < N; i++)
	{
		cout << bitset_data[i] << " ";
		if ((i + 1) % 8 == 0 && (i + 1) % 16 != 0)
		{
			cout << "| ";
		}
		if ((i + 1) % 16 == 0)
		{
			cout << endl;
		}
	}
	cout << endl;
}

// 每轮迭代中，向左循环移动的位数
const static unsigned char bit_circulation[ENCRYPTION_ITERATION] = {
	1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};

// 密钥置换表，将64位密钥置换压缩置换为56位中间密钥
const static unsigned char temp_secret_key_table[TEMP_SECRET_KEY_LEN] = {
	57, 49, 41, 33, 25, 17, 9, 1,
	58, 50, 42, 34, 26, 18, 10, 2,
	59, 51, 43, 35, 27, 19, 11, 3,
	60, 52, 44, 36, 63, 55, 47, 39,
	31, 23, 15, 7, 62, 54, 46, 38,
	30, 22, 14, 6, 61, 53, 45, 37,
	29, 21, 13, 5, 28, 20, 12, 4};

// 密钥置换表，56位中间密钥压缩位48位子密钥
const static unsigned char sub_secret_key_table[SUB_SECRET_KEY_LEN] = {
	14, 17, 11, 24, 1, 5, 3, 28,
	15, 6, 21, 10, 23, 19, 12, 4,
	26, 8, 16, 7, 27, 20, 13, 2,
	41, 52, 31, 37, 47, 55, 30, 40,
	51, 45, 33, 48, 44, 49, 39, 56,
	34, 53, 46, 42, 50, 36, 29, 32};

bitset<SUB_SECRET_KEY_LEN> get_sub_secret_key(const size_t &current_round, const bitset<SECRET_KEY_LEN> &secret_key)
{
	// 1. 根据置换表 temp_key_table ，对密钥进行压缩，密钥长度 SECRET_KEY_LEN -> TEMP_SECRET_KEY_LEN
	bitset<TEMP_SECRET_KEY_LEN> temp_secret_key; // 中间密钥，长度为 TEMP_SECRET_KEY_LEN
	for (size_t i = 0; i < temp_secret_key.size(); i++)
	{
		temp_secret_key[i] = secret_key[temp_secret_key_table[i] - 1];
	}

	// 2. 根据当前轮次，对中间密钥进行移位操作
	// 2.1. 存放移位前的中间密钥，等价于 temp_secret_key
	bitset<TEMP_SECRET_KEY_LEN> temp;
	for (size_t i = 0; i < temp.size(); i++)
	{
		temp[i] = temp_secret_key[i];
	}

	// 2.2. 存放当前轮次共需移位的量
	unsigned int total_bit_circulation = 0;
	for (size_t i = 0; i < current_round && i < array_len(bit_circulation); i++)
	{
		total_bit_circulation += bit_circulation[i];
	}

	// 2.3 循环移位，分为左右两部分分别进行循环移位，左移
	for (size_t i = 0; i < temp_secret_key.size() / 2; i++)
	{
		// 左半部分移位
		temp_secret_key[i] = temp[(i + total_bit_circulation) % (temp_secret_key.size() / 2)];
		// 右半部分移位
		temp_secret_key[i + temp_secret_key.size() / 2] = temp[(i + total_bit_circulation) % (temp_secret_key.size() / 2) + temp_secret_key.size() / 2];
	}

	// 3. 根据置换表 sub_secret_key_table ，对密钥进行压缩，密钥长度 TEMP_SECRET_KEY_LEN -> SUB_SECRET_KEY_LEN
	bitset<SUB_SECRET_KEY_LEN> sub_secret_key; // 子密钥，长度为 SUB_SECRET_KEY_LEN
	for (size_t i = 0; i < sub_secret_key.size(); i++)
	{
		sub_secret_key[i] = temp_secret_key[sub_secret_key_table[i] - 1];
	}
	return sub_secret_key;
}

/**
 * @brief 从字符串类型转为bitset类型，用于密钥转换和明文转换
 * @param bitset_data	长度为SECRET_KEY_LEN，是密钥的长度或明文长度
 * @param str_data		转换前的数据
 * @param str_data_len	转换前的数据的数据长度
 * @return 无
 */
void str_to_bitset(bitset<SECRET_KEY_LEN> &bitset_data, const char *str_data, const ssize_t &str_data_len)
{
	for (int i = 0; i < bitset_data.size(); i++)
	{
		if (i < str_data_len * 8)
		{
			unsigned char temp = *((unsigned char *)str_data + i / 8);
			if (0 != (temp & (1 << (7 - i % 8))))
			{
				bitset_data[i] = true;
			}
			else
			{
				bitset_data[i] = false;
			}
		}
		else
		{
			bitset_data[i] = false;
		}
	}
}

void data_encryption_standard(const char *secret_key_str)
{
	bitset<SECRET_KEY_LEN> secret_key;	// 密钥的位图形式

	// 将字符串形式的密钥转为位图形式
	str_to_bitset(secret_key, secret_key_str, strlen(secret_key_str));
}

int main()
{
	data_encryption_standard("12345678");
}
