#include "des.h"

#define ENCRYPTION_ITERATION 16							  // DES算法迭代加密轮次
#define TEXT_LEN 64										  // 一次加密的数据长度
#define SECRET_KEY_LEN 64								  // 密钥长度，应该等于一次加密的数据长度
#define TEMP_SECRET_KEY_LEN 56							  // 生成子密钥过程中的中间密钥长度
#define SUB_SECRET_KEY_LEN 48							  // 子密钥的长度
#define array_len(array) sizeof(array) / sizeof(array[0]) // 获取数组的长度

// 每轮迭代中，向左循环移动的位数
static const unsigned int bit_circulation[ENCRYPTION_ITERATION] = {
	1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};

// 密钥置换表，将64位密钥置换压缩置换为56位中间密钥
static const unsigned int temp_secret_key_table[TEMP_SECRET_KEY_LEN] = {
	57, 49, 41, 33, 25, 17, 9, 1,
	58, 50, 42, 34, 26, 18, 10, 2,
	59, 51, 43, 35, 27, 19, 11, 3,
	60, 52, 44, 36, 63, 55, 47, 39,
	31, 23, 15, 7, 62, 54, 46, 38,
	30, 22, 14, 6, 61, 53, 45, 37,
	29, 21, 13, 5, 28, 20, 12, 4};

// 密钥置换表，56位中间密钥压缩位48位子密钥
static const unsigned int sub_secret_key_table[SUB_SECRET_KEY_LEN] = {
	14, 17, 11, 24, 1, 5, 3, 28,
	15, 6, 21, 10, 23, 19, 12, 4,
	26, 8, 16, 7, 27, 20, 13, 2,
	41, 52, 31, 37, 47, 55, 30, 40,
	51, 45, 33, 48, 44, 49, 39, 56,
	34, 53, 46, 42, 50, 36, 29, 32};

// 数据初始置换表，将数据进行重新排列
static const unsigned int initial_permutation_table[TEXT_LEN] = {
	58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
	62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
	57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
	61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7};

// 数据末置换表，将数据重新排列，其取值跟数据初始置换表有关
// 即数据如果只经过初始置换表和末置换表，数据不会发生任何改变
static const unsigned int final_permutation_table[TEXT_LEN] = {
	40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
	38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
	36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
	34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25};

// 数据扩展置换表，将数据从32位扩展为48位，与子密钥的长度一致
static const unsigned int extend_table[SUB_SECRET_KEY_LEN] = {
	32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11,
	12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21,
	22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1};

// S盒置换表，共有8个子盒子，每个子盒子都将6位输入压缩为4位
// 由于是由6位压缩为4位，则每个子盒子有 2^6 个元素，里面元素的最大值为 2^4-1
static const unsigned int sbox_table[8][64] = {
	{// S1盒子
	 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
	 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
	 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
	 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13},
	{// S2盒子
	 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
	 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
	 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
	 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9},
	{// S3盒子
	 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
	 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
	 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
	 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12},
	{// S4盒子
	 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
	 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
	 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
	 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14},
	{// S5盒子
	 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
	 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
	 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
	 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3},
	{// S6盒子
	 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
	 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
	 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
	 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13},
	{// S7盒子
	 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
	 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
	 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
	 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12},
	{// S8盒子
	 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
	 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
	 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
	 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}};

// P盒置换表
static const unsigned int pbox_table[TEXT_LEN / 2] = {
	16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
	2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25};

/**
 * @brief 输出 bitset 到屏幕
 * @param bitset_data	需要被输出的bitset，长度为模板
 * @return 无
 */
template <size_t N>
static void show_bitset(const bitset<N> &bitset_data)
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

/**
 * @brief 输出 数组 到屏幕
 * @param array_data	需要被输出的 array_data
 * @param array_len		需要被输出的 array_data 的长度
 * @return 无
 */
static void show_array(const unsigned int *array_data, const size_t array_len)
{
	for (size_t i = 0; i < array_len; i++)
	{
		cout << setw(2) << setfill('0') << array_data[i] << " ";
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

/**
 * @brief 根据当前轮次，生成子密钥
 * @param current_round	当前轮次
 * @param secret_key	密钥
 * @return 子密钥
 */
static bitset<SUB_SECRET_KEY_LEN> generate_sub_secret_key(const size_t &current_round, const bitset<SECRET_KEY_LEN> &secret_key)
{
	// 1. 根据置换表 temp_key_table ，对密钥进行压缩，密钥长度 SECRET_KEY_LEN -> TEMP_SECRET_KEY_LEN
	bitset<TEMP_SECRET_KEY_LEN> temp_secret_key; // 中间密钥，长度为 TEMP_SECRET_KEY_LEN
	for (size_t i = 0; i < temp_secret_key.size(); i++)
	{
		temp_secret_key[i] = secret_key[temp_secret_key_table[i] - 1];
	}

	// 2. 根据当前轮次，对中间密钥进行移位操作
	// 2.1. 存放移位前的中间密钥，等价于 temp_secret_key
	bitset<TEMP_SECRET_KEY_LEN> temp = temp_secret_key;

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
static void str_to_bitset(bitset<SECRET_KEY_LEN> &bitset_data, const char *str_data, const ssize_t str_data_len)
{
	for (size_t i = 0; i < bitset_data.size(); i++)
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

/**
 * @brief 从bitset类型转为字符串类型，用于密文转换
 * @param bitset_data	长度为SECRET_KEY_LEN，是密文长度
 * @param str_data		转换后的数据
 * @param str_data_len	转换后的数据的数据长度
 * @return 无
 */
static void bitset_to_str(const bitset<SECRET_KEY_LEN> &bitset_data, char *str_data, ssize_t str_data_len)
{
	memset(str_data, 0, str_data_len);
	for (size_t i = 0; i < bitset_data.size(); i++)
	{
		if (true == bitset_data[i])
		{
			*((unsigned char *)(str_data) + i / 8) |= (1 << (7 - i % 8));
		}
	}
}

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
							  const des_method method)
{
	bitset<SECRET_KEY_LEN> secret_key; // 密钥的位图形式
	bitset<TEXT_LEN> text;			   // 明文的位图形式

	// 将字符串形式的密钥、明文转为位图形式
	str_to_bitset(secret_key, secret_key_str, secret_key_str_len);
	str_to_bitset(text, plain_text_str, plain_text_str_len);

	// 1. 初始置换，将数据进行重新排列
	bitset<TEXT_LEN> ip_text;
	for (size_t i = 0; i < text.size(); i++)
	{
		ip_text[i] = text[initial_permutation_table[i] - 1];
	}

	// 2. 将数据划分为左右两部分
	bitset<TEXT_LEN / 2> left_text;	 // 数据左部分
	bitset<TEXT_LEN / 2> right_text; // 数据右部分
	for (size_t i = 0; i < TEXT_LEN / 2; i++)
	{
		left_text[i] = ip_text[i];
		right_text[i] = ip_text[i + TEXT_LEN / 2];
	}

	// 3. 迭代加密，每次加密都只加密左侧数据，加密完后左右数据互换，继续进行加密
	// 如果是解密，只需要将当前轮次倒转即可
	for (size_t i = 1; i <= ENCRYPTION_ITERATION; i++)
	{
		// 3.1. 获取迭代轮次，如果是解密就将迭代轮次倒转
		size_t current_round = i;
		if (des_decode == method)
		{
			current_round = ENCRYPTION_ITERATION - i + 1;
		}

		// 3.2. 生成48位的子密钥
		bitset<SUB_SECRET_KEY_LEN> sub_secret_key = generate_sub_secret_key(current_round, secret_key);

		// 3.3 扩展置换，将32位的右侧数据扩展为48位，与子密钥的长度保持一致
		bitset<SUB_SECRET_KEY_LEN> right_extend_text;
		for (size_t j = 0; j < right_extend_text.size(); j++)
		{
			right_extend_text[j] = right_text[extend_table[j] - 1];
		}

		// 3.4 将扩展后的右侧数据与子密钥进行异或操作
		right_extend_text ^= sub_secret_key;

		// 3.5 进行S盒压缩，每个S盒接受6位输入，返回4位输出，将48位数据重新压缩回32位
		bitset<TEXT_LEN / 2> right_compress_text;
		for (size_t j = 0; j < array_len(sbox_table); j++)
		{
			bitset<6> sbox_index; // sbox_index的索引，其值由6位输入调换顺序可得
			sbox_index[0] = right_extend_text[j * 6];
			sbox_index[1] = right_extend_text[j * 6 + 5];
			sbox_index[2] = right_extend_text[j * 6 + 1];
			sbox_index[3] = right_extend_text[j * 6 + 2];
			sbox_index[4] = right_extend_text[j * 6 + 3];
			sbox_index[5] = right_extend_text[j * 6 + 4];

			bitset<4> sbox_output(sbox_table[j][sbox_index.to_ulong()]); // 4位输出
			for (size_t k = 0; k < sbox_output.size(); k++)
			{
				right_compress_text[j * 4 + k] = sbox_output[k];
			}
		}

		// 3.6 进行P盒置换，对数据进行重新排序，得到加密左侧数据的实际密钥
		bitset<TEXT_LEN / 2> real_secret_key;
		for (size_t j = 0; j < real_secret_key.size(); j++)
		{
			real_secret_key[j] = right_compress_text[pbox_table[j] - 1];
		}

		// 3.7 加密左侧数据，进行异或操作
		left_text ^= real_secret_key;

		// 3.8 非最后一次迭代，交换左右侧数据，下轮迭代应该加密右侧数据
		// 最后一次迭代，不能交换数据，用于解密操作
		if (ENCRYPTION_ITERATION != i)
		{
			bitset<TEXT_LEN / 2> temp_text = left_text;
			left_text = right_text;
			right_text = temp_text;
		}
	}

	// 4. 合并左右数据
	bitset<TEXT_LEN> merge_text;
	for (size_t i = 0; i < TEXT_LEN / 2; i++)
	{
		merge_text[i] = left_text[i];
		merge_text[i + TEXT_LEN / 2] = right_text[i];
	}

	// 5. 末置换，将数据进行重新排列，得到最终加密的密文
	bitset<SECRET_KEY_LEN> cipher_text;
	for (size_t i = 0; i < text.size(); i++)
	{
		cipher_text[i] = merge_text[final_permutation_table[i] - 1];
	}

	// 6. 将密文由位图形式转为字符串
	bitset_to_str(cipher_text, cipher_text_str, cipher_text_str_len);
}
