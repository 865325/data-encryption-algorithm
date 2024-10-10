#include <iostream>
#include <fstream>
#include "des.h"

using namespace std;

void des(const char *met, const char *input_file_name, const char *output_file_name, const char *secret_key)
{
	des_method method;
	if (0 == strcmp(met, "-e"))
	{
		method = des_encode;
	}
	else if (0 == strcmp(met, "-d"))
	{
		method = des_decode;
	}
	else
	{
		cout << "可运行程序，加密或者解密(-e or -d) 输入文件 输出文件 密钥" << endl;
		cout << "./a.out -e|-d input_file_name output_file_name secret_key" << endl;
		exit(EXIT_FAILURE);
	}

	ifstream input_file(input_file_name, ios::binary);
	ofstream output_file(output_file_name, ios::binary);

	if (!input_file || !output_file)
	{
		exit(EXIT_FAILURE);
	}

	char plain_text[8];
	char cipher_text[8];
	streamsize bytes_read;
	while (1)
	{
		memset(plain_text, 0, sizeof(plain_text));
		bytes_read = input_file.readsome(plain_text, sizeof(plain_text));

		if (bytes_read <= 0)
		{
			break;
		}
		if (8 == bytes_read)
		{
			data_encryption_standard(secret_key, strlen(secret_key), plain_text, sizeof(plain_text),
									 cipher_text, sizeof(cipher_text), method);
		}
		// 不满八个字节，直接拷贝
		else
		{
			memcpy(cipher_text, plain_text, sizeof(cipher_text));
		}
		output_file.write(cipher_text, bytes_read);
	}

	input_file.close();
	output_file.close();
}

int main(int argc, char *argv[])
{
	if (argc < 5)
	{
		cout << "可运行程序，加密或者解密(-e or -d) 输入文件 输出文件 密钥" << endl;
		cout << "./a.out -e|-d input_file_name output_file_name secret_key" << endl;
		exit(EXIT_FAILURE);
	}

	des(argv[1], argv[2], argv[3], argv[4]);
}
