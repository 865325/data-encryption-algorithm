all: main.cpp ./data-encryption-standard/des.cpp
	-@g++ main.cpp ./data-encryption-standard/des.cpp -I ./data-encryption-standard/
	-@./a.out -e plain_text cipher_text 12345678
	-@./a.out -d cipher_text new_plain_text 12345678