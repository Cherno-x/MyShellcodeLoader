# Base64

Base64是常见的编码方式，是一种将二进制数据编码为可打印字符的方法，通常用于在文本环境中传输或存储二进制数据，比如在电子邮件中传输二进制文件、在网页中嵌入图片等场景。

Base64 编码使用 64 个 ASCII 字符（A-Z、a-z、0-9 和 "+"、"/" 两个特殊字符）来表示二进制数据，每个字符表示 6 位二进制数据。由于 2^6 = 64，所以每 3 个字节的二进制数据可以编码成 4 个 Base64 字符。

Base64 编码的基本流程如下：

1. 将待编码的数据划分成每 3 个字节一组的块。
2. 将每个字节拆分成两部分，高位和低位。
3. 将每组 3 个字节（24 位）转换成 4 个 Base64 字符。
4. 如果原始数据的字节数不是 3 的倍数，需要在末尾补充 0，然后在编码结果中用 "=" 补全。

Base64 解码则是编码过程的逆向过程，将 Base64 字符串转换回原始的二进制数据。

### python编码

```python
import base64

data = b'shellcode'
encoded_data = base64.b64encode(data)
print("Base64 编码后的数据:", encoded_data.decode()) 
```



### c++解码

```c++
int DecodeBase64( const BYTE * src, unsigned int srcLen, char * dst, unsigned int dstLen ) {

	DWORD outLen;
	BOOL fRet;

	outLen = dstLen;
	fRet = CryptStringToBinary( (LPCSTR) src, srcLen, CRYPT_STRING_BASE64, (BYTE * )dst, &outLen, NULL, NULL);
	
	if (!fRet) outLen = 0;  // failed
	
	return( outLen );
}
```





# AES

AES（Advanced Encryption Standard）是一种对称加密算法，它是目前使用最广泛的对称加密算法之一。对称加密算法使用相同的密钥进行加密和解密，因此在安全性和效率上通常比非对称加密算法更高效。

AES 加密的基本步骤：

1. **密钥生成**：选择一个适当长度的密钥。AES支持多种密钥长度，包括128位、192位和256位。

2. **初始轮密钥生成**：通过密钥扩展算法，根据初始密钥生成一系列轮密钥，用于加密轮中的每一轮。

3. **轮密钥加**：将明文与第一轮密钥进行按位异或操作。

4. **轮**：执行多轮的加密操作，每一轮都包括四个步骤：SubBytes、ShiftRows、MixColumns 和 AddRoundKey。这些步骤的具体操作会对明文进行不同的置换和替换操作，结合当前轮的轮密钥进行处理。

5. **最后一轮**：最后一轮不包括 MixColumns 步骤，只执行 SubBytes、ShiftRows 和 AddRoundKey。

6. **密文输出**：最后一轮完成后，得到的结果就是加密后的密文。

解密过程与加密过程类似，只是轮密钥的应用顺序相反，并且在解密时不需要进行密钥扩展。

在示例代码中使用了第三方库来实现AES加密，当然，也可以自实现。

### python加密函数

PyCryptodome 是 Python 的一个密码学工具包，提供了对称加密、非对称加密、哈希函数等密码学功能的实现。

```python
import sys
from Crypto.Cipher import AES
from os import urandom
import hashlib

KEY = urandom(16)

def pad(s):
	return s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size)

def aesenc(plaintext, key):

	k = hashlib.sha256(key).digest()
	iv = 16 * '\x00'
	plaintext = pad(plaintext)
	cipher = AES.new(k, AES.MODE_CBC, iv)

	return cipher.encrypt(bytes(plaintext))


try:
    plaintext = open(sys.argv[1], "r").read()
except:
    print("File argument needed! %s <raw payload file>" % sys.argv[0])
    sys.exit()

ciphertext = aesenc(plaintext, KEY)
print('AESkey[] = { 0x' + ', 0x'.join(hex(ord(x))[2:] for x in KEY) + ' };')
print('payload[] = { 0x' + ', 0x'.join(hex(ord(x))[2:] for x in ciphertext) + ' };')

```



#### C++解密函数

`#include <wincrypt.h>` 是一个C/C++程序中用于引入 Windows Cryptography API 的头文件。Windows Cryptography API（简称CryptoAPI）提供了一组函数和数据结构，用于实现加密、解密、哈希和证书管理等密码学操作。在程序中使用 CryptoAPI，通常需要链接到 `Advapi32.lib`，这可以通过在程序中添加 `#pragma comment(lib, "Advapi32.lib")` 来实现。

```c++
int AESDecrypt(char * payload, unsigned int payload_len, char * key, size_t keylen) {
        HCRYPTPROV hProv;
        HCRYPTHASH hHash;
        HCRYPTKEY hKey;

        if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)){
                return -1;
        }
        if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)){
                return -1;
        }
        if (!CryptHashData(hHash, (BYTE*)key, (DWORD)keylen, 0)){
                return -1;              
        }
        if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0,&hKey)){
                return -1;
        }
        
        if (!CryptDecrypt(hKey, (HCRYPTHASH) NULL, 0, 0, payload, &payload_len)){
                return -1;
        }
        
        CryptReleaseContext(hProv, 0);
        CryptDestroyHash(hHash);
        CryptDestroyKey(hKey);
        
        return 0;
}

```



# XOR

异或加密：异或运算（XOR，Exclusive OR）是一种逻辑运算符，它在两个操作数中，当且仅当其中一个操作数为真时返回真。如果两个操作数都为真或都为假，则返回假。

### python加密

```python
def XorEncrypt(shellcode):
    key = 0xcb
    encrypt_shellcode = ''.join([chr(ord(char)^key)for char in shellcode])
    return encrypt_shellcode

shellcode = "";

encrypt_shellcode = XorEncrypt(shellcode)

print("unsigned char shellcode[] = \"",''.join(f'\\x{ord(char):02x}'for char in encrypt_shellcode),"\"")
```

### c++解密

```c++
void XOR(char * data, size_t data_len, char * key, size_t key_len) {
	int j;
	
	j = 0;
	for (int i = 0; i < data_len; i++) {
		if (j == key_len - 1) j = 0;

		data[i] = data[i] ^ key[j];
		j++;
	}
}
```



# RC4

RC4（Rivest Cipher 4）是一种流密码算法，它将明文与密钥流按位进行异或运算来实现加密和解密。密钥流是由一个伪随机生成器生成的伪随机序列，这个序列是根据密钥生成的，所以密钥的选择对加密的安全性至关重要。

RC4 算法相对于其他对称加密算法来说，实现相对简单，加解密速度也很快。

### C++加解密

```c++
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct rc4_state
{
    int x, y, m[256];
};

void rc4_setup(struct rc4_state* s, unsigned char* key, int length);
void rc4_crypt(struct rc4_state* s, unsigned char* data, int length);

void rc4_setup(struct rc4_state* s, unsigned char* key, int length)
{
    int i, j, k, * m, a;

    s->x = 0;
    s->y = 0;
    m = s->m;

    for (i = 0; i < 256; i++)
    {
        m[i] = i;
    }

    j = k = 0;

    for (i = 0; i < 256; i++)
    {
        a = m[i];
        j = (unsigned char)(j + a + key[k]);
        m[i] = m[j]; m[j] = a;
        if (++k >= length) k = 0;
    }
}

void rc4_crypt(struct rc4_state* s, unsigned char* data, int length)
{
    int i, x, y, * m, a, b;

    x = s->x;
    y = s->y;
    m = s->m;

    for (i = 0; i < length; i++)
    {
        x = (unsigned char)(x + 1); a = m[x];
        y = (unsigned char)(y + a);
        m[x] = b = m[y];
        m[y] = a;
        data[i] ^= m[(unsigned char)(a + b)];
    }

    s->x = x;
    s->y = y;
}

int main()
{
    
    unsigned char key[] = { 'c', 'a', 'i', 'g', 'o', 'u', '1', '1' };
    unsigned char shellcode[] = "";


    struct rc4_state* s;
    s = (struct rc4_state*)malloc(sizeof(struct rc4_state));

    printf("key : %s\n", key);
    //printf("raw : %s\n", shellcode);

    rc4_setup(s, key, sizeof(key) - 1);

    rc4_crypt(s, shellcode, sizeof(shellcode) - 1);

    printf("encrypted  : ");
    for (int i = 0; i < sizeof(shellcode) - 1; i++) {
        printf("\\x%02x", shellcode[i]);
    }
    printf("\n");


    free(s);


    

    return 0;
}

```

