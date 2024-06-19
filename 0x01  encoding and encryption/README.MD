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



异或加密也可以进行拓展，比如使用16进制数组轮流加密，这样能够增加爆破难度。

示例

```python
def xor_encrypt_bytes(bytes_array, key):
    encrypted_data = bytearray()
    key_index = 0
    for byte in bytes_array:
        encrypted_byte = byte ^ key[key_index]
        encrypted_data.append(encrypted_byte)
        key_index = (key_index + 1) % len(key)

    return encrypted_data
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

### RC4 加密 - 方法 2

未公开的 Windows NTAPI`SystemFunction032`提供了更快、更小的 RC4 算法实现。有关此 API 的其他信息可以在[此 Wine API 页面](https://source.winehq.org/WineAPI/SystemFunction032.html)上找到。

文档页面指出该函数`SystemFunction032`接受两个类型的参数`USTRING`。

```c++
 NTSTATUS SystemFunction032
 (
  struct ustring*       data,
  const struct ustring* key
 )
```

`USTRING`是一个未公开结构，可以在[wine/crypt.h](https://github.com/wine-mirror/wine/blob/master/dlls/advapi32/crypt.h#L94)中找到结构定义。结构如下图所示。

```c++
typedef struct
{
	DWORD	Length;         // Size of the data to encrypt/decrypt
	DWORD	MaximumLength;  // Max size of the data to encrypt/decrypt, although often its the same as Length (USTRING.Length = USTRING.MaximumLength = X)
	PVOID	Buffer;         // The base address of the data to encrypt/decrypt

} USTRING;
```

既然`知道了`USTRING结构体，`SystemFunction032`就可以使用该函数了。

#### 检索 SystemFunction032 的地址

要使用`SystemFunction032`，必须首先检索其地址。由于`SystemFunction032`是从导出的`advapi32.dll`，因此必须使用 DLL 将其加载到进程中`LoadLibrary`。函数调用的返回值可以直接在`GetProcAddress`.

一旦成功检索到 的地址，就应该将其类型转换为与先前引用的[Wine API 页面](https://source.winehq.org/WineAPI/SystemFunction032.html)`SystemFunction032`上找到的定义相匹配的函数指针。但是，返回的地址可以直接从 进行转换。这一切都在下面的代码片段中得到了证明。

`GetProcAddress`

```c++
fnSystemFunction032 SystemFunction032 = (fnSystemFunction032) GetProcAddress(LoadLibraryA("Advapi32"), "SystemFunction032");
```

`SystemFunction032`函数指针定义为`fnSystemFunction032`，数据类型如下所示。

```c++
typedef NTSTATUS(NTAPI* fnSystemFunction032)(
	struct USTRING* Data,   // Structure of type USTRING that holds information about the buffer to encrypt / decrypt 
	struct USTRING* Key     // Structure of type USTRING that holds information about the key used while encryption / decryption
);
```

demo

```c++
typedef struct
{
	DWORD	Length;
	DWORD	MaximumLength;
	PVOID	Buffer;

} USTRING;

typedef NTSTATUS(NTAPI* fnSystemFunction032)(
	struct USTRING* Data,
	struct USTRING* Key
);

BOOL Rc4EncryptionViaSystemFunc032(IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize) {

	NTSTATUS STATUS	= NULL;
	
	USTRING Data = { 
		.Buffer         = pPayloadData,
		.Length         = sPayloadSize,
		.MaximumLength  = sPayloadSize
	};

	USTRING	Key = {
		.Buffer         = pRc4Key,
		.Length         = dwRc4KeySize,
		.MaximumLength  = dwRc4KeySize
	},

	fnSystemFunction032 SystemFunction032 = (fnSystemFunction032)GetProcAddress(LoadLibraryA("Advapi32"), "SystemFunction032");

	if ((STATUS = SystemFunction032(&Data, &Key)) != 0x0) {
		printf("[!] SystemFunction032 FAILED With Error: 0x%0.8X \n", STATUS);
		return FALSE;
	}

	return TRUE;
}
```



# IPv4/IPv6 混淆

IPv4/IPv6Fuscation 是一种混淆技术，其中 shellcode 的字节被转换为 IPv4 或 IPv6 字符串。

- **IPv4混淆** - 由于 IPv4 地址由 4 个八位位组组成，因此 IPv4 混淆使用 4 个字节生成单个 IPv4 字符串，每个字节代表一个八位位组。获取当前为十六进制的每个字节并将其转换为十进制格式以获得一个八位字节。如，FC十进制为 252，FC 48 83 E4将为252.72.131.228
- **IPv6混淆** - 这与 IPv4混淆是类似的逻辑，但每个 IP 地址不使用 4 个字节，而是使用 16 个字节来生成一个 IPv6 地址。此外，IPv6 地址不需要将字节转换为十进制。以FC 48 83 E4 F0 E8 C0 00 00 00 41 51 41 50 52 51为例，它将是`FC48:83E4:F0E8:C000:0000:4151:4150:5251`.

### IPv4

生成 IPv4 地址需要 4 个字节，因此 shellcode 必须是 4 的倍数。如果不满足该要求，可以创建一个填充 shellcode 的函数。

`GenerateIpv4`是一个辅助函数，需要 4 个 shellcode 字节并用于`sprintf`生成 IPv4 地址。

```c++
// 这个函数取4个字节并且把他们输出为IPv4格式
char* GenerateIpv4(int a, int b, int c, int d) {
	unsigned char Output [32];
  
	sprintf(Output, "%d.%d.%d.%d", a, b, c, d);
	return (char*)Output;
}


// 生成shellcode的IPv4格式
BOOL GenerateIpv4Output(unsigned char* pShellcode, SIZE_T ShellcodeSize) {
	if (pShellcode == NULL || ShellcodeSize == NULL || ShellcodeSize % 4 != 0){
		return FALSE;
	}
	printf("char* Ipv4Array[%d] = { \n\t", (int)(ShellcodeSize / 4));

	int c = 4, counter = 0;
	char* IP = NULL;

	for (int i = 0; i < ShellcodeSize; i++) {
		if (c == 4) {
			counter++;
			IP = GenerateIpv4(pShellcode[i], pShellcode[i + 1], pShellcode[i + 2], pShellcode[i + 3]);

			if (i == ShellcodeSize - 4) {
				printf("\"%s\"", IP);
				break;
			}
			else {
				printf("\"%s\", ", IP);
			}

			c = 1;

			if (counter % 8 == 0) {
				printf("\n\t");
			}
		}
		else {
			c++;
		}
	}
	printf("\n};\n\n");
	return TRUE;
}
```



### IPv6

使用 IPv6混淆时，shellcode 应为 16 的倍数。同样，如果不满足该要求，则可以创建一个填充 shellcode 的函数。

```c++
char* GenerateIpv6(int a, int b, int c, int d, int e, int f, int g, int h, int i, int j, int k, int l, int m, int n, int o, int p) {
	char Output0[32], Output1[32], Output2[32], Output3[32];
	char result[128];

	sprintf(Output0, "%0.2X%0.2X:%0.2X%0.2X", a, b, c, d);

	sprintf(Output1, "%0.2X%0.2X:%0.2X%0.2X", e, f, g, h);

	sprintf(Output2, "%0.2X%0.2X:%0.2X%0.2X", i, j, k, l);

	sprintf(Output3, "%0.2X%0.2X:%0.2X%0.2X", m, n, o, p);

	sprintf(result, "%s:%s:%s:%s", Output0, Output1, Output2, Output3);

	return (char*)result;
}


BOOL GenerateIpv6Output(unsigned char* pShellcode, SIZE_T ShellcodeSize) {
	if (pShellcode == NULL || ShellcodeSize == NULL || ShellcodeSize % 16 != 0){
		return FALSE;
	}
	printf("char* Ipv6Array [%d] = { \n\t", (int)(ShellcodeSize / 16));

	int c = 16, counter = 0;
	char* IP = NULL;
	
	for (int i = 0; i < ShellcodeSize; i++) {
		if (c == 16) {
			counter++;
			IP = GenerateIpv6(
				pShellcode[i], pShellcode[i + 1], pShellcode[i + 2], pShellcode[i + 3],
				pShellcode[i + 4], pShellcode[i + 5], pShellcode[i + 6], pShellcode[i + 7],
				pShellcode[i + 8], pShellcode[i + 9], pShellcode[i + 10], pShellcode[i + 11],
				pShellcode[i + 12], pShellcode[i + 13], pShellcode[i + 14], pShellcode[i + 15]
			);
			if (i == ShellcodeSize - 16) {
				printf("\"%s\"", IP);
				break;
			}
			else {
				printf("\"%s\", ", IP);
			}
			c = 1;

			if (counter % 3 == 0) {
				printf("\n\t");
			}
		}
		else {
			c++;
		}
	}
	printf("\n};\n\n");
	return TRUE;
}
```



一旦混淆的payload逃避了静态检测，就需要对其进行反混淆才能执行。反混淆过程将反转混淆过程，允许 IP 地址生成字节。执行反混淆需要满足以下条件：

- **IPv4 反混淆**- 这需要使用 NTAPI [RtlIpv4StringToAddressA](https://learn.microsoft.com/en-us/windows/win32/api/ip2string/nf-ip2string-rtlipv4stringtoaddressa)。它将 IPv4 地址的字符串表示形式转换为二进制 IPv4 地址。
- **IPv6 反混淆**- 与之前的功能类似，IPv6 反混淆将需要使用另一个 NTAPI [RtlIpv6StringToAddressA](https://learn.microsoft.com/en-us/windows/win32/api/ip2string/nf-ip2string-rtlipv6stringtoaddressa)。该函数将 IPv6 地址转换为二进制 IPv6 地址。

### IPv4反混淆

代码示例

```c++
typedef NTSTATUS (NTAPI* fnRtlIpv4StringToAddressA)(
	PCSTR		S,
	BOOLEAN		Strict,
	PCSTR*		Terminator,
   	PVOID		Addr
);

BOOL Ipv4Deobfuscation(IN CHAR* Ipv4Array[], IN SIZE_T NmbrOfElements, OUT PBYTE* ppDAddress, OUT SIZE_T* pDSize) {

	PBYTE           pBuffer                 = NULL, 
                    TmpBuffer               = NULL;

	SIZE_T          sBuffSize               = NULL;

	PCSTR           Terminator              = NULL;

	NTSTATUS        STATUS                  = NULL;

	// Getting RtlIpv4StringToAddressA address from ntdll.dll
	fnRtlIpv4StringToAddressA pRtlIpv4StringToAddressA = (fnRtlIpv4StringToAddressA)GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "RtlIpv4StringToAddressA");
	if (pRtlIpv4StringToAddressA == NULL){
		printf("[!] GetProcAddress Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Getting the real size of the shellcode which is the number of IPv4 addresses * 4
	sBuffSize = NmbrOfElements * 4;

	// Allocating memory which will hold the deobfuscated shellcode
	pBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, sBuffSize);
	if (pBuffer == NULL){
		printf("[!] HeapAlloc Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	
	// Setting TmpBuffer to be equal to pBuffer
	TmpBuffer = pBuffer;

	// Loop through all the IPv4 addresses saved in Ipv4Array
	for (int i = 0; i < NmbrOfElements; i++) {

		// Deobfuscating one IPv4 address at a time
		// Ipv4Array[i] is a single ipv4 address from the array Ipv4Array
		if ((STATUS = pRtlIpv4StringToAddressA(Ipv4Array[i], FALSE, &Terminator, TmpBuffer)) != 0x0) {
			// if it failed
			printf("[!] RtlIpv4StringToAddressA Failed At [%s] With Error 0x%0.8X", Ipv4Array[i], STATUS);
			return FALSE;
		}

		// 4 bytes are written to TmpBuffer at a time
		// Therefore Tmpbuffer will be incremented by 4 to store the upcoming 4 bytes
		TmpBuffer = (PBYTE)(TmpBuffer + 4);

	}

	// Save the base address & size of the deobfuscated payload
	*ppDAddress     = pBuffer;
	*pDSize         = sBuffSize;

	return TRUE;
}
```

### IPv6反混淆

代码示例

```c++
typedef NTSTATUS(NTAPI* fnRtlIpv6StringToAddressA)(
	PCSTR		S,
	PCSTR*		Terminator,
	PVOID		Addr
);

BOOL Ipv6Deobfuscation(IN CHAR* Ipv6Array[], IN SIZE_T NmbrOfElements, OUT PBYTE* ppDAddress, OUT SIZE_T* pDSize) {

	PBYTE           pBuffer                 = NULL, 
                    TmpBuffer               = NULL;

	SIZE_T          sBuffSize               = NULL;

	PCSTR           Terminator              = NULL;

	NTSTATUS        STATUS                  = NULL;

	// Getting RtlIpv6StringToAddressA address from ntdll.dll
	fnRtlIpv6StringToAddressA pRtlIpv6StringToAddressA = (fnRtlIpv6StringToAddressA)GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "RtlIpv6StringToAddressA");
	if (pRtlIpv6StringToAddressA == NULL) {
		printf("[!] GetProcAddress Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Getting the real size of the shellcode which is the number of IPv6 addresses * 16
	sBuffSize = NmbrOfElements * 16;


	// Allocating memory which will hold the deobfuscated shellcode
	pBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, sBuffSize);
	if (pBuffer == NULL) {
		printf("[!] HeapAlloc Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	TmpBuffer = pBuffer;

	// Loop through all the IPv6 addresses saved in Ipv6Array
	for (int i = 0; i < NmbrOfElements; i++) {

		// Deobfuscating one IPv6 address at a time
		// Ipv6Array[i] is a single IPv6 address from the array Ipv6Array
		if ((STATUS = pRtlIpv6StringToAddressA(Ipv6Array[i], &Terminator, TmpBuffer)) != 0x0) {
			// if it failed
			printf("[!] RtlIpv6StringToAddressA Failed At [%s] With Error 0x%0.8X", Ipv6Array[i], STATUS);
			return FALSE;
		}

		// 16 bytes are written to TmpBuffer at a time
		// Therefore Tmpbuffer will be incremented by 16 to store the upcoming 16 bytes
		TmpBuffer = (PBYTE)(TmpBuffer + 16);

	}

	// Save the base address & size of the deobfuscated payload
	*ppDAddress  = pBuffer;
	*pDSize      = sBuffSize;

	return TRUE;

}
```

