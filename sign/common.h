/*
 * Comman macro, constant, typedef, external variable declaration and function declaration
 *
 * Date:2016-01-22
 *
 * Author:4056 Group
 */


#ifndef ____COMMON_H____
#define ____COMMON_H____

#include <stdbool.h>
#include <stdint.h>


// 版本信息
#define VERSION 	 			"1.3.1.0"

// 版权信息
#define COPYRIGHT 	 		"Copyright (C) Feb.2016 EastSoft Inc."

// 帮助信息
#define USAGE  "\
\n\
Infomation:\n\
  -h, --help            Show this message.\n\
  -v, --version         Print the program version.\n\
\n\
Configuration:\n\
  -l, --fraglen         Set the length of hash-updating fragmentation.\n\
\n\
Data:\n\
  -f, --file            File to be operated.\n\
\n\
Operation:\n\
  -s, --sign            Signing, mutex with \"-r, --verify\", effective for all choosen hashing type.\n\
  -r, --verify          Verifying, mutex with \"-s, --sign\", effective for just one choosen hashing type.\n\
  -k, --key             Filename of private key(for Singing) or public key(for Verifying), compulsory for each.\n\
  -g, --signature       Signature file name, valid and compulsory for Verifying.\n\
\n\
Hashing type Selection: (All will be choosen if no choise be done. But one type and only should be choosen if \"-r, --verify\" is selected.)\n\
  --md2\n\
  --md4\n\
  --md5\n\
  --ripemd160\n\
  --gosthash94\n\
  --sha1\n\
  --sha224\n\
  --sha256\n\
  --sha384\n\
  --sha512\n\
  --sha3-224\n\
  --sha3-256\n\
  --sha3-384\n\
  --sha3-512\n"

#define KB                          (1024)
#define MB                          (KB * KB)
#define CAPACITY(NUM, UNIT)			(NUM * UNIT)
#define DEFAULT_FRAGLEN				(CAPACITY(1, MB))    // 默认文件缓存大小

#define FILENAME_LEN_MAX			(256)

#define BUF_SIZE					(CAPACITY(1, MB))

// 文件操作类型的枚举定义
typedef enum FILE_OPTR_E
{
	FILE_OPTR_E_HASH,                           // Hash
	FILE_OPTR_E_SIGN,                           // 签名
	FILE_OPTR_E_VERIFY,                         // 校验
	FILE_OPTR_E_NUM
} FILE_OPTR_E;

// 命令行参数结构
typedef struct GETOPT_PRM_S
{
	unsigned long   * pFragLen;                 // 文件缓存大小
	char            * pFilename;				// 待操作文件名
	FILE_OPTR_E     * pFileOptr;                // 文件操作类型
	char            * pKeyFilename;             // 秘钥文件名
	char            * pSigFilename;             // 签名文件名
	bool			* pHashTypeSelVec;          // Hash方法选择向量
} GETOPT_PRM_S, * P_GETOPT_PRM_S;

void GetOptHandle(int argc, char * argv[], P_GETOPT_PRM_S pgetoptPrm);

char * UpperStrFromHex(unsigned char * str, unsigned char * strLen,	uint8_t * hex, unsigned char hexLen);


#endif /* ____COMMON_H____ */
