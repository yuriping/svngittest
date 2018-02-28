#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <getopt.h>
#include <libgen.h>
#include <errno.h>
#include <stdbool.h>
#include <ctype.h>
#include "common.h"
#include "HashType.h"

#include <nettle/rsa.h>


/*
 * 打印版本信息
 */
void PrintVersion(char * progName, char * version, char * copyright)
{
	printf("%s version %s\n%s\n", progName, version, copyright);

	return;
}

/*
 * 打印帮助信息
 */
void PrintHelp(char * progName, char * usage)
{
	printf("Usage: %s [OPTIONS]\n", progName);
	printf("\nOPTIONS\n%s\n", usage);

	return;
}

/*
 * 处理命令行参数
 */
void GetOptHandle(int argc, char * argv[], P_GETOPT_PRM_S pgetoptPrm)
{
	// 各参数初始化
	*(pgetoptPrm->pFragLen) = DEFAULT_FRAGLEN;                  // 设置文件缓存大小，即Hash片段大小的默认值

	bzero(pgetoptPrm->pFilename, FILENAME_LEN_MAX);             // 清空操作文件名缓冲区

	*(pgetoptPrm->pFileOptr) = FILE_OPTR_E_HASH;                // 设置文件操作类型，默认为只做Hash

	bzero(pgetoptPrm->pKeyFilename, FILENAME_LEN_MAX);          // 清空秘钥文件名缓冲区

	bzero(pgetoptPrm->pSigFilename, FILENAME_LEN_MAX);          // 清空签名文件名缓冲区

	unsigned char idx;                                          // 预置Hash选择向量为全未选中
	for (idx = HASH_TYPE_MD2; idx < HASH_TYPE_NUM; idx ++)
	{
		pgetoptPrm->pHashTypeSelVec[idx] = false;
	}

	/*
	 * 命令行参数向量表
	 */
	static struct option longopts[] =
    {
        { "help",      no_argument,       0, 'h'                   },
        { "version",   no_argument,       0, 'v'                   },
        { "fraglen",   required_argument, 0, 'l'                   },
        { "file",      required_argument, 0, 'f'                   },
        { "sign",      no_argument,       0, 's'                   },
        { "verify",    no_argument,       0, 'r'                   },
        { "key",       required_argument, 0, 'k'                   },
        { "signature", required_argument, 0, 'g'                   },
        { "md2",       no_argument,		  0,  HASH_TYPE_MD2        },
        { "md4",       no_argument,		  0,  HASH_TYPE_MD4        },
        { "md5",       no_argument,		  0,  HASH_TYPE_MD5        },
        { "ripemd160", no_argument,		  0,  HASH_TYPE_RIPEMD160  },
        { "gosthash94",no_argument,		  0,  HASH_TYPE_GOSTHASH94 },
        { "sha1",      no_argument,       0,  HASH_TYPE_SHA1       },
        { "sha224",    no_argument,       0,  HASH_TYPE_SHA224     },
        { "sha256",    no_argument,       0,  HASH_TYPE_SHA256     },
        { "sha384",    no_argument,		  0,  HASH_TYPE_SHA384     },
        { "sha512",    no_argument,       0,  HASH_TYPE_SHA512     },
        { "sha3-224",  no_argument,       0,  HASH_TYPE_SHA3_224   },
        { "sha3-256",  no_argument,       0,  HASH_TYPE_SHA3_256   },
        { "sha3-384",  no_argument,       0,  HASH_TYPE_SHA3_384   },
        { "sha3-512",  no_argument,       0,  HASH_TYPE_SHA3_512   },
        { 0,           0,                 0,  0                    }
    };

	// 签名操作类型与验证操作类型暂存，用于比较这两种类型是否被同时指定，以判断指定的合法性
	bool bSignFlag   = false;
	bool bVerifyFlag = false;

	/*
	 * 获取命令行参数值
	 */
    int ch;
    while ((ch = getopt_long(argc, argv, "hvl:f:srk:g:", longopts, 0)) != -1)
    {
    	switch (ch)
    	{
    	case 'h':               // 接收到打印帮助信息的命令
    		PrintHelp(basename(argv[0]), USAGE);
    		exit(0);
    		break;
    	case 'v':               // 接收到显示版本信息的命令
    		PrintVersion(basename(argv[0]), VERSION, COPYRIGHT);
    		exit(0);
    		break;
    	case 'l':               // 接收到设置文件缓存大小，即Hash片段大小的命令
    		*(pgetoptPrm->pFragLen) = atoi(optarg);
    		break;
    	case 'f':               // 接收到指定操作文件名的命令
    		strcpy(pgetoptPrm->pFilename, optarg);
    		break;
    	case 's':               // 接收到指定签名操作的命令，暂存
    		bSignFlag = true;
    		break;
    	case 'r':               // 接收到指定校验操作的命令，暂存
    		bVerifyFlag = true;
    		break;
    	case 'k':               // 接收到指定秘钥文件名的命令
    		strcpy(pgetoptPrm->pKeyFilename, optarg);
    		break;
    	case 'g':               // 接收到指定签名文件名的命令
    		strcpy(pgetoptPrm->pSigFilename, optarg);
    		break;
                                // 接收到指定Hash类型的命令呢，逐个存入Hash类型选择向量
    	case HASH_TYPE_MD2:
    	case HASH_TYPE_MD4:
    	case HASH_TYPE_MD5:
    	case HASH_TYPE_RIPEMD160:
    	case HASH_TYPE_GOSTHASH94:
    	case HASH_TYPE_SHA1:
    	case HASH_TYPE_SHA224:
        case HASH_TYPE_SHA256:
        case HASH_TYPE_SHA384:
        case HASH_TYPE_SHA512:
        case HASH_TYPE_SHA3_224:
        case HASH_TYPE_SHA3_256:
        case HASH_TYPE_SHA3_384:
        case HASH_TYPE_SHA3_512:
        	pgetoptPrm->pHashTypeSelVec[ch] = true;
    		break;
    	default:                // 接收到非法的参数命令
    		PrintHelp(basename(argv[0]), USAGE);
    		exit(0);
    		break;
    	}
    }

    // 如果未指定操作文件，则打印帮助信息并退出.
    if (0 == strlen(pgetoptPrm->pFilename))
    {
    	PrintHelp(basename(argv[0]), USAGE);
    	exit(0);
    }

    if (bSignFlag && bVerifyFlag)
    {  // 如果同时指定了签名与验证操作，则打印帮助信息并退出
    	PrintHelp(basename(argv[0]), USAGE);
    	exit(0);
    }
    else
    {  // 如果指定了签名或验证操作，将标志存入永久量，如果均未指定，保持默认Hash操作
    	if (bSignFlag)
    	{
    		*(pgetoptPrm->pFileOptr) = FILE_OPTR_E_SIGN;
    	}
    	if (bVerifyFlag)
    	{
    		*(pgetoptPrm->pFileOptr) = FILE_OPTR_E_VERIFY;
    	}
    }

    // 检测是否有Hash类型被选中，选中的个数存放在 numOfHashTypeSel 中
    unsigned char numOfHashTypeSel = 0;
    for (idx = HASH_TYPE_MD2; idx < HASH_TYPE_NUM; idx ++)
    {
    	if (true == pgetoptPrm->pHashTypeSelVec[idx])
    	{
    		numOfHashTypeSel ++;
    	}
    }
    // 如果没有任何Hash类型被选中，则设定默认值：所有Hash类型均被选中
    if (0 == numOfHashTypeSel)
    {
		for (idx = HASH_TYPE_MD2; idx < HASH_TYPE_NUM; idx ++)
		{
			pgetoptPrm->pHashTypeSelVec[idx] = true;
		}
		numOfHashTypeSel = HASH_TYPE_NUM;                       // numOfHashTypeSel 依然指示最终被选中的Hash类型数量
    }

    // 如果操作类型为签名或校验，但没有指定秘钥文件，则打印帮助信息并退出
    if ((FILE_OPTR_E_HASH != *(pgetoptPrm->pFileOptr)) && (0 == strlen(pgetoptPrm->pKeyFilename)))
    {
    	PrintHelp(basename(argv[0]), USAGE);
    	exit(0);
    }

    // 如果操作类型为校验，但没有指定签名文件，或者有效的Hash类型多于一个，则打印帮助信息并退出
    if ((FILE_OPTR_E_VERIFY == *(pgetoptPrm->pFileOptr)) && ((0 == strlen(pgetoptPrm->pSigFilename)) || (numOfHashTypeSel > 1)))
    {
    	PrintHelp(basename(argv[0]), USAGE);
    	exit(0);
    }

	return;
}

/*
 * 十六进制字符串转大写函数
 */
char * UpperStrFromHex(unsigned char * str, unsigned char * strLen,
		uint8_t * hex, unsigned char hexLen)
{
	* strLen = hexLen * 2 +1;
	bzero(str, * strLen);

	unsigned char idx;
	for (idx = 0; idx < hexLen; idx ++)
	{
		char strCurr2HalfByte[3];
		sprintf(strCurr2HalfByte, "%02x", hex[idx]);
		if (islower(strCurr2HalfByte[0])) {strCurr2HalfByte[0] -= 'a' - 'A';}
		if (islower(strCurr2HalfByte[1])) {strCurr2HalfByte[1] -= 'a' - 'A';}
		strcat(str, strCurr2HalfByte);
	}

	return str;
}

unsigned read_file(const char *name, unsigned max_size, char **contents)
{
	unsigned size, done;
	char *buffer;
	FILE *f;

	f = fopen(name, "rb");
	if (!f)
	{
		printf("Opening `%s' failed: %s\n", name, strerror(errno));
		return 0;
	}

	size = 100;

	for (buffer = NULL, done = 0;; size *= 2)
    {
		char *p;

		if (max_size && size > max_size)
			size = max_size;

		/* Space for terminating NUL */
		p = realloc(buffer, size + 1);

		if (!p)
		{
			fail:
			fclose(f);
			free(buffer);
			*contents = NULL;
			return 0;
		}

		buffer = p;
		done += fread(buffer + done, 1, size - done, f);

		if (done < size)
		{
			/* Short count means EOF or read error */
			if (ferror(f))
			{
				fprintf (stderr, "Reading `%s' failed: %s\n", name, strerror(errno));

				goto fail;
			}
			if (done == 0)
				/* Treat empty file as error */
				goto fail;

			break;
		}

		if (size == max_size)
			break;
    }

	fclose(f);

	/* NUL-terminate the data. */
	buffer[done] = '\0';
	*contents = buffer;

	return done;
}

/*
 * 秘钥获取
 */
/* Split out from io.c, since it depends on hogweed. */
int read_rsa_key(const char *name,
	     struct rsa_public_key *pub,
	     struct rsa_private_key *priv)
{
	unsigned length;
	char *buffer;
	int res;

	length = read_file(name, 0, &buffer);
	if (!length)
		return 0;

	res = rsa_keypair_from_sexp(pub, priv, 0, length, buffer);
	free(buffer);

	return res;
}

/*
 *
 */
int read_signature(const char *name, mpz_t s)
{
	char *buffer;
	unsigned length;
	int res;

	length = read_file(name, 0, &buffer);
	if (!length)
	{
		return 0;
	}

	res = (mpz_set_str(s, buffer, 16) == 0);
	free(buffer);

	return res;
}
