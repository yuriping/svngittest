#include <stdlib.h>
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include "common.h"
#include "HashType.h"

#include <nettle/rsa.h>


int main(int argc, char * argv[])
{
	// 处理命令行参数
	unsigned long fragLen;
	char          filename[FILENAME_LEN_MAX];
	FILE_OPTR_E   fileOptr;
	char          keyFilename[FILENAME_LEN_MAX];
	char          sigFilename[FILENAME_LEN_MAX];
	bool          hashTypeSelVec[HASH_TYPE_NUM];

	GETOPT_PRM_S getoptPrm;
	getoptPrm.pFragLen            = &fragLen;
	getoptPrm.pFilename           = filename;
	getoptPrm.pFileOptr           = &fileOptr;
	getoptPrm.pKeyFilename        = keyFilename;
	getoptPrm.pSigFilename        = sigFilename;
	getoptPrm.pHashTypeSelVec     = hashTypeSelVec;

	GetOptHandle(argc, argv, &getoptPrm);

	unsigned char idx;

#ifdef DEBUG

	printf("Fragmentation Length = %ld\n", fragLen);
	printf("File Name : %s\n", filename);
	printf("File Operation = %d\n", fileOptr);
	printf("Key File Name : %s\n", keyFilename);
	printf("Signature File Name : %s\n", sigFilename);
	for (idx = HASH_TYPE_MD2; idx < HASH_TYPE_NUM; idx ++)
	{
		printf("%16s : %d\n", hashTypeName[idx], hashTypeSelVec[idx]);
	}

#endif

	// 打开文件，准备操作
	FILE * fd = fopen(filename, "rb");
	if (-1 == fd)
	{
		printf("file open failed...\n");
		exit(1);
	}

	uint8_t digest[DIGEST_LEN_MAX];
	unsigned char digestLen;

	// 按照Hash向量循环执行相关Hash操作
	for (idx = HASH_TYPE_MD2; idx < HASH_TYPE_NUM; idx ++)
	{
		if (hashTypeSelVec[idx]) // 如果需要执行该类型Hash操作
		{
//			struct timeval tStart;			gettimeofday(&tStart, NULL);

			fseek(fd, 0, SEEK_SET);    // 文件复位
			HashTypeFuncVec[idx](fd, fragLen, digest, &digestLen);  // 执行Hash操作

//			struct timeval tEnd;			gettimeofday(&tEnd, NULL);
//			double tElapse = (((double)tEnd.tv_sec * 1000000 + tEnd.tv_usec) - ((double)tStart.tv_sec * 1000000 + tStart.tv_usec)) / ((double)1000000);
//			printf("[%9.6f]", tElapse);

			unsigned char strLen;
			char strHash[digestLen * 2 + 1];
			UpperStrFromHex(strHash, &strLen, digest, digestLen);

			printf("%10s : %s\n", hashTypeName[idx], strHash);

			////////////////////////////////////////////////////////////////

			if ((FILE_OPTR_E_SIGN == fileOptr) && RSASignDigestVec[idx])  // 如果需要执行签名操作
			{
				// 初始化私钥
				struct rsa_private_key key;
				rsa_private_key_init(&key);

				if (!read_rsa_key(keyFilename, NULL, &key))
				{
					printf("Invalid key\n");
					return EXIT_FAILURE;
				}

				// 初始化结果
				mpz_t s;
				mpz_init(s);

				// 执行签名
				RSASignDigestVec[idx](&key, digest, s);

				// 输出结果到文件
				char signFileName[FILENAME_LEN_MAX + 10 + 3 + 1];
				sprintf(signFileName, "%s.%s.sig", filename, hashTypeName[idx]);
				FILE * fSign = fopen(signFileName, "wb");
				mpz_out_str(fSign, 16, s);
			}

			if ((FILE_OPTR_E_VERIFY == fileOptr) && (RSAVerifyDigestVec[idx]))  // 如果需要执行校验操作
			{
				// 初始化公钥
				struct rsa_public_key key;
				rsa_public_key_init(&key);

				if (!read_rsa_key(keyFilename, &key, NULL))
			    {
					printf("Invalid key\n");
					return EXIT_FAILURE;
			    }

				mpz_t s;
				mpz_init(s);
				if (!read_signature(sigFilename, s))
			    {
					printf("Failed to read signature file `%s'\n", sigFilename);
					return EXIT_FAILURE;
			    }

				if (RSAVerifyDigestVec[idx](&key, digest, s))
				{
					printf("Good Sig!\n");
				}
				else
				{
					printf("Bad Sig\n");
				}
			}
		}
	}

    return 0;
}
