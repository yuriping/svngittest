#include "common.h"
#include <stdio.h>
#include <nettle/md2.h>
#include <nettle/md4.h>
#include <nettle/md5.h>
#include <nettle/ripemd160.h>
#include <nettle/gosthash94.h>
#include <nettle/sha1.h>
#include <nettle/sha2.h>
#include <nettle/sha3.h>


/*
 * Hash方法函数集合
 */


void Hash_MD2(FILE * fd, long fragLen, uint8_t * digest, unsigned char * pDigestLen)
{
    char fragBuf[BUF_SIZE];
    int  currFragLen;

    struct md2_ctx ctx;

    md2_init(&ctx);

    do
    {
    	currFragLen = fread(fragBuf, 1, fragLen, fd);

        if (currFragLen)
        {
        	md2_update(&ctx, currFragLen, fragBuf);
        }
    } while (currFragLen != 0);

    md2_digest(&ctx, MD2_DIGEST_SIZE, digest);
    * pDigestLen = MD2_DIGEST_SIZE;

	return;
}

void Hash_MD4(FILE * fd, long fragLen, uint8_t * digest, unsigned char * pDigestLen)
{
    char fragBuf[BUF_SIZE];
    int  currFragLen;

    struct md4_ctx ctx;

    md4_init(&ctx);

    do
    {
    	currFragLen = fread(fragBuf, 1, fragLen, fd);

        if (currFragLen)
        {
        	md4_update(&ctx, currFragLen, fragBuf);
        }
    } while (currFragLen != 0);

    md4_digest(&ctx, MD4_DIGEST_SIZE, digest);
    * pDigestLen = MD4_DIGEST_SIZE;

	return;
}

void Hash_MD5(FILE * fd, long fragLen, uint8_t * digest, unsigned char * pDigestLen)
{
    char fragBuf[BUF_SIZE];
    int  currFragLen;

    struct md5_ctx ctx;

    md5_init(&ctx);

    do
    {
    	currFragLen = fread(fragBuf, 1, fragLen, fd);

        if (currFragLen)
        {
        	md5_update(&ctx, currFragLen, fragBuf);
        }
    } while (currFragLen != 0);

    md5_digest(&ctx, MD5_DIGEST_SIZE, digest);
    * pDigestLen = MD5_DIGEST_SIZE;

	return;
}

void Hash_RIPEMD160(FILE * fd, long fragLen, uint8_t * digest, unsigned char * pDigestLen)
{
    char fragBuf[BUF_SIZE];
    int  currFragLen;

    struct ripemd160_ctx ctx;

    ripemd160_init(&ctx);

    do
    {
    	currFragLen = fread(fragBuf, 1, fragLen, fd);

        if (currFragLen)
        {
        	ripemd160_update(&ctx, currFragLen, fragBuf);
        }
    } while (currFragLen != 0);

    ripemd160_digest(&ctx, RIPEMD160_DIGEST_SIZE, digest);
    * pDigestLen = RIPEMD160_DIGEST_SIZE;

	return;
}

void Hash_GOSTHASH94(FILE * fd, long fragLen, uint8_t * digest, unsigned char * pDigestLen)
{
    char fragBuf[BUF_SIZE];
    int  currFragLen;

    struct gosthash94_ctx ctx;

    gosthash94_init(&ctx);

    do
    {
    	currFragLen = fread(fragBuf, 1, fragLen, fd);

        if (currFragLen)
        {
        	gosthash94_update(&ctx, currFragLen, fragBuf);
        }
    } while (currFragLen != 0);

    gosthash94_digest(&ctx, GOSTHASH94_DIGEST_SIZE, digest);
    * pDigestLen = GOSTHASH94_DIGEST_SIZE;

	return;
}

void Hash_SHA1(FILE * fd, long fragLen, uint8_t * digest, unsigned char * pDigestLen)
{
    char fragBuf[BUF_SIZE];
    int  currFragLen;

    struct sha1_ctx ctx;

    sha1_init(&ctx);

    do
    {
    	currFragLen = fread(fragBuf, 1, fragLen, fd);

        if (currFragLen)
        {
            sha1_update(&ctx, currFragLen, fragBuf);
        }
    } while (currFragLen != 0);

    sha1_digest(&ctx, SHA1_DIGEST_SIZE, digest);

    * pDigestLen = SHA1_DIGEST_SIZE;

	return;
}

void Hash_SHA224(FILE * fd, long fragLen, uint8_t * digest, unsigned char * pDigestLen)
{
    char fragBuf[BUF_SIZE];
    int  currFragLen;

    struct sha224_ctx ctx;

    sha224_init(&ctx);

    do
    {
    	currFragLen = fread(fragBuf, 1, fragLen, fd);

        if (currFragLen)
        {
        	sha224_update(&ctx, currFragLen, fragBuf);
        }
    } while (currFragLen != 0);

    sha224_digest(&ctx, SHA224_DIGEST_SIZE, digest);
    * pDigestLen = SHA224_DIGEST_SIZE;

	return;
}

void Hash_SHA256(FILE * fd, long fragLen, uint8_t * digest, unsigned char * pDigestLen)
{
    char fragBuf[BUF_SIZE];
    int  currFragLen;

    struct sha256_ctx ctx;

    sha256_init(&ctx);

    do
    {
    	currFragLen = fread(fragBuf, 1, fragLen, fd);

        if (currFragLen)
        {
            sha256_update(&ctx, currFragLen, fragBuf);
        }
    } while (currFragLen != 0);

    sha256_digest(&ctx, SHA256_DIGEST_SIZE, digest);
    * pDigestLen = SHA256_DIGEST_SIZE;

	return;
}

void Hash_SHA384(FILE * fd, long fragLen, uint8_t * digest, unsigned char * pDigestLen)
{
    char fragBuf[BUF_SIZE];
    int  currFragLen;

    struct sha384_ctx ctx;

    sha384_init(&ctx);

    do
    {
    	currFragLen = fread(fragBuf, 1, fragLen, fd);

        if (currFragLen)
        {
            sha384_update(&ctx, currFragLen, fragBuf);
        }
    } while (currFragLen != 0);

    sha384_digest(&ctx, SHA384_DIGEST_SIZE, digest);
    * pDigestLen = SHA384_DIGEST_SIZE;

	return;
}

void Hash_SHA512(FILE * fd, long fragLen, uint8_t * digest, unsigned char * pDigestLen)
{
    char fragBuf[BUF_SIZE];
    int  currFragLen;

    struct sha512_ctx ctx;

    sha512_init(&ctx);

    do
    {
    	currFragLen = fread(fragBuf, 1, fragLen, fd);

        if (currFragLen)
        {
            sha512_update(&ctx, currFragLen, fragBuf);
        }
    } while (currFragLen != 0);

    sha512_digest(&ctx, SHA512_DIGEST_SIZE, digest);
    * pDigestLen = SHA512_DIGEST_SIZE;

	return;
}

void Hash_SHA3_224(FILE * fd, long fragLen, uint8_t * digest, unsigned char * pDigestLen)
{
    char fragBuf[BUF_SIZE];
    int  currFragLen;

    struct sha3_224_ctx ctx;

    sha3_224_init(&ctx);

    do
    {
    	currFragLen = fread(fragBuf, 1, fragLen, fd);

        if (currFragLen)
        {
            sha3_224_update(&ctx, currFragLen, fragBuf);
        }
    } while (currFragLen != 0);

    sha3_224_digest(&ctx, SHA3_224_DIGEST_SIZE, digest);
    * pDigestLen = SHA3_224_DIGEST_SIZE;

	return;
}

void Hash_SHA3_256(FILE * fd, long fragLen, uint8_t * digest, unsigned char * pDigestLen)
{
    char fragBuf[BUF_SIZE];
    int  currFragLen;

    struct sha3_256_ctx ctx;

    sha3_256_init(&ctx);

    do
    {
    	currFragLen = fread(fragBuf, 1, fragLen, fd);

        if (currFragLen)
        {
            sha3_256_update(&ctx, currFragLen, fragBuf);
        }
    } while (currFragLen != 0);

    sha3_256_digest(&ctx, SHA3_256_DIGEST_SIZE, digest);
    * pDigestLen = SHA3_256_DIGEST_SIZE;

	return;
}

void Hash_SHA3_384(FILE * fd, long fragLen, uint8_t * digest, unsigned char * pDigestLen)
{
    char fragBuf[BUF_SIZE];
    int  currFragLen;

    struct sha3_384_ctx ctx;

    sha3_384_init(&ctx);

    do
    {
    	currFragLen = fread(fragBuf, 1, fragLen, fd);

        if (currFragLen)
        {
            sha3_384_update(&ctx, currFragLen, fragBuf);
        }
    } while (currFragLen != 0);

    sha3_384_digest(&ctx, SHA3_384_DIGEST_SIZE, digest);
    * pDigestLen = SHA3_384_DIGEST_SIZE;

	return;
}

void Hash_SHA3_512(FILE * fd, long fragLen, uint8_t * digest, unsigned char * pDigestLen)
{
    char fragBuf[BUF_SIZE];
    int  currFragLen;

    struct sha3_512_ctx ctx;

    sha3_512_init(&ctx);

    do
    {
    	currFragLen = fread(fragBuf, 1, fragLen, fd);

        if (currFragLen)
        {
            sha3_512_update(&ctx, currFragLen, fragBuf);
        }
    } while (currFragLen != 0);

    sha3_512_digest(&ctx, SHA3_512_DIGEST_SIZE, digest);
    * pDigestLen = SHA3_512_DIGEST_SIZE;

	return;
}
