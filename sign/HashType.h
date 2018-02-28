
#ifndef ____HASHTYPE_H____
#define ____HASHTYPE_H____


#include <nettle/sha3.h>
#include <nettle/rsa.h>


#define DIGEST_LEN_MAX	(SHA3_512_DIGEST_SIZE)


/*
 * Hash方法的枚举形式
 */
typedef enum HASH_TYPE_E
{
    HASH_TYPE_MD2,
    HASH_TYPE_MD4,
    HASH_TYPE_MD5,
    HASH_TYPE_RIPEMD160,
    HASH_TYPE_GOSTHASH94,
    HASH_TYPE_SHA1,
    HASH_TYPE_SHA224,
    HASH_TYPE_SHA256,
    HASH_TYPE_SHA384,
    HASH_TYPE_SHA512,
    HASH_TYPE_SHA3_224,
    HASH_TYPE_SHA3_256,
    HASH_TYPE_SHA3_384,
    HASH_TYPE_SHA3_512,
	HASH_TYPE_NUM
} HASH_TYPE_E;

/*
 * Hash方法的字符串形式
 */
static char * hashTypeName[HASH_TYPE_NUM] =
{
	"md2",
	"md4",
	"md5",
	"ripemd160",
	"gosthash94",
	"sha1",
	"sha224",
	"sha256",
	"sha384",
	"sha512",
	"sha3_224",
	"sha3_256",
	"sha3_384",
	"sha3_512",
};


// Hash方法函数类型
typedef void (* HASH_TYPE_FUNC_T)(FILE * fd, long fragLen, uint8_t * digest, unsigned char * pDigestLen);


/*
 * Hash方法函数声明
 */
void Hash_MD2(FILE * fd, long fragLen, uint8_t * digest, unsigned char * pDigestLen);
void Hash_MD4(FILE * fd, long fragLen, uint8_t * digest, unsigned char * pDigestLen);
void Hash_MD5(FILE * fd, long fragLen, uint8_t * digest, unsigned char * pDigestLen);
void Hash_RIPEMD160(FILE * fd, long fragLen, uint8_t * digest, unsigned char * pDigestLen);
void Hash_GOSTHASH94(FILE * fd, long fragLen, uint8_t * digest, unsigned char * pDigestLen);
void Hash_SHA1(FILE * fd, long fragLen, uint8_t * digest, unsigned char * pDigestLen);
void Hash_SHA224(FILE * fd, long fragLen, uint8_t * digest, unsigned char * pDigestLen);
void Hash_SHA256(FILE * fd, long fragLen, uint8_t * digest, unsigned char * pDigestLen);
void Hash_SHA384(FILE * fd, long fragLen, uint8_t * digest, unsigned char * pDigestLen);
void Hash_SHA512(FILE * fd, long fragLen, uint8_t * digest, unsigned char * pDigestLen);
void Hash_SHA3_224(FILE * fd, long fragLen, uint8_t * digest, unsigned char * pDigestLen);
void Hash_SHA3_256(FILE * fd, long fragLen, uint8_t * digest, unsigned char * pDigestLen);
void Hash_SHA3_384(FILE * fd, long fragLen, uint8_t * digest, unsigned char * pDigestLen);
void Hash_SHA3_512(FILE * fd, long fragLen, uint8_t * digest, unsigned char * pDigestLen);

/*
 * Hash方法函数向量
 */
static HASH_TYPE_FUNC_T HashTypeFuncVec[HASH_TYPE_NUM] =
{
	Hash_MD2,
	Hash_MD4,
	Hash_MD5,
	Hash_RIPEMD160,
	Hash_GOSTHASH94,
	Hash_SHA1,
	Hash_SHA224,
	Hash_SHA256,
	Hash_SHA384,
	Hash_SHA512,
	Hash_SHA3_224,
	Hash_SHA3_256,
	Hash_SHA3_384,
	Hash_SHA3_512
};

// 签名函数类型
typedef int (* RSA_SIGN_DIGEST_T)(const struct rsa_private_key *key, const uint8_t *digest, mpz_t s);

/*
 * 签名函数向量
 */
static RSA_SIGN_DIGEST_T RSASignDigestVec[HASH_TYPE_NUM] =
{
	NULL,
	NULL,
	rsa_md5_sign_digest,
	NULL,
	NULL,
	rsa_sha1_sign_digest,
	NULL,
	rsa_sha256_sign_digest,
	NULL,
	rsa_sha512_sign_digest,
	NULL,
	NULL,
	NULL,
	NULL
};


// 校验函数类型
typedef int (* RSA_VERIFY_DIGEST_T)(const struct rsa_public_key *key, const uint8_t *digest, const mpz_t signature);

/*
 * 校验函数向量
 */
static RSA_VERIFY_DIGEST_T RSAVerifyDigestVec[HASH_TYPE_NUM] =
{
	NULL,
	NULL,
	rsa_md5_verify_digest,
	NULL,
	NULL,
	rsa_sha1_verify_digest,
	NULL,
	rsa_sha256_verify_digest,
	NULL,
	rsa_sha512_verify_digest,
	NULL,
	NULL,
	NULL,
	NULL
};

#endif /* ____HASHTYPE_H____ */
