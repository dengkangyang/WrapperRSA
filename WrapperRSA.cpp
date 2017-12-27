
#include "WrapperRSA.h"
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/rand.h>
#include <assert.h>

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#	ifdef _WIN64
#	pragma comment(lib, "openssl/x64/libcrypto64MD")
#	else
#	pragma comment(lib, "openssl/x86/libcrypto32MD")
#	endif
#else
#	ifdef _WIN64
#	pragma comment(lib, "openssl/x64/libcrypto64MD")
#	else
#	pragma comment(lib, "openssl/x86/libcrypto32MD")
#	endif
#endif


void CWrapperOpenSSL::Init()
{
	srand( (unsigned)time( NULL ) );

	OpenSSL_add_all_digests() ;
	OpenSSL_add_all_algorithms() ;
	OpenSSL_add_all_ciphers() ;

}

void CWrapperOpenSSL::Cleanup()
{
	CRYPTO_cleanup_all_ex_data();	// 如果没有这个, RSA_free()有些内容不能完全释放.
	EVP_cleanup() ;
	
}


///////////////////////////////////////////////////////////////////////////////////////////////

CWrapperRSA::CWrapperRSA()
{
	m_pKey = NULL ;
	m_padding = RSA_PKCS1_PADDING ;

}

CWrapperRSA::~CWrapperRSA()
{
	ReInit() ;
}

void CWrapperRSA::ReInit()
{
	if( m_pKey!=NULL )
	{
	    RSA_free(m_pKey);
		m_pKey = NULL ;		
	}

}

bool CWrapperRSA::InitPublicKey( const char * pN, const char * pE )
{
	if( pN==NULL || pE==NULL )
		return false ;

	ReInit() ;

    BIGNUM *bnn, *bne ;
    bnn = BN_new();
    bne = BN_new();
    BN_hex2bn( &bnn, pN );
    BN_hex2bn( &bne, pE );

	m_pKey = RSA_new() ;
	RSA_set0_key(m_pKey, bnn, bne, nullptr);
//    m_pKey->n = bnn;
//    m_pKey->e = bne;
	
	return true ;

}

bool CWrapperRSA::InitPrivateKey( const char * pN, const char * pE, const char * pD ) 
{
	if( pN==NULL || pE==NULL || pD==NULL )
		return false ;

	ReInit() ;

    BIGNUM *bnn, *bne, *bnd ;
    bnn = BN_new();
    bne = BN_new();
    bnd = BN_new();
    BN_hex2bn( &bnn, pN );
    BN_hex2bn( &bne, pE );
    BN_hex2bn( &bnd, pD );

	m_pKey = RSA_new() ;
	RSA_set0_key(m_pKey, bnn, bne, bnd);
//    m_pKey->n = bnn;
//    m_pKey->e = bne;
//    m_pKey->d = bnd;
	
	return true ;

}



bool CWrapperRSA::GenKey( std::string& echoN, std::string& echoE, std::string& echoD, int BitLength ) 
{

/*	
	警告: openssl中 RSA_generate_key()有轻微内存泄露.
	
	疑问:	
		  看openssl文档, 说RSA_generate_key()之前要初试化 随机数种子, 未清楚openssl中 如何初试化随机数种子.

*/
	char rand_buff[16];
	RAND_seed(rand_buff, 16);

	RSA* r = NULL ;
	r = RSA_generate_key( BitLength, RSA_F4, NULL, NULL ) ;
	if( r==NULL )
		return false ;

	const BIGNUM *bnn = nullptr;
	const BIGNUM *bne = nullptr;
	const BIGNUM *bnd = nullptr;
	RSA_get0_key(r, &bnn, &bne, &bnd);
	char* pN =  BN_bn2hex( bnn ) ;
	char* pE =  BN_bn2hex( bne ) ;
	char* pD =  BN_bn2hex( bnd ) ;
	assert( pN!=NULL && pE!=NULL && pD!=NULL ) ;

	bool error = false ;
	if( pN==NULL || pE==NULL || pD==NULL )
	{
		error = true ;
		goto ErrorExit ;
	}

	echoN = pN ; 
	echoE = pE ;
	echoD = pD ;

	OPENSSL_free(pN) ;
	OPENSSL_free(pE) ;
	OPENSSL_free(pD) ;
    RSA_free(r);
	return true ;

ErrorExit:	

	if( pN!=NULL )
	{
		OPENSSL_free(pN) ;
	}
	if( pE!=NULL )
	{
		OPENSSL_free(pE) ;
	}
	if( pD!=NULL )
	{
		OPENSSL_free(pD) ;
	}
    RSA_free(r);
	return false ;	

}

int	 CWrapperRSA::QueryAtomSize()
{
	if( m_pKey==NULL )
		return 0 ;

	return  RSA_size(m_pKey); 

}

int	 CWrapperRSA::QueryAtomSize_SubPadding()
{
	// 只支持RSA_PKCS1_PADDING方式填充.
	return  QueryAtomSize()-11 ;

}

bool   CWrapperRSA::Encrpt( unsigned char* pSrcBuf, int SrcSize, unsigned char* pDestBuf, int& echoDestSize ) 
{
	if( m_pKey==NULL )
		return false ;
	if( pSrcBuf==NULL || SrcSize<=0 )
		return false ;
	if( pDestBuf==NULL || echoDestSize<=0 )
		return false ;

	int	AtomSize = QueryAtomSize() ;
	if( AtomSize<=0 )
		return false ;
	int SrcAtomSize = QueryAtomSize_SubPadding() ;
	if( SrcAtomSize<=0 )
		return false ;

	div_t div_result;
	div_result = div( SrcSize, SrcAtomSize );
	int MinDestSize = AtomSize*div_result.quot ;
	if( div_result.rem>0 )
	{
		MinDestSize += AtomSize ;
	}
	if( echoDestSize<MinDestSize )
		return false ;

	int PackSize	= 0 ;		// 已经加密的 明文长度.
	int EncryptSize = 0 ;		// 已经生成的 密文长度.
	while( PackSize<SrcSize )
	{
		int ps = SrcAtomSize < SrcSize-PackSize ? SrcAtomSize : SrcSize - PackSize;
	    int ret = RSA_public_encrypt( ps, pSrcBuf+PackSize, pDestBuf+EncryptSize, m_pKey,  RSA_PKCS1_PADDING );
		if( ret<=0 || ret!=AtomSize )
			return false ;

		PackSize += ps ;
		EncryptSize += ret ;
	}
	echoDestSize = EncryptSize ;
	return true ;

}

bool CWrapperRSA::Decrpt( unsigned char* pSrcBuf, int SrcSize, unsigned char* pDestBuf, int& echoDestSize ) 
{
	if( m_pKey==NULL )
		return false ;
	if( pSrcBuf==NULL || SrcSize<=0 )
		return false ;
	if( pDestBuf==NULL || echoDestSize<=0 )
		return false ;

	int	AtomSize = QueryAtomSize() ;
	if( AtomSize<=0 )
		return false ;
	if( SrcSize<AtomSize )
		return false ;

	div_t div_result ;
	div_result = div( SrcSize, AtomSize );
	int MinDestSize = AtomSize*div_result.quot ;
	if( div_result.rem!=0 )
	{
		return false ;
	}
	if( echoDestSize<MinDestSize )
		return false ;

	int PackSize	= 0 ;		// 已经解密的 密文长度.
	int DecryptSize = 0 ;		// 已经生成的 明文长度.
	while( PackSize<SrcSize )
	{
		int ps = AtomSize ;
	    //int ret = RSA_private_decrypt( ps, pSrcBuf+PackSize, pDestBuf+DecryptSize, m_pKey,  RSA_PKCS1_PADDING );
	    int ret = RSA_private_decrypt( ps, pSrcBuf+PackSize, pDestBuf+DecryptSize, m_pKey,  m_padding );
		if( ret<=0 )
			return false ;

		PackSize += ps ;
		DecryptSize += ret ;
	}
	echoDestSize = DecryptSize ;
	return true ;
}