
/*
	��openssl RSA�㷨�ķ�װ

	RSA�㷨����֪ʶ:

		RSA�㷨���� Rivest,Shamir��Adleman��1978�������һ�ֹ��������㷨.
		RSA�㷨�ǵ�һ��������ƵĹ��������㷨. ���㷨����ѧ������Euler����, �������ڴ������ֽ�������֮��.
		��: ��������������������������׵�, ���ֽ������������Ļ��Ǽ����ϲ����е�.

    RSA�㷨����:

		�ܳ�����:

			����������Ĵ�����p��q, ����n=pq �� f(n)=(p-1)(q-1) ;
			ѡ�������e(һ����0x10001), ����e�� f(n)����.
			
			���� d = exp( e, -1 ) mod f(n)
			
			���ף� (n,e)
			˽�ף� (n,d,p,q)	// ʵ�� (n,e,d)Ҳ������.
			
	Ŀǰn����Ч������1024bit�ǰ�ȫ��, ����2048bit.
	
	�����������:
	
		��׼�����PKCS1 �� PSS.
		���1024bit(128byte), ��ÿ�μ���������ദ��117�ֽ�.

*/

#ifndef _WRAPPERRSA_H_
#define	_WRAPPERRSA_H_

#include <string>
#include <openssl/rsa.h>

class CWrapperOpenSSL
{
public:

/*
	openssl�ĳ�ʼ������.
*/
	static void Init() ;

/*
	openssl�Ľ����������.
*/
	static void Cleanup() ;
};


class CWrapperRSA
{
public:
	CWrapperRSA() ;
	~CWrapperRSA() ;

	void ReInit() ;

/*
	���Ի� public key.
*/
	bool InitPublicKey( const char * pN, const char * pE ) ;

/*
	���Ի� private key.
*/
	bool InitPrivateKey( const char * pN, const char * pE, const char * pD ) ;

/*
	����һ�� BitLengthλ�� key.

	���ף� (n,e)					// 16����string	
	˽�ף� (n,e,d)					// 16����string	

*/
	static bool GenKey( std::string& echoN, std::string& echoE, std::string& echoD, int BitLength = 1024 ) ;

/*
	(�ù���)����.
*/
	bool   Encrpt( unsigned char* pSrcBuf, int SrcSize, unsigned char* pDestBuf, int& echoDestSize ) ;


/*
	(��˽��)����.
*/
	bool   Decrpt( unsigned char* pSrcBuf, int SrcSize, unsigned char* pDestBuf, int& echoDestSize ) ;

/*
	��ѯԭ�Ӱ��Ĵ�С.
*/
	int	   QueryAtomSize() ; 	

/*
	��ѯ �۳���䲿�� �Ĵ�С.
*/
	int	   QueryAtomSize_SubPadding() ; 	

public:

	RSA*	m_pKey ;

	// ���ģʽ, paul, 2010-11-20, add.

		// ע: Ŀǰֻ֧����RSA_PKCS1_PADDING, ����ģʽδ֧��.
	int		m_padding ;
};



#endif 