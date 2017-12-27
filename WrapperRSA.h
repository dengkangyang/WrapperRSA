
/*
	对openssl RSA算法的封装

	RSA算法基础知识:

		RSA算法是由 Rivest,Shamir和Adleman在1978年提出发一种公匙密码算法.
		RSA算法是第一个设计完善的公匙密码算法. 该算法的数学基础是Euler定理, 并建立在大整数分解困难性之上.
		即: 将两个大素数乘起来上相对容易的, 而分解两个大素数的积是计算上不可行的.

    RSA算法描述:

		密匙生成:

			找两个随机的大素数p和q, 计算n=pq 和 f(n)=(p-1)(q-1) ;
			选择随机数e(一般用0x10001), 满足e与 f(n)互素.
			
			计算 d = exp( e, -1 ) mod f(n)
			
			公匙： (n,e)
			私匙： (n,d,p,q)	// 实际 (n,e,d)也都可以.
			
	目前n的有效长度是1024bit是安全的, 建议2048bit.
	
	数据填充问题:
	
		标准填充有PKCS1 和 PSS.
		如果1024bit(128byte), 则每次加密运算最多处理117字节.

*/

#ifndef _WRAPPERRSA_H_
#define	_WRAPPERRSA_H_

#include <string>
#include <openssl/rsa.h>

class CWrapperOpenSSL
{
public:

/*
	openssl的初始化动作.
*/
	static void Init() ;

/*
	openssl的结束清除动作.
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
	初试化 public key.
*/
	bool InitPublicKey( const char * pN, const char * pE ) ;

/*
	初试化 private key.
*/
	bool InitPrivateKey( const char * pN, const char * pE, const char * pD ) ;

/*
	产生一个 BitLength位的 key.

	公匙： (n,e)					// 16进制string	
	私匙： (n,e,d)					// 16进制string	

*/
	static bool GenKey( std::string& echoN, std::string& echoE, std::string& echoD, int BitLength = 1024 ) ;

/*
	(用公匙)加密.
*/
	bool   Encrpt( unsigned char* pSrcBuf, int SrcSize, unsigned char* pDestBuf, int& echoDestSize ) ;


/*
	(用私匙)解密.
*/
	bool   Decrpt( unsigned char* pSrcBuf, int SrcSize, unsigned char* pDestBuf, int& echoDestSize ) ;

/*
	查询原子包的大小.
*/
	int	   QueryAtomSize() ; 	

/*
	查询 扣除填充部分 的大小.
*/
	int	   QueryAtomSize_SubPadding() ; 	

public:

	RSA*	m_pKey ;

	// 填充模式, paul, 2010-11-20, add.

		// 注: 目前只支持了RSA_PKCS1_PADDING, 其他模式未支持.
	int		m_padding ;
};



#endif 