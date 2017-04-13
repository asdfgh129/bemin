//this file is part of eMule
//Copyright (C)2002-2008 Merkur ( strEmail.Format("%s@%s", "devteam", "emule-project.net") / http://www.emule-project.net )
//
//This program is free software; you can redistribute it and/or
//modify it under the terms of the GNU General Public License
//as published by the Free Software Foundation; either
//version 2 of the License, or (at your option) any later version.
//
//This program is distributed in the hope that it will be useful,
//but WITHOUT ANY WARRANTY; without even the implied warranty of
//MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	See the
//GNU General Public License for more details.
//
//You should have received a copy of the GNU General Public License
//along with this program; if not, write to the Free Software
//Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

/* Basic Obfuscated Handshake Protocol Client <-> Client:
	-Keycreation:
	 - Client A (Outgoing connection):
				Sendkey:	Md5(<UserHashClientB 16><MagicValue34 1><RandomKeyPartClientA 4>)  21
				Receivekey: Md5(<UserHashClientB 16><MagicValue203 1><RandomKeyPartClientA 4>) 21
	 - Client B (Incomming connection):
				Sendkey:	Md5(<UserHashClientB 16><MagicValue203 1><RandomKeyPartClientA 4>) 21
				Receivekey: Md5(<UserHashClientB 16><MagicValue34 1><RandomKeyPartClientA 4>)  21
		NOTE: First 1024 Bytes are discarded

	- Handshake
			-> The handshake is encrypted - except otherwise noted - by the Keys created above
			-> Handshake is blocking - do not start sending an answer before the request is completly received (this includes the random bytes)
			-> EncryptionMethod = 0 is Obfuscation and the only supported right now
		Client A: <SemiRandomNotProtocolMarker 1[Unencrypted]><RandomKeyPart 4[Unencrypted]><MagicValue 4><EncryptionMethodsSupported 1><EncryptionMethodPreferred 1><PaddingLen 1><RandomBytes PaddingLen%max256>
		Client B: <MagicValue 4><EncryptionMethodsSelected 1><PaddingLen 1><RandomBytes PaddingLen%max 256>
			-> The basic handshake is finished here, if an additional/different EncryptionMethod was selected it may continue negotiating details for this one

	- Overhead: 18-48 (~33) Bytes + 2 * IP/TCP Headers per Connection

	- Security for Basic Obfuscation:
			- Random looking stream, very limited protection against passive eavesdropping single connections

	- Additional Comments:
			- RandomKeyPart is needed to make multiple connections between two clients look different (but still random), since otherwise the same key
			  would be used and RC4 would create the same output. Since the key is a MD5 hash it doesnt weakens the key if that part is known
		    - Why DH-KeyAgreement isn't used as basic obfuscation key: It doesn't offers substantial more protection against passive connection based protocol identification, it has about 200 bytes more overhead,
			  needs more CPU time, we cannot say if the received data is junk, unencrypted or part of the keyagreement before the handshake is finished without loosing the complete randomness,
			  it doesn't offers substantial protection against eavesdropping without added authentification

Basic Obfuscated Handshake Protocol Client <-> Server:
    - RC4 Keycreation:
     - Client (Outgoing connection):
                Sendkey:    Md5(<S 96><MagicValue34 1>)  97
                Receivekey: Md5(<S 96><MagicValue203 1>) 97
     - Server (Incomming connection):
                Sendkey:    Md5(<S 96><MagicValue203 1>)  97
                Receivekey: Md5(<S 96><MagicValue34 1>) 97

     NOTE: First 1024 Bytes are discarded

    - Handshake
            -> The handshake is encrypted - except otherwise noted - by the Keys created above
            -> Handshake is blocking - do not start sending an answer before the request is completly received (this includes the random bytes)
            -> EncryptionMethod = 0 is Obfuscation and the only supported right now

        Client: <SemiRandomNotProtocolMarker 1[Unencrypted]><G^A 96 [Unencrypted]><RandomBytes 0-15 [Unencrypted]>
        Server: <G^B 96 [Unencrypted]><MagicValue 4><EncryptionMethodsSupported 1><EncryptionMethodPreferred 1><PaddingLen 1><RandomBytes PaddingLen>
        Client: <MagicValue 4><EncryptionMethodsSelected 1><PaddingLen 1><RandomBytes PaddingLen> (Answer delayed till first payload to save a frame)


            -> The basic handshake is finished here, if an additional/different EncryptionMethod was selected it may continue negotiating details for this one

    - Overhead: 206-251 (~229) Bytes + 2 * IP/TCP Headers Headers per Connectionon

	- DH Agreement Specifics: sizeof(a) and sizeof(b) = 128 Bits, g = 2, p = dh768_p (see below), sizeof p, s, etc. = 768 bits
*/

#include "stdafx.h"
#include "EncryptedStreamSocket.h"
#include "emule.h"
#include "md5sum.h"
#include "Log.h"
#include "preferences.h"
#include "otherfunctions.h"
#include "safefile.h"
#include "opcodes.h"
#include "clientlist.h"
#include "sockets.h"
// cryptoPP used for DH integer calculations
#pragma warning(disable:4516) // access-declarations are deprecated; member using-declarations provide a better alternative
#pragma warning(disable:4100) // unreferenced formal parameter
#include <cryptopp/osrng.h>
#pragma warning(default:4100) // unreferenced formal parameter
#pragma warning(default:4516) // access-declarations are deprecated; member using-declarations provide a better alternative

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif


#define	MAGICVALUE_REQUESTER	34							// modification of the requester-send and server-receive key
#define	MAGICVALUE_SERVER		203							// modification of the server-send and requester-receive key
#define	MAGICVALUE_SYNC			0x835E6FC4					// value to check if we have a working encrypted stream
#define DHAGREEMENT_A_BITS		128

#define PRIMESIZE_BYTES	 96
///snow : 素数P prime number
static unsigned char dh768_p[]={
        0xF2,0xBF,0x52,0xC5,0x5F,0x58,0x7A,0xDD,0x53,0x71,0xA9,0x36,
        0xE8,0x86,0xEB,0x3C,0x62,0x17,0xA3,0x3E,0xC3,0x4C,0xB4,0x0D,
        0xC7,0x3A,0x41,0xA6,0x43,0xAF,0xFC,0xE7,0x21,0xFC,0x28,0x63,
        0x66,0x53,0x5B,0xDB,0xCE,0x25,0x9F,0x22,0x86,0xDA,0x4A,0x91,
        0xB2,0x07,0xCB,0xAA,0x52,0x55,0xD4,0xF6,0x1C,0xCE,0xAE,0xD4,
        0x5A,0xD5,0xE0,0x74,0x7D,0xF7,0x78,0x18,0x28,0x10,0x5F,0x34,
        0x0F,0x76,0x23,0x87,0xF8,0x8B,0x28,0x91,0x42,0xFB,0x42,0x68,
        0x8F,0x05,0x15,0x0F,0x54,0x8B,0x5F,0x43,0x6A,0xF7,0x0D,0xF3,
        };

static CryptoPP::AutoSeededRandomPool cryptRandomGen;

IMPLEMENT_DYNAMIC(CEncryptedStreamSocket, CAsyncSocketEx)

CEncryptedStreamSocket::CEncryptedStreamSocket(){
	///snow:如果客户端支持加密连接，则m_StreamCryptState初始状态为ECS_UNKNOWN，否则为ECS_NONE
	m_StreamCryptState = thePrefs.IsClientCryptLayerSupported() ? ECS_UNKNOWN : ECS_NONE;
	m_NegotiatingState = ONS_NONE;
	m_pRC4ReceiveKey = NULL;
	m_pRC4SendKey = NULL;
	m_nObfuscationBytesReceived = 0;
	m_bFullReceive = true;
	m_dbgbyEncryptionSupported = 0xFF;
	m_dbgbyEncryptionRequested = 0xFF;
	m_dbgbyEncryptionMethodSet = 0xFF;
	m_nReceiveBytesWanted = 0;
	m_pfiReceiveBuffer = NULL;
	m_pfiSendBuffer = NULL;
	m_EncryptionMethod = ENM_OBFUSCATION;
	m_nRandomKeyPart = 0;
	m_bServerCrypt = false;
};

CEncryptedStreamSocket::~CEncryptedStreamSocket(){
	delete m_pRC4ReceiveKey;
	delete m_pRC4SendKey;
	if (m_pfiReceiveBuffer != NULL)
		free(m_pfiReceiveBuffer->Detach());
	delete m_pfiReceiveBuffer;
	delete m_pfiSendBuffer;
};

void CEncryptedStreamSocket::CryptPrepareSendData(uchar* pBuffer, uint32 nLen){
	if (!IsEncryptionLayerReady()){
		ASSERT( false ); // must be a bug
		return;
	}
	///snow:意思是当m_StreamCryptState == ECS_UNKNOWN时，表示程序接收到呼入连接，还未协商一致，这个时候不可能发送数据
	///snow:m_StreamCryptState == ECS_UNKNOWN的情况只有在CEncryptedStreamSocket构造函数中可能被赋值
	///snow:	m_StreamCryptState = thePrefs.IsClientCryptLayerSupported() ? ECS_UNKNOWN : ECS_NONE;
	if (m_StreamCryptState == ECS_UNKNOWN){
		//this happens when the encryption option was not set on a outgoing connection
		//or if we try to send before receiving on a incoming connection - both shouldn't happen
		m_StreamCryptState = ECS_NONE;
		DebugLogError(_T("CEncryptedStreamSocket: Overwriting State ECS_UNKNOWN with ECS_NONE because of premature Send() (%s)"), DbgGetIPString());
	}
	///snow:要发送数据，状态必须是ECS_ENCRYPTING，错了，是状态如果是ECS_ENCRYPTING，则加密数据，否则，啥也不干
	if (m_StreamCryptState == ECS_ENCRYPTING)
	{
		///snow:add by snow
		theApp.QueueTraceLogLine(TRACE_STREAM_DATA,_T("Function:%hs|Line:%i|Socket:%i|IP:%s|Port:%i|Size:%i|Opcode:|Protocol:|Content(Hex):%s|Content:"),__FUNCTION__,__LINE__,m_SocketData.hSocket,GetPeerAddress().GetBuffer(0),GetPeerPort(),nLen,ByteToHexStr(pBuffer,nLen).GetBuffer(0));

		RC4Crypt(pBuffer, pBuffer, nLen, m_pRC4SendKey);

		///snow:add by snow
		theApp.QueueTraceLogLine(TRACE_STREAM_DATA,_T("Function:%hs|Line:%i|Socket:%i|IP:%s|Port:%i|Size:%i|Opcode:|Protocol:|Content(Hex):%s|Content:"),__FUNCTION__,__LINE__,m_SocketData.hSocket,GetPeerAddress().GetBuffer(0),GetPeerPort(),nLen,ByteToHexStr(pBuffer,nLen).GetBuffer(0));
	}
}

// unfortunatly sending cannot be made transparent for the derived class, because of WSA_WOULDBLOCK
// together with the fact that each byte must pass the keystream only once
int CEncryptedStreamSocket::Send(const void* lpBuf, int nBufLen, int nFlags){
	if (!IsEncryptionLayerReady()){
		ASSERT( false ); // must be a bug
		return 0;
	}
	///snow:发送在Negotiate()阶段延迟发送的数据包
	else if (m_bServerCrypt && m_StreamCryptState == ECS_ENCRYPTING && m_pfiSendBuffer != NULL){
		ASSERT( m_NegotiatingState == ONS_BASIC_SERVER_DELAYEDSENDING );
		// handshakedata was delayed to put it into one frame with the first paypload to the server
		// do so now with the payload attached
		int nRes = SendNegotiatingData(lpBuf, nBufLen, nBufLen);///snow:这里的调用发生在Negotiate()调用SendNegotiatingData之后，是第二次调用SendNegotiatingData，这次将真正的发送出数据
		ASSERT( nRes != SOCKET_ERROR );
		(void)nRes;
		return nBufLen;	// report a full send, even if we didn't for some reason - the data is know in our buffer and will be handled later
	}
	else if (m_NegotiatingState == ONS_BASIC_SERVER_DELAYEDSENDING)  ///snow:标记是ONS_BASIC_SERVER_DELAYEDSENDING，但没有m_pfiSendBuffer，出错了！
		ASSERT( false );

	///snow:这段代码同CryptPrepareSendData()中的代码
	if (m_StreamCryptState == ECS_UNKNOWN){
		//this happens when the encryption option was not set on a outgoing connection
		//or if we try to send before receiving on a incoming connection - both shouldn't happen
		m_StreamCryptState = ECS_NONE;
		DebugLogError(_T("CEncryptedStreamSocket: Overwriting State ECS_UNKNOWN with ECS_NONE because of premature Send() (%s)"), DbgGetIPString());
	}

	///snow:如果不需要加密连接，则直接调用父类Send()函数
	return CAsyncSocketEx::Send(lpBuf, nBufLen, nFlags);
}

bool CEncryptedStreamSocket::IsEncryptionLayerReady(){

	///snow:如果m_streamCryptState不为三者之一：ECS_NONE 、 ECS_ENCRYPTING 、 ECS_UNKNOWN，返回false，其它情况为ECS_PENDING,ECS_PENDING_SERVER,ECS_NEGOTIATING，三种情况均表示正在协商中
	///snow:m_pfiSendBuffer为空或者 服务器支持乱序加密且协商状态为延迟发送
	return ( (m_StreamCryptState == ECS_NONE || m_StreamCryptState == ECS_ENCRYPTING || m_StreamCryptState == ECS_UNKNOWN )
		&& (m_pfiSendBuffer == NULL || (m_bServerCrypt && m_NegotiatingState == ONS_BASIC_SERVER_DELAYEDSENDING)) );
}


int CEncryptedStreamSocket::Receive(void* lpBuf, int nBufLen, int nFlags){
	m_nObfuscationBytesReceived = CAsyncSocketEx::Receive(lpBuf, nBufLen, nFlags);///snow:实际接收的字节数，是未解密的字节数
	m_bFullReceive = m_nObfuscationBytesReceived == (uint32)nBufLen;   ///snow:是否全部接收，在CEMSocket::Receive()中给pendingOnReceive赋值

	if(m_nObfuscationBytesReceived == SOCKET_ERROR || m_nObfuscationBytesReceived <= 0){
		return m_nObfuscationBytesReceived;
	}
	switch (m_StreamCryptState) {
		case ECS_NONE: // disabled, just pass it through
			return m_nObfuscationBytesReceived;
		case ECS_PENDING:
		case ECS_PENDING_SERVER:
			ASSERT( false );
			DebugLogError(_T("CEncryptedStreamSocket Received data before sending on outgoing connection"));
			m_StreamCryptState = ECS_NONE;
			return m_nObfuscationBytesReceived;
		case ECS_UNKNOWN:{   ///snow:呼入连接incomimg
			uint32 nRead = 1;
			bool bNormalHeader = false;
			switch (((uchar*)lpBuf)[0]){
				case OP_EDONKEYPROT:
				case OP_PACKEDPROT:
				case OP_EMULEPROT:
					bNormalHeader = true;
					break;
			}
			if (!bNormalHeader){  ///snow:不是正常的包头，表示已加密
				StartNegotiation(false);   ///snow:开始呼入连接的协商
				const uint32 nNegRes = Negotiate((uchar*)lpBuf + nRead, m_nObfuscationBytesReceived - nRead);
				if (nNegRes == (-1))
					return 0;
				nRead += nNegRes;
				if (nRead != (uint32)m_nObfuscationBytesReceived){
					// this means we have more data then the current negotiation step required (or there is a bug) and this should never happen
					// (note: even if it just finished the handshake here, there still can be no data left, since the other client didnt received our response yet)
					DebugLogError(_T("CEncryptedStreamSocket: Client %s sent more data then expected while negotiating, disconnecting (1)"), DbgGetIPString());
					OnError(ERR_ENCRYPTION);
				}
				return 0;
			}
			else{   ///snow:呼入的连接没有加密，重置m_StreamCryptState为ECS_NONE
				// doesn't seems to be encrypted
				m_StreamCryptState = ECS_NONE;

				// if we require an encrypted connection, cut the connection here. This shouldn't happen that often
				// at least with other up-to-date eMule clients because they check for incompability before connecting if possible
				if (thePrefs.IsClientCryptLayerRequired()){
					// TODO: Remove me when i have been solved
					// Even if the Require option is enabled, we currently have to accept unencrypted connection which are made
					// for lowid/firewall checks from servers and other from us selected client. Otherwise, this option would
					// always result in a lowid/firewalled status. This is of course not nice, but we can't avoid this walkarround
					// untill servers and kad completely support encryption too, which will at least for kad take a bit
					// only exception is the .ini option ClientCryptLayerRequiredStrict which will even ignore test connections
					// Update: New server now support encrypted callbacks

					SOCKADDR_IN sockAddr = {0};
					int nSockAddrLen = sizeof(sockAddr);
					GetPeerName((SOCKADDR*)&sockAddr, &nSockAddrLen);
					if (thePrefs.IsClientCryptLayerRequiredStrict() || (!theApp.serverconnect->AwaitingTestFromIP(sockAddr.sin_addr.S_un.S_addr)
						&& !theApp.clientlist->IsKadFirewallCheckIP(sockAddr.sin_addr.S_un.S_addr)) )
					{
#if defined(_DEBUG) || defined(_BETA)
					// TODO: Remove after testing
					AddDebugLogLine(DLP_DEFAULT, false, _T("Rejected incoming connection because Obfuscation was required but not used %s"), DbgGetIPString() );
#endif
						OnError(ERR_ENCRYPTION_NOTALLOWED);
						return 0;
					}
					else
						AddDebugLogLine(DLP_DEFAULT, false, _T("Incoming unencrypted firewallcheck connection permitted despite RequireEncryption setting  - %s"), DbgGetIPString() );
				}

				return m_nObfuscationBytesReceived; // buffer was unchanged, we can just pass it through
			}
		}
		case ECS_ENCRYPTING:   ///snow:已加密协商完成，直接解密
			// basic obfuscation enabled and set, so decrypt and pass along
			RC4Crypt((uchar*)lpBuf, (uchar*)lpBuf, m_nObfuscationBytesReceived, m_pRC4ReceiveKey);

			///snow:add by snow
			theApp.QueueTraceLogLine(TRACE_STREAM_DATA,_T("Function:%hs|Line:%i|Socket:%i|IP:%s|Port:%i|Size:%i|Opcode:|Protocol:|Content(Hex):%s|Content:"),__FUNCTION__,__LINE__,m_SocketData.hSocket,GetPeerAddress().GetBuffer(0),GetPeerPort(),m_nObfuscationBytesReceived,ByteToHexStr((uchar*)lpBuf,m_nObfuscationBytesReceived).GetBuffer(0));

			return m_nObfuscationBytesReceived;
		case ECS_NEGOTIATING:{   ///snow:还在协商阶段
			const uint32 nRead = Negotiate((uchar*)lpBuf, m_nObfuscationBytesReceived);   ///snow:返回值有三种情况：0，表示m_nReceiveBytesWanted > 512
			                                                                              ///snow:              nRead，表示已读取的字节数，如果nRead==m_nObfuscationBytesReceived，正常，
			                                                                              ///snow:                     如果nRead!=m_nObfuscationBytesReceived，表示剩下未读的字节数<m_nReceiveBytesWanted，数据不全
			                                                                              ///snow:                 -1，表示发生错误，两类：Magic Value错，或Method错
			if (nRead == (-1))   ///snow:发生错误
				return 0;
			else if (nRead != (uint32)m_nObfuscationBytesReceived && m_StreamCryptState != ECS_ENCRYPTING){  ///snow:尚未加密，数据不全
				// this means we have more data then the current negotiation step required (or there is a bug) and this should never happen
				DebugLogError(_T("CEncryptedStreamSocket: Client %s sent more data then expected while negotiating, disconnecting (2)"), DbgGetIPString());
				OnError(ERR_ENCRYPTION);
				return 0;
			}
			else if (nRead != (uint32)m_nObfuscationBytesReceived && m_StreamCryptState == ECS_ENCRYPTING){   ///snow:已经加密了，数据多了
				// we finished the handshake and if we this was an outgoing connection it is allowed (but strange and unlikely) that the client sent payload
				DebugLogWarning(_T("CEncryptedStreamSocket: Client %s has finished the handshake but also sent payload on a outgoing connection"), DbgGetIPString());
				memmove(lpBuf, (uchar*)lpBuf + nRead, m_nObfuscationBytesReceived - nRead);
				return m_nObfuscationBytesReceived - nRead;
			}
			else
				return 0;
		}
		default:
			ASSERT( false );
			return m_nObfuscationBytesReceived;
	}
}

///snow: 在CServerSocket::ConnectTo()，CHttpClientReqSocket::CHttpClientReqSocket（），CUpDownClient::Connect()中通过变量（CClientReqSocket）socket调用，

void CEncryptedStreamSocket::SetConnectionEncryption(bool bEnabled, const uchar* pTargetClientHash, bool bServerConnection){

	///snow start:流加密状态既不是未加密也不是呼入连接（是其它四种情况：
	///          ECS_PENDING,			// Outgoing connection, will start sending encryption protocol
	///          ECS_PENDING_SERVER,		// Outgoing serverconnection, will start sending encryption protocol
	///          ECS_NEGOTIATING,		// Encryption supported, handshake still uncompleted
	///          ECS_ENCRYPTING			// Encryption enabled
	///          表示客户端已处于等待加密连接状态或已建立加密连接状态，无需再次设置，函数直接返回  ：  snow end    

	if (m_StreamCryptState != ECS_UNKNOWN && m_StreamCryptState != ECS_NONE){
		
		///snow : !m_StreamCryptState == ECS_NONE一定为true!此句多余！
		
		if (!m_StreamCryptState == ECS_NONE || bEnabled)
			
			///snow ：如果bEnabled为true，则抛出断言，表示连接已经处于加密状态，不需要再次enable，程序代码逻辑有误，是个错误调用，
			ASSERT( false );
		return;
	}

	/// snow start : m_StreamCryptState现在可能是
	///	    ECS_NONE = 0,			// Disabled or not available
	///     ECS_UNKNOWN,			// Incoming connection, will test the first incoming data for encrypted protocol
    ///     Key还没创建！  ：snow end

	ASSERT( m_pRC4SendKey == NULL );
	ASSERT( m_pRC4ReceiveKey == NULL );

	/// snow :不是到服务器的连接，目标客户端的ID哈希值不是NULL,且目的是要启动加密连接，在CUpDownClient::Connect()中调用
	if (bEnabled && pTargetClientHash != NULL && !bServerConnection){
		m_StreamCryptState = ECS_PENDING;  ///snow:是outgoing connection，状态为连接等待
		
		///snow start：建立混淆密钥	 - Client A (Outgoing connection):
		///		Sendkey:	Md5(<UserHashClientB 16><MagicValue34 1><RandomKeyPartClientA 4>)  21
		///		Receivekey: Md5(<UserHashClientB 16><MagicValue203 1><RandomKeyPartClientA 4>) 21
		// create obfuscation keys, see on top for key format

		// use the crypt random generator
		m_nRandomKeyPart = cryptRandomGen.GenerateWord32();

		
		uchar achKeyData[21];
		md4cpy(achKeyData, pTargetClientHash);
		memcpy(achKeyData + 17, &m_nRandomKeyPart, 4);
		///snow:sendkey的MagicValue是 MAGICVALUE_REQUESTER，receivekey的magicvalue是MAGICVALUE_SERVER，所以是Client A
		achKeyData[16] = MAGICVALUE_REQUESTER;
		MD5Sum md5(achKeyData, sizeof(achKeyData));
		m_pRC4SendKey = RC4CreateKey(md5.GetRawHash(), 16, NULL);

		achKeyData[16] = MAGICVALUE_SERVER;
		md5.Calculate(achKeyData, sizeof(achKeyData));
		m_pRC4ReceiveKey = RC4CreateKey(md5.GetRawHash(), 16, NULL);
	}
	/// snow :是到服务器的连接，且目的是要启动加密连接
	else if (bServerConnection && bEnabled){
		m_bServerCrypt = true;
		m_StreamCryptState = ECS_PENDING_SERVER;
	}
	else{   ///snow:取消加密连接,bEnabled为false
		ASSERT( !bEnabled ); 
		///snow start:如果bEnabled为true，则抛出断言，不考虑bEnabled为true时，剩下的两种情况是：
		///!bServerConnection&&pTargetClientHash == NULL 和  bServerConnection&&pTargetClientHash != NULL，
		///snow end:如果有这种情况的调用，则属程序代码逻辑有误，是个错误调用
		m_StreamCryptState = ECS_NONE;
	}
}

///snow:两种情况会被触发：connect连接成功之后，WSAEWOULDBLOCK解除之时。本函数只处理connect连接成功之后的情况
void CEncryptedStreamSocket::OnSend(int){
	///snow:呼出连接，准备开始握手，开始协商，退出函数
	///snow:ECS_PENDING或ECS_PENDING_SERVER状态在SetConnectionEncryption函数中设置
	// if the socket just connected and this is outgoing, we might want to start the handshake here
	if (m_StreamCryptState == ECS_PENDING || m_StreamCryptState == ECS_PENDING_SERVER){
		StartNegotiation(true);
		return;
	}
	///snow:其它状态，必须是ECS_NEGOTIATING或ECS_ENCRYPTING
	// check if we have negotiating data pending
	if (m_pfiSendBuffer != NULL){   ///snow:有未发送的数据
		ASSERT( m_StreamCryptState >= ECS_NEGOTIATING );
		SendNegotiatingData(NULL, 0);
	}
}

///snow:此函数在两个地方被调用，一个是Receive()函数，以StartNegotiation（false)方式调用，表示是incoming connection，
///    一个是OnSend()函数，以StartNegotiation（true）方式调用，表示是outgoing connection
void CEncryptedStreamSocket::StartNegotiation(bool bOutgoing){
	///snow:incoming connection，获取4字节的ClientA的RandomPart
	if (!bOutgoing){
		m_NegotiatingState = ONS_BASIC_CLIENTA_RANDOMPART;
		m_StreamCryptState = ECS_NEGOTIATING;
		m_nReceiveBytesWanted = 4;
	}
	else if (m_StreamCryptState == ECS_PENDING){   ///snow:到客户端的Outgoing connection
		///snow:握手,准备ClientA报文，共29字节
	    ///  Client A: <SemiRandomNotProtocolMarker 1[Unencrypted]><RandomKeyPart 4[Unencrypted]><MagicValue 4><EncryptionMethodsSupported 1><EncryptionMethodPreferred 1><PaddingLen 1><RandomBytes PaddingLen%max256>
		CSafeMemFile fileRequest(29);
		const uint8 bySemiRandomNotProtocolMarker = GetSemiRandomNotProtocolMarker();
		fileRequest.WriteUInt8(bySemiRandomNotProtocolMarker);
		fileRequest.WriteUInt32(m_nRandomKeyPart);
		fileRequest.WriteUInt32(MAGICVALUE_SYNC);
		const uint8 bySupportedEncryptionMethod = ENM_OBFUSCATION; // we do not support any further encryption in this version
		fileRequest.WriteUInt8(bySupportedEncryptionMethod);
		fileRequest.WriteUInt8(bySupportedEncryptionMethod); // so we also prefer this one
		uint8 byPadding = (uint8)(cryptRandomGen.GenerateByte() % (thePrefs.GetCryptTCPPaddingLength() + 1));
		fileRequest.WriteUInt8(byPadding);
		for (int i = 0; i < byPadding; i++)
			fileRequest.WriteUInt8(cryptRandomGen.GenerateByte());
		///snow:发送握手CleintA报文后，设置协商状态为等待ClientB回送协商报文
		m_NegotiatingState = ONS_BASIC_CLIENTB_MAGICVALUE;
		m_StreamCryptState = ECS_NEGOTIATING;
		m_nReceiveBytesWanted = 4;

		SendNegotiatingData(fileRequest.GetBuffer(), (uint32)fileRequest.GetLength(), 5);
	}
	else if (m_StreamCryptState == ECS_PENDING_SERVER){///snow:到服务器的Outgoing connection
		///snow:准备Client端的握手协商报文，报文格式与内容：总共111字节，1个字节的协议标志，96字节的密钥，14字节的随机数
		///   Client: <SemiRandomNotProtocolMarker 1[Unencrypted]><G^A 96 [Unencrypted]><RandomBytes 0-15 [Unencrypted]>

		CSafeMemFile fileRequest(113);
		const uint8 bySemiRandomNotProtocolMarker = GetSemiRandomNotProtocolMarker();
		fileRequest.WriteUInt8(bySemiRandomNotProtocolMarker);
		///snow:随机生成私有a（m_cryptDHA）
		m_cryptDHA.Randomize(cryptRandomGen, DHAGREEMENT_A_BITS); // our random a
		ASSERT( m_cryptDHA.MinEncodedSize() <= DHAGREEMENT_A_BITS / 8 );
		///snow:将dh768_p数组转换为素数P
		CryptoPP::Integer cryptDHPrime((byte*)dh768_p, PRIMESIZE_BYTES);  // our fixed prime
		///snow:设g=2(CryptoPP::Integer(2)),求公有A(cryptDHGexpAmodP)
		// calculate g^a % p
		CryptoPP::Integer cryptDHGexpAmodP = CryptoPP::a_exp_b_mod_c(CryptoPP::Integer(2), m_cryptDHA, cryptDHPrime);
		ASSERT( m_cryptDHA.MinEncodedSize() <= PRIMESIZE_BYTES );
		// put the result into a buffer
		uchar aBuffer[PRIMESIZE_BYTES];
		cryptDHGexpAmodP.Encode(aBuffer, PRIMESIZE_BYTES);

		///snow:将公钥A发送给服务器，服务器可以据此计算出公钥B及共享密钥K  B=G exp b mod P  K=A exp b mod P  其中b为服务器端的私钥，P（dh768_p）和G（2）为固定数值，可公开，所以服务器和客户端约定一致，不可更改！
		fileRequest.Write(aBuffer, PRIMESIZE_BYTES);
		uint8 byPadding = (uint8)(cryptRandomGen.GenerateByte() % 16); // add random padding
		fileRequest.WriteUInt8(byPadding);
		for (int i = 0; i < byPadding; i++)
			fileRequest.WriteUInt8(cryptRandomGen.GenerateByte());
		///snow:发送握手Cleint报文后，设置协商状态为等待Server回送协商报文
		m_NegotiatingState = ONS_BASIC_SERVER_DHANSWER;
		m_StreamCryptState = ECS_NEGOTIATING;
		m_nReceiveBytesWanted = 96;

		SendNegotiatingData(fileRequest.GetBuffer(), (uint32)fileRequest.GetLength(), (uint32)fileRequest.GetLength());
	}
	else{
		ASSERT( false );
		m_StreamCryptState = ECS_NONE;
		return;
	}
}


/*******************************************snow:start*********************************************************
/*   两处调用，均为被Reveive()函数调用
/*  case ECS_UNKNOWN:处
/*				const uint32 nNegRes = Negotiate((uchar*)lpBuf + nRead, m_nObfuscationBytesReceived - nRead);
/*  case ECS_NEGOTIATING:处
/* 			const uint32 nRead = Negotiate((uchar*)lpBuf, m_nObfuscationBytesReceived);

        Client: <MagicValue 4><EncryptionMethodsSelected 1><PaddingLen 1><RandomBytes PaddingLen> (Answer delayed till first payload to save a frame)
*******************************************snow:end************************************************************/
int CEncryptedStreamSocket::Negotiate(const uchar* pBuffer, uint32 nLen){
	uint32 nRead = 0;
	ASSERT( m_nReceiveBytesWanted > 0 );
	try{

		///snow：报文一次性发过来，根据需要(m_nReceiveBytesWanted的值，在case处理完后重新赋值），反复提取
		while (m_NegotiatingState != ONS_COMPLETE && m_nReceiveBytesWanted > 0){  ///snow:协商尚未完成
			if (m_nReceiveBytesWanted > 512){
				ASSERT( false );
				return 0;
			}
			///snow:分配内存，pBuffer存放的是接收到的整个报文，m_pfiReceiveBuffer存入的是报文中的片断
			if (m_pfiReceiveBuffer == NULL){
				BYTE* pReceiveBuffer = (BYTE*)malloc(512); // use a fixed size buffer
				if (pReceiveBuffer == NULL)
					AfxThrowMemoryException();
				m_pfiReceiveBuffer = new CSafeMemFile(pReceiveBuffer, 512);
			}
			///snow:nRead初始为0，所以第一次比较是min(nLen,m_nReceiveBytesWanted),
			///如果nLen>=m_nReceiveBytesWanted,nToRead=m_nReceiveBytesWanted=nRead，m_nReceiveBytesWanted=0;
			///如果nLen<m_nReceiveBytesWanted,nToRead=nLen=nRead,m_nReceiveBytesWanted-=nToRead>0,return nRead;然后再次调用
			///const uint32 nNegRes = Negotiate((uchar*)lpBuf + nRead, m_nObfuscationBytesReceived - nRead);
			///报文一次性发过来，根据需要分多次读取
			const uint32 nToRead =  min(nLen - nRead, m_nReceiveBytesWanted);
			m_pfiReceiveBuffer->Write(pBuffer + nRead, nToRead);
			nRead += nToRead;
			m_nReceiveBytesWanted -= nToRead;  ///snow:m_nReceiveBytesWanted==0
			if (m_nReceiveBytesWanted > 0)   ///snow:数据不全，没有读取到完整的数据
				return nRead;
			///snow:m_nReceiveBytesWanted=0;握手协商报文数据已读取完毕，
			const uint32 nCurrentBytesLen = (uint32)m_pfiReceiveBuffer->GetPosition();

			if (m_NegotiatingState != ONS_BASIC_CLIENTA_RANDOMPART && m_NegotiatingState != ONS_BASIC_SERVER_DHANSWER){ // don't have the keys yet
				BYTE* pCryptBuffer = m_pfiReceiveBuffer->Detach();
				RC4Crypt(pCryptBuffer, pCryptBuffer, nCurrentBytesLen, m_pRC4ReceiveKey);
				m_pfiReceiveBuffer->Attach(pCryptBuffer, 512);
			}
			m_pfiReceiveBuffer->SeekToBegin();

			switch (m_NegotiatingState){
				case ONS_NONE: // would be a bug
					ASSERT( false );
					return 0;
				case ONS_BASIC_CLIENTA_RANDOMPART:{  ///snow:incoming connection
					ASSERT( m_pRC4ReceiveKey == NULL );
					///snow:准备ClientB Key
					///	 - Client B (Incomming connection):
				    ///  Sendkey:	Md5(<UserHashClientB 16><MagicValue203 1><RandomKeyPartClientA 4>) 21
				    /// Receivekey: Md5(<UserHashClientB 16><MagicValue34 1><RandomKeyPartClientA 4>)  21
					uchar achKeyData[21];
					md4cpy(achKeyData, thePrefs.GetUserHash());
					achKeyData[16] = MAGICVALUE_REQUESTER;
					m_pfiReceiveBuffer->Read(achKeyData + 17, 4); // random key part sent from remote client

					MD5Sum md5(achKeyData, sizeof(achKeyData));
					m_pRC4ReceiveKey = RC4CreateKey(md5.GetRawHash(), 16, NULL);
					achKeyData[16] = MAGICVALUE_SERVER;
					md5.Calculate(achKeyData, sizeof(achKeyData));
					m_pRC4SendKey = RC4CreateKey(md5.GetRawHash(), 16, NULL);

					m_NegotiatingState = ONS_BASIC_CLIENTA_MAGICVALUE;
					m_nReceiveBytesWanted = 4;  ///snow:MAGICVALUE_SYNC是4字节
					break;
				}
				case ONS_BASIC_CLIENTA_MAGICVALUE:{
					uint32 dwValue = m_pfiReceiveBuffer->ReadUInt32();
					if (dwValue == MAGICVALUE_SYNC){  ///snow:randompart同步成功，协商加密方法
						// yup, the one or the other way it worked, this is an encrypted stream
						//DEBUG_ONLY( DebugLog(_T("Received proper magic value, clientIP: %s"), DbgGetIPString()) );
						// set the receiver key
						m_NegotiatingState = ONS_BASIC_CLIENTA_METHODTAGSPADLEN;
						m_nReceiveBytesWanted = 3;  ///snow:为什么是3字节？ClientB是2字节，而Method只需1字节
					}
					else{
						DebugLogError(_T("CEncryptedStreamSocket: Received wrong magic value from clientIP %s on a supposly encrytped stream / Wrong Header"), DbgGetIPString());
						OnError(ERR_ENCRYPTION);
						return (-1);
					}
					break;
			    }
				case ONS_BASIC_CLIENTA_METHODTAGSPADLEN:
					m_dbgbyEncryptionSupported = m_pfiReceiveBuffer->ReadUInt8();
					m_dbgbyEncryptionRequested = m_pfiReceiveBuffer->ReadUInt8();
					if (m_dbgbyEncryptionRequested != ENM_OBFUSCATION)
						AddDebugLogLine(DLP_LOW, false, _T("CEncryptedStreamSocket: Client %s preffered unsupported encryption method (%i)"), DbgGetIPString(), m_dbgbyEncryptionRequested);
					m_nReceiveBytesWanted = m_pfiReceiveBuffer->ReadUInt8();
					m_NegotiatingState = ONS_BASIC_CLIENTA_PADDING;
					//if (m_nReceiveBytesWanted > 16)
					//	AddDebugLogLine(DLP_LOW, false, _T("CEncryptedStreamSocket: Client %s sent more than 16 (%i) padding bytes"), DbgGetIPString(), m_nReceiveBytesWanted);
					if (m_nReceiveBytesWanted > 0)
						break;
				case ONS_BASIC_CLIENTA_PADDING:{

					///snow:准备HandShake ClientB报文，
					///		Client B: <MagicValue 4><EncryptionMethodsSelected 1><PaddingLen 1><RandomBytes PaddingLen%max 256>

					// ignore the random bytes, send the response, set status complete
					CSafeMemFile fileResponse(26);
					fileResponse.WriteUInt32(MAGICVALUE_SYNC);
					const uint8 bySelectedEncryptionMethod = ENM_OBFUSCATION; // we do not support any further encryption in this version, so no need to look which the other client preferred
					fileResponse.WriteUInt8(bySelectedEncryptionMethod);

					SOCKADDR_IN sockAddr = {0};
					int nSockAddrLen = sizeof(sockAddr);
					GetPeerName((SOCKADDR*)&sockAddr, &nSockAddrLen);
					const uint8 byPaddingLen = theApp.serverconnect->AwaitingTestFromIP(sockAddr.sin_addr.S_un.S_addr) ? 16 : (thePrefs.GetCryptTCPPaddingLength() + 1);
					uint8 byPadding = (uint8)(cryptRandomGen.GenerateByte() % byPaddingLen);

					fileResponse.WriteUInt8(byPadding);
					for (int i = 0; i < byPadding; i++)
						fileResponse.WriteUInt8((uint8)rand());
					SendNegotiatingData(fileResponse.GetBuffer(), (uint32)fileResponse.GetLength());   ///snow:不同于服务器连接，这里没有延迟发送
					m_NegotiatingState = ONS_COMPLETE;
					m_StreamCryptState = ECS_ENCRYPTING;
					//DEBUG_ONLY( DebugLog(_T("CEncryptedStreamSocket: Finished Obufscation handshake with client %s (incoming)"), DbgGetIPString()) );
					break;
				}


				///snow:处理呼出连接
				case ONS_BASIC_CLIENTB_MAGICVALUE:{
					if (m_pfiReceiveBuffer->ReadUInt32() != MAGICVALUE_SYNC){
						DebugLogError(_T("CEncryptedStreamSocket: EncryptedstreamSyncError: Client sent wrong Magic Value as answer, cannot complete handshake (%s)"), DbgGetIPString());
						OnError(ERR_ENCRYPTION);
						return (-1);
					}
					m_NegotiatingState = ONS_BASIC_CLIENTB_METHODTAGSPADLEN;
					m_nReceiveBytesWanted = 2;
					break;
				}
				case ONS_BASIC_CLIENTB_METHODTAGSPADLEN:{
					m_dbgbyEncryptionMethodSet = m_pfiReceiveBuffer->ReadUInt8();
					if (m_dbgbyEncryptionMethodSet != ENM_OBFUSCATION){
						DebugLogError( _T("CEncryptedStreamSocket: Client %s set unsupported encryption method (%i), handshake failed"), DbgGetIPString(), m_dbgbyEncryptionMethodSet);
						OnError(ERR_ENCRYPTION);
						return (-1);
					}
					m_nReceiveBytesWanted = m_pfiReceiveBuffer->ReadUInt8();
					m_NegotiatingState = ONS_BASIC_CLIENTB_PADDING;
					if (m_nReceiveBytesWanted > 0)
						break;
				}
				case ONS_BASIC_CLIENTB_PADDING:
					// ignore the random bytes, the handshake is complete
					m_NegotiatingState = ONS_COMPLETE;
					m_StreamCryptState = ECS_ENCRYPTING;
					//DEBUG_ONLY( DebugLog(_T("CEncryptedStreamSocket: Finished Obufscation handshake with client %s (outgoing)"), DbgGetIPString()) );
					break;
				
				//  此处开始处理与服务器DH协商握手时服务器发来的报文，总共112字节，包括96字节的密钥，4字节的MagicValue，3个字节的加密方法，9字节的随机填充数
                //  Server: <G^B 96 [Unencrypted]><MagicValue 4><EncryptionMethodsSupported 1><EncryptionMethodPreferred 1><PaddingLen 1><RandomBytes PaddingLen>
                //  在读取时分四次读取，第一次处理DHANSWER,读取96字节，第二次处理MAGIVVALUE，读取4个字节，第三次处理METHODTAGSPADLEN，读取3个字节，第四次处理PADDING，读取9个字节 */
				
				case ONS_BASIC_SERVER_DHANSWER:{   ///snow:在StartNegotiation()中m_StreamCryptState == ECS_PENDING_SERVER时设置
					ASSERT( !m_cryptDHA.IsZero() );
					
					///snow start :    - RC4 Keycreation:
                    ///- Client (Outgoing connection)
                    ///           Sendkey:    Md5(<S 96><MagicValue34 1>)  97
                    ///           Receivekey: Md5(<S 96><MagicValue203 1>) 97
                    ///- Server (Incomming connection):
                    ///           Sendkey:    Md5(<S 96><MagicValue203 1>)  97
                    ///           Receivekey: Md5(<S 96><MagicValue34 1>) 97

					uchar aBuffer[PRIMESIZE_BYTES + 1];
					m_pfiReceiveBuffer->Read(aBuffer, PRIMESIZE_BYTES);
					CryptoPP::Integer cryptDHAnswer((byte*)aBuffer, PRIMESIZE_BYTES);
					CryptoPP::Integer cryptDHPrime((byte*)dh768_p, PRIMESIZE_BYTES);  // our fixed prime
					///snow:cryptDHAnswer为服务器计算出的公钥B，客户端根据公钥B，私钥a，素数P计算出共享密钥K，存入cryptResult  K=B exp a mod p
					CryptoPP::Integer cryptResult = CryptoPP::a_exp_b_mod_c(cryptDHAnswer, m_cryptDHA, cryptDHPrime);

					m_cryptDHA = 0;
					DEBUG_ONLY( ZeroMemory(aBuffer, sizeof(aBuffer)) );
					ASSERT( cryptResult.MinEncodedSize() <= PRIMESIZE_BYTES );

					// create the keys
					///snow:对DH交换计算出的共享密钥K进行md5和rc4加密，产生最后的密钥
					cryptResult.Encode(aBuffer, PRIMESIZE_BYTES);
					aBuffer[PRIMESIZE_BYTES] = MAGICVALUE_REQUESTER;
					MD5Sum md5(aBuffer, sizeof(aBuffer));
					m_pRC4SendKey = RC4CreateKey(md5.GetRawHash(), 16, NULL);
					aBuffer[PRIMESIZE_BYTES] = MAGICVALUE_SERVER;
					md5.Calculate(aBuffer, sizeof(aBuffer));
					m_pRC4ReceiveKey = RC4CreateKey(md5.GetRawHash(), 16, NULL);

					///snow:设置读取进度（m_NegotiatingState）及准备读取的字节数(m_nReceiveBytesWanted)，重新开始新一轮while
					m_NegotiatingState = ONS_BASIC_SERVER_MAGICVALUE;
					m_nReceiveBytesWanted = 4;  
					break;
				}
				case ONS_BASIC_SERVER_MAGICVALUE:{   ///snow:读取的值是C46F5E83，反序
					uint32 dwValue = m_pfiReceiveBuffer->ReadUInt32();
					if (dwValue == MAGICVALUE_SYNC){  ///snow:835E6FC4
						// yup, the one or the other way it worked, this is an encrypted stream
						DebugLog(_T("Received proper magic value after DH-Agreement from Serverconnection IP: %s"), DbgGetIPString());
						// set the receiver key
						m_NegotiatingState = ONS_BASIC_SERVER_METHODTAGSPADLEN;
						m_nReceiveBytesWanted = 3;
					}
					else{
						DebugLogError(_T("CEncryptedStreamSocket: Received wrong magic value after DH-Agreement from Serverconnection"), DbgGetIPString());
						OnError(ERR_ENCRYPTION);
						return (-1);
					}
					break;
			    }
				case ONS_BASIC_SERVER_METHODTAGSPADLEN:   ///snow:读取的数据是00 00 09，前两个字节表示是支持ENM_OBFUSCATION，使用ENM_OBFUSCATION，第三个字节是随机数字节数，下一次需要读取的字节数
					m_dbgbyEncryptionSupported = m_pfiReceiveBuffer->ReadUInt8();
					m_dbgbyEncryptionRequested = m_pfiReceiveBuffer->ReadUInt8();
					if (m_dbgbyEncryptionRequested != ENM_OBFUSCATION)
						AddDebugLogLine(DLP_LOW, false, _T("CEncryptedStreamSocket: Server %s preffered unsupported encryption method (%i)"), DbgGetIPString(), m_dbgbyEncryptionRequested);
					m_nReceiveBytesWanted = m_pfiReceiveBuffer->ReadUInt8();  ///snow:随机数字节数
					m_NegotiatingState = ONS_BASIC_SERVER_PADDING;
					if (m_nReceiveBytesWanted > 16)   ///snow:不可能大于16，大于16表示出错了
						AddDebugLogLine(DLP_LOW, false, _T("CEncryptedStreamSocket: Server %s sent more than 16 (%i) padding bytes"), DbgGetIPString(), m_nReceiveBytesWanted);
					if (m_nReceiveBytesWanted > 0)
						break;
				case ONS_BASIC_SERVER_PADDING:{
					///snow:服务器发来的报文读取并处理完毕，发回确认报文，完成DH乱序加密协商握手过程 
					///snow:   Client: <MagicValue 4><EncryptionMethodsSelected 1><PaddingLen 1><RandomBytes PaddingLen> (Answer delayed till first payload to save a frame)
					// ignore the random bytes (they are decrypted already), send the response, set status complete
					CSafeMemFile fileResponse(26);
					fileResponse.WriteUInt32(MAGICVALUE_SYNC);
					const uint8 bySelectedEncryptionMethod = ENM_OBFUSCATION; // we do not support any further encryption in this version, so no need to look which the other client preferred
					fileResponse.WriteUInt8(bySelectedEncryptionMethod);
					uint8 byPadding = (uint8)(cryptRandomGen.GenerateByte() % 16);///snow:填充的随机数字节数
					fileResponse.WriteUInt8(byPadding);
					for (int i = 0; i < byPadding; i++)
						fileResponse.WriteUInt8((uint8)rand());

					m_NegotiatingState = ONS_BASIC_SERVER_DELAYEDSENDING;   ///snow:延迟发送，这边发送的内容是835E6FC40000
					SendNegotiatingData(fileResponse.GetBuffer(), (uint32)fileResponse.GetLength(), 0, true); // don't actually send it right now, store it in our sendbuffer
					m_StreamCryptState = ECS_ENCRYPTING;
					DEBUG_ONLY( DebugLog(_T("CEncryptedStreamSocket: Finished DH Obufscation handshake with Server %s"), DbgGetIPString()) );
					break;
					///snow:在本语句块中，并未对m_nReceiveBytesWanted赋值，所以m_nReceiveBytesWanted！=0，还等于上次的填充随机数的字节数，while循环还将继续
					///snow:上面的理解错了，m_nReceiveBytesWanted在switch开始前清0了，所以循环结束了。新的问题是：SendNegotiatingData延迟发送的数据什么时候发出去呢？
					///snow:答案是在Send()被调用的时候发送，Send()会首先判断是否有delaysend的数据
				}
				default:
					ASSERT( false );
			}///snow:end of switch
			m_pfiReceiveBuffer->SeekToBegin();   ///snow:重置m_pfiReceiveBuffer指针，为了在下一轮while循环中写入数据
		}///snow:end of while
		if (m_pfiReceiveBuffer != NULL)
			free(m_pfiReceiveBuffer->Detach());
		delete m_pfiReceiveBuffer;
		m_pfiReceiveBuffer = NULL;
		return nRead;
	}
	catch(CFileException* error){
		// can only be caused by a bug in negationhandling, not by the datastream
		error->Delete();
		ASSERT( false );
		OnError(ERR_ENCRYPTION);
		if (m_pfiReceiveBuffer != NULL)
			free(m_pfiReceiveBuffer->Detach());
		delete m_pfiReceiveBuffer;
		m_pfiReceiveBuffer = NULL;
		return (-1);
	}

}

///snow start:此函数在四个地方被调用：Send(),OnSend(),StartNegotiation(),Negotiate()
///   在Send()中，int nRes = SendNegotiatingData(lpBuf, nBufLen, nBufLen);作用是将Negotiate()时没发送的数据包真正的发出去
int CEncryptedStreamSocket::SendNegotiatingData(const void* lpBuf, uint32 nBufLen, uint32 nStartCryptFromByte, bool bDelaySend){
	ASSERT( m_StreamCryptState == ECS_NEGOTIATING || m_StreamCryptState == ECS_ENCRYPTING );
	ASSERT( nStartCryptFromByte <= nBufLen );
	ASSERT( m_NegotiatingState == ONS_BASIC_SERVER_DELAYEDSENDING || !bDelaySend );

	BYTE* pBuffer = NULL;
	bool bProcess = false;
	if (lpBuf != NULL){
		pBuffer = (BYTE*)malloc(nBufLen);
		if (pBuffer == NULL)
			AfxThrowMemoryException();
		if (nStartCryptFromByte > 0)
			memcpy(pBuffer, lpBuf, nStartCryptFromByte);///snow:将lpBuf中不需要加密的数据拷贝到pBuffer

		///snow:在StartNegotiation()中，ECS_PENDING_SERVER时，nBufLen == nStartCryptFromByte==lpBuf.length；ECS_PENDING时nStartCryptFromByte=5，表示从第6次开始进行加密处理
		///snow:在Negotiate()中，nStartCryptFromByte=0，所以进行加密处理
		if (nBufLen - nStartCryptFromByte > 0)
		{
			///snow:add by snow
			theApp.QueueTraceLogLine(TRACE_STREAM_DATA,_T("Function:%hs|Line:%i|Socket:%i|IP:%s|Port:%i|Size:%i|Opcode:|Protocol:|Content(Hex):%s|Content:"),__FUNCTION__,__LINE__,m_SocketData.hSocket,GetPeerAddress().GetBuffer(0),GetPeerPort(),nBufLen - nStartCryptFromByte,ByteToHexStr((uchar*)lpBuf + nStartCryptFromByte,nBufLen - nStartCryptFromByte).GetBuffer(0));

			RC4Crypt((uchar*)lpBuf + nStartCryptFromByte, pBuffer + nStartCryptFromByte, nBufLen - nStartCryptFromByte, m_pRC4SendKey);

			///snow:add by snow
			theApp.QueueTraceLogLine(TRACE_STREAM_DATA,_T("Function:%hs|Line:%i|Socket:%i|IP:%s|Port:%i|Size:%i|Opcode:|Protocol:|Content(Hex):%s|Content:"),__FUNCTION__,__LINE__,m_SocketData.hSocket,GetPeerAddress().GetBuffer(0),GetPeerPort(),nBufLen - nStartCryptFromByte,ByteToHexStr((uchar*)pBuffer + nStartCryptFromByte,nBufLen - nStartCryptFromByte).GetBuffer(0));
		}

		///snow:下面的语句在Send()中调用SendNegotiatingData()时发生
		if (m_pfiSendBuffer != NULL){  ///snow:存在延迟发送的信息包，在后面的语句块中赋值  if (result == (uint32)SOCKET_ERROR || bDelaySend)时
			// we already have data pending. Attach it and try to send
			if (m_NegotiatingState == ONS_BASIC_SERVER_DELAYEDSENDING)
				m_NegotiatingState = ONS_COMPLETE;
			else
				ASSERT( false );
			m_pfiSendBuffer->SeekToEnd();///snow:移动指针到末尾，方便添加数据
			m_pfiSendBuffer->Write(pBuffer, nBufLen);///snow:将Send()时要发送的数据pBuffer附加到m_pfiSendBuffer后面，两个数据一起发送！！！
			free(pBuffer);
			pBuffer = NULL;
			nStartCryptFromByte = 0;
			bProcess = true; // we want to try to send it right now
		}
	}
	if (lpBuf == NULL || bProcess){   ///snow:在OnSend()中调用，SendNegotiatingData(NULL,0),bProcess在上面的语句被赋值为true，表示有延迟发送的数据，需要立即发送
		// this call is for processing pending data
		if (m_pfiSendBuffer == NULL || nStartCryptFromByte != 0){
			ASSERT( false );
			return 0;							// or not
		}
		nBufLen = (uint32)m_pfiSendBuffer->GetLength();
		pBuffer = m_pfiSendBuffer->Detach();
		delete m_pfiSendBuffer;
		m_pfiSendBuffer = NULL;   ///snow:清空m_pfiSendBuffer
	}
    ASSERT( m_pfiSendBuffer == NULL );
	uint32 result = 0;
	if (!bDelaySend)  
		result = CAsyncSocketEx::Send(pBuffer, nBufLen);

		///snow:在Negotiate()中调用：
	///snow:m_NegotiatingState = ONS_BASIC_SERVER_DELAYEDSENDING;
	///snow:SendNegotiatingData(fileResponse.GetBuffer(), (uint32)fileResponse.GetLength(), 0, true);

	if (result == (uint32)SOCKET_ERROR || bDelaySend){   ///snow:延迟发送，写入m_pfiSendBuffer
		m_pfiSendBuffer = new CSafeMemFile(128);
		m_pfiSendBuffer->Write(pBuffer, nBufLen);
		free(pBuffer);
		return result;
    }
	else {
		if (result < nBufLen){   ///snow:没发送完，还剩有数据，写入m_pfiSendBuffer
			m_pfiSendBuffer = new CSafeMemFile(128);
			m_pfiSendBuffer->Write(pBuffer + result, nBufLen - result);
		}
		free(pBuffer);
		return result;
	}
}

CString	CEncryptedStreamSocket::DbgGetIPString(){
	SOCKADDR_IN sockAddr = {0};
	int nSockAddrLen = sizeof(sockAddr);
	GetPeerName((SOCKADDR*)&sockAddr, &nSockAddrLen);
	return ipstr(sockAddr.sin_addr.S_un.S_addr);
}

uint8 CEncryptedStreamSocket::GetSemiRandomNotProtocolMarker() const{
	uint8 bySemiRandomNotProtocolMarker = 0;
	int i;
	for (i = 0; i < 128; i++){
		bySemiRandomNotProtocolMarker = cryptRandomGen.GenerateByte();
		bool bOk = false;
		switch (bySemiRandomNotProtocolMarker){ // not allowed values
				case OP_EDONKEYPROT:
				case OP_PACKEDPROT:
				case OP_EMULEPROT:
					break;
				default:
					bOk = true;
		}
		if (bOk)
			break;
	}
	if (i >= 128){
		// either we have _real_ bad luck or the randomgenerator is a bit messed up
		ASSERT( false );
		bySemiRandomNotProtocolMarker = 0x01;
	}
	return bySemiRandomNotProtocolMarker;
}
