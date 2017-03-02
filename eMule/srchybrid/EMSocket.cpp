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
//MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//GNU General Public License for more details.
//
//You should have received a copy of the GNU General Public License
//along with this program; if not, write to the Free Software
//Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#include "stdafx.h"
#ifdef _DEBUG
#include "DebugHelpers.h"
#endif
#include "emule.h"
#include "emsocket.h"
#include "AsyncProxySocketLayer.h"
#include "Packets.h"
#include "OtherFunctions.h"
#include "UploadBandwidthThrottler.h"
#include "Preferences.h"
#include "emuleDlg.h"
#include "Log.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif


namespace {
	inline void EMTrace(char* fmt, ...) {
#ifdef EMSOCKET_DEBUG
		va_list argptr;
		char bufferline[512];
		va_start(argptr, fmt);
		_vsnprintf(bufferline, 512, fmt, argptr);
		va_end(argptr);
		//(Ornis+)
		char osDate[30],osTime[30]; 
		char temp[1024]; 
		_strtime( osTime );
		_strdate( osDate );
		int len = _snprintf(temp,1021,"%s %s: %s",osDate,osTime,bufferline);
		temp[len++] = 0x0d;
		temp[len++] = 0x0a;
		temp[len+1] = 0;
		HANDLE hFile = CreateFile("c:\\EMSocket.log",           // open MYFILE.TXT 
                GENERIC_WRITE,              // open for reading 
                FILE_SHARE_READ,           // share for reading 
                NULL,                      // no security 
                OPEN_ALWAYS,               // existing file only 
                FILE_ATTRIBUTE_NORMAL,     // normal file 
                NULL);                     // no attr. template 
  
		if (hFile != INVALID_HANDLE_VALUE) 
		{ 
			DWORD nbBytesWritten = 0;
			SetFilePointer(hFile, 0, NULL, FILE_END);
			BOOL b = WriteFile(
				hFile,                    // handle to file
				temp,                // data buffer
				len,     // number of bytes to write
				&nbBytesWritten,  // number of bytes written
				NULL        // overlapped buffer
			);
			CloseHandle(hFile);
		}
#else 
		//va_list argptr;
		//va_start(argptr, fmt);
		//va_end(argptr);
		UNREFERENCED_PARAMETER(fmt);
#endif //EMSOCKET_DEBUG
	}
}

IMPLEMENT_DYNAMIC(CEMSocket, CEncryptedStreamSocket)

CEMSocket::CEMSocket(void){
	byConnected = ES_NOTCONNECTED;
	m_uTimeOut = CONNECTION_TIMEOUT; // default timeout for ed2k sockets

	// Download (pseudo) rate control	
	downloadLimit = 0;
	downloadLimitEnable = false;
	pendingOnReceive = false;

	// Download partial header
	pendingHeaderSize = 0;

	// Download partial packet
	pendingPacket = NULL;
	pendingPacketSize = 0;

	// Upload control
	sendbuffer = NULL;
	sendblen = 0;
	sent = 0;
	//m_bLinkedPackets = false;

	// deadlake PROXYSUPPORT
	m_pProxyLayer = NULL;
	m_bProxyConnectFailed = false;

    //m_startSendTick = 0;
    //m_lastSendLatency = 0;
    //m_latency_sum = 0;
    //m_wasBlocked = false;

    m_currentPacket_is_controlpacket = false;
	m_currentPackageIsFromPartFile = false;

    m_numberOfSentBytesCompleteFile = 0;
    m_numberOfSentBytesPartFile = 0;
    m_numberOfSentBytesControlPacket = 0;

    lastCalledSend = ::GetTickCount();
    lastSent = ::GetTickCount()-1000;

	m_bAccelerateUpload = false;

    m_actualPayloadSize = 0;
    m_actualPayloadSizeSent = 0;

    m_bBusy = false;
    m_hasSent = false;
	m_bUsesBigSendBuffers = false;
}

CEMSocket::~CEMSocket(){
	EMTrace("CEMSocket::~CEMSocket() on %d",(SOCKET)this);

    // need to be locked here to know that the other methods
    // won't be in the middle of things
    sendLocker.Lock();
	byConnected = ES_DISCONNECTED;
    sendLocker.Unlock();

    // now that we know no other method will keep adding to the queue
    // we can remove ourself from the queue
    theApp.uploadBandwidthThrottler->RemoveFromAllQueues(this);

    ClearQueues();
	RemoveAllLayers(); // deadlake PROXYSUPPORT
	AsyncSelect(0);
}

// deadlake PROXYSUPPORT
// By Maverick: Connection initialisition is done by class itself
BOOL CEMSocket::Connect(LPCSTR lpszHostAddress, UINT nHostPort)
{
	InitProxySupport();
	return CEncryptedStreamSocket::Connect(lpszHostAddress, nHostPort);
}
// end deadlake

// deadlake PROXYSUPPORT
// By Maverick: Connection initialisition is done by class itself
//BOOL CEMSocket::Connect(LPCTSTR lpszHostAddress, UINT nHostPort)
BOOL CEMSocket::Connect(SOCKADDR* pSockAddr, int iSockAddrLen)
{
	InitProxySupport();
	return CEncryptedStreamSocket::Connect(pSockAddr, iSockAddrLen);
}
// end deadlake

void CEMSocket::InitProxySupport()
{
	m_bProxyConnectFailed = false;

	// ProxyInitialisation
	const ProxySettings& settings = thePrefs.GetProxySettings();
	if (settings.UseProxy && settings.type != PROXYTYPE_NOPROXY)
	{
		Close();

		m_pProxyLayer = new CAsyncProxySocketLayer;
		switch (settings.type)
		{
			case PROXYTYPE_SOCKS4:
			case PROXYTYPE_SOCKS4A:
				m_pProxyLayer->SetProxy(settings.type, settings.name, settings.port);
				break;
			case PROXYTYPE_SOCKS5:
			case PROXYTYPE_HTTP10:
			case PROXYTYPE_HTTP11:
				if (settings.EnablePassword)
					m_pProxyLayer->SetProxy(settings.type, settings.name, settings.port, settings.user, settings.password);
				else
					m_pProxyLayer->SetProxy(settings.type, settings.name, settings.port);
				break;
			default:
				ASSERT(0);
		}
		AddLayer(m_pProxyLayer);

		// Connection Initialisation
		Create(0, SOCK_STREAM, FD_READ | FD_WRITE | FD_OOB | FD_ACCEPT | FD_CONNECT | FD_CLOSE, thePrefs.GetBindAddrA());
		AsyncSelect(FD_READ | FD_WRITE | FD_OOB | FD_ACCEPT | FD_CONNECT | FD_CLOSE);
	}
}

void CEMSocket::ClearQueues(){
	EMTrace("CEMSocket::ClearQueues on %d",(SOCKET)this);

    sendLocker.Lock();
	for(POSITION pos = controlpacket_queue.GetHeadPosition(); pos != NULL; )
		delete controlpacket_queue.GetNext(pos);
	controlpacket_queue.RemoveAll();

	for(POSITION pos = standartpacket_queue.GetHeadPosition(); pos != NULL; )
		delete standartpacket_queue.GetNext(pos).packet;
	standartpacket_queue.RemoveAll();
    sendLocker.Unlock();

	// Download (pseudo) rate control	
	downloadLimit = 0;
	downloadLimitEnable = false;
	pendingOnReceive = false;

	// Download partial header
	pendingHeaderSize = 0;

	// Download partial packet
	delete pendingPacket;
	pendingPacket = NULL;
	pendingPacketSize = 0;

	// Upload control
	delete[] sendbuffer;
	sendbuffer = NULL;

	sendblen = 0;
	sent = 0;
}

void CEMSocket::OnClose(int nErrorCode){
    // need to be locked here to know that the other methods
    // won't be in the middle of things
    sendLocker.Lock();
	byConnected = ES_DISCONNECTED;
    sendLocker.Unlock();

    // now that we know no other method will keep adding to the queue
    // we can remove ourself from the queue
    theApp.uploadBandwidthThrottler->RemoveFromAllQueues(this);

	CEncryptedStreamSocket::OnClose(nErrorCode); // deadlake changed socket to PROXYSUPPORT ( AsyncSocketEx )
	RemoveAllLayers(); // deadlake PROXYSUPPORT
	ClearQueues();
}

BOOL CEMSocket::AsyncSelect(long lEvent){
#ifdef EMSOCKET_DEBUG
	if (lEvent&FD_READ)
		EMTrace("  FD_READ");
	if (lEvent&FD_CLOSE)
		EMTrace("  FD_CLOSE");
	if (lEvent&FD_WRITE)
		EMTrace("  FD_WRITE");
#endif
	// deadlake changed to AsyncSocketEx PROXYSUPPORT
	if (m_SocketData.hSocket != INVALID_SOCKET)
		return CEncryptedStreamSocket::AsyncSelect(lEvent);
	return true;
}

///snow:父类中均没有实现OnReceive()
void CEMSocket::OnReceive(int nErrorCode){
	// the 2 meg size was taken from another place
	static char GlobalReadBuffer[2000000];  ///snow:2M的接收缓冲区

	// Check for an error code
	if(nErrorCode != 0){  ///snow:接收数据错误了
		OnError(nErrorCode);
		return;
	}
	
	// Check current connection state
	if(byConnected == ES_DISCONNECTED){
		return;
	}
	else {	  ///snow:都能接收数据了，状态肯定是已连接，如果状态不是未连接，则都重置为已连接
		byConnected = ES_CONNECTED; // ES_DISCONNECTED, ES_NOTCONNECTED, ES_CONNECTED
	}

    // CPU load improvement
	///snow:下载速度限制，暂缓接收
    if(downloadLimitEnable == true && downloadLimit == 0){
        EMTrace("CEMSocket::OnReceive blocked by limit");
        pendingOnReceive = true;

        //Receive(GlobalReadBuffer + pendingHeaderSize, 0);
        return;
    }

	// Remark: an overflow can not occur here
	///snow:缓冲区大小为200万字节（2M），可以接收的字节数为（缓冲区字节数-待处理的头字节数）与downloadLimit的小值
	///snow:pendingHeaderSize表示上一次接收数据时剩余的字节数，为什么会有剩余？估计跟包的分割有关
	uint32 readMax = sizeof(GlobalReadBuffer) - pendingHeaderSize; 
	if(downloadLimitEnable == true && readMax > downloadLimit) {
		readMax = downloadLimit;
	}

	// We attempt to read up to 2 megs at a time (minus whatever is in our internal read buffer)
	///接收readMax字节，存入GlobalReadBuffer[GlobalReadBuffer + pendingHeaderSize]处，1次最多可接收2M字节，前面的pendingHeaderSize字节留给pendingHeader
	uint32 ret = Receive(GlobalReadBuffer + pendingHeaderSize, readMax); ///snow:CEMSocket::Recevive()-->CEncryptStreamSocket::Receive()
	if(ret == SOCKET_ERROR || byConnected == ES_DISCONNECTED){
		return;
	}

	// Bandwidth control
	if(downloadLimitEnable == true){
		// Update limit   ///snow:更新下载限制数
		downloadLimit -= GetRealReceivedBytes();  ///snow:返回m_nObfuscationBytesReceived，在CEncryptedStreamSocket::Receive(lpBuf,nBufLen,nFlags)中赋值
	}

	// CPU load improvement
	// Detect if the socket's buffer is empty (or the size did match...)
	///snow:判断socket的缓冲区是否为空，为空则表示则全部接收完毕
	pendingOnReceive = m_bFullReceive; ///m_bFullReceive为父类成员变量，在CEncryptedStreamSocket::Receive()中被赋值
	///pendingOnReceive在设置downloadLimit时被调用，跟下载速度设置有关，但是没看懂在这里跟m_bFullReceive有什么关系？
	///pendingOnReceive为true时调用OnReceive(0），为什么？

	if (ret == 0)   ///snow:接收的字节数=m_nObfuscationBytesReceived，ret==0表示没收到数据
		return;

	///snow:将存放在pendingHeader的数据存入GlobalReadBuffer
	// Copy back the partial header into the global read buffer for processing
	if(pendingHeaderSize > 0) {   ///snow:在函数尾被赋值 pendingHeaderSize = rend - rptr;
		memcpy(GlobalReadBuffer, pendingHeader, pendingHeaderSize); ///snow:因为在前面的Receive()中在GlobalReadBuffer头部预留了pendingHeaderSize字节
		ret += pendingHeaderSize;   ///snow:pendingHeader被放入GlobalReadBuffer，所以没有pendingHeader数据了，而接收的字节数需要加上上次待处理的字节数
		pendingHeaderSize = 0;   ///snow:重新置0，没有PendingHeader
	}

	if (IsRawDataMode())  ///snow:这段代码只在子类CHttpClientReqSocket中有用
	{
		DataReceived((BYTE*)GlobalReadBuffer, ret);  ///snow:虚函数，在子类中实现， CHttpClientReqSocket::DataReceived（）有具体实现
		return;
	}

	char *rptr = GlobalReadBuffer; // floating index initialized with begin of buffer
	const char *rend = GlobalReadBuffer + ret; // end of buffer   ///snow:指向GlobalReadBuffer实际数据的尾部

	// Loop, processing packets until we run out of them
	///snow:表示GlobalReadBuffer缓冲区中的数据没被处理的数据不小于6个字节（包头的长度）或 存在未处理完的packet且GlobalReadBuffer还有数据（不一定大于6字节）
	while ((rend - rptr >= PACKET_HEADER_SIZE) || ((pendingPacket != NULL) && (rend - rptr > 0)))
	{
		// Two possibilities here: 
		//
		// 1. There is no pending incoming packet
		// 2. There is already a partial pending incoming packet
		//
		// It's important to remember that emule exchange two kinds of packet
		// - The control packet
		// - The data packet for the transport of the block
		// 
		// The biggest part of the traffic is done with the data packets. 
		// The default size of one block is 10240 bytes (or less if compressed), but the
		// maximal size for one packet on the network is 1300 bytes. It's the reason
		// why most of the Blocks are splitted before to be sent. 
		//
		// Conclusion: When the download limit is disabled, this method can be at least 
		// called 8 times (10240/1300) by the lower layer before a splitted packet is 
		// rebuild and transferred to the above layer for processing.
		//
		// The purpose of this algorithm is to limit the amount of data exchanged between buffers

		///snow:上面这段话的意思大致是说：eMule允许发送10240字节的块，但网络传输只能是1300字节，所以块在发送的时候会被分割，分成8次发送，而接收的时候需要再把它们拼接起来

		///snow:在这里，将接收到的数据封装成一个一个的Packet，实现从socket到packet的转化

		///snow:没有上次OnReceive还没处理完的packet
		if(pendingPacket == NULL){  ///snow:什么情况下pendingPacket != NULL?  答案 是 pendingPacket->size != pendingPacketSize的时候，在本次OnReceive中还有数据没接收到
			pendingPacket = new Packet(rptr); // Create new packet container. ///snow:用接收到的数据构建一个Packet
			rptr += 6;                        // Only the header is initialized so far  ///snow:指针前移6个字节，前6个字节是包头（size(4字节）,opcode（1字节）,prot（1字节）)，后面的是包的具体内容

			// Bugfix We still need to check for a valid protocol
			// Remark: the default eMule v0.26b had removed this test......
			///snow:数据到这里的时候，如果是加密的，也已经解密了（在CEncryptedStreamSocket::Receive()中进行了解密）case ECS_ENCRYPTING: RC4Crypt
			///snow:所以包头如果不是下面的三种属性，就是收到了错误包了
			switch (pendingPacket->prot){   ///snow:构建Packet的时候，用rptr前6个字节中的数据给packet的成员变量赋值
				case OP_EDONKEYPROT:
				case OP_PACKEDPROT:
				case OP_EMULEPROT:
					break;
				default:
					EMTrace("CEMSocket::OnReceive ERROR Wrong header");
					delete pendingPacket;
					pendingPacket = NULL;
					OnError(ERR_WRONGHEADER);
					return;
			}

			// Security: Check for buffer overflow (2MB)
			///snow:包大于2M了，溢出了
			if(pendingPacket->size > sizeof(GlobalReadBuffer)) {
				delete pendingPacket;
				pendingPacket = NULL;
				OnError(ERR_TOOBIG);
				return;
			}

			// Init data buffer
			///snow:在前面用Packet(rptr)构建pendingPacket的时候，只有包头（size,opcode,prot)被赋值了，包体还是空的，就是数据还没有复制到pendingPacket中
			pendingPacket->pBuffer = new char[pendingPacket->size + 1];
			pendingPacketSize = 0;
		}  ///snow:end of if(pendingPacket == NULL)

		// Bytes ready to be copied into packet's internal buffer
		/************************************************snow:start****************************************************************
		/*   为什么要编写下面这段代码呢？
		/*   这是因为从rptr中构建的packet的size不一定等于rptr的长度，如果一个packet的size大于1300，那么它就要被拆分，
		/*   那么接收到的数据长度就要小于packet的size了
		/*   而如果一个packet很小，就有可能是几个packet合起来一起发送，那么接收到的数据里可能包含好几个packet，数据的长度就会大于packet的size
		/*   还有一个可能是接收到的数据中既包含上次pendingPacket的剩余部分，又包含新packet的数据（全部或部分）
		/*   pendingPacketSize表示已经从rptr中读取的字节数，pendingPacket->size - pendingPacketSize表示构建一个完整的packet还需要的字节数
		/*   rend-rptr表示缓冲区中还未被处理的字节数
		*************************************************snow:end*****************************************************************/
		ASSERT(rptr <= rend);
		uint32 toCopy = ((pendingPacket->size - pendingPacketSize) < (uint32)(rend - rptr)) ? 
			             (pendingPacket->size - pendingPacketSize) : (uint32)(rend - rptr);

		// Copy Bytes from Global buffer to packet's internal buffer
		///snow:rtpr在前面被前移了6个字节，所以这时的rptr指向的是真正的包体数据了，将包体数据拷贝到pendingPacket的pBuffer中
		memcpy(&pendingPacket->pBuffer[pendingPacketSize], rptr, toCopy);
		pendingPacketSize += toCopy;  ///snow:pBuffer中的指针前移
		rptr += toCopy;               ///snow:rptr的指针前移,到尾了吗？不一定，看包的大小
		
		// Check if packet is complet
		ASSERT(pendingPacket->size >= pendingPacketSize);
		if(pendingPacket->size == pendingPacketSize){   ///snow:pendingPacket是个完整的包了，可以进行数据处理了
#ifdef EMSOCKET_DEBUG
			EMTrace("CEMSocket::PacketReceived on %d, opcode=%X, realSize=%d", 
				    (SOCKET)this, pendingPacket->opcode, pendingPacket->GetRealPacketSize());
#endif

			// Process packet   ///snow:处理接收到的数据，接收到一个完整的Packet，就调用PacketReceived()交由ProcessPacket()对信息包进行处理
			bool bPacketResult = PacketReceived(pendingPacket);
			delete pendingPacket;	
			pendingPacket = NULL;
			pendingPacketSize = 0;

			if (!bPacketResult)
				return;
		}///snow:end of if(pendingPacket->size == pendingPacketSize)
		///snow:如果pendingPacket->size != pendingPacketSize，那么包还不完整，需要下一次接收到数据时处理
		///snow:如果rend-prtr>=PACKET_HEADER_SIZE，循环继续，处理下一个packet。到这里已不可能发生(pendingPacket != NULL) && (rend - rptr > 0)的情况了，因为这种情况在本轮循环时肯定被处理了
	}///snow:end of while

	// Finally, if there is any data left over, save it for next time
	ASSERT(rptr <= rend);
	ASSERT(rend - rptr < PACKET_HEADER_SIZE);
	if(rptr != rend) {   ///snow:还剩不到6个字节的数据，是包头的一部分，暂时存放在pendingHeader中，在下一次接收到数据时处理
		// Keep the partial head
		pendingHeaderSize = rend - rptr;
		memcpy(pendingHeader, rptr, pendingHeaderSize);
	}	
}

///snow:在CPartFile::Process（）中调用，仅此一处
void CEMSocket::SetDownloadLimit(uint32 limit){	
	downloadLimit = limit;
	downloadLimitEnable = true;	
	
	// CPU load improvement
	if(limit > 0 && pendingOnReceive == true){
		OnReceive(0);
	}
}

void CEMSocket::DisableDownloadLimit(){
	downloadLimitEnable = false;

	// CPU load improvement
	if(pendingOnReceive == true){
		OnReceive(0);
	}
}

/**
 * Queues up the packet to be sent. Another thread will actually send the packet.
 *
 * If the packet is not a control packet, and if the socket decides that its queue is
 * full and forceAdd is false, then the socket is allowed to refuse to add the packet
 * to its queue. It will then return false and it is up to the calling thread to try
 * to call SendPacket for that packet again at a later time.
 *
 * @param packet address to the packet that should be added to the queue
 *
 * @param delpacket if true, the responsibility for deleting the packet after it has been sent
 *                  has been transferred to this object. If false, don't delete the packet after it
 *                  has been sent.
 *
 * @param controlpacket the packet is a controlpacket
 *
 * @param forceAdd this packet must be added to the queue, even if it is full. If this flag is true
 *                 then the method can not refuse to add the packet, and therefore not return false.
 *
 * @return true if the packet was added to the queue, false otherwise
 */
void CEMSocket::SendPacket(Packet* packet, bool delpacket, bool controlpacket, uint32 actualPayloadSize, bool bForceImmediateSend){
	//EMTrace("CEMSocket::OnSenPacked1 linked: %i, controlcount %i, standartcount %i, isbusy: %i",m_bLinkedPackets, controlpacket_queue.GetCount(), standartpacket_queue.GetCount(), IsBusy());

    sendLocker.Lock();

	///snow:未连接状态，
    if (byConnected == ES_DISCONNECTED) {
        sendLocker.Unlock();
        if(delpacket) {
			delete packet;
        }
		return;
    } else {
		if (!delpacket){  ///snow:不删除包，复制一份包
            //ASSERT ( !packet->IsSplitted() );
            Packet* copy = new Packet(packet->opcode,packet->size);
		    memcpy(copy->pBuffer,packet->pBuffer,packet->size);
		    packet = copy;
	    }

        //if(m_startSendTick > 0) {
        //    m_lastSendLatency = ::GetTickCount() - m_startSendTick;
        //}

        if (controlpacket) {
	        controlpacket_queue.AddTail(packet);  ///把packet对象添加到控制包队列末尾，packet对象在发送时应重新编码成字节流

            // queue up for controlpacket
            theApp.uploadBandwidthThrottler->QueueForSendingControlPacket(this, HasSent());
		} else {   ///snow:不是控制包，是标准包，添加到标准包队列
            bool first = !((sendbuffer && !m_currentPacket_is_controlpacket) || !standartpacket_queue.IsEmpty());
            StandardPacketQueueEntry queueEntry = { actualPayloadSize, packet };
		    standartpacket_queue.AddTail(queueEntry);

            // reset timeout for the first time
            if (first) {
                lastFinishedStandard = ::GetTickCount();
                m_bAccelerateUpload = true;	// Always accelerate first packet in a block
            }
	    }
    }

    sendLocker.Unlock();
	if (bForceImmediateSend){  ///snow:需要立即发送，不存入队列，调用Send()立即发送数据
		ASSERT( controlpacket_queue.GetSize() == 1 );
		Send(1024, 0, true);
	}
}

uint64 CEMSocket::GetSentBytesCompleteFileSinceLastCallAndReset() {
    sendLocker.Lock();

    uint64 sentBytes = m_numberOfSentBytesCompleteFile;
    m_numberOfSentBytesCompleteFile = 0;

    sendLocker.Unlock();

    return sentBytes;
}

uint64 CEMSocket::GetSentBytesPartFileSinceLastCallAndReset() {
    sendLocker.Lock();

    uint64 sentBytes = m_numberOfSentBytesPartFile;
    m_numberOfSentBytesPartFile = 0;

    sendLocker.Unlock();

    return sentBytes;
}

uint64 CEMSocket::GetSentBytesControlPacketSinceLastCallAndReset() {
    sendLocker.Lock();

    uint64 sentBytes = m_numberOfSentBytesControlPacket;
    m_numberOfSentBytesControlPacket = 0;

    sendLocker.Unlock();

    return sentBytes;
}

uint64 CEMSocket::GetSentPayloadSinceLastCallAndReset() {
    sendLocker.Lock();

    uint64 sentBytes = m_actualPayloadSizeSent;
    m_actualPayloadSizeSent = 0;

    sendLocker.Unlock();

    return sentBytes;
}

void CEMSocket::OnSend(int nErrorCode){
    //onSendWillBeCalledOuter = false;

    if (nErrorCode){
		OnError(nErrorCode);
		return;
	}

	//EMTrace("CEMSocket::OnSend linked: %i, controlcount %i, standartcount %i, isbusy: %i",m_bLinkedPackets, controlpacket_queue.GetCount(), standartpacket_queue.GetCount(), IsBusy());
	CEncryptedStreamSocket::OnSend(0);

    sendLocker.Lock();

    m_bBusy = false;

    // stopped sending here.
    //StoppedSendSoUpdateStats();

    if (byConnected == ES_DISCONNECTED) {
        sendLocker.Unlock();
		return;
    } else
		byConnected = ES_CONNECTED;

    if(m_currentPacket_is_controlpacket) {
        // queue up for control packet
        theApp.uploadBandwidthThrottler->QueueForSendingControlPacket(this, HasSent());
    }
	
    sendLocker.Unlock();
}

//void CEMSocket::StoppedSendSoUpdateStats() {
//    if(m_startSendTick > 0) {
//        m_lastSendLatency = ::GetTickCount()-m_startSendTick;
//        
//        if(m_lastSendLatency > 0) {
//            if(m_wasBlocked == true) {
//                SocketTransferStats newLatencyStat = { m_lastSendLatency, ::GetTickCount() };
//                m_Average_sendlatency_list.AddTail(newLatencyStat);
//                m_latency_sum += m_lastSendLatency;
//            }
//
//            m_startSendTick = 0;
//            m_wasBlocked = false;
//
//            CleanSendLatencyList();
//        }
//    }
//}
//
//void CEMSocket::CleanSendLatencyList() {
//    while(m_Average_sendlatency_list.GetCount() > 0 && ::GetTickCount() - m_Average_sendlatency_list.GetHead().timestamp > 3*1000) {
//        SocketTransferStats removedLatencyStat = m_Average_sendlatency_list.RemoveHead();
//        m_latency_sum -= removedLatencyStat.latency;
//    }
//}

/**
 * Try to put queued up data on the socket.
 * 控制包优先发送，数据包可以分割成小包，但是分割成的小包必须连续发送，不能插入控制包
 * Control packets have higher priority, and will be sent first, if possible.
 * Standard packets can be split up in several package containers. In that case
 * all the parts of a split package must be sent in a row, without any control packet
 * in between.
 *
 * @param maxNumberOfBytesToSend This is the maximum number of bytes that is allowed to be put on the socket
 *                               this call. The actual number of sent bytes will be returned from the method.
 *
 * @param onlyAllowedToSendControlPacket This call we only try to put control packets on the sockets.
 *                                       If there's a standard packet "in the way", and we think that this socket
 *                                       is no longer an upload slot, then it is ok to send the standard packet to
 *                                       get it out of the way. But it is not allowed to pick a new standard packet
 *                                       from the queue during this call. Several split packets are counted as one
 *                                       standard packet though, so it is ok to finish them all off if necessary.
 *  在发送时，如果onlyAllowedToSendControlPacket被置为true，则不允许再往socket中添加数据包，
 *  已在socket中的数据包继续发送完毕，发送完后只发送控制包
 *
 * @return the actual number of bytes that were put on the socket.
 */
SocketSentBytes CEMSocket::Send(uint32 maxNumberOfBytesToSend, uint32 minFragSize, bool onlyAllowedToSendControlPacket) {
	//EMTrace("CEMSocket::Send linked: %i, controlcount %i, standartcount %i, isbusy: %i",m_bLinkedPackets, controlpacket_queue.GetCount(), standartpacket_queue.GetCount(), IsBusy());
    sendLocker.Lock();
	///snow:未连接
    if (byConnected == ES_DISCONNECTED) {
        sendLocker.Unlock();
        SocketSentBytes returnVal = { false, 0, 0 };
        return returnVal;
    }

    bool anErrorHasOccured = false;
	uint32 sentStandardPacketBytesThisCall = 0;  ///snow:统计用
    uint32 sentControlPacketBytesThisCall = 0;

	///snow:同时满足三个条件：1、如果已建立连接，2、加密层已准备好，IsEncryptionLayerReady不是表示加密已协商好，是表示不需要不加密或已加密完成，而不是处于协商中
	///snow:  3、socket处于非阻塞状态或允许发送两种数据包（m_bBusy和onlyAllowedToSendControlPacket不同时为true)
    if(byConnected == ES_CONNECTED && IsEncryptionLayerReady() && !(m_bBusy && onlyAllowedToSendControlPacket)) {
        if(minFragSize < 1) {
            minFragSize = 1;
        }

        maxNumberOfBytesToSend = GetNextFragSize(maxNumberOfBytesToSend, minFragSize);

        bool bWasLongTimeSinceSend = (::GetTickCount() - lastSent) > 1000;

        lastCalledSend = ::GetTickCount();

		/**** snow:同时满足以下条件，执行循环：
        *          1、本次调用发送的控制包字节数和标准包字节数之和小于最大准备发送字节数
		*          2、发送还没有发生错误
		*          3、sendbuffer,controlpacket_queue,standartpacket_queue三者中有一个不为空
		*          4、以下情况满足任意一种：
		*            4.1、允许发送两种数据包
		*            4.2、sendbuffer不为空且当前包是控制包，发送控制包的时候（send!=sendlen)
		*            4.3、本次调用发送的控制包字节数和标准包字节数之和大于0 且 两者之和 % minFragSize != 0 
		*            4.4、sendbuffer为空且控制包队列不为空
		*            4.5、sendbuffer不为空 且 当前包不是控制包 且 已经发送很长时间了 且 控制包队列不为空 且 本次调用发送的控制包字节数和标准包字节数之和小于minFragSize
		*/
		
        while(sentStandardPacketBytesThisCall + sentControlPacketBytesThisCall < maxNumberOfBytesToSend && anErrorHasOccured == false && // don't send more than allowed. Also, there should have been no error in earlier loop
			///snow:不发送超过最大允许发送字节数的数据，并且还没有错误发生
              (sendbuffer != NULL || !controlpacket_queue.IsEmpty() || !standartpacket_queue.IsEmpty()) && // there must exist something to send
			  ///snow:sendbuffer,controlpacket_queue,standartpacket_queue三者中有一个不为空，要发送就必须有数据可送
               (onlyAllowedToSendControlPacket == false || // this means we are allowed to send both types of packets, so proceed
                sendbuffer != NULL && m_currentPacket_is_controlpacket == true || // We are in the progress of sending a control packet. We are always allowed to send those
				///snow:允许发送两种数据包或者当前正在发送控制包，表示什么？？？
                sentStandardPacketBytesThisCall + sentControlPacketBytesThisCall > 0 && (sentStandardPacketBytesThisCall + sentControlPacketBytesThisCall) % minFragSize != 0 || // Once we've started, continue to send until an even minFragsize to minimize packet overhead
				///snow:如果已经开始发送，则继续发送直到已发送数据%minFragSize==0，？？？minFragSize表示？
                sendbuffer == NULL && !controlpacket_queue.IsEmpty() || // There's a control packet in queue, and we are not currently sending anything, so we will handle the control packet next
				///snow:队列中只有控制包，当前不发送，延后处理  为什么？
                sendbuffer != NULL && m_currentPacket_is_controlpacket == false && bWasLongTimeSinceSend && !controlpacket_queue.IsEmpty() && (sentStandardPacketBytesThisCall + sentControlPacketBytesThisCall) < minFragSize // We have waited to long to clean the current packet (which may be a standard packet that is in the way). Proceed no matter what the value of onlyAllowedToSendControlPacket.
				///snow:等待处理当前包，可能是正在发送标准数据包，不考虑onlyAllowedToSendControlPacket标志
               )
             )
		{

            // If we are currently not in the progress of sending a packet, we will need to find the next one to send
			///snow:这段if语句块就是从两个队列里取包，先控制队列，如果没有，则后标准队列
			if(sendbuffer == NULL) {   ///snow:发送缓冲区为空,控制包队列和标准包队列有一个不为空
                Packet* curPacket = NULL;
                if(!controlpacket_queue.IsEmpty()) {
                    // There's a control packet to send
                    m_currentPacket_is_controlpacket = true;
                    curPacket = controlpacket_queue.RemoveHead();
                } else if(!standartpacket_queue.IsEmpty()) {
                    // There's a standard packet to send
                    m_currentPacket_is_controlpacket = false;
					///snow:标准数据包的封包格式跟控制包不同，标准包为控制包额外加上actualPayloadSize等信息
                    StandardPacketQueueEntry queueEntry = standartpacket_queue.RemoveHead();
                    curPacket = queueEntry.packet;
                    m_actualPayloadSize = queueEntry.actualPayloadSize;

                    // remember this for statistics purposes.
                    m_currentPackageIsFromPartFile = curPacket->IsFromPF();
				} else {  ///snow:按道理不可能执行到这里来，因为sendbuffer为空，控制包队列和标准包队列必定有一个不为空，而这里的else表示两者都为空
                    // Just to be safe. Shouldn't happen?
                    sendLocker.Unlock();

                    // if we reach this point, then there's something wrong with the while condition above!
                    ASSERT(0);
                    theApp.QueueDebugLogLine(true,_T("EMSocket: Couldn't get a new packet! There's an error in the first while condition in EMSocket::Send()"));

                    SocketSentBytes returnVal = { true, sentStandardPacketBytesThisCall, sentControlPacketBytesThisCall };
                    return returnVal;
                }

                // We found a package to send. Get the data to send from the
                // package container and dispose of the container.
				sendblen = curPacket->GetRealPacketSize();  ///snow:获取包的长度
				sendbuffer = curPacket->DetachPacket();     ///snow:获取包的内容,进入缓冲区的就是completebuffer,或者pBuffer+HEAD
                sent = 0;
                delete curPacket;

				// encrypting which cannot be done transparent by base class
				CryptPrepareSendData((uchar*)sendbuffer, sendblen);  ///snow:加密准备发送的数据
			} ///snow:fi(sendbuffer == NULL)

			///snow:到这里sendbuffer里已经有一个包待发送了，有且只有一个包
            // At this point we've got a packet to send in sendbuffer. Try to send it. Loop until entire packet
            // is sent, or until we reach maximum bytes to send for this call, or until we get an error.
            // NOTE! If send would block (returns WSAEWOULDBLOCK), we will return from this method INSIDE this loop.
			///snow:已经将待发送的包存入发送缓冲区，循环发送直至：整个包发送完毕，或达到最大发送数，或遇到错误
			///snow:如果返回WSAEWOULDBLOCK
            while (sent < sendblen &&
                   sentStandardPacketBytesThisCall + sentControlPacketBytesThisCall < maxNumberOfBytesToSend &&
                   (
                    onlyAllowedToSendControlPacket == false || // this means we are allowed to send both types of packets, so proceed
                    m_currentPacket_is_controlpacket ||
                    bWasLongTimeSinceSend && (sentStandardPacketBytesThisCall + sentControlPacketBytesThisCall) < minFragSize ||
                    (sentStandardPacketBytesThisCall + sentControlPacketBytesThisCall) % minFragSize != 0
                   ) &&
                   anErrorHasOccured == false)
			{
		        uint32 tosend = sendblen-sent;  
				///snow:确定准备发送的字节数
				if(!onlyAllowedToSendControlPacket || m_currentPacket_is_controlpacket) { ///snow:当前包是控制包，且允许发送标准包
    		        if (maxNumberOfBytesToSend >= sentStandardPacketBytesThisCall + sentControlPacketBytesThisCall && tosend > maxNumberOfBytesToSend-(sentStandardPacketBytesThisCall + sentControlPacketBytesThisCall))
						///snow:如果最大准备发送字节数大于等于本次调用已发送字节数，且tosend>剩下可以发送的字节数，tosend=剩下可以发送的字节数
                        tosend = maxNumberOfBytesToSend-(sentStandardPacketBytesThisCall + sentControlPacketBytesThisCall);
                } else if(bWasLongTimeSinceSend && (sentStandardPacketBytesThisCall + sentControlPacketBytesThisCall) < minFragSize) {
    		        if (minFragSize >= sentStandardPacketBytesThisCall + sentControlPacketBytesThisCall && tosend > minFragSize-(sentStandardPacketBytesThisCall + sentControlPacketBytesThisCall))
                        tosend = minFragSize-(sentStandardPacketBytesThisCall + sentControlPacketBytesThisCall);
                } else {
                    uint32 nextFragMaxBytesToSent = GetNextFragSize(sentStandardPacketBytesThisCall + sentControlPacketBytesThisCall, minFragSize);
    		        if (nextFragMaxBytesToSent >= sentStandardPacketBytesThisCall + sentControlPacketBytesThisCall && tosend > nextFragMaxBytesToSent-(sentStandardPacketBytesThisCall + sentControlPacketBytesThisCall))
                        tosend = nextFragMaxBytesToSent-(sentStandardPacketBytesThisCall + sentControlPacketBytesThisCall);
                }
		        ASSERT (tosend != 0 && tosend <= sendblen-sent);
        		
                //DWORD tempStartSendTick = ::GetTickCount();

                lastSent = ::GetTickCount();
				///snow:调用父类函数发送数据
		        uint32 result = CEncryptedStreamSocket::Send(sendbuffer+sent,tosend); // deadlake PROXYSUPPORT - changed to AsyncSocketEx
		        if (result == (uint32)SOCKET_ERROR){
			        uint32 error = GetLastError();
					if (error == WSAEWOULDBLOCK){  ///snow:数据包被阻塞，设置忙状态，统计发送字节数，直接返回，不再继续发送
                        m_bBusy = true;

                        //m_wasBlocked = true;
                        sendLocker.Unlock();

                        SocketSentBytes returnVal = { true, sentStandardPacketBytesThisCall, sentControlPacketBytesThisCall };
                        return returnVal; // Send() blocked, onsend will be called when ready to send again
			        } else{
                        // Send() gave an error
						anErrorHasOccured = true;  ///snow:跳出本级while循环，后再跳出上级while循环
                        //DEBUG_ONLY( AddDebugLogLine(true,"EMSocket: An error has occured: %i", error) );
                    }
                } else {   
					///snow:没有发送错误，已经发送成功
                    // we managed to send some bytes. Perform bookkeeping.
                    m_bBusy = false;
                    m_hasSent = true;

					sent += result;  ///snow:本次调用已经发送的字节数，跟sendlen比较，如果小于sendlen，表示本次的数据包还没发送完毕，需要继续发送

                    // Log send bytes in correct class
                    if(m_currentPacket_is_controlpacket == false) {
						sentStandardPacketBytesThisCall += result;   ///snow:统计标准包发送字节数

                        if(m_currentPackageIsFromPartFile == true) {
							m_numberOfSentBytesPartFile += result;   ///snow:PartFile和CompleteFile各指什么？
                        } else {
                            m_numberOfSentBytesCompleteFile += result;
                        }
                    } else {
                        sentControlPacketBytesThisCall += result; ///snow:统计控制包发送字节数
                        m_numberOfSentBytesControlPacket += result;
                    }
				} ///snow:发送成功，继续执行while循环
			}
			///snow:while (sent < sendblen && .... end

			if (sent == sendblen){   ///snow:一个数据包已经发送完毕，删除sendbuffer,sendlen置0，如果是标准包，统计m_actualPayloadSizeSent
                // we are done sending the current package. Delete it and set
                // sendbuffer to NULL so a new packet can be fetched.
		        delete[] sendbuffer;
		        sendbuffer = NULL;
			    sendblen = 0;

                if(!m_currentPacket_is_controlpacket) {
                    m_actualPayloadSizeSent += m_actualPayloadSize;
                    m_actualPayloadSize = 0;

                    lastFinishedStandard = ::GetTickCount(); // reset timeout
                    m_bAccelerateUpload = false; // Safe until told otherwise
                }

                sent = 0;
			}  ///没有else，就是说当sent ！= sendblen时，重新执行大while循环，如果是控制包，则满足4.2条件，重新发送该控制包；如果是标准包，再根据其它条件判断
			///snow:fi(sent == sendblen)
		}  ///snow:如果还没达到最大准备发送字节数，则继续从队列里取包，准备发送
		///snow:while(sentStandardPacketBytesThisCall +  ... end
	}
	///snow:fi(byConnected == ES_CONNECTED...

	///snow:同时满足两个条件：1、如果只允许发送控制包，
	///snow: 2、控制包队列不为空，或者 sendbuffer不为空且当前包是控制包
    if(onlyAllowedToSendControlPacket && (!controlpacket_queue.IsEmpty() || sendbuffer != NULL && m_currentPacket_is_controlpacket)) {
        // enter control packet send queue
        // we might enter control packet queue several times for the same package,
        // but that costs very little overhead. Less overhead than trying to make sure
        // that we only enter the queue once.
        theApp.uploadBandwidthThrottler->QueueForSendingControlPacket(this, HasSent());
    }

    //CleanSendLatencyList();

    sendLocker.Unlock();

    SocketSentBytes returnVal = { !anErrorHasOccured, sentStandardPacketBytesThisCall, sentControlPacketBytesThisCall };
    return returnVal;
}

uint32 CEMSocket::GetNextFragSize(uint32 current, uint32 minFragSize) {
    if(current % minFragSize == 0) {
        return current;
    } else {
        return minFragSize*(current/minFragSize+1);
    }
}

/**
 * Decides the (minimum) amount the socket needs to send to prevent timeout.
 * 
 * @author SlugFiller
 */
uint32 CEMSocket::GetNeededBytes() {
	sendLocker.Lock();
	if (byConnected == ES_DISCONNECTED) {
		sendLocker.Unlock();
		return 0;
	}

    if (!((sendbuffer && !m_currentPacket_is_controlpacket) || !standartpacket_queue.IsEmpty())) {
    	// No standard packet to send. Even if data needs to be sent to prevent timout, there's nothing to send.
        sendLocker.Unlock();
		return 0;
	}

	if (((sendbuffer && !m_currentPacket_is_controlpacket)) && !controlpacket_queue.IsEmpty())
		m_bAccelerateUpload = true;	// We might be trying to send a block request, accelerate packet

	uint32 sendgap = ::GetTickCount() - lastCalledSend;

	uint64 timetotal = m_bAccelerateUpload?45000:90000;
	uint64 timeleft = ::GetTickCount() - lastFinishedStandard;
	uint64 sizeleft, sizetotal;
	if (sendbuffer && !m_currentPacket_is_controlpacket) {
		sizeleft = sendblen-sent;
		sizetotal = sendblen;
	}
	else {
		sizeleft = sizetotal = standartpacket_queue.GetHead().packet->GetRealPacketSize();
	}
	sendLocker.Unlock();

	if (timeleft >= timetotal)
		return (UINT)sizeleft;
	timeleft = timetotal-timeleft;
	if (timeleft*sizetotal >= timetotal*sizeleft) {
		// don't use 'GetTimeOut' here in case the timeout value is high,
		if (sendgap > SEC2MS(20))
			return 1;	// Don't let the socket itself time out - Might happen when switching from spread(non-focus) slot to trickle slot
		return 0;
	}
	uint64 decval = timeleft*sizetotal/timetotal;
	if (!decval)
		return (UINT)sizeleft;
	if (decval < sizeleft)
		return (UINT)(sizeleft-decval+1);	// Round up
	else
		return 1;
}

// pach2:
// written this overriden Receive to handle transparently FIN notifications coming from calls to recv()
// This was maybe(??) the cause of a lot of socket error, notably after a brutal close from peer
// also added trace so that we can debug after the fact ...
int CEMSocket::Receive(void* lpBuf, int nBufLen, int nFlags)
{
//	EMTrace("CEMSocket::Receive on %d, maxSize=%d",(SOCKET)this,nBufLen);
	int recvRetCode = CEncryptedStreamSocket::Receive(lpBuf,nBufLen,nFlags); // deadlake PROXYSUPPORT - changed to AsyncSocketEx
	switch (recvRetCode) {
	case 0:
		if (GetRealReceivedBytes() > 0) // we received data but it was for the underlying encryption layer - all fine
			return 0;
		//EMTrace("CEMSocket::##Received FIN on %d, maxSize=%d",(SOCKET)this,nBufLen);
		// FIN received on socket // Connection is being closed by peer
		//ASSERT (false);
		if ( 0 == AsyncSelect(FD_CLOSE|FD_WRITE) ) { // no more READ notifications ...
			//int waserr = GetLastError(); // oups, AsyncSelect failed !!!
			ASSERT(false);
		}
		return 0;
	case SOCKET_ERROR:
		switch(GetLastError()) {
		case WSANOTINITIALISED:
			ASSERT(false);
			EMTrace("CEMSocket::OnReceive:A successful AfxSocketInit must occur before using this API.");
			break;
		case WSAENETDOWN:
			ASSERT(true);
			EMTrace("CEMSocket::OnReceive:The socket %d received a net down error",(SOCKET)this);
			break;
		case WSAENOTCONN: // The socket is not connected. 
			EMTrace("CEMSocket::OnReceive:The socket %d is not connected",(SOCKET)this);
			break;
		case WSAEINPROGRESS:   // A blocking Windows Sockets operation is in progress. 
			EMTrace("CEMSocket::OnReceive:The socket %d is blocked",(SOCKET)this);
			break;
		case WSAEWOULDBLOCK:   // The socket is marked as nonblocking and the Receive operation would block. 
			EMTrace("CEMSocket::OnReceive:The socket %d would block",(SOCKET)this);
			break;
		case WSAENOTSOCK:   // The descriptor is not a socket. 
			EMTrace("CEMSocket::OnReceive:The descriptor %d is not a socket (may have been closed or never created)",(SOCKET)this);
			break;
		case WSAEOPNOTSUPP:  // MSG_OOB was specified, but the socket is not of type SOCK_STREAM. 
			break;
		case WSAESHUTDOWN:   // The socket has been shut down; it is not possible to call Receive on a socket after ShutDown has been invoked with nHow set to 0 or 2. 
			EMTrace("CEMSocket::OnReceive:The socket %d has been shut down",(SOCKET)this);
			break;
		case WSAEMSGSIZE:   // The datagram was too large to fit into the specified buffer and was truncated. 
			EMTrace("CEMSocket::OnReceive:The datagram was too large to fit and was truncated (socket %d)",(SOCKET)this);
			break;
		case WSAEINVAL:   // The socket has not been bound with Bind. 
			EMTrace("CEMSocket::OnReceive:The socket %d has not been bound",(SOCKET)this);
			break;
		case WSAECONNABORTED:   // The virtual circuit was aborted due to timeout or other failure. 
			EMTrace("CEMSocket::OnReceive:The socket %d has not been bound",(SOCKET)this);
			break;
		case WSAECONNRESET:   // The virtual circuit was reset by the remote side. 
			EMTrace("CEMSocket::OnReceive:The socket %d has not been bound",(SOCKET)this);
			break;
		default:
			EMTrace("CEMSocket::OnReceive:Unexpected socket error %x on socket %d",GetLastError(),(SOCKET)this);
			break;
		}
		break;
	default:
//		EMTrace("CEMSocket::OnReceive on %d, receivedSize=%d",(SOCKET)this,recvRetCode);
		return recvRetCode;
	}
	return SOCKET_ERROR;
}

void CEMSocket::RemoveAllLayers()
{
	CEncryptedStreamSocket::RemoveAllLayers();
	delete m_pProxyLayer;
	m_pProxyLayer = NULL;
}

int CEMSocket::OnLayerCallback(const CAsyncSocketExLayer *pLayer, int nType, int nCode, WPARAM wParam, LPARAM lParam)
{
	UNREFERENCED_PARAMETER(wParam);
	ASSERT( pLayer );
	if (nType == LAYERCALLBACK_STATECHANGE)
	{
		/*CString logline;
		if (pLayer==m_pProxyLayer)
		{
			//logline.Format(_T("ProxyLayer changed state from %d to %d"), wParam, nCode);
			//AddLogLine(false,logline);
		}else
			//logline.Format(_T("Layer @ %d changed state from %d to %d"), pLayer, wParam, nCode);
			//AddLogLine(false,logline);*/
		return 1;
	}
	else if (nType == LAYERCALLBACK_LAYERSPECIFIC)
	{
		if (pLayer == m_pProxyLayer)
		{
			switch (nCode)
			{
				case PROXYERROR_NOCONN:
					// We failed to connect to the proxy.
					m_bProxyConnectFailed = true;
					/* fall through */
				case PROXYERROR_REQUESTFAILED:
					// We are connected to the proxy but it failed to connect to the peer.
					if (thePrefs.GetVerbose()) {
						m_strLastProxyError = GetProxyError(nCode);
						if (lParam && ((LPCSTR)lParam)[0] != '\0') {
							m_strLastProxyError += _T(" - ");
							m_strLastProxyError += (LPCSTR)lParam;
						}
						// Appending the Winsock error code is actually not needed because that error code
						// gets reported by to the original caller anyway and will get reported eventually
						// by calling 'GetFullErrorMessage',
						/*if (wParam) {
							CString strErrInf;
							if (GetErrorMessage(wParam, strErrInf, 1))
								m_strLastProxyError += _T(" - ") + strErrInf;
						}*/
					}
					break;
				default:
					m_strLastProxyError = GetProxyError(nCode);
					LogWarning(false, _T("Proxy-Error: %s"), m_strLastProxyError);
			}
		}
	}
	return 1;
}

/**
 * Removes all packets from the standard queue that don't have to be sent for the socket to be able to send a control packet.
 *
 * Before a socket can send a new packet, the current packet has to be finished. If the current packet is part of
 * a split packet, then all parts of that split packet must be sent before the socket can send a control packet.
 *
 * This method keeps in standard queue only those packets that must be sent (rest of split packet), and removes everything
 * after it. The method doesn't touch the control packet queue.
 */
void CEMSocket::TruncateQueues() {
    sendLocker.Lock();

    // Clear the standard queue totally
    // Please note! There may still be a standardpacket in the sendbuffer variable!
	for(POSITION pos = standartpacket_queue.GetHeadPosition(); pos != NULL; )
		delete standartpacket_queue.GetNext(pos).packet;
	standartpacket_queue.RemoveAll();

    sendLocker.Unlock();
}

#ifdef _DEBUG
void CEMSocket::AssertValid() const
{
	CEncryptedStreamSocket::AssertValid();

	const_cast<CEMSocket*>(this)->sendLocker.Lock();

	ASSERT( byConnected==ES_DISCONNECTED || byConnected==ES_NOTCONNECTED || byConnected==ES_CONNECTED );
	CHECK_BOOL(m_bProxyConnectFailed);
	CHECK_PTR(m_pProxyLayer);
	(void)downloadLimit;
	CHECK_BOOL(downloadLimitEnable);
	CHECK_BOOL(pendingOnReceive);
	//char pendingHeader[PACKET_HEADER_SIZE];
	pendingHeaderSize;
	CHECK_PTR(pendingPacket);
	(void)pendingPacketSize;
	CHECK_ARR(sendbuffer, sendblen);
	(void)sent;
	controlpacket_queue.AssertValid();
	standartpacket_queue.AssertValid();
	CHECK_BOOL(m_currentPacket_is_controlpacket);
    //(void)sendLocker;
    (void)m_numberOfSentBytesCompleteFile;
    (void)m_numberOfSentBytesPartFile;
    (void)m_numberOfSentBytesControlPacket;
    CHECK_BOOL(m_currentPackageIsFromPartFile);
    (void)lastCalledSend;
    (void)m_actualPayloadSize;
    (void)m_actualPayloadSizeSent;

	const_cast<CEMSocket*>(this)->sendLocker.Unlock();
}
#endif

#ifdef _DEBUG
void CEMSocket::Dump(CDumpContext& dc) const
{
	CEncryptedStreamSocket::Dump(dc);
}
#endif

void CEMSocket::DataReceived(const BYTE*, UINT)
{
	ASSERT(0);
}

UINT CEMSocket::GetTimeOut() const
{
	return m_uTimeOut;
}

void CEMSocket::SetTimeOut(UINT uTimeOut)
{
	m_uTimeOut = uTimeOut;
}

CString CEMSocket::GetFullErrorMessage(DWORD nErrorCode)
{
	CString strError;

	// Proxy error
	if (!GetLastProxyError().IsEmpty())
	{
		strError = GetLastProxyError();
		// If we had a proxy error and the socket error is WSAECONNABORTED, we just 'aborted'
		// the TCP connection ourself - no need to show that self-created error too.
		if (nErrorCode == WSAECONNABORTED)
			return strError;
	}

	// Winsock error
	if (nErrorCode)
	{
		if (!strError.IsEmpty())
			strError += _T(": ");
		strError += GetErrorMessage(nErrorCode, 1);
	}

	return strError;
}

// increases the send buffer to a bigger size
bool CEMSocket::UseBigSendBuffer()
{
#define BIGSIZE 128 * 1024
	if (m_bUsesBigSendBuffers)
		return true;
	m_bUsesBigSendBuffers = true;
    int val = BIGSIZE;
    int vallen = sizeof(int);
	int oldval = 0;
	GetSockOpt(SO_SNDBUF, &oldval, &vallen);
	if (val > oldval)
		SetSockOpt(SO_SNDBUF, &val, sizeof(int));
	val = 0;
	vallen = sizeof(int);
	GetSockOpt(SO_SNDBUF, &val, &vallen);
#if defined(_DEBUG) || defined(_BETA)
	if (val == BIGSIZE)
		theApp.QueueDebugLogLine(false, _T("Increased Sendbuffer for uploading socket from %uKB to %uKB"), oldval/1024, val/1024);
	else
		theApp.QueueDebugLogLine(false, _T("Failed to increase Sendbuffer for uploading socket, stays at %uKB"), oldval/1024);
#endif
	return val == BIGSIZE;
}
