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
#include "emule.h"
#include "Sockets.h"
#include "Opcodes.h"
#include "UDPSocket.h"
#include "Exceptions.h"
#include "OtherFunctions.h"
#include "Statistics.h"
#include "ServerSocket.h"
#include "ServerList.h"
#include "Server.h"
#include "ListenSocket.h"
#include "SafeFile.h"
#include "Packets.h"
#include "SharedFileList.h"
#include "PeerCacheFinder.h"
#include "emuleDlg.h"
#include "SearchDlg.h"
#include "ServerWnd.h"
#include "TaskbarNotifier.h"
#include "Log.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

///snow:根据是否启用安全服务器连接决定是可以同时进行一或两个连接尝试，如果是，就只进行一个连接尝试，否，同时可以进行两个尝试
///snow:如果启用加密连接时没有服务器可连，则对全部服务器进行未加密连接尝试；如果没有启用，则暂停30秒后重新尝试连接
///snow:在本类中被ConnectToAnyServer、ConnectionFailed调用，在其它类中被UploadQueue::UploadTimer调用，在UploadTimer中启动第二个服务器连接尝试
void CServerConnect::TryAnotherConnectionRequest()
{
	///snow:根据选项中是否启用安全服务器连接，确定同时只能发起一个连接，还是可以两个连接
	if (connectionattemps.GetCount() < (thePrefs.IsSafeServerConnectEnabled() ? 1 : 2))
	{
		CServer* next_server = theApp.serverlist->GetNextServer(m_bTryObfuscated);    ///snow:如果bNoCrypt为true，m_bTryObfuscated一定为false
		if (next_server == NULL)  ///snow:已到列表末尾
		{
			if (connectionattemps.GetCount() == 0) ///snow:表示没有服务器正在尝试连接，
			{
				///snow:如果当前是启用加密连接，且选项中未设置只允许加密连接，则尝试未加密连接
				if (m_bTryObfuscated && !thePrefs.IsClientCryptLayerRequired()){  ///snow:IsClientCryptLayerRequired()返回的是:是否只允许加密连接（Allow obfuscated connections only）
					// try all servers on the non-obfuscated port next
					m_bTryObfuscated = false;
					ConnectToAnyServer(0, true, true, true);
				}
				///snow:如果当前是也没启用加密连接，则设定时间间隔，启动定时器在一段时间后重新连接，默认30秒
				else if (m_idRetryTimer == 0)
				{
					// 05-Nov-2003: If we have a very short server list, we could put serious load on those few servers
					// if we start the next connection tries without waiting.
					LogWarning(LOG_STATUSBAR, GetResString(IDS_OUTOFSERVERS));
					AddLogLine(false, GetResString(IDS_RECONNECT), CS_RETRYCONNECTTIME);
					m_uStartAutoConnectPos = 0; // default: start at 0
					VERIFY( (m_idRetryTimer = SetTimer(NULL, 0, 1000*CS_RETRYCONNECTTIME, RetryConnectTimer)) != NULL );
					if (thePrefs.GetVerbose() && !m_idRetryTimer)
						DebugLogError(_T("Failed to create 'server connect retry' timer - %s"), GetErrorMessage(GetLastError()));
				}
			}
			return;
		}

		// Barry - Only auto-connect to static server option
		if (thePrefs.GetAutoConnectToStaticServersOnly())
		{
			if (next_server->IsStaticMember())    ///snow:只连接静态服务器
				ConnectToServer(next_server, true, !m_bTryObfuscated);    
			///snow:这边的m_bTryObfuscated为什么取反？
			///snow:因为这个参数依然是bNoCrypt，如果ConnectToAnyServer()中参数bNoCrypt为true，m_bTryObfuscated为false，!m_bTryObfuscated=true，等于还是以bNoCrypt=true调用ConnectToServer()
		}
		else
			ConnectToServer(next_server, true, !m_bTryObfuscated);
	}
}

///snow:调用模式有4种：1、点击连接按钮；2、选项设置程序启动自动连接；3、点击服务器列表的中服务器启动连接选定服务器（可以多选）；4、定时器启动重新连接尝试
void CServerConnect::ConnectToAnyServer(UINT startAt, bool prioSort, bool isAuto, bool bNoCrypt)
{
	StopConnectionTry();
	Disconnect();
	connecting = true;
	singleconnecting = false;
	theApp.emuledlg->ShowConnectionState();

	///snow:选项中的Enable protocol obfuscation选中，Disable support for obfuscated connections未选中，IsServerCryptLayerTCPRequested()返回true
	///snow:bNoCrypt默认为false，但在加密连接都失败的情况下，bNoCrypt会被设置为true，未带参数的ConnectToAnyServer()中的bNoCrypt为true
	///snow:这个参数跟服务器没有关系，只是客户端的设置与跟服务器连接时的成败情况有关
	m_bTryObfuscated = thePrefs.IsServerCryptLayerTCPRequested() && !bNoCrypt;  

	// Barry - Only auto-connect to static server option   ///snow:自动连接静态服务器，检查服务器列表里是否存在静态服务器
	if (thePrefs.GetAutoConnectToStaticServersOnly() && isAuto)
	{
		bool anystatic = false;
		CServer *next_server;
		theApp.serverlist->SetServerPosition(startAt);
		while ((next_server = theApp.serverlist->GetNextServer(false)) != NULL)
		{
			if (next_server->IsStaticMember()) {
				anystatic = true;    ///snow:存在静态服务器
				break;
			}
		}
		if (!anystatic) {   ///snow:不存在
			connecting = false;
			LogError(LOG_STATUSBAR, GetResString(IDS_ERR_NOVALIDSERVERSFOUND));
			return;
		}
	}

	///snow:确定是否对服务器列表进行相应排序（用户排序和优先级排序）
	theApp.serverlist->SetServerPosition(startAt);
	if (thePrefs.GetUseUserSortedServerList() && startAt == 0 && prioSort)
		theApp.serverlist->GetUserSortedServers();///snow:排序
	if (thePrefs.GetUseServerPriorities() && prioSort) ///snow:优先级
		theApp.serverlist->Sort();

	///snow:列表为0，没有服务器
	if (theApp.serverlist->GetServerCount() == 0) {
		connecting = false;
		LogError(LOG_STATUSBAR, GetResString(IDS_ERR_NOVALIDSERVERSFOUND));
		return;
	}
	theApp.listensocket->Process();

	///snow:主要作用是发起多个连接，但是第一次连接时是只发起一个连接尝试
	TryAnotherConnectionRequest();
}

///snow:向服务器发起连接
void CServerConnect::ConnectToServer(CServer* server, bool multiconnect, bool bNoCrypt)
{
	if (!multiconnect) {
		StopConnectionTry();
		Disconnect();
	}
	connecting = true;
	singleconnecting = !multiconnect;
	theApp.emuledlg->ShowConnectionState();

	///snow:新建一个到服务器的Socket，如果连接成功，这个socket就成为客户端以后与服务器的连接通道
	CServerSocket* newsocket = new CServerSocket(this, !multiconnect);
	m_lstOpenSockets.AddTail((void*&)newsocket);
	newsocket->Create(0, SOCK_STREAM, FD_READ | FD_WRITE | FD_CLOSE | FD_CONNECT, thePrefs.GetBindAddrA());
	newsocket->ConnectTo(server, bNoCrypt);  ///snow:转向ServerSocket类的ConnectTo
	connectionattemps.SetAt(GetTickCount(), newsocket);  ///snow:加入connectionattemps，供TryAnotherConnectionRequest判断是否可同时发起两个连接
}

void CServerConnect::StopConnectionTry()
{
	connectionattemps.RemoveAll();
	connecting = false;
	singleconnecting = false;
	theApp.emuledlg->ShowConnectionState();

	if (m_idRetryTimer) 
	{ 
		KillTimer(NULL, m_idRetryTimer); 
		m_idRetryTimer= 0; 
	} 

	// close all currenty opened sockets except the one which is connected to our current server
	for( POSITION pos = m_lstOpenSockets.GetHeadPosition(); pos != NULL; )
	{
		CServerSocket* pSck = (CServerSocket*)m_lstOpenSockets.GetNext(pos);
		if (pSck == connectedsocket)		// don't destroy socket which is connected to server
			continue;
		if (pSck->m_bIsDeleting == false)	// don't destroy socket if it is going to destroy itself later on
			DestroySocket(pSck);
	}
}

/**********************************************************snow:start***************************************************
/*  在发出connect to server请求后，FD_CONNECT事件触发，OnConnect()被调用，
/* 根据OnConnect中返回的nErrorCode，如果成功，设置连接状态为等待登录（CS_WAITFORLOGIN）,调用ConnectionEstablished，
/*     如果失败，设置连接状态为CS_SERVERDEAD或CS——SERVERFATAL，调用ConnectionFailed
**********************************************************snow:end******************************************************/

///snow:这个函数名有点误导，实际上处理两种情况：一种是连接建立了，但尚未登录，需要向服务器发送登录信息；一种是已经登录成功了，连接正式建立
///snow:与ConnectionFailed一样，只在SetConnectionState()中调用
void CServerConnect::ConnectionEstablished(CServerSocket* sender)
{
	if (!connecting) {
		// we are already connected to another server
		DestroySocket(sender);
		return;
	}
	
	InitLocalIP();
	if (sender->GetConnectionState() == CS_WAITFORLOGIN) ///snow:连接建立了，但尚未登录，向服务器发送登录信息
	{
		AddLogLine(false, GetResString(IDS_CONNECTEDTOREQ), sender->cur_server->GetListName(), sender->cur_server->GetAddress(), sender->IsServerCryptEnabledConnection() ? sender->cur_server->GetObfuscationPortTCP() : sender->cur_server->GetPort());
		///snow:获取当前服务器
		CServer* pServer = theApp.serverlist->GetServerByAddress(sender->cur_server->GetAddress(), sender->cur_server->GetPort());
		if (pServer) {
			pServer->ResetFailedCount(); ///snow:重置该服务器的连接失败计数，刷新界面
			theApp.emuledlg->serverwnd->serverlistctrl.RefreshServer(pServer);
		}
		///snow:向服务器发送登录信息包
		// Send login packet
		CSafeMemFile data(256);
		data.WriteHash16(thePrefs.GetUserHash()); ///snow:16字节UserHash:9c 43 1e b7 1e 0e 14 2b f1 bc f5 2d 41 c1 6f b0
		data.WriteUInt32(GetClientID());          ///snow:4字节ClientID :00 00 00 00
		data.WriteUInt16(thePrefs.GetPort());     ///snow:2字节Port:3e d8  逆字节序，55358（0xD83E)

		UINT tagcount = 4;
		data.WriteUInt32(tagcount);               ///snow:写入四个字节，有四个标签 04 00 00 00

		CTag tagName(CT_NAME, thePrefs.GetUserNick());   ///snow:UserNick:http://emule-project.net
		tagName.WriteTagToFile(&data);   ///snow:写入的实际数据为02 01 00 01 18 00 68 74 74 70 3a 2f 2f 65 6d 75 6c 65 2d 70 72 6f 6a 65 63 74 2e 6e 65 74
		///snow:而http://emule-project.net 对应的数据为68 74 74 70 3a 2f 2f 65 6d 75 6c 65 2d 70 72 6f 6a 65 63 74 2e 6e 65 74
		///snow:多写的数据为02 01 00 01 18 00  m_uType=TAGTYPE_STRING(0x02),m_uName=CT_NAME(0x01),m_pszName = NULL(0x00),m_nBlobSize = 0(0x00);m_pstrVal字符串长度为24（0x18),没搞明白01是什么？还有字节的顺序，字符串的长度怎么写到tag的？
		///snow:上面的问题在WriteTagToFile（）中可以看得清楚，对各字节的理解有误，具体请参考在WriteTagToFile中的注释

		CTag tagVersion(CT_VERSION, EDONKEYVERSION);  ///snow:生成数据03 11 cc cc 00 00 00 00 00 00 00 00 3c 00 00 00 00 00 00 00
		tagVersion.WriteTagToFile(&data); ///snow:写入的数据为03 01 00 11 3c 00 00 00
		///snow:m_uType=TAGTYPE_UINT32(0x03),m_pszName = NULL（实际写入 01 00）,m_uName=CT_VERSION(0x11),m_uVal=EDONKEYVERSION(0x3c 00 00 00四个字节),m_nBlobSize 未写入;


		uint32 dwCryptFlags = 0;
		if (thePrefs.IsClientCryptLayerSupported())
			dwCryptFlags |= SRVCAP_SUPPORTCRYPT;
		if (thePrefs.IsClientCryptLayerRequested())
			dwCryptFlags |= SRVCAP_REQUESTCRYPT;
		if (thePrefs.IsClientCryptLayerRequired())
			dwCryptFlags |= SRVCAP_REQUIRECRYPT;

		CTag tagFlags(CT_SERVER_FLAGS, SRVCAP_ZLIB | SRVCAP_NEWTAGS | SRVCAP_LARGEFILES | SRVCAP_UNICODE | dwCryptFlags);
		///snow:生成数据 03 20 cc cc 00 00 00 00 00 00 00 00 19 03 00 00 00 00 00 00
		tagFlags.WriteTagToFile(&data);
		///snow:实际写入数据03（m_uType=TAGTYPE_UINT32） 01 00（m_pszName = NULL） 20（CT_SERVER_FLAGS） 19 03 00 00（ SRVCAP_ZLIB | SRVCAP_NEWTAGS | SRVCAP_LARGEFILES | SRVCAP_UNICODE | dwCryptFlags）

		// eMule Version (14-Mar-2004: requested by lugdunummaster (need for LowID clients which have no chance 
		// to send an Hello packet to the server during the callback test))
		CTag tagMuleVersion(CT_EMULE_VERSION, 
							//(uCompatibleClientID		<< 24) |
							(CemuleApp::m_nVersionMjr	<< 17) |
							(CemuleApp::m_nVersionMin	<< 10) |
							(CemuleApp::m_nVersionUpd	<<  7) );
		///snow:生成数据 03 fb cc cc 00 00 00 00 00 00 00 00 00 c8 00 00 00 00 00 00
		tagMuleVersion.WriteTagToFile(&data);
		///snow:写入数据：03（m_uType=TAGTYPE_UINT32） 01 00（m_pszName = NULL） fb（CT_EMULE_VERSION） 00 c8 00 00（版本号）

		Packet* packet = new Packet(&data);///snow:数据格式见Packet::Packet(CMemFile* datafile, uint8 protocol, uint8 ucOpcode)注释
		packet->opcode = OP_LOGINREQUEST;  ///snow:opcode位置1（OP_LOGINREQUEST）
		///snow:packet数据为5c c0 89 01 (Packet对象)be 5e de 04（pBuffer) 50(size，80字节） 00(m_bSplitted) 00(m_bLastSplitted) 00(m_bPacked) 01(ucOpcode) e3(protocol) 00 00 00 00（tempbuffer） cd cd b8 5e de 04(completebuffer) 00 00 00 00
		if (thePrefs.GetDebugServerTCPLevel() > 0)
			Debug(_T(">>> Sending OP__LoginRequest\n"));
		theStats.AddUpDataOverheadServer(packet->size);
		SendPacket(packet, true, sender); ///snow:由sender发送，sender为ServerSocket::OnConnect()传递过来的ServerSocket对象（this)
	}
	else if (sender->GetConnectionState() == CS_CONNECTED)   ///snow:连接成功，在ServerSocket::ProcessPack()的{case OP_IDCHANGE:}分支中被设置，也就是说当获得ID了，表示连接并登录成功！
	{
		theStats.reconnects++;
		theStats.serverConnectTime = GetTickCount();
		connected = true;
		CString strMsg;
		if (sender->IsObfusicating())
			strMsg.Format(GetResString(IDS_CONNECTEDTOOBFUSCATED) + _T(" (%s:%u)"), sender->cur_server->GetListName(), sender->cur_server->GetAddress(), sender->cur_server->GetObfuscationPortTCP());
		else
			strMsg.Format(GetResString(IDS_CONNECTEDTO) + _T(" (%s:%u)"), sender->cur_server->GetListName(), sender->cur_server->GetAddress(), sender->cur_server->GetPort());

		Log(LOG_SUCCESS | LOG_STATUSBAR, strMsg);
		theApp.emuledlg->ShowConnectionState();
		connectedsocket = sender;
		StopConnectionTry();   ///snow:停止其它正在进行的连接尝试
		theApp.sharedfiles->ClearED2KPublishInfo();
		theApp.sharedfiles->SendListToServer();  ///snow:向服务器发送本机的共享文件列表
		theApp.emuledlg->serverwnd->serverlistctrl.RemoveAllDeadServers();

		// tecxx 1609 2002 - serverlist update
		if (thePrefs.GetAddServersFromServer())  ///snow:如果选项“从服务器更新服务器列表”选中，则从登录的服务器上更新服务器列表，发送请求服务器列表的包
		{
			Packet* packet = new Packet(OP_GETSERVERLIST,0);
			if (thePrefs.GetDebugServerTCPLevel() > 0)
				Debug(_T(">>> Sending OP__GetServerList\n"));
			theStats.AddUpDataOverheadServer(packet->size);
			SendPacket(packet, true);
		}

		CServer* pServer = theApp.serverlist->GetServerByAddress(sender->cur_server->GetAddress(), sender->cur_server->GetPort());
		if (pServer)
			theApp.emuledlg->serverwnd->serverlistctrl.RefreshServer(pServer);
	}
	theApp.emuledlg->ShowConnectionState();
}

bool CServerConnect::SendPacket(Packet* packet,bool delpacket, CServerSocket* to){
	if (!to){ ///snow:to为NULL
		if (connected){ ///snow:已连接，由connectedsocket发送
			connectedsocket->SendPacket(packet,delpacket,true); ///snow:由CServerConnect对象发出的包均为控制包（controlpack)
		}
		else{  ///to为NULL，connected为NULL，则不发送，根据delpacket是否为true，删除packet
			if (delpacket)
				delete packet;
			return false;
		}
	}
	else{  ///snow:to不为NULL，由to发送
		to->SendPacket(packet,delpacket,true);///snow:由CServerConnect对象发出的包均为控制包（controlpack)
	}
	return true;
}

bool CServerConnect::SendUDPPacket(Packet* packet, CServer* host, bool delpacket, uint16 nSpecialPort, BYTE* pRawPacket, uint32 nLen){
	if (theApp.IsConnected()){
		if (udpsocket != NULL)
			udpsocket->SendPacket(packet, host, nSpecialPort, pRawPacket, nLen);
	}
	if (delpacket){
		delete packet;
		delete[] pRawPacket;
	}
	return true;
}

///snow:同ConnectionEstablished一样，只在SetConnectionState()中调用，而ConnectionState错误的来源可能来自三个方面：
///snow：OnHostNameResolved、OnConnect、OnClose
void CServerConnect::ConnectionFailed(CServerSocket* sender)
{
	if (!connecting && sender != connectedsocket) {
		// just return, cleanup is done by the socket itself
		return;
	}

	CServer* pServer = theApp.serverlist->GetServerByAddress(sender->cur_server->GetAddress(), sender->cur_server->GetPort());
	switch (sender->GetConnectionState())
	{
		case CS_FATALERROR:  ///snow:未知错误，已知状态之外的缺省设置，在OnConnect()中设置
			LogError(LOG_STATUSBAR, GetResString(IDS_ERR_FATAL));
			break;
		case CS_DISCONNECTED:///snow:服务器断开连接，返回的状态码是CS_DISCONNECTED，OnClose()中设置
			theApp.sharedfiles->ClearED2KPublishInfo();
			LogError(LOG_STATUSBAR, GetResString(IDS_ERR_LOSTC), sender->cur_server->GetListName(), sender->cur_server->GetAddress(), sender->cur_server->GetPort());
			break;
		case CS_SERVERDEAD:   ///snow:服务器未响应，在OnConnect()中设置
			LogError(LOG_STATUSBAR, GetResString(IDS_ERR_DEAD), sender->cur_server->GetListName(), sender->cur_server->GetAddress(), sender->cur_server->GetPort());
			if (pServer) {
				pServer->AddFailedCount();  ///snow:服务器连接失败计数+1
				theApp.emuledlg->serverwnd->serverlistctrl.RefreshServer(pServer);
			}
			break;
		case CS_ERROR:    ///snow:OnHostNameResolved()中设置，服务器被过滤了
			break;
		case CS_SERVERFULL:    ///snow:服务器断开连接，返回的状态码是CS_SERVERFULL，OnClose()中设置
			LogError(LOG_STATUSBAR, GetResString(IDS_ERR_FULL), sender->cur_server->GetListName(), sender->cur_server->GetAddress(), sender->cur_server->GetPort());
			break;
		case CS_NOTCONNECTED:  ///snow:服务器断开连接，返回的状态码是CS_NOTCONNECTED，OnClose()中设置
			break;
	}

	// IMPORTANT: mark this socket not to be deleted in StopConnectionTry(),
	// because it will delete itself after this function!
	sender->m_bIsDeleting = true;

	switch (sender->GetConnectionState())
	{
		///snow:连接时遭遇未知错误，停止连接尝试，暂停30秒后重新连接全部服务器
		case CS_FATALERROR:{
			bool autoretry = !singleconnecting;
			StopConnectionTry();
			if (thePrefs.Reconnect() && autoretry && !m_idRetryTimer) {
				LogWarning(GetResString(IDS_RECONNECT), CS_RETRYCONNECTTIME);

				// There are situations where we may get Winsock error codes which indicate
				// that the network is down, although it is not. Those error codes may get
				// thrown only for particular IPs. If the first server in our list has such
				// an IP and will therefor throw such an error we would never connect to
				// any server at all. To circumvent that, start the next auto-connection
				// attempt with a different server (use the next server in the list).
				///snow:从下一服务器开始，原因是防止第一个服务器就发生fatalerror，如果还是从当前服务器开始，则连接将一直无法进行
				m_uStartAutoConnectPos = 0; // default: start at 0
				if (pServer) {
					// If possible, use the "next" server.
					int iPosInList = theApp.serverlist->GetPositionOfServer(pServer);
					if (iPosInList >= 0)
						m_uStartAutoConnectPos = (iPosInList + 1) % theApp.serverlist->GetServerCount();
				}
				VERIFY( (m_idRetryTimer = SetTimer(NULL, 0, 1000*CS_RETRYCONNECTTIME, RetryConnectTimer)) != NULL );
				if (thePrefs.GetVerbose() && !m_idRetryTimer)
					DebugLogError(_T("Failed to create 'server connect retry' timer - %s"), GetErrorMessage(GetLastError()));
			}
			break;
		}
		case CS_DISCONNECTED:{
			theApp.sharedfiles->ClearED2KPublishInfo();
			connected = false;
			if (connectedsocket) {   ///snow:如果已存在与服务器连接的SOCKET，关闭该socket
				connectedsocket->Close();
				connectedsocket = NULL;
			}
			theApp.emuledlg->searchwnd->CancelEd2kSearch();
			theStats.serverConnectTime = 0;
			theStats.Add2TotalServerDuration();
			if (thePrefs.Reconnect() && !connecting)
				ConnectToAnyServer();	 ///snow:重新发起连接，从服务器列表开始位置发起连接	
			if (thePrefs.GetNotifierOnImportantError())
				theApp.emuledlg->ShowNotifier(GetResString(IDS_CONNECTIONLOST), TBN_IMPORTANTEVENT);
			break;
		}
		case CS_ERROR:
		case CS_NOTCONNECTED:{
			if (!connecting)
				break;
		}
		case CS_SERVERDEAD:
		case CS_SERVERFULL:{
			if (!connecting)
				break;
			if (singleconnecting){  ///snow:缺省为false，只在本语句块中被置为true。这就好奇怪了，这样永远不可能被置为true呀？？？
				///snow:上面的理解错了，ConnectToServer()中的multiconnect缺省为false， 当直接双击服务器列表中的服务器进行连接时，进行的是singleconnecting！
				if (pServer != NULL && sender->IsServerCryptEnabledConnection() && !thePrefs.IsClientCryptLayerRequired()){   
					// try reconnecting without obfuscation  ///snow:进行不加密连接，前提是上一次连接失败的是加密连接！
					ConnectToServer(pServer, false, true);  ///snow:置singleconnecting为true，就是说如果是双击界面中服务器列表的服务器进行连接的，则接下来的连接都是singleconnecting!
					break;
				}
				StopConnectionTry();
				break;
			}

			///snow:从connectionattemps列表中移除当前socket
			DWORD tmpkey;
			CServerSocket* tmpsock;
			POSITION pos = connectionattemps.GetStartPosition();
			while (pos) {
				connectionattemps.GetNextAssoc(pos, tmpkey, tmpsock);
				if (tmpsock == sender) {
					connectionattemps.RemoveKey(tmpkey);
					break;
				}
			}
			///snow:从下一服务器开始进行连接尝试
			TryAnotherConnectionRequest();///snow:没找出什么时候就开始同时进行两个服务器连接尝试了？看来只可能是在CheckforTimeout()中了
			///snow:不是在CheckforTimeout中，而应该在CUploadQueue::UploadTimer中
		}
	}
	theApp.emuledlg->ShowConnectionState();
}

///snow:定时器，30秒后重新尝试连接
VOID CALLBACK CServerConnect::RetryConnectTimer(HWND /*hWnd*/, UINT /*nMsg*/, UINT /*nId*/, DWORD /*dwTime*/) 
{ 
	// NOTE: Always handle all type of MFC exceptions in TimerProcs - otherwise we'll get mem leaks
	try
	{
		CServerConnect *_this = theApp.serverconnect;
		ASSERT( _this );
		if (_this)
		{
			_this->StopConnectionTry();
			if (_this->IsConnected())
				return;
			if (_this->m_uStartAutoConnectPos >= theApp.serverlist->GetServerCount())
				_this->m_uStartAutoConnectPos = 0;
			_this->ConnectToAnyServer(_this->m_uStartAutoConnectPos, true, true);
		}
	}
	CATCH_DFLT_EXCEPTIONS(_T("CServerConnect::RetryConnectTimer"))
}

///snow:在CUploadQueue::UploadTimer()中调用
void CServerConnect::CheckForTimeout()
{ 
	DWORD dwServerConnectTimeout = CONSERVTIMEOUT;
	// If we are using a proxy, increase server connection timeout to default connection timeout
	if (thePrefs.GetProxySettings().UseProxy)
		dwServerConnectTimeout = max(dwServerConnectTimeout, CONNECTION_TIMEOUT);

	DWORD dwCurTick = GetTickCount();
	DWORD tmpkey;
	CServerSocket* tmpsock;
	POSITION pos = connectionattemps.GetStartPosition();
	while (pos){
		connectionattemps.GetNextAssoc(pos,tmpkey,tmpsock);
		if (!tmpsock){
			if (thePrefs.GetVerbose())
				DebugLogError(_T("Error: Socket invalid at timeoutcheck"));
			connectionattemps.RemoveKey(tmpkey);
			return;
		}

		if (dwCurTick - tmpkey > dwServerConnectTimeout){
			LogWarning(GetResString(IDS_ERR_CONTIMEOUT), tmpsock->cur_server->GetListName(), tmpsock->cur_server->GetAddress(), tmpsock->cur_server->GetPort());
			connectionattemps.RemoveKey(tmpkey);
			DestroySocket(tmpsock);
			if (singleconnecting)
				StopConnectionTry();
			else
				TryAnotherConnectionRequest(); ///snow:进行第二个连接尝试？看着也不对呀？CUploadQueue::UploadTimer在调用CheckforTimeout之前，直接调用了TryAnotherConnectionRequest
			///snow:而CUploadQueue::UploadTimer在CUploadQueue对象构造时调用

		}
	}
}

bool CServerConnect::Disconnect()
{
	if (connected && connectedsocket)
	{
		theApp.sharedfiles->ClearED2KPublishInfo();
		connected = false;
		CServer* pServer = theApp.serverlist->GetServerByAddress(connectedsocket->cur_server->GetAddress(), connectedsocket->cur_server->GetPort());
		if (pServer)
			theApp.emuledlg->serverwnd->serverlistctrl.RefreshServer(pServer);
		theApp.SetPublicIP(0);
		DestroySocket(connectedsocket);
		connectedsocket = NULL;
		theApp.emuledlg->ShowConnectionState();
		theStats.serverConnectTime = 0;
		theStats.Add2TotalServerDuration();
		return true;
	}
	return false;
}

CServerConnect::CServerConnect()
{
	connectedsocket = NULL;
	max_simcons = (thePrefs.IsSafeServerConnectEnabled()) ? 1 : 2;
	connecting = false;
	connected = false;
	clientid = 0;
	singleconnecting = false;
	if (thePrefs.GetServerUDPPort() != 0){
	    udpsocket = new CUDPSocket(); // initalize socket for udp packets
		if (!udpsocket->Create()){
			delete udpsocket;
			udpsocket = NULL;
		}
	}
	else
		udpsocket = NULL;
	m_idRetryTimer = 0;
	m_uStartAutoConnectPos = 0;
	InitLocalIP();
}

CServerConnect::~CServerConnect(){
	// stop all connections
	StopConnectionTry();
	// close connected socket, if any
	DestroySocket(connectedsocket);
	connectedsocket = NULL;
	// close udp socket
	if (udpsocket){
	    udpsocket->Close();
	    delete udpsocket;
    }
}

CServer* CServerConnect::GetCurrentServer(){
	if (IsConnected() && connectedsocket)
		return connectedsocket->cur_server;
	return NULL;
}

void CServerConnect::SetClientID(uint32 newid){
	clientid = newid;

	if (!::IsLowID(newid))
		theApp.SetPublicIP(newid);
	
	theApp.emuledlg->ShowConnectionState();
}

void CServerConnect::DestroySocket(CServerSocket* pSck){
	if (pSck == NULL)
		return;
	// remove socket from list of opened sockets
	for( POSITION pos = m_lstOpenSockets.GetHeadPosition(); pos != NULL; )
	{
		POSITION posDel = pos;
		CServerSocket* pTestSck = (CServerSocket*)m_lstOpenSockets.GetNext(pos);
		if (pTestSck == pSck)
		{
			m_lstOpenSockets.RemoveAt(posDel);
			break;
		}
	}
	if (pSck->m_SocketData.hSocket != INVALID_SOCKET){ // deadlake PROXYSUPPORT - changed to AsyncSocketEx
		pSck->AsyncSelect(0);
		pSck->Close();
	}

	delete pSck;
}

bool CServerConnect::IsLocalServer(uint32 dwIP, uint16 nPort){
	if (IsConnected()){
		if (connectedsocket->cur_server->GetIP() == dwIP && connectedsocket->cur_server->GetPort() == nPort)
			return true;
	}
	return false;
}

void CServerConnect::InitLocalIP()
{
	m_nLocalIP = 0;

	// Using 'gethostname/gethostbyname' does not solve the problem when we have more than 
	// one IP address. Using 'gethostname/gethostbyname' even seems to return the last IP 
	// address which we got. e.g. if we already got an IP from our ISP, 
	// 'gethostname/gethostbyname' will returned that (primary) IP, but if we add another
	// IP by opening a VPN connection, 'gethostname' will still return the same hostname, 
	// but 'gethostbyname' will return the 2nd IP.
	// To weaken that problem at least for users which are binding eMule to a certain IP,
	// we use the explicitly specified bind address as our local IP address.
	if (thePrefs.GetBindAddrA() != NULL) {
		unsigned long ulBindAddr = inet_addr(thePrefs.GetBindAddrA());
		if (ulBindAddr != INADDR_ANY && ulBindAddr != INADDR_NONE) {
			m_nLocalIP = ulBindAddr;
			return;
		}
	}

	// Don't use 'gethostbyname(NULL)'. The winsock DLL may be replaced by a DLL from a third party
	// which is not fully compatible to the original winsock DLL. ppl reported crash with SCORSOCK.DLL
	// when using 'gethostbyname(NULL)'.
	__try{
		char szHost[256];
		if (gethostname(szHost, sizeof szHost) == 0){
			hostent* pHostEnt = gethostbyname(szHost);
			if (pHostEnt != NULL && pHostEnt->h_length == 4 && pHostEnt->h_addr_list[0] != NULL)
				m_nLocalIP = *((uint32*)pHostEnt->h_addr_list[0]);
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER){
		// at least two ppl reported crashs when using 'gethostbyname' with third party winsock DLLs
		if (thePrefs.GetVerbose())
			DebugLogError(_T("Unknown exception in CServerConnect::InitLocalIP"));
		ASSERT(0);
	}
}

void CServerConnect::KeepConnectionAlive()
{
	DWORD dwServerKeepAliveTimeout = thePrefs.GetServerKeepAliveTimeout();
	if (dwServerKeepAliveTimeout && connected && connectedsocket && connectedsocket->connectionstate == CS_CONNECTED &&
		GetTickCount() - connectedsocket->GetLastTransmission() >= dwServerKeepAliveTimeout)
	{
		// "Ping" the server if the TCP connection was not used for the specified interval with 
		// an empty publish files packet -> recommended by lugdunummaster himself!
		CSafeMemFile files(4);
		files.WriteUInt32(0); // nr. of files
		Packet* packet = new Packet(&files);
		packet->opcode = OP_OFFERFILES;
		if (thePrefs.GetVerbose())
			AddDebugLogLine(false, _T("Refreshing server connection"));
		if (thePrefs.GetDebugServerTCPLevel() > 0)
			Debug(_T(">>> Sending OP__OfferFiles(KeepAlive) to server\n"));
		theStats.AddUpDataOverheadServer(packet->size);
		connectedsocket->SendPacket(packet,true);
	}
}

bool CServerConnect::IsLowID()
{
	return ::IsLowID(clientid);
}

// true if the IP is one of a server which we currently try to connect to
bool CServerConnect::AwaitingTestFromIP(uint32 dwIP) const{
	if (connectionattemps.IsEmpty())
		return false;
	DWORD tmpkey;
	CServerSocket* tmpsock;
	POSITION pos = connectionattemps.GetStartPosition();
	while (pos) {
		connectionattemps.GetNextAssoc(pos, tmpkey, tmpsock);
		if (tmpsock != NULL && tmpsock->cur_server != NULL && tmpsock->cur_server->GetIP() == dwIP && tmpsock->GetConnectionState() == CS_WAITFORLOGIN)
			return true;
	}
	return false;
}

bool CServerConnect::IsConnectedObfuscated() const {
	return connectedsocket != NULL && connectedsocket->IsObfusicating();
}
