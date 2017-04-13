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
#include "ServerSocket.h"
#include "SearchList.h"
#include "DownloadQueue.h"
#include "Statistics.h"
#include "ClientList.h"
#include "Server.h"
#include "ServerList.h"
#include "Sockets.h"
#include "OtherFunctions.h"
#include "Opcodes.h"
#include "Preferences.h"
#include "SafeFile.h"
#include "PartFile.h"
#include "Packets.h"
#include "UpDownClient.h"
#include "emuleDlg.h"
#include "ServerWnd.h"
#include "SearchDlg.h"
#include "IPFilter.h"
#include "Log.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif


#pragma pack(1)
struct LoginAnswer_Struct {
	uint32	clientid;
};
#pragma pack()


CServerSocket::CServerSocket(CServerConnect* in_serverconnect, bool bManualSingleConnect)
{
	serverconnect = in_serverconnect;
	connectionstate = CS_NOTCONNECTED;  ///snow:初始状态为未连接
	cur_server = NULL;
	m_bIsDeleting = false;
	m_dwLastTransmission = 0;
	m_bStartNewMessageLog = true;
	m_bManualSingleConnect = bManualSingleConnect;
}

CServerSocket::~CServerSocket()
{
	delete cur_server;
}

///snow:在CAsyncSocketExHelperWindow::WindowProc()中message == WM_SOCKETEX_GETHOST时调用，解决dynIP-server by DN的主机名解析问题
///snow: CAsyncSocketEx::Connect()过程中发出WM_SOCKETEX_GETHOST请求
BOOL CServerSocket::OnHostNameResolved(const SOCKADDR_IN *pSockAddr)
{
	// If we are connecting to a dynIP-server by DN, we will get this callback after the
	// DNS query finished.
	///snow:连接到具有动态IP的服务器
	if (cur_server->HasDynIP())
	{
		// Update the IP of this dynIP-server
		//
		cur_server->SetIP(pSockAddr->sin_addr.S_un.S_addr);///snow:给cur_server.ip,cur_server.ipfull赋值
		///snow:在serverlist中找是否存在同一IP和PORT的server，如果找到，则从列表中删除
		CServer* pServer = theApp.serverlist->GetServerByAddress(cur_server->GetAddress(), cur_server->GetPort());
		if (pServer) {
			pServer->SetIP(pSockAddr->sin_addr.S_un.S_addr);
			// If we already have entries in the server list (dynIP-servers without a DN)
			// with the same IP as this dynIP-server, remove the duplicates.
			theApp.serverlist->RemoveDuplicatesByIP(pServer);
		}
		DEBUG_ONLY( DebugLog(_T("Resolved DN for server '%s': IP=%s"), cur_server->GetAddress(), ipstr(cur_server->GetIP())) );

		// As this is a dynIP-server, we need to check the IP against the IP-filter
		// and eventually disconnect and delete that server.
		///snow:检查服务器的IP是否在FilterServer中，如果是，从服务器列表中删除，并重置连接状态
		if (thePrefs.GetFilterServerByIP() && theApp.ipfilter->IsFiltered(cur_server->GetIP())) {
			if (thePrefs.GetLogFilteredIPs())
				AddDebugLogLine(false, _T("IPFilter(TCP/DNSResolve): Filtered server \"%s\" (IP=%s) - IP filter (%s)"), pServer ? pServer->GetAddress() : cur_server->GetAddress(), ipstr(cur_server->GetIP()), theApp.ipfilter->GetLastHit());
			if (pServer)
				theApp.emuledlg->serverwnd->serverlistctrl.RemoveServer(pServer);
			m_bIsDeleting = true;
			SetConnectionState(CS_ERROR);
			serverconnect->DestroySocket(this);
			return FALSE;	// Do *NOT* connect to this server
		}
	}
	return TRUE; // Connect to this server
}

///snow:向服务器发起连接请求时被调用，根据返回信息分别设置连接状态，再调用相应的处理程序
void CServerSocket::OnConnect(int nErrorCode)
{
	CAsyncSocketEx::OnConnect(nErrorCode);

	switch (nErrorCode)
	{
		case 0:
			SetConnectionState(CS_WAITFORLOGIN);
			break;
			///snow:地址不可用,拒绝连接,超时,地址使用中四种情况时，设置删除标志，设置连接状态为CS_SERVERDEAD，销毁socket
		case WSAEADDRNOTAVAIL:///snow:地址不可用
		case WSAECONNREFUSED:///snow:拒绝连接
		//case WSAENETUNREACH:	// let this error default to 'fatal error' as it does not increase the server's failed count
		case WSAETIMEDOUT:///snow:超时
		case WSAEADDRINUSE:///snow:地址使用中
			if (thePrefs.GetVerbose())
				DebugLogError(_T("Failed to connect to server %s; %s"), cur_server->GetAddress(), GetFullErrorMessage(nErrorCode));
			m_bIsDeleting = true;
			SetConnectionState(CS_SERVERDEAD);
			serverconnect->DestroySocket(this);
			return;
			///snow:连接中止，代理连接失败，重置代理连接失败标志为false，设置删除标志，设置连接状态为CS_SERVERDEAD，销毁socket
		case WSAECONNABORTED:
			if (m_bProxyConnectFailed)
			{
				if (thePrefs.GetVerbose())
					DebugLogError(_T("Failed to connect to server %s; %s"), cur_server->GetAddress(), GetFullErrorMessage(nErrorCode));
				m_bProxyConnectFailed = false;
				m_bIsDeleting = true;
				SetConnectionState(CS_SERVERDEAD);
				serverconnect->DestroySocket(this);
				return;
			}
			/* fall through */ ///snow:严重错误，设置删除标志，设置连接状态为CS_FATALERROR，销毁socket
		default:
			if (thePrefs.GetVerbose())
				DebugLogError(_T("Failed to connect to server %s; %s"), cur_server->GetAddress(), GetFullErrorMessage(nErrorCode));
			m_bIsDeleting = true;
			SetConnectionState(CS_FATALERROR);
			serverconnect->DestroySocket(this);
			return;
	}
}

void CServerSocket::OnReceive(int nErrorCode){
	///snow:连接尚未建立或不在正在连接中，销毁socket
	if (connectionstate != CS_CONNECTED && !this->serverconnect->IsConnecting()){
		serverconnect->DestroySocket(this);
		return;
	}
	///snow:调用父类OnReceive（），并检索时钟，
	CEMSocket::OnReceive(nErrorCode);
	m_dwLastTransmission = GetTickCount();///nsow:Retrieves the number of milliseconds that have elapsed since the system was started, up to 49.7 days.

}

///snow:在PacketReceived()中调用，最主要的函数，集中处理收到的各种服务器包类型，在OnReceive()中收到数据，分割成一个一个packet，然后逐个packet调用PacketReceived-->ProcessPacket处理
bool CServerSocket::ProcessPacket(const BYTE* packet, uint32 size, uint8 opcode)
{
	try
	{
		switch (opcode) ///snow:在Opcodes.h定义 opcode包含中packet中
		{
			///snow:服务器返回服务器相关信息
			case OP_SERVERMESSAGE:{
				if (thePrefs.GetDebugServerTCPLevel() > 0)
					Debug(_T("ServerMsg - OP_ServerMessage\n"));

				CServer* pServer = cur_server ? theApp.serverlist->GetServerByAddress(cur_server->GetAddress(), cur_server->GetPort()) : NULL;
				CSafeMemFile data(packet, size);
				CString strMessages(data.ReadString(pServer ? pServer->GetUnicodeSupport() : false));

				if (thePrefs.GetDebugServerTCPLevel() > 0){
					UINT uAddData = (UINT)(data.GetLength() - data.GetPosition());
					if (uAddData > 0){
						Debug(_T("*** NOTE: OP_ServerMessage: ***AddData: %u bytes\n"), uAddData);
						DebugHexDump(packet + data.GetPosition(), uAddData);
					}
				}

				// 16.40 servers do not send separate OP_SERVERMESSAGE packets for each line;
				// instead of this they are sending all text lines with one OP_SERVERMESSAGE packet.
				int iPos = 0;
				CString message = strMessages.Tokenize(_T("\r\n"), iPos);
				while (!message.IsEmpty())
				{
					bool bOutputMessage = true;
					if (_tcsnicmp(message, _T("server version"), 14) == 0){
						CString strVer = message.Mid(14);
						strVer.Trim();
						strVer = strVer.Left(64); // truncate string to avoid misuse by servers in showing ads
						if (pServer){
							UINT nVerMaj, nVerMin;
							if (_stscanf(strVer, _T("%u.%u"), &nVerMaj, &nVerMin) == 2)
								strVer.Format(_T("%u.%02u"), nVerMaj, nVerMin);
							pServer->SetVersion(strVer);
							theApp.emuledlg->serverwnd->serverlistctrl.RefreshServer(pServer);
							theApp.emuledlg->serverwnd->UpdateMyInfo();
						}
						if (thePrefs.GetDebugServerTCPLevel() > 0)
							Debug(_T("%s\n"), message);
					}
					else if (_tcsncmp(message, _T("ERROR"), 5) == 0){
						LogError(LOG_STATUSBAR, _T("%s %s (%s:%u) - %s"), 
							GetResString(IDS_ERROR),
							pServer ? pServer->GetListName() : GetResString(IDS_PW_SERVER), 
							cur_server ? cur_server->GetAddress() : _T(""), 
							cur_server ? cur_server->GetPort() : 0, message.Mid(5).Trim(_T(" :")));
						bOutputMessage = false;
					}
					else if (_tcsncmp(message, _T("WARNING"), 7) == 0){
						LogWarning(LOG_STATUSBAR, _T("%s %s (%s:%u) - %s"), 
							GetResString(IDS_WARNING),
							pServer ? pServer->GetListName() : GetResString(IDS_PW_SERVER), 
							cur_server ? cur_server->GetAddress() : _T(""),
							cur_server ? cur_server->GetPort() : 0, message.Mid(7).Trim(_T(" :")));
						bOutputMessage = false;
					}

					if (message.Find(_T("[emDynIP: ")) != -1 && message.Find(_T("]")) != -1 && message.Find(_T("[emDynIP: ")) < message.Find(_T("]"))){
						CString dynip = message.Mid(message.Find(_T("[emDynIP: ")) + 10, message.Find(_T("]")) - (message.Find(_T("[emDynIP: ")) + 10));
						dynip.Trim();
						if (dynip.GetLength() && dynip.GetLength() < 51){
							// Verify that we really received a DN.
							if (pServer && inet_addr(CStringA(dynip)) == INADDR_NONE){
								// Update the dynIP of this server, but do not reset it's IP
								// which we just determined during connecting.
								CString strOldDynIP = pServer->GetDynIP();
								pServer->SetDynIP(dynip);
								// If a dynIP-server changed its address or, if this is the
								// first time we get the dynIP-address for a server which we
								// already have as non-dynIP in our list, we need to remove
								// an already available server with the same 'dynIP:port'.
								if (strOldDynIP.CompareNoCase(pServer->GetDynIP()) != 0)
									theApp.serverlist->RemoveDuplicatesByAddress(pServer);
								if (cur_server)
									cur_server->SetDynIP(dynip);
								theApp.emuledlg->serverwnd->serverlistctrl.RefreshServer(pServer);
								theApp.emuledlg->serverwnd->UpdateMyInfo();
							}
						}
					}

					if (bOutputMessage) {
						if (m_bStartNewMessageLog) {
							m_bStartNewMessageLog = false;
							theApp.emuledlg->AddServerMessageLine(LOG_INFO, _T(""));
							if (cur_server) {
								CString strMsg;
								if (IsObfusicating())
									strMsg.Format(_T("%s: ") + GetResString(IDS_CONNECTEDTOOBFUSCATED) + _T(" (%s:%u)"), CTime::GetCurrentTime().Format(thePrefs.GetDateTimeFormat4Log()), cur_server->GetListName(), cur_server->GetAddress(), cur_server->GetObfuscationPortTCP());
								else
									strMsg.Format(_T("%s: ") + GetResString(IDS_CONNECTEDTO) + _T(" (%s:%u)"), CTime::GetCurrentTime().Format(thePrefs.GetDateTimeFormat4Log()), cur_server->GetListName(), cur_server->GetAddress(), cur_server->GetPort());
								theApp.emuledlg->AddServerMessageLine(LOG_SUCCESS, strMsg);
							}
						}
						theApp.emuledlg->AddServerMessageLine(LOG_INFO, message);
					}

					message = strMessages.Tokenize(_T("\r\n"), iPos);
				}
				break;
			}
			///snow:连接并登录成功，获得服务器分配的ID
			case OP_IDCHANGE:{   
				if (thePrefs.GetDebugServerTCPLevel() > 0)
					Debug(_T("ServerMsg - OP_IDChange\n"));
				if (size < sizeof(LoginAnswer_Struct)){   ///snow:4字节
					throw GetResString(IDS_ERR_BADSERVERREPLY);
				}
				LoginAnswer_Struct* la = (LoginAnswer_Struct*)packet; ///snow:packet的前四个字节就是User ID

				// save TCP flags in 'cur_server'
				CServer* pServer = NULL;
				ASSERT( cur_server );
				if (cur_server){
					if (size >= sizeof(LoginAnswer_Struct)+4){   ///snow:获取TCP FLAGS
						DWORD dwFlags = *((uint32*)(packet + sizeof(LoginAnswer_Struct)));  ///snow:ID后两个字节
						if (thePrefs.GetDebugServerTCPLevel() > 0){
							CString strInfo;
							strInfo.AppendFormat(_T("  TCP Flags=0x%08x"), dwFlags);
							const DWORD dwKnownBits = SRV_TCPFLG_COMPRESSION | SRV_TCPFLG_NEWTAGS | SRV_TCPFLG_UNICODE | SRV_TCPFLG_RELATEDSEARCH | SRV_TCPFLG_TYPETAGINTEGER | SRV_TCPFLG_LARGEFILES | SRV_TCPFLG_TCPOBFUSCATION;  ///snow:0101 1101 1001
							if (dwFlags & ~dwKnownBits)
								strInfo.AppendFormat(_T("  ***UnkBits=0x%08x"), dwFlags & ~dwKnownBits);
							if (dwFlags & SRV_TCPFLG_COMPRESSION)
								strInfo.AppendFormat(_T("  Compression=1"));
							if (dwFlags & SRV_TCPFLG_NEWTAGS)
								strInfo.AppendFormat(_T("  NewTags=1"));
							if (dwFlags & SRV_TCPFLG_UNICODE)
								strInfo.AppendFormat(_T("  Unicode=1"));
							if (dwFlags & SRV_TCPFLG_RELATEDSEARCH)
								strInfo.AppendFormat(_T("  RelatedSearch=1"));
							if (dwFlags & SRV_TCPFLG_TYPETAGINTEGER)
								strInfo.AppendFormat(_T("  IntTypeTags=1"));
							if (dwFlags & SRV_TCPFLG_LARGEFILES)
								strInfo.AppendFormat(_T("  LargeFiles=1"));
							if (dwFlags & SRV_TCPFLG_TCPOBFUSCATION)
								strInfo.AppendFormat(_T("  TCP_Obfscation=1"));
							Debug(_T("%s\n"), strInfo);
						}
						cur_server->SetTCPFlags(dwFlags);
					}
					else
						cur_server->SetTCPFlags(0);

					// copy TCP flags into the server in the server list
					pServer = theApp.serverlist->GetServerByAddress(cur_server->GetAddress(), cur_server->GetPort());
					if (pServer)
						pServer->SetTCPFlags(cur_server->GetTCPFlags());
				}

				uint32 dwServerReportedIP = 0;
				uint32 dwObfuscationTCPPort = 0;
				if (size >= 20){   ///snow:size大于20字节  小于20字节的情况呢？
					dwServerReportedIP = *((uint32*)(packet + 12)); ///snow:13到16字节是dwServerReportedIP
					if (::IsLowID(dwServerReportedIP)){
						ASSERT( false );
						dwServerReportedIP = 0;
					}
					ASSERT( dwServerReportedIP == la->clientid || ::IsLowID(la->clientid) );
					dwObfuscationTCPPort = *((uint32*)(packet + 16));   ///snow:17到20字节是dwObfuscationTCPPort
					if (cur_server != NULL && dwObfuscationTCPPort != 0)
						cur_server->SetObfuscationPortTCP((uint16)dwObfuscationTCPPort);
					if (pServer != NULL && dwObfuscationTCPPort != 0)
						pServer->SetObfuscationPortTCP((uint16)dwObfuscationTCPPort);

				}

				if (la->clientid == 0)
				{
					uint8 state = thePrefs.GetSmartIdState();
					if ( state > 0 )
					{
						if (state == 1)
							theApp.emuledlg->RefreshUPnP(false); // refresh the UPnP mappings once
						state++;
						if( state > 2 )
							thePrefs.SetSmartIdState(0);
						else
							thePrefs.SetSmartIdState(state);
					}
					break;
				}
				if( thePrefs.GetSmartIdCheck() ){
					if (!IsLowID(la->clientid))
						thePrefs.SetSmartIdState(1);
					else{
						uint8 state = thePrefs.GetSmartIdState();
						if ( state > 0 )
						{
							if (state == 1)
								theApp.emuledlg->RefreshUPnP(false); // refresh the UPnP mappings once
							state++;
							if( state > 2 )
								thePrefs.SetSmartIdState(0);
							else
								thePrefs.SetSmartIdState(state);

							if (!m_bManualSingleConnect)
								break; // if this is a connect to any/multiple server connection try, disconnect and try another one
						}
					}
				}
				
				// we need to know our client's HighID when sending our shared files (done indirectly on SetConnectionState)
				serverconnect->clientid = la->clientid;

				if (connectionstate != CS_CONNECTED) {
					SetConnectionState(CS_CONNECTED);   ///snow:设置连接状态为CS_CONNECTED，表示正式连接成功！调用ConnectionEstablished()中的CS_CONNECTED部分
					theApp.OnlineSig();       // Added By Bouc7 
				}
				serverconnect->SetClientID(la->clientid);
				if (::IsLowID(la->clientid) && dwServerReportedIP != 0)
					theApp.SetPublicIP(dwServerReportedIP);
				AddLogLine(false, GetResString(IDS_NEWCLIENTID), la->clientid);

				theApp.downloadqueue->ResetLocalServerRequests();
				break;
			}
			case OP_SEARCHRESULT:{   ///snow:使用server或globalserver搜索时，返回搜索结果
				if (thePrefs.GetDebugServerTCPLevel() > 0)
					Debug(_T("ServerMsg - OP_SearchResult\n"));
				CServer* cur_srv = (serverconnect) ? serverconnect->GetCurrentServer() : NULL;
				CServer* pServer = cur_srv ? theApp.serverlist->GetServerByAddress(cur_srv->GetAddress(), cur_srv->GetPort()) : NULL;
				(void)pServer;
				bool bMoreResultsAvailable;

				///snow:调用CSearchList::ProcessSearchAnswer()对搜索结果进行处理
				UINT uSearchResults = theApp.searchlist->ProcessSearchAnswer(packet, size, true/*pServer ? pServer->GetUnicodeSupport() : false*/, cur_srv ? cur_srv->GetIP() : 0, cur_srv ? cur_srv->GetPort() : (uint16)0, &bMoreResultsAvailable);
				theApp.emuledlg->searchwnd->LocalEd2kSearchEnd(uSearchResults, bMoreResultsAvailable);
				break;
			}
			case OP_FOUNDSOURCES_OBFU:
			case OP_FOUNDSOURCES:{
				if (thePrefs.GetDebugServerTCPLevel() > 0)
					Debug(_T("ServerMsg - OP_FoundSources%s; Sources=%u  %s\n"), (opcode == OP_FOUNDSOURCES_OBFU) ? _T("_OBFU") : _T(""), (UINT)packet[16], DbgGetFileInfo(packet));

				ASSERT( cur_server );
				if (cur_server)
				{
				    CSafeMemFile sources(packet, size);
					uchar fileid[16];
					sources.ReadHash16(fileid);
					if (CPartFile* file = theApp.downloadqueue->GetFileByID(fileid))
						file->AddSources(&sources,cur_server->GetIP(), cur_server->GetPort(), (opcode == OP_FOUNDSOURCES_OBFU));
				}
				break;
			}
			case OP_SERVERSTATUS:{  ///snow:服务器的用户数和文件数
				if (thePrefs.GetDebugServerTCPLevel() > 0)
					Debug(_T("ServerMsg - OP_ServerStatus\n"));
				// FIXME some statuspackets have a different size -> why? structur?
				if (size < 8)
					break;//throw "Invalid status packet";
				uint32 cur_user = PeekUInt32(packet);  ///snow:前四个字节，连接用户数
				uint32 cur_files = PeekUInt32(packet+4);  ///后四个字节：文件数
				CServer* pServer = cur_server ? theApp.serverlist->GetServerByAddress(cur_server->GetAddress(), cur_server->GetPort()) : NULL;
				if (pServer){
					pServer->SetUserCount(cur_user);
					pServer->SetFileCount(cur_files);
					theApp.emuledlg->ShowUserCount();
					theApp.emuledlg->serverwnd->serverlistctrl.RefreshServer(pServer);
					theApp.emuledlg->serverwnd->UpdateMyInfo();
				}
				if (thePrefs.GetDebugServerTCPLevel() > 0){
					if (size > 8){
						Debug(_T("*** NOTE: OP_ServerStatus: ***AddData: %u bytes\n"), size - 8);
						DebugHexDump(packet + 8, size - 8);
					}
				}
				break;
			}
			case OP_SERVERIDENT:{
				// OP_SERVERIDENT - this is sent by the server only if we send a OP_GETSERVERLIST
				if (thePrefs.GetDebugServerTCPLevel() > 0)
					Debug(_T("ServerMsg - OP_ServerIdent\n"));
				if (size<16+4+2+4){
					if (thePrefs.GetVerbose())
						DebugLogError(_T("%s"), GetResString(IDS_ERR_KNOWNSERVERINFOREC));
					break;// throw "Invalid server info received"; 
				} 

				CServer* pServer = cur_server ? theApp.serverlist->GetServerByAddress(cur_server->GetAddress(),cur_server->GetPort()) : NULL;
				CString strInfo;
				CSafeMemFile data(packet, size);
				
				uint8 aucHash[16];
				data.ReadHash16(aucHash);   ///snow:16字节的HASH
				if (thePrefs.GetDebugServerTCPLevel() > 0)
					strInfo.AppendFormat(_T("Hash=%s (%s)"), md4str(aucHash), DbgGetHashTypeString(aucHash));
				uint32 nServerIP = data.ReadUInt32();   ///snow:4字节的IP
				uint16 nServerPort = data.ReadUInt16();  ///snow:2字节的Port
				if (thePrefs.GetDebugServerTCPLevel() > 0)
					strInfo.AppendFormat(_T("  IP=%s:%u"), ipstr(nServerIP), nServerPort);
				UINT nTags = data.ReadUInt32();  ///snow:4字节的Tags
				if (thePrefs.GetDebugServerTCPLevel() > 0)
					strInfo.AppendFormat(_T("  Tags=%u"), nTags);

				CString strName;
				CString strDescription;
				for (UINT i = 0; i < nTags; i++){
					CTag tag(&data, pServer ? pServer->GetUnicodeSupport() : false);
					if (tag.GetNameID() == ST_SERVERNAME){    ///snow:服务器名字
						if (tag.IsStr()){
							strName = tag.GetStr();
							if (thePrefs.GetDebugServerTCPLevel() > 0)
								strInfo.AppendFormat(_T("  Name=%s"), strName);
						}
					}
					else if (tag.GetNameID() == ST_DESCRIPTION){   ///snow:服务器描述
						if (tag.IsStr()){
							strDescription = tag.GetStr();
							if (thePrefs.GetDebugServerTCPLevel() > 0)
								strInfo.AppendFormat(_T("  Desc=%s"), strDescription);
						}
					}
					else if (thePrefs.GetDebugServerTCPLevel() > 0)
						strInfo.AppendFormat(_T("  ***UnkTag: 0x%02x=%u"), tag.GetNameID(), tag.GetInt());
				}
				if (thePrefs.GetDebugServerTCPLevel() > 0){
					strInfo += _T('\n');
					Debug(_T("%s"), strInfo);

					UINT uAddData = (UINT)(data.GetLength() - data.GetPosition());
					if (uAddData > 0){
						Debug(_T("*** NOTE: OP_ServerIdent: ***AddData: %u bytes\n"), uAddData);
						DebugHexDump(packet + data.GetPosition(), uAddData);
					}
				}

				if (pServer){
					pServer->SetListName(strName);
					pServer->SetDescription(strDescription);
					if (((uint32*)aucHash)[0] == 0x2A2A2A2A){
						const CString& rstrVersion = pServer->GetVersion();
						if (!rstrVersion.IsEmpty())
							pServer->SetVersion(_T("eFarm ") + rstrVersion);
						else
							pServer->SetVersion(_T("eFarm"));
					}
					theApp.emuledlg->ShowConnectionState(); 
					theApp.emuledlg->serverwnd->serverlistctrl.RefreshServer(pServer); 
				}
				break;
			} 
			// tecxx 1609 2002 - add server's serverlist to own serverlist
			case OP_SERVERLIST:{
				if (!thePrefs.GetAddServersFromServer())
					break;
				if (thePrefs.GetDebugServerTCPLevel() > 0)
					Debug(_T("ServerMsg - OP_ServerList\n"));
				try{
					CSafeMemFile servers(packet, size);
					UINT count = servers.ReadUInt8();   ///snow:返回列表中的服务器数（1个字节，最多255个服务器）
					// check if packet is valid
					if (1 + count*(4+2) > size)      ///snow:每个服务器占6个字节，4字节IP+2字节Port
						count = 0;
					int addcount = 0;
					while(count)
					{
						uint32 ip = servers.ReadUInt32();
						uint16 port = servers.ReadUInt16();
						CServer* srv = new CServer(port, ipstr(ip));
						srv->SetListName(srv->GetFullIP());
						srv->SetPreference(SRV_PR_LOW);
						if (!theApp.emuledlg->serverwnd->serverlistctrl.AddServer(srv, true))
							delete srv;
						else
							addcount++;
						count--;
					}
					if (addcount)
						AddLogLine(false, GetResString(IDS_NEWSERVERS), addcount);
					if (thePrefs.GetDebugServerTCPLevel() > 0){
						UINT uAddData = (UINT)(servers.GetLength() - servers.GetPosition());
						if (uAddData > 0){
							Debug(_T("*** NOTE: OP_ServerList: ***AddData: %u bytes\n"), uAddData);
							DebugHexDump(packet + servers.GetPosition(), uAddData);
						}
					}
				}
				catch(CFileException* error){
					if (thePrefs.GetVerbose())
						DebugLogError(_T("%s"), GetResString(IDS_ERR_BADSERVERLISTRECEIVED));
					error->Delete();
				}
				break;
			}
			case OP_CALLBACKREQUESTED:{
				if (thePrefs.GetDebugServerTCPLevel() > 0)
					Debug(_T("ServerMsg - OP_CallbackRequested: %s\n"), (size >= 23) ? _T("With Cryptflag and Userhash") : _T("Without Cryptflag and Userhash"));
				if (size >= 6)
				{
					uint32 dwIP = PeekUInt32(packet);

					if (theApp.ipfilter->IsFiltered(dwIP)){
						theStats.filteredclients++;
						if (thePrefs.GetLogFilteredIPs())
							AddDebugLogLine(false, _T("Ignored callback request (IP=%s) - IP filter (%s)"), ipstr(dwIP), theApp.ipfilter->GetLastHit());
						break;
					}

					if (theApp.clientlist->IsBannedClient(dwIP)){
						if (thePrefs.GetLogBannedClients()){
							CUpDownClient* pClient = theApp.clientlist->FindClientByIP(dwIP);
							AddDebugLogLine(false, _T("Ignored callback request from banned client %s; %s"), ipstr(dwIP), pClient->DbgGetClientInfo());
						}
						break;
					}

					uint16 nPort = PeekUInt16(packet+4);
					uint8 byCryptOptions = 0;
					uchar achUserHash[16];
					if (size >= 23){
						byCryptOptions = packet[6];
						md4cpy(achUserHash, packet + 7);
					}
					
					CUpDownClient* client = theApp.clientlist->FindClientByIP(dwIP,nPort);
					if (client == NULL)
					{
						client = new CUpDownClient(0,nPort,dwIP,0,0,true);
						theApp.clientlist->AddClient(client);
					}
					if (size >= 23 && client->HasValidHash()){
						if (md4cmp(client->GetUserHash(), achUserHash) != 0){
							DebugLogError(_T("Reported Userhash from OP_CALLBACKREQUESTED differs with our stored hash"));
							// disable crypt support since we dont know which hash is true
							client->SetCryptLayerRequest(false);
							client->SetCryptLayerSupport(false);
							client->SetCryptLayerRequires(false);
						}
						else{
							client->SetConnectOptions(byCryptOptions, true, false);
							client->SetDirectUDPCallbackSupport(false);
						}
					}
					else if (size >= 23){
						client->SetUserHash(achUserHash);
						client->SetCryptLayerSupport((byCryptOptions & 0x01) != 0);
						client->SetCryptLayerRequest((byCryptOptions & 0x02) != 0);
						client->SetCryptLayerRequires((byCryptOptions & 0x04) != 0);
						client->SetDirectUDPCallbackSupport(false);
					}
					client->TryToConnect();
				}
				break;
			}
			case OP_CALLBACK_FAIL:{
				if (thePrefs.GetDebugServerTCPLevel() > 0)
					Debug(_T("ServerMsg - OP_Callback_Fail %s\n"), DbgGetHexDump(packet, size));
				break;
			}
			case OP_REJECT:{
				if (thePrefs.GetDebugServerTCPLevel() > 0)
					Debug(_T("ServerMsg - OP_Reject %s\n"), DbgGetHexDump(packet, size));
				// this could happen if we send a command with the wrong protocol (e.g. sending a compressed packet to
				// a server which does not support that protocol).
				if (thePrefs.GetVerbose())
					DebugLogError(_T("Server rejected last command"));
				break;
			}
			default:
				if (thePrefs.GetDebugServerTCPLevel() > 0)
					Debug(_T("***NOTE: ServerMsg - Unknown message; opcode=0x%02x  %s\n"), opcode, DbgGetHexDump(packet, size));
				;
		}

		return true;
	}
	catch(CFileException* error)
	{
		if (thePrefs.GetVerbose())
		{
			TCHAR szError[MAX_CFEXP_ERRORMSG];
			error->m_strFileName = _T("server packet");
			error->GetErrorMessage(szError, ARRSIZE(szError));
			ProcessPacketError(size, opcode, szError);
		}
		ASSERT(0);
		error->Delete();
		if (opcode==OP_SEARCHRESULT || opcode==OP_FOUNDSOURCES)
			return true;
	}
	catch(CMemoryException* error)
	{
		ProcessPacketError(size, opcode, _T("CMemoryException"));
		ASSERT(0);
		error->Delete();
		if (opcode==OP_SEARCHRESULT || opcode==OP_FOUNDSOURCES)
			return true;
	}
	catch(CString error)
	{
		ProcessPacketError(size, opcode, error);
		ASSERT(0);
	}
#ifndef _DEBUG
	catch(...)
	{
		ProcessPacketError(size, opcode, _T("Unknown exception"));
		ASSERT(0);
	}
#endif

	SetConnectionState(CS_DISCONNECTED);
	return false;
}

void CServerSocket::ProcessPacketError(UINT size, UINT opcode, LPCTSTR pszError)
{
	if (thePrefs.GetVerbose())
	{
		CString strServer;
		try{
			if (cur_server)
				strServer.Format(_T("%s:%u"), cur_server->GetAddress(), cur_server->GetPort());
			else
				strServer = _T("Unknown");
		}
		catch(...){
		}
		DebugLogWarning(false, _T("Error: Failed to process server TCP packet from %s: opcode=0x%02x size=%u - %s"), strServer, opcode, size, pszError);
	}
}

void CServerSocket::ConnectTo(CServer* server, bool bNoCrypt)
{
	if (cur_server){  ///snow: 在连接服务器之前，应该先断开当前服务器的连接，cur_server置NULL
		ASSERT(0);
		delete cur_server;
		cur_server = NULL;
	}

	uint16 nPort = 0;
	cur_server = new CServer(server);
	///snow:建立加密连接
	if ( !bNoCrypt && thePrefs.IsServerCryptLayerTCPRequested() && server->GetObfuscationPortTCP() != 0 && server->SupportsObfuscationTCP()){
		Log(GetResString(IDS_CONNECTINGTOOBFUSCATED), cur_server->GetListName(), cur_server->GetAddress(), cur_server->GetObfuscationPortTCP());
		nPort = cur_server->GetObfuscationPortTCP();
		SetConnectionEncryption(true, NULL, true);
	}
	else{ ///snow:建立未加密连接
		Log(GetResString(IDS_CONNECTINGTO), cur_server->GetListName(), cur_server->GetAddress(), cur_server->GetPort());
		nPort = cur_server->GetPort();
		SetConnectionEncryption(false, NULL, true);
	}

	// IP-filter: We do not need to IP-filter any servers here, even dynIP-servers are not
	// needed to get filtered here.
	//	1.) Non dynIP-servers were already IP-filtered when they were added to the server
	//		list.
	//	2.) Whenever the IP-filter is updated all servers for which an IP is known (this
	//		includes also dynIP-servers for which we received already an IP) get filtered.
	//	3.)	dynIP-servers get filtered after their DN was resolved. For TCP-connections this
	//		is done in OnConnect. For outgoing UDP packets this is done when explicitly
	//		resolving the DN right before sending the UDP packet.
	//
	SetConnectionState(CS_CONNECTING);

	///snow:最终通过windows socket api函数connect()向服务器发出连接请求
	if (!Connect(CStringA(server->GetAddress()), nPort)){
		DWORD dwError = GetLastError();
		if (dwError != WSAEWOULDBLOCK){
			LogError(GetResString(IDS_ERR_CONNECTIONERROR), cur_server->GetListName(), cur_server->GetAddress(), nPort, GetFullErrorMessage(dwError));
			SetConnectionState(CS_FATALERROR);
			return;
		}
	}
}

void CServerSocket::OnError(int nErrorCode)
{
	SetConnectionState(CS_DISCONNECTED);
	if (thePrefs.GetVerbose())
		DebugLogError(GetResString(IDS_ERR_SOCKET), cur_server->GetListName(), cur_server->GetAddress(), cur_server->GetPort(), GetFullErrorMessage(nErrorCode));
}

///snow:接收到数据包了，由OnReceive()调用，这里在调试时应该跟踪一下接收到的数据包
bool CServerSocket::PacketReceived(Packet* packet)
{
#ifndef _DEBUG
	try {
#endif
		theStats.AddDownDataOverheadServer(packet->size);
		if (packet->prot == OP_PACKEDPROT)  ///snow:压缩的数据包(0xD4)，先用UnPackPacket进行解包
		{
			uint32 uComprSize = packet->size;
			if (!packet->UnPackPacket(250000)){
				if (thePrefs.GetVerbose())
					DebugLogError(_T("Failed to decompress server TCP packet: protocol=0x%02x  opcode=0x%02x  size=%u"), packet ? packet->prot : 0, packet ? packet->opcode : 0, packet ? packet->size : 0);
				return true;
			}
			packet->prot = OP_EDONKEYPROT;
			if (thePrefs.GetDebugServerTCPLevel() > 1)
				Debug(_T("Received compressed server TCP packet; opcode=0x%02x  size=%u  uncompr size=%u\n"), packet->opcode, uComprSize, packet->size);
		}

		if (packet->prot == OP_EDONKEYPROT)  ///snow:是Edonkey包（0xE3),这里不处理OP_EMULEPROT(0xC5)的包
		{
			///snow:add by snow
			theApp.QueueTraceLogLine(TRACE_PACKET_DATA,_T("Class:CServerSocket|Function:PacketReceived|Socket:%i|IP:%s|Port:%i|Size:%i|Opcode:%s|Protocol:%s|Content(Hex):%s|Content:%s"),__FUNCTION__,__LINE__,m_SocketData.hSocket,GetPeerAddress().GetBuffer(0),GetPeerPort(),packet->size,GetOpcodeStr(packet->opcode,CLIENT2SERVER).GetBuffer(0),GetProtocolStr(packet->prot).GetBuffer(0),ByteToHexStr((uchar*)packet->pBuffer,packet->size).GetBuffer(0),TrimZero((uchar*)packet->pBuffer,packet->size).GetBuffer(0));

			ProcessPacket((const BYTE*)packet->pBuffer, packet->size, packet->opcode);
		}
		else
		{
			if (thePrefs.GetVerbose())
				DebugLogWarning(_T("Received server TCP packet with unknown protocol: protocol=0x%02x  opcode=0x%02x  size=%u"), packet ? packet->prot : 0, packet ? packet->opcode : 0, packet ? packet->size : 0);
		}
#ifndef _DEBUG
	}
	catch(...)
	{
		if (thePrefs.GetVerbose())
			DebugLogError(_T("Error: Unhandled exception while processing server TCP packet: protocol=0x%02x  opcode=0x%02x  size=%u"), packet ? packet->prot : 0, packet ? packet->opcode : 0, packet ? packet->size : 0);
		ASSERT(0);
		return false;
	}
#endif
	return true;
}

void CServerSocket::OnClose(int /*nErrorCode*/)
{ 
	///snow:服务器拒绝连接请求，连接断开
	CEMSocket::OnClose(0);
	if (connectionstate == CS_WAITFORLOGIN){  ///snow:客户端正在请求连接登录
		SetConnectionState(CS_SERVERFULL);
	}
	else if (connectionstate == CS_CONNECTED){  ///snow:客户端已连接，服务器或客户端断开连接
		SetConnectionState(CS_DISCONNECTED);
	}
	else{   ///snow:其它情形
		SetConnectionState(CS_NOTCONNECTED);
	}
	serverconnect->DestroySocket(this);
}

///snow:设置连接状态，然后根据状态，决定是调用ConnectionFailed，还是ConnectionEstablished
void CServerSocket::SetConnectionState(int newstate){
	connectionstate = newstate;
	if (newstate < 1){
		serverconnect->ConnectionFailed(this);
	}
	else if (newstate == CS_CONNECTED || newstate == CS_WAITFORLOGIN){
		if (serverconnect)
			serverconnect->ConnectionEstablished(this);
	}
}

void CServerSocket::SendPacket(Packet* packet, bool delpacket, bool controlpacket, uint32 actualPayloadSize, bool bForceImmediateSend){
	m_dwLastTransmission = GetTickCount();

	///snow:add by snow
	theApp.QueueTraceLogLine(TRACE_PACKET_DATA,_T("Class:CServerSocket|Function:SendPacket|Socket:%i|IP:%s|Port:%i|Size:%i|Opcode:%s|Protocol:%s|Content(Hex):%s|Content:%s"),__FUNCTION__,__LINE__,m_SocketData.hSocket,GetPeerAddress().GetBuffer(0),GetPeerPort(),packet->size,GetOpcodeStr(packet->opcode,CLIENT2SERVER).GetBuffer(0),GetProtocolStr(packet->prot).GetBuffer(0),ByteToHexStr((uchar*)packet->pBuffer,packet->size).GetBuffer(0),TrimZero((uchar*)packet->pBuffer,packet->size).GetBuffer(0));


	CEMSocket::SendPacket(packet, delpacket, controlpacket, actualPayloadSize, bForceImmediateSend);
}
