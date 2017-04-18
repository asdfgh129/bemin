/*
Copyright (C)2003 Barry Dunne (http://www.emule-project.net)
Copyright (C)2004-2010 Merkur ( strEmail.Format("%s@%s", "devteam", "emule-project.net") / http://www.emule-project.net )
 
This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either
version 2 of the License, or (at your option) any later version.
 
This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
 
You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

// Note To Mods //
/*
Please do not change anything here and release it..
There is going to be a new forum created just for the Kademlia side of the client..
If you feel there is an error or a way to improve something, please
post it in the forum first and let us look at it.. If it is a real improvement,
it will be added to the offical client.. Changing something without knowing
what all it does can cause great harm to the network if released in mass form..
Any mod that changes anything within the Kademlia side will not be allowed to advertise
there client on the eMule forum..
*/

#include "stdafx.h"
#include "./Search.h"
#include "./Kademlia.h"
#include "./Entry.h"
#include "./Defines.h"
#include "./Prefs.h"
#include "./Indexed.h"
#include "./UDPFirewallTester.h"
#include "./SearchManager.h"
#include "../io/IOException.h"
#include "../io/ByteIO.h"
#include "../routing/RoutingZone.h"
#include "../net/KademliaUDPListener.h"
#include "../../emule.h"
#include "../../sharedfilelist.h"
#include "../../Packets.h"
#include "../../partfile.h"
#include "../../emuledlg.h"
#include "../../KadSearchListCtrl.h"
#include "../../kademliawnd.h"
#include "../../DownloadQueue.h"
#include "../../SearchList.h"
#include "../../ClientList.h"
#include "../../UpDownClient.h"
#include "../../Log.h"
#include "../../KnownFileList.h"
#include "../utils/KadClientSearcher.h"
#include "../utils/LookupHistory.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

using namespace Kademlia;

void DebugSend(LPCTSTR pszMsg, uint32 uIP, uint16 uUDPPort);

CSearch::CSearch()
{
	m_pLookupHistory = new CLookupHistory();
	m_tCreated = time(NULL);
	m_uType = (uint32)-1;
	m_uAnswers = 0;
	m_uTotalRequestAnswers = 0;
	m_uKadPacketSent = 0;
	m_uSearchID = (uint32)-1;
	m_bStoping = false;
	m_uTotalLoad = 0;
	m_uTotalLoadResponses = 0;
	theApp.emuledlg->kademliawnd->searchList->SearchAdd(this);
	m_uLastResponse = time(NULL);
	m_pucSearchTermsData = NULL;
	m_uSearchTermsDataSize = 0;
	pNodeSpecialSearchRequester = NULL;
	m_uClosestDistantFound = 0;
	m_pSearchTerm = NULL;
	pRequestedMoreNodesContact = NULL;
}

CSearch::~CSearch()
{
	
	// remember the closest node we found and tried to contact (if any) during this search
	// for statistical caluclations, but only if its a certain type
	switch(m_uType)
	{
		case NODECOMPLETE:
		case FILE:
		case KEYWORD:
		case NOTES:
		case STOREFILE:
		case STOREKEYWORD:
		case STORENOTES:
		case FINDSOURCE: // maybe also exclude
			if (m_uClosestDistantFound != 0)
				CKademlia::StatsAddClosestDistance(m_uClosestDistantFound);
			break;
		default: // NODE, NODESPECIAL, NODEFWCHECKUDP, FINDBUDDY
			break;
	}

	if (pNodeSpecialSearchRequester != NULL){
		// inform requester that our search failed
		pNodeSpecialSearchRequester->KadSearchIPByNodeIDResult(KCSR_NOTFOUND, 0, 0);
		pNodeSpecialSearchRequester = NULL;
	}

	// Remove search from GUI
	theApp.emuledlg->kademliawnd->searchList->SearchRem(this);

	// delete/deref searchhistory (will delete itself if not used by the GUI)
	m_pLookupHistory->SetSearchDeleted();
	m_pLookupHistory = NULL;
	theApp.emuledlg->kademliawnd->UpdateSearchGraph(NULL);

	// Check if a source search is currently being done.
	CPartFile* pPartFile = theApp.downloadqueue->GetFileByKadFileSearchID(GetSearchID());

	// Reset the searchID if a source search is currently being done.
	if(pPartFile){
		pPartFile->SetKadFileSearchID(0);
	}
	if (m_uType == NOTES){
		CAbstractFile* pAbstractFile = theApp.knownfiles->FindKnownFileByID(CUInt128(GetTarget().GetData()).GetData());
		if (pAbstractFile != NULL)
			pAbstractFile->SetKadCommentSearchRunning(false);

		pAbstractFile = theApp.downloadqueue->GetFileByID(CUInt128(GetTarget().GetData()).GetData());
		if (pAbstractFile != NULL)
			pAbstractFile->SetKadCommentSearchRunning(false);

		theApp.searchlist->SetNotesSearchStatus(CUInt128(GetTarget().GetData()).GetData(), false);
	}

	// Decrease the use count for any contacts that are in your contact list.
	for (ContactMap::iterator itContactMap = m_mapInUse.begin(); itContactMap != m_mapInUse.end(); ++itContactMap)
		((CContact*)itContactMap->second)->DecUse();

	// Delete any temp contacts..
	for (ContactList::const_iterator itContactList = m_listDelete.begin(); itContactList != m_listDelete.end(); ++itContactList)
	{
		if (!((CContact*)*itContactList)->InUse())
			delete *itContactList;
	}

	// Check if this search was contacting a overload node and adjust time of next time we use that node.
	if(CKademlia::IsRunning() && GetNodeLoad() > 20)
	{
		///snow:这边有个疑问：m_uTotalLoad和m_uTotalLoadResponses是成员变量，只在STOREFILE的CSearch对象中根据响应返回的值赋值，不可能跟发起STOREKEYWORD的CSearch对象有关系呀？
		///snow:错了，在Process_KADEMLIA2_PUBLISH_KEY_REQ()中pIndexed->AddKeyword(uFile, uTarget, pEntry, uLoad)返回了uLoad值，也同样发回了KADEMLIA2_PUBLISH_RES信息包
		///snow:新的疑问：AddSource时的uLoad做什么用？
		switch(GetSearchTypes())
		{
			case CSearch::STOREKEYWORD:   
				Kademlia::CKademlia::GetIndexed()->AddLoad(GetTarget(), ((uint32)(DAY2S(7)*((double)GetNodeLoad()/100.0))+(uint32)time(NULL)));
				break;
		}
	}
	if(m_pucSearchTermsData)
		delete[] m_pucSearchTermsData;

	CKademlia::GetUDPListener()->Free(m_pSearchTerm);
	m_pSearchTerm = NULL;
}

///snow:三个地方发起调用：CSearchManager::StartSearch、PrepareFindKeywords、PrepareLookup
void CSearch::Go()
{
	// Start with a lot of possible contacts, this is a fallback in case search stalls due to dead contacts
	if (m_mapPossible.empty())  ///snow:如果m_mapPossible为空，根据m_uTarget取最近的50个节点，存入m_mapPossible
	{
		CUInt128 uDistance(CKademlia::GetPrefs()->GetKadID());
		uDistance.Xor(m_uTarget);
		CKademlia::GetRoutingZone()->GetClosestTo(3, m_uTarget, uDistance, 50, &m_mapPossible, true, true);

		for (ContactMap::iterator itContactMap = m_mapPossible.begin(); itContactMap != m_mapPossible.end(); ++itContactMap)
			///snow:将这些准备对其发起搜索的联系人添加到历史列表m_aHistoryEntries
			m_pLookupHistory->ContactReceived(itContactMap->second, NULL, itContactMap->first, false);
		theApp.emuledlg->kademliawnd->UpdateSearchGraph(m_pLookupHistory);
	}
	if (!m_mapPossible.empty())  ///snow:存在最接近的联系人
	{
		//Lets keep our contact list entries in mind to dec the inUse flag.
		for (ContactMap::iterator itContactMap = m_mapPossible.begin(); itContactMap != m_mapPossible.end(); ++itContactMap)
			m_mapInUse[itContactMap->first] = itContactMap->second;   ///snow:添加到使用中联系人列表

		ASSERT(m_mapPossible.size() == m_mapInUse.size());

		// Take top ALPHA_QUERY to start search with.
		int iCount;
		
		if(m_uType == NODE)   ///snow:通过SetSearchTypes()设置
			iCount = 1;
		else
			iCount = min(ALPHA_QUERY, (int)m_mapPossible.size());  ///snow:对最多3个节点进行搜索

		ContactMap::iterator itContactMap2 = m_mapPossible.begin();
		// Send initial packets to start the search.
		for (int iIndex=0; iIndex<iCount; iIndex++)
		{
			CContact* pContact = itContactMap2->second;
			// Move to tried
			m_mapTried[itContactMap2->first] = pContact;    ///snow:添加到尝试联系人列表
			// Send the KadID so other side can check if I think it has the right KadID. (Saftey net)
			///snow:发送对方的KadID是为了让对方验证我们是否拥有正确的对方ID
			// Send request
			SendFindValue(pContact);   ///snow:向该联系人发送数据包
			++itContactMap2;
		}
	}
	// Update search for the GUI
	theApp.emuledlg->kademliawnd->searchList->SearchRef(this);
}

//If we allow about a 15 sec delay before deleting, we won't miss a lot of delayed returning packets.
void CSearch::PrepareToStop()
{
	// Check if already stoping..
	if( m_bStoping )
		return;

	// Set basetime by search type.
	uint32 uBaseTime;
	switch(m_uType)
	{
		case NODE:
		case NODECOMPLETE:
		case NODESPECIAL:
		case NODEFWCHECKUDP:
			uBaseTime = SEARCHNODE_LIFETIME;
			break;
		case FILE:
			uBaseTime = SEARCHFILE_LIFETIME;
			break;
		case KEYWORD:
			uBaseTime = SEARCHKEYWORD_LIFETIME;
			break;
		case NOTES:
			uBaseTime = SEARCHNOTES_LIFETIME;
			break;
		case STOREFILE:
			uBaseTime = SEARCHSTOREFILE_LIFETIME;
			break;
		case STOREKEYWORD:
			uBaseTime = SEARCHSTOREKEYWORD_LIFETIME;
			break;
		case STORENOTES:
			uBaseTime = SEARCHSTORENOTES_LIFETIME;
			break;
		case FINDBUDDY:
			uBaseTime = SEARCHFINDBUDDY_LIFETIME;
			break;
		case FINDSOURCE:
			uBaseTime = SEARCHFINDSOURCE_LIFETIME;
			break;
		default:
			uBaseTime = SEARCH_LIFETIME;
	}

	// Adjust created time so that search will delete within 15 seconds.
	// This gives late results time to be processed.
	m_tCreated = time(NULL) - uBaseTime + SEC(15);   ///snow:建立时间为当前时间后15秒，在CSearchManager::JumpStart()中取值判断
	m_bStoping = true;

	//Update search within GUI.
	theApp.emuledlg->kademliawnd->searchList->SearchRef(this);
	m_pLookupHistory->SetSearchStopped();   ///snow:设置停止标志 m_bSearchStopped = true;
	theApp.emuledlg->kademliawnd->UpdateSearchGraph(m_pLookupHistory);
}

///snow:CSearchManager::JumpStart()调用
void CSearch::JumpStart()
{
	// If we had a response within the last 3 seconds, no need to jumpstart the search.
	if (m_uLastResponse + SEC(3) > (uint32)time(NULL))   ///snow:离上次回应未超3秒，ProcessResponse()中赋值
		return;

	// If we ran out of contacts, stop search.
	if (m_mapPossible.empty())
	{
		PrepareToStop();
		return;
	}

	// Is this a find lookup and are the best two (=KADEMLIA_FIND_VALUE) nodes dead/unreachable?
	// In this case try to discover more close nodes before using our other results
	// The reason for this is that we may not have found the closest node alive due to results beeing limited to 2 contacts,
	// which could very well have been the duplicates of our dead closest nodes [link paper]
	bool bLookupCloserNodes = false;

	///snow:m_mapTried在三个地方添加值：Go()、JumpStart()、ProcessResponse()，
	///snow:pRequestedMoreNodesContact在SendFindValue()参数bReAskMore=true时被赋值
	if (pRequestedMoreNodesContact == NULL && GetRequestContactCount() == KADEMLIA_FIND_VALUE && m_mapTried.size() >= 3*KADEMLIA_FIND_VALUE)
	{
		///snow:对m_mapTried中的前两个联系人进行判断，他们是否有回应过请求
		ContactMap::const_iterator itContactMap = m_mapTried.begin();
		bLookupCloserNodes = true;
		for (uint32 i = 0; i < KADEMLIA_FIND_VALUE; i++)
		{
			if (m_mapResponded.count(itContactMap->first) > 0)   ///snow:m_mapResponded在ProcessResponse()中被赋值，表示有联系人回应了
			{
				bLookupCloserNodes = false;
				break;
			}
			itContactMap++;
		}
		if (bLookupCloserNodes)  ///snow：在前两个联系人没有回应的情况下
		{
			while (itContactMap != m_mapTried.end())   ///snow:从第三个联系人开始，直到最后一个联系人，发送搜索请求，bReAskMore=true
			{
				if (m_mapResponded.count(itContactMap->first) > 0)
				{
					DEBUG_ONLY( DebugLogWarning(_T("Best KADEMLIA_FIND_VALUE nodes for LookUp (%s) were unreachable or dead, reasking closest for more"), GetGUIName()) );
					SendFindValue(itContactMap->second, true);
					return;
				}
				itContactMap++;
			}
		}
	}   ///snow:endif

	// Search for contacts that can be used to jumpstart a stalled search.
	while(!m_mapPossible.empty())   ///snow:在两个地方被赋值，Go()中GetClosestTo()和ProcessResponse()中回应的联系人 m_mapPossible[uDistance] = pContact;

	{
		///snow:遍历m_mapPossible，从第一个开始，用后删除，直到整个列表为空
		// Get a contact closest to our target.
		CContact* pContact = m_mapPossible.begin()->second;  ///snow:从m_mapPossible中取出第一个联系人，发起StorePacket()后被删除

		// Have we already tried to contact this node.
		if (m_mapTried.count(m_mapPossible.begin()->first) > 0)  ///snow:m_mapTried中已存在该联系人
		{
			// Did we get a response from this node, if so, try to store or get info.
			if(m_mapResponded.count(m_mapPossible.begin()->first) > 0)  ///snow:该联系人也已经回应了
			{
				StorePacket();   ///snow:名字上看是将Packet存储起来，实际是发送搜索请求数据包，跟SendFindValue()有什么区别?
				///snow:SendFindValue()发送的opcode是KADEMLIA2_REQ，应该是搜索更接近的联系人
				///snow:StorePacket()发送的opcode是KADEMLIA2_SEARCH_XXX_REQ、KADEMLIA2_PUBLISH_XXX_REQ等，应该是搜索拟搜索的具体目标
			}
			// Remove from possible list.
			m_mapPossible.erase(m_mapPossible.begin());///snow:将m_mapPossible中的第一个联系人删除
		}
		else  ///snow:如果m_mapTried中没有该联系人，则添加到m_mapTried中，发送数据包请求搜索
		{
			// Add to tried list.
			m_mapTried[m_mapPossible.begin()->first] = pContact;
			// Send the KadID so other side can check if I think it has the right KadID. (Saftey net)
			// Send request
			SendFindValue(pContact);
			break;///snow:跳出循环，等下一次JumpStart()执行时，就会执行上面的if语句块
		}
	}
}

void CSearch::ProcessResponse(uint32 uFromIP, uint16 uFromPort, ContactList *plistResults)
{
	// Remember the contacts to be deleted when finished
	for (ContactList::iterator itContactList = plistResults->begin(); itContactList != plistResults->end(); ++itContactList)
		m_listDelete.push_back(*itContactList);   ///snow:回应的联系人列表在处理完成后进行删除

	m_uLastResponse = time(NULL);  ///snow:记录下回应时间，在JumpStart中取值判断

	//Find contact that is responding.
	CUInt128 uFromDistance((ULONG)0);
	CContact* pFromContact = NULL;
	///snow:判断回应的联系人是否是我们发出搜索请求的联系人
	for (ContactMap::const_iterator itContactMap = m_mapTried.begin(); itContactMap != m_mapTried.end(); ++itContactMap)
	{
		CContact* pTmpContact = itContactMap->second;
		if ((pTmpContact->GetIPAddress() == uFromIP) && (pTmpContact->GetUDPPort() == uFromPort))
		{
			uFromDistance = itContactMap->first;
			pFromContact = pTmpContact;
			break;
		}   ///snow:如果没找到，pFromContact为NULL
	}
	
	// Make sure the node is not sending more results than we requested, which is not only a protocol vialoation
	// but most likely a malicous answer
	///snow:防止骚扰信息：返回的结果数比我们要求的多
	if (plistResults->size() > GetRequestContactCount() && !(pRequestedMoreNodesContact == pFromContact && plistResults->size() <= KADEMLIA_FIND_VALUE_MORE) )
	{
		DebugLogWarning(_T("Node %s sent more contacts than requested on a routing query, ignoring response"), ipstr(ntohl(uFromIP)));
		return;
	}

	///snow:如果searchType==NODEFWCHECKUDP或NODE，则可以不用在意pFromContact，主要的处理动作是检查m_pLookupHistory，添加新的接收到的联系人
	
	if (m_uType == NODEFWCHECKUDP){   ///snow:检查防火墙
		m_uAnswers++;   ///snow:统计回应数
		// Results are not passed to the search and not much point in changing this, but make sure we show on the graph that the contact responded
		m_pLookupHistory->ContactReceived(NULL, pFromContact, (ULONG)0, true);   ///snow:检查回应的联系人是否已在m_aIntrestingHistoryEntries中，如果已存在，则m_uRespondedContact+1
		theApp.emuledlg->kademliawnd->UpdateSearchGraph(m_pLookupHistory);
		delete plistResults;
		// Update search on the GUI.
		theApp.emuledlg->kademliawnd->searchList->SearchRef(this);
		return;
	}
	// Not interested in responses for FIND_NODE.
	// Once we get a results we stop the search.
	// These contacts are added to contacts by UDPListener.
	if (m_uType == NODE)
	{
		// Note we got an answer
		m_uAnswers++;
		// Add contacts to the History for GUI purposes
		for (ContactList::iterator itContactList = plistResults->begin(); itContactList != plistResults->end(); ++itContactList)
		{			
			CUInt128 uDistance(((CContact*)*itContactList)->GetClientID().Xor(m_uTarget));
			m_pLookupHistory->ContactReceived(*itContactList, pFromContact, uDistance, uDistance < uFromDistance, true);
		}
		theApp.emuledlg->kademliawnd->UpdateSearchGraph(m_pLookupHistory);
		// We clear the possible list to force the search to stop.
		// We do this so the user has time to visually see the results.
		m_mapPossible.clear();
		delete plistResults;
		// Update search on the GUI.
		theApp.emuledlg->kademliawnd->searchList->SearchRef(this);
		return;
	}

	///snow:除了上述两种类型外的其它情形的处理，遍历plistResults，判断是否找到更近的联系人，如果是，则SendFindValue()
	try
	{
		if (pFromContact != NULL)   ///snow:回应的联系人在我们的尝试列表中，如果不在，则不做任何处理
		{
			bool bProvidedCloserContacts = false;
			std::map<uint32, uint32> mapReceivedIPs;
			std::map<uint32, uint32> mapReceivedSubnets;
			mapReceivedIPs[uFromIP] = 1; // A node is not allowd to answer with contacts to itself
			mapReceivedSubnets[uFromIP & 0xFFFFFF00] = 1;
			// Loop through their responses
			for (ContactList::iterator itContactList = plistResults->begin(); itContactList != plistResults->end(); ++itContactList)
			{
				// Get next result
				CContact* pContact = *itContactList;

				// Calc distance this result is to the target.
				CUInt128 uDistance(pContact->GetClientID());
				uDistance.Xor(m_uTarget);

				if (uDistance < uFromDistance)   ///snow:找到更接近目标的联系人
					bProvidedCloserContacts = true;

				m_pLookupHistory->ContactReceived(pContact, pFromContact, uDistance, bProvidedCloserContacts);
				theApp.emuledlg->kademliawnd->UpdateSearchGraph(m_pLookupHistory);

				// Ignore this contact if already know or tried it.
				if (m_mapPossible.count(uDistance) > 0)
					continue;
				if (m_mapTried.count(uDistance) > 0)
					continue;

				// we only accept unique IPs in the answer, having multiple IDs pointing to one IP in the routing tables
				// is no longer allowed since 0.49a anyway
				if (mapReceivedIPs.count(pContact->GetIPAddress()) > 0){
					DebugLogWarning(_T("Multiple KadIDs pointing to same IP (%s) in KADEMLIA(2)_RES answer - ignored, sent by %s")
						, ipstr(ntohl(pContact->GetIPAddress())), ipstr(ntohl(pFromContact->GetIPAddress())));
					continue;
				}
				else
					mapReceivedIPs[pContact->GetIPAddress()] = 1;

				// and no more than 2 IPs from the same /28 subnet
				if (mapReceivedSubnets.count(pContact->GetIPAddress() & 0xFFFFFF00) > 0 && !::IsLANIP(ntohl(pContact->GetIPAddress())))
				{
					ASSERT( mapReceivedSubnets.find(pContact->GetIPAddress() & 0xFFFFFF00) != mapReceivedSubnets.end() );
					int nSubNetCount = mapReceivedSubnets.find(pContact->GetIPAddress() & 0xFFFFFF00)->second;
					if (nSubNetCount >= 2)   ///snow:超过两个KadIDs在同一个子网
					{
						DebugLogWarning(_T("More than 2 KadIDs pointing to same Subnet (%s) in KADEMLIA(2)_RES answer - ignored, sent by %s")
							, ipstr(ntohl(pContact->GetIPAddress() & 0xFFFFFF00)), ipstr(ntohl(pFromContact->GetIPAddress())));
						continue;
					}
					else   ///snow:已经有一个，再加一个成2个
						mapReceivedSubnets[pContact->GetIPAddress() & 0xFFFFFF00] = nSubNetCount + 1;

				}
				else ///snow:一个也没有
					mapReceivedSubnets[pContact->GetIPAddress() & 0xFFFFFF00] = 1;

				// Add to possible
				m_mapPossible[uDistance] = pContact;

				// Verify if the result is closer to the target then the one we just checked.
				///snow:返回的联系人更接近搜索目标，
				if (uDistance < uFromDistance)
				{
					// The top APLPHA_QUERY of results are used to determine if we send a request.
					bool bTop = false;
					if (m_mapBest.size() < ALPHA_QUERY)   ///snow:m_mapBest列表中的联系人少于3个，则将新搜索到的联系人添加到m_mapBest中
					{
						bTop = true;
						m_mapBest[uDistance] = pContact;
					}
					else
					{
						ContactMap::iterator itContactMapBest = m_mapBest.end();
						itContactMapBest--;
						if (uDistance < itContactMapBest->first)  ///snow:如果新联系人比m_mapBest中的最后一个联系人更接近，替换掉该联系人
						{
							// Prevent having more then ALPHA_QUERY within the Best list.
							m_mapBest.erase(itContactMapBest);
							m_mapBest[uDistance] = pContact;
							bTop = true;
						}
					}

					if(bTop)   ///snow:新的联系人被添加了
					{
						// We determined this contact is a canditate for a request.
						// Add to the tried list.
						m_mapTried[uDistance] = pContact;  ///snow:添加到m_mapTried
						// Send the KadID so other side can check if I think it has the right KadID. (Saftey net)
						// Send request
						SendFindValue(pContact);
					}
				}///snow:end if (uDistance < uFromDistance)
			}///snow:end for

			// Add to list of people who responded
			///snow:添加到有回应联系人列表中
			m_mapResponded[uFromDistance] = bProvidedCloserContacts;

			// Complete node search, just increase the answers and update the GUI
			if( m_uType == NODECOMPLETE || m_uType == NODESPECIAL)
			{
				m_uAnswers++;
				theApp.emuledlg->kademliawnd->searchList->SearchRef(this);
			}
		}///snow:endif
	}
	catch (...)
	{
		AddDebugLogLine(false, _T("Exception in CSearch::ProcessResponse"));
	}
	delete plistResults;
}

///snow:只有JumpStart()调用
void CSearch::StorePacket()
{
	ASSERT(!m_mapPossible.empty());

	// This method is currently only called by jumpstart so only use best possible.
	ContactMap::const_iterator itContactMap = m_mapPossible.begin();
	CUInt128 uFromDistance(itContactMap->first);
	CContact* pFromContact = itContactMap->second;

	if (uFromDistance < m_uClosestDistantFound || m_uClosestDistantFound == 0)
		m_uClosestDistantFound = uFromDistance;   ///snow:除了赋初值外，只在这里赋值，保留最近的距离
	// Make sure this is a valid Node to store too.
	///snow:回应的联系人不是LAnIP,距离的第一位是如果不是0，表示距离有点远
	if(uFromDistance.Get32BitChunk(0) > SEARCHTOLERANCE/*0x1 00 00 00*/ && !::IsLANIP(ntohl(pFromContact->GetIPAddress())))
		return;
	m_pLookupHistory->ContactAskedKeyword(pFromContact);  ///snow:主要是更新pFromContact的m_dwAskedSearchItemTime
	theApp.emuledlg->kademliawnd->UpdateSearchGraph(m_pLookupHistory);
	// What kind of search are we doing?

	///snow:根据pFromContact的Version构造准备发送的信息包，调用UDPListener发送
	switch(m_uType)
	{
		case FILE:
			{
				CSafeMemFile m_pfileSearchTerms;
				m_pfileSearchTerms.WriteUInt128(&m_uTarget);
				if (pFromContact->GetVersion() >= 3/*47b*/)
				{
					// Find file we are storing info about.
					uchar ucharFileid[16];
					m_uTarget.ToByteArray(ucharFileid);
					CKnownFile* pFile = theApp.downloadqueue->GetFileByID(ucharFileid);
					if(pFile)
					{
						// JOHNTODO -- Add start position
						// Start Position range (0x0 to 0x7FFF)
						m_pfileSearchTerms.WriteUInt16(0);
						m_pfileSearchTerms.WriteUInt64(pFile->GetFileSize());
						if (thePrefs.GetDebugClientKadUDPLevel() > 0)
							DebugSend("KADEMLIA2_SEARCH_SOURCE_REQ", pFromContact->GetIPAddress(), pFromContact->GetUDPPort());
						if (pFromContact->GetVersion() >= 6){ /*48b*/
							CUInt128 uClientID = pFromContact->GetClientID();
							CKademlia::GetUDPListener()->SendPacket(&m_pfileSearchTerms, KADEMLIA2_SEARCH_SOURCE_REQ, pFromContact->GetIPAddress(), pFromContact->GetUDPPort(), pFromContact->GetUDPKey(), &uClientID);
						}
						else {
							CKademlia::GetUDPListener()->SendPacket(&m_pfileSearchTerms, KADEMLIA2_SEARCH_SOURCE_REQ, pFromContact->GetIPAddress(), pFromContact->GetUDPPort(), 0, NULL);
							ASSERT( CKadUDPKey(0) == pFromContact->GetUDPKey() );
						}
					}
					else
					{
						PrepareToStop();
						break;
					}
				}
				else   ///snow:KAD1版本
				{
					m_pfileSearchTerms.WriteUInt8(1);
					if (thePrefs.GetDebugClientKadUDPLevel() > 0)
						DebugSend("KADEMLIA_SEARCH_REQ(File)", pFromContact->GetIPAddress(), pFromContact->GetUDPPort());
					CKademlia::GetUDPListener()->SendPacket(&m_pfileSearchTerms, KADEMLIA_SEARCH_REQ, pFromContact->GetIPAddress(), pFromContact->GetUDPPort(), 0, NULL);
				}
				// Inc total request answers
				m_uTotalRequestAnswers++;
				// Update search in the GUI
				theApp.emuledlg->kademliawnd->searchList->SearchRef(this);
				break;
			}
		case KEYWORD:
			{
				//JOHNTODO -- We cannot precreate these packets as we do not know
				// before hand if we are talking to Kad1.0 or Kad2.0..
				CSafeMemFile m_pfileSearchTerms;
				m_pfileSearchTerms.WriteUInt128(&m_uTarget);
				if (pFromContact->GetVersion() >= 3/*47b*/)
				{
					if (m_uSearchTermsDataSize == 0)
					{
						// JOHNTODO - Need to add ability to change start position.
						// Start position range (0x0 to 0x7FFF)
						m_pfileSearchTerms.WriteUInt16((uint16)0x0000);
					}
					else
					{
						// JOHNTODO - Need to add ability to change start position.
						// Start position range (0x8000 to 0xFFFF)
						m_pfileSearchTerms.WriteUInt16((uint16)0x8000);
						m_pfileSearchTerms.Write(m_pucSearchTermsData, m_uSearchTermsDataSize);
					}
				}
				else
				{
					if (m_uSearchTermsDataSize == 0)
					{
						m_pfileSearchTerms.WriteUInt8(0);
						// We send this extra byte to flag we handle large files.
						m_pfileSearchTerms.WriteUInt8(0);
					}
					else
					{
						// Set to 2 to flag we handle handle large files.
						m_pfileSearchTerms.WriteUInt8(2);
						m_pfileSearchTerms.Write(m_pucSearchTermsData, m_uSearchTermsDataSize);
					}
				}
				
				if (pFromContact->GetVersion() >= 6){ /*48b*/
					if (thePrefs.GetDebugClientKadUDPLevel() > 0)
						DebugSend("KADEMLIA2_SEARCH_KEY_REQ", pFromContact->GetIPAddress(), pFromContact->GetUDPPort());
					CUInt128 uClientID = pFromContact->GetClientID();
					CKademlia::GetUDPListener()->SendPacket(&m_pfileSearchTerms, KADEMLIA2_SEARCH_KEY_REQ, pFromContact->GetIPAddress(), pFromContact->GetUDPPort(), pFromContact->GetUDPKey(), &uClientID);

				}
				else if (pFromContact->GetVersion() >= 3/*47b*/)
				{
					if (thePrefs.GetDebugClientKadUDPLevel() > 0)
						DebugSend("KADEMLIA2_SEARCH_KEY_REQ", pFromContact->GetIPAddress(), pFromContact->GetUDPPort());
					CKademlia::GetUDPListener()->SendPacket(&m_pfileSearchTerms, KADEMLIA2_SEARCH_KEY_REQ, pFromContact->GetIPAddress(), pFromContact->GetUDPPort(), 0, NULL);
					ASSERT( CKadUDPKey(0) == pFromContact->GetUDPKey() );
				}
				else
				{
					if (thePrefs.GetDebugClientKadUDPLevel() > 0)
						DebugSend("KADEMLIA_SEARCH_REQ(KEYWORD)", pFromContact->GetIPAddress(), pFromContact->GetUDPPort());
					CKademlia::GetUDPListener()->SendPacket(&m_pfileSearchTerms, KADEMLIA_SEARCH_REQ, pFromContact->GetIPAddress(), pFromContact->GetUDPPort(), 0, NULL);
				}
				// Inc total request answers
				m_uTotalRequestAnswers++;
				// Update search in the GUI
				theApp.emuledlg->kademliawnd->searchList->SearchRef(this);
				break;
			}
		case NOTES:
			{
				// Write complete packet
				CSafeMemFile m_pfileSearchTerms;
				m_pfileSearchTerms.WriteUInt128(&m_uTarget);

				if (pFromContact->GetVersion() >= 3/*47b*/)
				{
					// Find file we are storing info about.
					uchar ucharFileid[16];
					m_uTarget.ToByteArray(ucharFileid);
					CKnownFile* pFile = theApp.sharedfiles->GetFileByID(ucharFileid);
					if(pFile)
					{
						m_pfileSearchTerms.WriteUInt64(pFile->GetFileSize());
						if (thePrefs.GetDebugClientKadUDPLevel() > 0)
							DebugSend("KADEMLIA2_SEARCH_NOTES_REQ", pFromContact->GetIPAddress(), pFromContact->GetUDPPort());
						if (pFromContact->GetVersion() >= 6){ /*48b*/
							CUInt128 uClientID = pFromContact->GetClientID();
							CKademlia::GetUDPListener()->SendPacket(&m_pfileSearchTerms, KADEMLIA2_SEARCH_NOTES_REQ, pFromContact->GetIPAddress(), pFromContact->GetUDPPort(), pFromContact->GetUDPKey(), &uClientID);
						}
						else {
							CKademlia::GetUDPListener()->SendPacket(&m_pfileSearchTerms, KADEMLIA2_SEARCH_NOTES_REQ, pFromContact->GetIPAddress(), pFromContact->GetUDPPort(), 0, NULL);
							ASSERT( CKadUDPKey(0) == pFromContact->GetUDPKey() );
						}
					}
					else
					{
						PrepareToStop();
						break;
					}
				}
				else
				{
					m_pfileSearchTerms.WriteUInt128(&CKademlia::GetPrefs()->GetKadID());
					if (thePrefs.GetDebugClientKadUDPLevel() > 0)
						DebugSend("KADEMLIA_SEARCH_NOTES_REQ", pFromContact->GetIPAddress(), pFromContact->GetUDPPort());
					CKademlia::GetUDPListener()->SendPacket(&m_pfileSearchTerms, KADEMLIA_SEARCH_NOTES_REQ, pFromContact->GetIPAddress(), pFromContact->GetUDPPort(), 0, NULL);
				}
				// Inc total request answers
				m_uTotalRequestAnswers++;
				// Update search in the GUI
				theApp.emuledlg->kademliawnd->searchList->SearchRef(this);
				break;
			}
		case STOREFILE:   ///snow:将自己的资源发布到网络节点上
			{
				// Try to store yourself as a source to a Node.
				// As a safe guard, check to see if we already stored to the Max Nodes
				if( m_uAnswers > SEARCHSTOREFILE_TOTAL )  ///snow:最多10个
				{
					PrepareToStop();
					break;
				}

				// Find the file we are trying to store as a source too.
				uchar ucharFileid[16];
				m_uTarget.ToByteArray(ucharFileid);
				CKnownFile* pFile = theApp.sharedfiles->GetFileByID(ucharFileid);   ///snow:共享的文件

				if (pFile)
				{
					// We set this mostly for GUI resonse.
					SetGUIName(pFile->GetFileName());

					// Get our clientID for the packet.
					CUInt128 uID(CKademlia::GetPrefs()->GetClientHash());

					//We can use type for different types of sources.  ///snow:SOURCETYPE类别，用1-6表示(2保留）
					//1 HighID Sources..
					//2 cannot be used as older clients will not work.
					//3 Firewalled Kad Source.
					//4 >4GB file HighID Source.
					//5 >4GB file Firewalled Kad source.
					//6 Firewalled Source with Direct Callback (supports >4GB)
					
					bool bDirectCallback = false;
					TagList listTag;
					if( theApp.IsFirewalled() )   ///snow:低ID用户，要求对方向自己发送回调请求连接对方
					{
						bDirectCallback = (Kademlia::CKademlia::IsRunning() && !Kademlia::CUDPFirewallTester::IsFirewalledUDP(true) && Kademlia::CUDPFirewallTester::IsVerified());   ///snow:本机UDP端口没有被墙
						if (bDirectCallback){
							// firewalled, but direct udp callback is possible so no need for buddies
							// We are not firewalled..
							listTag.push_back(new CKadTagUInt(TAG_SOURCETYPE, 6)); ///snow:Firewalled Source with Direct Callback (supports >4GB)
							listTag.push_back(new CKadTagUInt(TAG_SOURCEPORT, thePrefs.GetPort()));
							if (!CKademlia::GetPrefs()->GetUseExternKadPort())
								listTag.push_back(new CKadTagUInt16(TAG_SOURCEUPORT, CKademlia::GetPrefs()->GetInternKadPort()));
							if (pFromContact->GetVersion() >= 2/*47a*/)
							{
								listTag.push_back(new CKadTagUInt(TAG_FILESIZE, pFile->GetFileSize()));
							}							
						}
						else if( theApp.clientlist->GetBuddy() ) // We are firewalled, make sure we have a buddy.
						{   ///snow:我们被墙了，需要一个Buddy中转连接
							// We send the ID to our buddy so they can do a callback.
							CUInt128 uBuddyID(true);
							uBuddyID.Xor(CKademlia::GetPrefs()->GetKadID());
							if(pFile->GetFileSize() > OLD_MAX_EMULE_FILE_SIZE)   ///snow:大于4GB
								listTag.push_back(new CKadTagUInt8(TAG_SOURCETYPE, 5)); ///snow:>4GB file Firewalled Kad source.
							else
								listTag.push_back(new CKadTagUInt8(TAG_SOURCETYPE, 3));///snow:Firewalled Kad Source.
							listTag.push_back(new CKadTagUInt(TAG_SERVERIP, theApp.clientlist->GetBuddy()->GetIP()));
							listTag.push_back(new CKadTagUInt(TAG_SERVERPORT, theApp.clientlist->GetBuddy()->GetUDPPort()));
							listTag.push_back(new CKadTagStr(TAG_BUDDYHASH, CStringW(md4str(uBuddyID.GetData()))));
							listTag.push_back(new CKadTagUInt(TAG_SOURCEPORT, thePrefs.GetPort()));
							if (!CKademlia::GetPrefs()->GetUseExternKadPort())
								listTag.push_back(new CKadTagUInt16(TAG_SOURCEUPORT, CKademlia::GetPrefs()->GetInternKadPort()));

							if (pFromContact->GetVersion() >= 2/*47a*/)
							{
								listTag.push_back(new CKadTagUInt(TAG_FILESIZE, pFile->GetFileSize()));
							}
						}
						else
						{
							// We are firewalled, but lost our buddy.. Stop everything.
							PrepareToStop();
							break;
						}
					}
					else   ///snow:我们是高ID用户
					{
						// We are not firewalled..
						if(pFile->GetFileSize() > OLD_MAX_EMULE_FILE_SIZE)
							listTag.push_back(new CKadTagUInt(TAG_SOURCETYPE, 4));  ///snow:>4GB file HighID Source.
						else
							listTag.push_back(new CKadTagUInt(TAG_SOURCETYPE, 1));  ///snow:HighID Sources.
						listTag.push_back(new CKadTagUInt(TAG_SOURCEPORT, thePrefs.GetPort()));
						if (!CKademlia::GetPrefs()->GetUseExternKadPort())
							listTag.push_back(new CKadTagUInt16(TAG_SOURCEUPORT, CKademlia::GetPrefs()->GetInternKadPort()));

						if (pFromContact->GetVersion() >= 2/*47a*/)
						{
							listTag.push_back(new CKadTagUInt(TAG_FILESIZE, pFile->GetFileSize()));
						}
					}

					listTag.push_back(new CKadTagUInt8(TAG_ENCRYPTION, CKademlia::GetPrefs()->GetMyConnectOptions(true, true)));
					

					// Send packet
					///snow:向回应的联系人发布源信息包，不是调用SendPacket()
					CKademlia::GetUDPListener()->SendPublishSourcePacket(pFromContact, m_uTarget, uID, listTag);
					// Inc total request answers
					m_uTotalRequestAnswers++;
					// Update search in the GUI
					theApp.emuledlg->kademliawnd->searchList->SearchRef(this);
					// Delete all tags.
					for (TagList::const_iterator itTagList = listTag.begin(); itTagList != listTag.end(); ++itTagList)
						delete *itTagList;
				}
				else
					PrepareToStop();
				break;
			}
		case STOREKEYWORD:
			{
				// Try to store keywords to a Node.
				// As a safe guard, check to see if we already stored to the Max Nodes
				if( m_uAnswers > SEARCHSTOREKEYWORD_TOTAL )   ///snow:最多10个
				{
					PrepareToStop();
					break;
				}

				uint16 iCount = (uint16)m_listFileIDs.size();   ///snow:AddFileID()中赋值

				if(iCount == 0)
				{
					PrepareToStop();
					break;
				}
				else if(iCount > 150)   ///snow:最多150个文件
					iCount = 150;

				UIntList::const_iterator itListFileID = m_listFileIDs.begin();
				uchar ucharFileid[16];

				///snow:在这里写入的数据在Process_KADEMLIA2_PUBLISH_KEY_REQ()中读取处理
				while(iCount && (itListFileID != m_listFileIDs.end()))  ///snow:遍历m_listFileIDs，每50个文件一个信息包
				{
					uint16 iPacketCount = 0;
					byte byPacket[1024*50];
					CByteIO byIO(byPacket,sizeof(byPacket));
					byIO.WriteUInt128(m_uTarget);  ///snow:拟发送的Keyword，在PrepareLookup中通过参数传入
					byIO.WriteUInt16(0); // Will be corrected before sending. ///snow:文件ID数，在后面更新
					while((iPacketCount < 50) && (itListFileID != m_listFileIDs.end()))   ///snow:添加50个文件ID及Tags
					{
						CUInt128 iID = *itListFileID;
						iID.ToByteArray(ucharFileid);
						CKnownFile* pFile = theApp.sharedfiles->GetFileByID(ucharFileid);
						if(pFile)
						{
							iCount--;
							iPacketCount++;
							byIO.WriteUInt128(iID);
							PreparePacketForTags( &byIO, pFile, pFromContact->GetVersion() );  ///snow:给每个文件添加Tags
						}
						++itListFileID;
					}
					
					// Correct file count.
					uint32 current_pos = byIO.GetUsed();
					byIO.Seek(16);
					byIO.WriteUInt16(iPacketCount);  ///snow:以实际文件ID数更新之前写入的0
					byIO.Seek(current_pos);
					
					// Send packet
					if (pFromContact->GetVersion() >= 6){ /*48b*/
						if (thePrefs.GetDebugClientKadUDPLevel() > 0)
							DebugSend("KADEMLIA2_PUBLISH_KEY_REQ", pFromContact->GetIPAddress(), pFromContact->GetUDPPort());
						CUInt128 uClientID = pFromContact->GetClientID();
						CKademlia::GetUDPListener()->SendPacket( byPacket, sizeof(byPacket)-byIO.GetAvailable(), KADEMLIA2_PUBLISH_KEY_REQ, pFromContact->GetIPAddress(), pFromContact->GetUDPPort(), pFromContact->GetUDPKey(), &uClientID);

					}	
					else if (pFromContact->GetVersion() >= 2/*47a*/)
					{
						if (thePrefs.GetDebugClientKadUDPLevel() > 0)
							DebugSend("KADEMLIA2_PUBLISH_KEY_REQ", pFromContact->GetIPAddress(), pFromContact->GetUDPPort());
						CKademlia::GetUDPListener()->SendPacket( byPacket, sizeof(byPacket)-byIO.GetAvailable(), KADEMLIA2_PUBLISH_KEY_REQ, pFromContact->GetIPAddress(), pFromContact->GetUDPPort(), 0, NULL);
						ASSERT( CKadUDPKey(0) == pFromContact->GetUDPKey() );
					}
					else
						ASSERT( false );
				}
				// Inc total request answers
				m_uTotalRequestAnswers++;
				// Update search in the GUI
				theApp.emuledlg->kademliawnd->searchList->SearchRef(this);
				break;
			}
		case STORENOTES:
			{
				// Find file we are storing info about.
				uchar ucharFileid[16];
				m_uTarget.ToByteArray(ucharFileid);
				CKnownFile* pFile = theApp.sharedfiles->GetFileByID(ucharFileid);

				if (pFile)
				{
					byte byPacket[1024*2];
					CByteIO byIO(byPacket,sizeof(byPacket));

					// Send the Hash of the file we are storing info about.
					byIO.WriteUInt128(m_uTarget);
					// Send our ID with the info.
					byIO.WriteUInt128(CKademlia::GetPrefs()->GetKadID());

					// Create our taglist
					TagList listTag;
					listTag.push_back(new CKadTagStr(TAG_FILENAME, pFile->GetFileName()));
					if(pFile->GetFileRating() != 0)
						listTag.push_back(new CKadTagUInt(TAG_FILERATING, pFile->GetFileRating()));
					if(pFile->GetFileComment() != _T(""))
						listTag.push_back(new CKadTagStr(TAG_DESCRIPTION, pFile->GetFileComment()));
					if (pFromContact->GetVersion() >= 2/*47a*/)
						listTag.push_back(new CKadTagUInt(TAG_FILESIZE, pFile->GetFileSize()));
					byIO.WriteTagList(listTag);

					// Send packet
					if (pFromContact->GetVersion() >= 6){ /*48b*/
						if (thePrefs.GetDebugClientKadUDPLevel() > 0)
							DebugSend("KADEMLIA2_PUBLISH_NOTES_REQ", pFromContact->GetIPAddress(), pFromContact->GetUDPPort());
						CUInt128 uClientID = pFromContact->GetClientID();
						CKademlia::GetUDPListener()->SendPacket( byPacket, sizeof(byPacket)-byIO.GetAvailable(), KADEMLIA2_PUBLISH_NOTES_REQ, pFromContact->GetIPAddress(), pFromContact->GetUDPPort(), pFromContact->GetUDPKey(), &uClientID);
					}
					else if (pFromContact->GetVersion() >= 2/*47a*/)
					{
						if (thePrefs.GetDebugClientKadUDPLevel() > 0)
							DebugSend("KADEMLIA2_PUBLISH_NOTES_REQ", pFromContact->GetIPAddress(), pFromContact->GetUDPPort());
						CKademlia::GetUDPListener()->SendPacket( byPacket, sizeof(byPacket)-byIO.GetAvailable(), KADEMLIA2_PUBLISH_NOTES_REQ, pFromContact->GetIPAddress(), pFromContact->GetUDPPort(), 0, NULL);
						ASSERT( CKadUDPKey(0) == pFromContact->GetUDPKey() );
					}
					else
						ASSERT( false );
					// Inc total request answers
					m_uTotalRequestAnswers++;
					// Update search in the GUI
					theApp.emuledlg->kademliawnd->searchList->SearchRef(this);
					// Delete all tags.
					for (TagList::const_iterator itTagList = listTag.begin(); itTagList != listTag.end(); ++itTagList)
						delete *itTagList;
				}
				else
					PrepareToStop();
				break;
			}
		case FINDBUDDY:
			{
				// Send a buddy request as we are firewalled.
				// As a safe guard, check to see if we already requested the Max Nodes
				if( m_uAnswers > SEARCHFINDBUDDY_TOTAL )
				{
					PrepareToStop();
					break;
				}

				CSafeMemFile m_pfileSearchTerms;
				// Send the ID we used to find our buddy. Used for checks later and allows users to callback someone if they change buddies.
				m_pfileSearchTerms.WriteUInt128(&m_uTarget);
				// Send client hash so they can do a callback.
				m_pfileSearchTerms.WriteUInt128(&CKademlia::GetPrefs()->GetClientHash());
				// Send client port so they can do a callback
				m_pfileSearchTerms.WriteUInt16(thePrefs.GetPort());

				// Do a keyword/source search request to this Node.
				// Send packet
				if (thePrefs.GetDebugClientKadUDPLevel() > 0)
					DebugSend("KADEMLIA_FINDBUDDY_REQ", pFromContact->GetIPAddress(), pFromContact->GetUDPPort());
				if (pFromContact->GetVersion() >= 6){ /*48b*/
					CUInt128 uClientID = pFromContact->GetClientID();
					CKademlia::GetUDPListener()->SendPacket(&m_pfileSearchTerms, KADEMLIA_FINDBUDDY_REQ, pFromContact->GetIPAddress(), pFromContact->GetUDPPort(), pFromContact->GetUDPKey(), &uClientID);
				}
				else {
					CKademlia::GetUDPListener()->SendPacket(&m_pfileSearchTerms, KADEMLIA_FINDBUDDY_REQ, pFromContact->GetIPAddress(), pFromContact->GetUDPPort(), 0, NULL);
					ASSERT( CKadUDPKey(0) == pFromContact->GetUDPKey() );
				}
				// Inc total request answers
				m_uAnswers++;
				// Update search in the GUI
				theApp.emuledlg->kademliawnd->searchList->SearchRef(this);
				break;
			}
		case FINDSOURCE:
			{
				// Try to find if this is a buddy to someone we want to contact.
				// As a safe guard, check to see if we already requested the Max Nodes
				if( m_uAnswers > SEARCHFINDSOURCE_TOTAL )
				{
					PrepareToStop();
					break;
				}

				CSafeMemFile fileIO(34);
				// This is the ID the the person we want to contact used to find a buddy.
				fileIO.WriteUInt128(&m_uTarget);
				if( m_listFileIDs.size() != 1)
					throw CString(_T("Kademlia.CSearch.ProcessResponse: m_listFileIDs.size() != 1"));
				// Currently, we limit they type of callbacks for sources.. We must know a file it person has for it to work.
				fileIO.WriteUInt128(&m_listFileIDs.front());
				// Send our port so the callback works.
				fileIO.WriteUInt16(thePrefs.GetPort());
				// Send packet
				if (thePrefs.GetDebugClientKadUDPLevel() > 0)
					DebugSend("KADEMLIA_CALLBACK_REQ", pFromContact->GetIPAddress(), pFromContact->GetUDPPort());
				if (pFromContact->GetVersion() >= 6){ /*48b*/
					CUInt128 uClientID = pFromContact->GetClientID();
					CKademlia::GetUDPListener()->SendPacket( &fileIO, KADEMLIA_CALLBACK_REQ, pFromContact->GetIPAddress(), pFromContact->GetUDPPort(), pFromContact->GetUDPKey(), &uClientID);
				}
				else {
					CKademlia::GetUDPListener()->SendPacket( &fileIO, KADEMLIA_CALLBACK_REQ, pFromContact->GetIPAddress(), pFromContact->GetUDPPort(), 0, NULL);
					ASSERT( CKadUDPKey(0) == pFromContact->GetUDPKey() );
				}
				// Inc total request answers
				m_uAnswers++;
				// Update search in the GUI
				theApp.emuledlg->kademliawnd->searchList->SearchRef(this);
				break;
			}
		case NODESPECIAL:
			{
				// we are looking for the IP of a given nodeid, so we just check if we 0 distance and if so, report the
				// tip to the requester
				if (uFromDistance == CUInt128((ULONG)0)){
					pNodeSpecialSearchRequester->KadSearchIPByNodeIDResult(KCSR_SUCCEEDED, ntohl(pFromContact->GetIPAddress()), pFromContact->GetTCPPort());
					pNodeSpecialSearchRequester = NULL;
					PrepareToStop();
				}
				break;
			}
	}
}

///snow: CSearchManager::ProcessResult()中调用，处理三种类型的结果：FILE、KEYWORD、NOTES
void CSearch::ProcessResult(const CUInt128 &uAnswer, TagList *plistInfo, uint32 uFromIP, uint16 uFromPort)
{
	// We received a result, process it based on type.
	uint32 iAnswerBefore = m_uAnswers;
	switch(m_uType)
	{
		case FILE:  ///snow:在CPartFile::Process()中通过调用CSearchManager::PrepareLookup(Kademlia::CSearch::FILE，...)传入
			ProcessResultFile(uAnswer, plistInfo);
			break;
		case KEYWORD:   ///snow:m_uType的值在 CSearchManager::PrepareFindKeywords()设置，并将Search对象存入m_mapSearches
			ProcessResultKeyword(uAnswer, plistInfo, uFromIP, uFromPort);
			break;
		case NOTES: ///snow:CCommentDialog类中以Notes参数调用PrepareLookup()传入
			ProcessResultNotes(uAnswer, plistInfo);
			break;
	}
	if (iAnswerBefore < m_uAnswers)
	{
		m_pLookupHistory->ContactRespondedKeyword(uFromIP, uFromPort, m_uAnswers - iAnswerBefore);
		theApp.emuledlg->kademliawnd->UpdateSearchGraph(m_pLookupHistory);
	}
	// Update search for the GUI
	theApp.emuledlg->kademliawnd->searchList->SearchRef(this);
}

void CSearch::ProcessResultFile(const CUInt128 &uAnswer, TagList *plistInfo)
{
	///snow:从Result中获取各Tag，赋值给下列变量，调用KademliaSearchFile()
	// Process a possible source to a file.
	// Set of data we could receive from the result.
	uint8 uType = 0;
	uint32 uIP = 0;
	uint16 uTCPPort = 0;
	uint16 uUDPPort = 0;
	uint32 uBuddyIP = 0;
	uint16 uBuddyPort = 0;
	//uint32 uClientID = 0;
	CUInt128 uBuddy;
	uint8 byCryptOptions = 0; // 0 = not supported

	for (TagList::const_iterator itTagList = plistInfo->begin(); itTagList != plistInfo->end(); ++itTagList)
	{
		CKadTag* pTag = *itTagList;
		if (!pTag->m_name.Compare(TAG_SOURCETYPE))
			uType = (uint8)pTag->GetInt();
		else if (!pTag->m_name.Compare(TAG_SOURCEIP))
			uIP = (uint32)pTag->GetInt();
		else if (!pTag->m_name.Compare(TAG_SOURCEPORT))
			uTCPPort = (uint16)pTag->GetInt();
		else if (!pTag->m_name.Compare(TAG_SOURCEUPORT))
			uUDPPort = (uint16)pTag->GetInt();
		else if (!pTag->m_name.Compare(TAG_SERVERIP))
			uBuddyIP = (uint32)pTag->GetInt();
		else if (!pTag->m_name.Compare(TAG_SERVERPORT))
			uBuddyPort = (uint16)pTag->GetInt();
		//else if (!pTag->m_name.Compare(TAG_CLIENTLOWID))
		//  uClientID = pTag->GetInt();
		else if (!pTag->m_name.Compare(TAG_BUDDYHASH))
		{
			uchar ucharBuddyHash[16];
			if (pTag->IsStr() && strmd4(pTag->GetStr(), ucharBuddyHash))
				md4cpy(uBuddy.GetDataPtr(), ucharBuddyHash);
			else
				TRACE("+++ Invalid TAG_BUDDYHASH tag\n");
		}
		else if (!pTag->m_name.Compare(TAG_ENCRYPTION))
			byCryptOptions = (uint8)pTag->GetInt();

		delete pTag;
	}
	delete plistInfo;

	// Process source based on it's type. Currently only one method is needed to process all types.
	switch( uType )
	{
		case 1:
		case 3:
		case 4:
		case 5:
		case 6:
			m_uAnswers++;
			theApp.emuledlg->kademliawnd->searchList->SearchRef(this);
			theApp.downloadqueue->KademliaSearchFile(m_uSearchID, &uAnswer, &uBuddy, uType, uIP, uTCPPort, uUDPPort, uBuddyIP, uBuddyPort, byCryptOptions);
			break;
	}
}

///snow:从回复中提取Tag信息，然后再匹配共享文件列表或下载文件列表，如果找到，则添加Note；最后增加m_uAnswers，更新Search GUI
void CSearch::ProcessResultNotes(const CUInt128 &uAnswer, TagList *plistInfo)
{
	// Process a received Note to a file.
	// Create a Note and set the ID's.
	CEntry* pEntry = new CEntry();
	pEntry->m_uKeyID.SetValue(m_uTarget);
	pEntry->m_uSourceID.SetValue(uAnswer);
	// Create flag to determine if we keep this note.
	bool bFilterComment = false;

	// Loops through tags and pull wanted into. Currently we only keep Filename, Rating, Comment.
	for (TagList::const_iterator itTagList = plistInfo->begin(); itTagList != plistInfo->end(); ++itTagList)
	{
		CKadTag* pTag = *itTagList;
		if (!pTag->m_name.Compare(TAG_SOURCEIP))
		{
			pEntry->m_uIP = (uint32)pTag->GetInt();
			delete pTag;
		}
		else if (!pTag->m_name.Compare(TAG_SOURCEPORT))
		{
			pEntry->m_uTCPPort = (uint16)pTag->GetInt();
			delete pTag;
		}
		else if (!pTag->m_name.Compare(TAG_FILENAME) || !pTag->m_name.Compare(TAG_DESCRIPTION))
		{
			// Run the filter against the comment as well as against the filename since both values could be misused
			if (!thePrefs.GetCommentFilter().IsEmpty())
			{
				CString strCommentLower(pTag->GetStr());
				// Verified Locale Dependency: Locale dependent string conversion (OK)
				strCommentLower.MakeLower();

				int iPos = 0;
				CString strFilter(thePrefs.GetCommentFilter().Tokenize(_T("|"), iPos));
				while (!strFilter.IsEmpty())
				{
					// comment filters are already in lowercase, compare with temp. lowercased received comment
					if (strCommentLower.Find(strFilter) >= 0)
					{
						bFilterComment = true;
						break;
					}
					strFilter = thePrefs.GetCommentFilter().Tokenize(_T("|"), iPos);
				}
			}
			if (!pTag->m_name.Compare(TAG_FILENAME))
			{
				pEntry->SetFileName(pTag->GetStr());
				delete pTag;
			}
			else
			{
				ASSERT( !pTag->m_name.Compare(TAG_DESCRIPTION) );
				if (pTag->GetStr().GetLength() > MAXFILECOMMENTLEN)
				{
					CKadTagStr* pReplace = new CKadTagStr(pTag->m_name, pTag->GetStr().Left(MAXFILECOMMENTLEN));
					delete pTag;
					pTag = pReplace;
				}
				pEntry->AddTag(pTag);
			}
		}
		else if (!pTag->m_name.Compare(TAG_FILERATING))
			pEntry->AddTag(pTag);
		else
			delete pTag;
	}
	delete plistInfo;

	// If we think this should be filtered, delete the note.
	if(bFilterComment)
	{
		delete pEntry;
		return;
	}

	uchar ucharFileid[16];
	m_uTarget.ToByteArray(ucharFileid);

	// Add notes to any searches we have done.
	// The returned entry object will never be attached
	// to anything. So you can delete the entry object
	// at any time after this call..
	bool bFlag = theApp.searchlist->AddNotes(pEntry, ucharFileid);

	///snow:先从共享文件列表找，如果没找到，再从下载列表找
	// Check if this hash is in our shared files..
	CAbstractFile* pFile = (CAbstractFile*)theApp.sharedfiles->GetFileByID(ucharFileid);

	// If we didn't find a file in the shares check if it's in our download queue.
	if(!pFile)   
		pFile = (CAbstractFile*)theApp.downloadqueue->GetFileByID(ucharFileid);

	///snow:如果从上面两个列表有找到，则添加Note
	// If we found a file try to add the Note to the file.
	if( pFile && pFile->AddNote(pEntry) )
	{
		// Inc the number of answers.
		m_uAnswers++;
		// Update the search in the GUI
		theApp.emuledlg->kademliawnd->searchList->SearchRef(this);
		// We do note delete the NOTE in this case.
		return;
	}

	///snow:没从上面两个列表找到
	// It is possible that pFile->AddNote can fail even if we found a File.
	if (bFlag)
	{
		// Inc the number of answers.
		m_uAnswers++;
		// Update the search in the GUI
		theApp.emuledlg->kademliawnd->searchList->SearchRef(this);
	}

	// We always delete the entry object if pFile->AddNote fails..
	delete pEntry;
}

void CSearch::ProcessResultKeyword(const CUInt128 &uAnswer, TagList *plistInfo, uint32 uFromIP, uint16 uFromPort)
{
	// Find the contact who sent the answer - we need to know its protocol version
	// Special publish answer tags need to be filtered based on its remote protocol version, because if an old node is not aware
	// of those special tags, it doesn't knows it is not supposed accept and store such tags on publish request, so a malicious
	// publisher could fake them and our remote node would relay them on answers
	///snow:首先检查回应的联系人是不是我们发出请求的
	uint8 uFromKadVersion = 0;
	CContact* pFromContact = NULL;
	for (ContactMap::const_iterator itContactMap = m_mapTried.begin(); itContactMap != m_mapTried.end(); ++itContactMap)
	{
		CContact* pTmpContact = itContactMap->second;
		if ((pTmpContact->GetIPAddress() == uFromIP) && (pTmpContact->GetUDPPort() == uFromPort))
			pFromContact = pTmpContact;
	}
	if (pFromContact != NULL)
		uFromKadVersion = pFromContact->GetVersion();
	else
		DebugLogWarning(_T("Unable to find answering contact in ProcessResultKeyword - %s"), ipstr(ntohl(uFromIP)));
	// Process a keyword that we received.
	// Set of data we can use for a keyword result
	CKadTagValueString sName;
	uint64 uSize = 0;
	CKadTagValueString sType;
	CKadTagValueString sFormat;
	CKadTagValueString sArtist;
	CKadTagValueString sAlbum;
	CKadTagValueString sTitle;
	uint32 uLength = 0;
	CKadTagValueString sCodec;
	uint32 uBitrate = 0;
	uint32 uAvailability = 0;
	uint32 uPublishInfo = 0;
	CArray<CAICHHash> aAICHHashs;
	CArray<uint8> aAICHHashPopularity;
	// Flag that is set if we want this keyword.
	bool bFileName = false;
	bool bFileSize = false;

	///snow:处理回应报文中的TagList信息
	for (TagList::const_iterator itTagList = plistInfo->begin(); itTagList != plistInfo->end(); ++itTagList)
	{
		CKadTag* pTag = *itTagList;

		if (!pTag->m_name.Compare(TAG_FILENAME))
		{
			// Set flag based on last tag we saw.
			sName = pTag->GetStr();
			if( sName != L"" )
				bFileName = true;
			else
				bFileName = false;
		}
		else if (!pTag->m_name.Compare(TAG_FILESIZE))
		{
			if(pTag->IsBsob() && pTag->GetBsobSize() == 8)
				uSize = *((uint64*)pTag->GetBsob());
			else
				uSize = pTag->GetInt();

			// Set flag based on last tag we saw.
			if(uSize)
				bFileSize = true;
			else
				bFileSize = false;
		}
		else if (!pTag->m_name.Compare(TAG_FILETYPE))
			sType = pTag->GetStr();
		else if (!pTag->m_name.Compare(TAG_FILEFORMAT))
			sFormat = pTag->GetStr();
		else if (!pTag->m_name.Compare(TAG_MEDIA_ARTIST))
			sArtist = pTag->GetStr();
		else if (!pTag->m_name.Compare(TAG_MEDIA_ALBUM))
			sAlbum = pTag->GetStr();
		else if (!pTag->m_name.Compare(TAG_MEDIA_TITLE))
			sTitle = pTag->GetStr();
		else if (!pTag->m_name.Compare(TAG_MEDIA_LENGTH))
			uLength = (uint32)pTag->GetInt();
		else if (!pTag->m_name.Compare(TAG_MEDIA_BITRATE))
			uBitrate = (uint32)pTag->GetInt();
		else if (!pTag->m_name.Compare(TAG_MEDIA_CODEC))
			sCodec = pTag->GetStr();
		else if (!pTag->m_name.Compare(TAG_SOURCES))
		{
			// Some rouge client was setting a invalid availability, just set it to 0
			uAvailability = (uint32)pTag->GetInt();
			if( uAvailability > 65500 )
				uAvailability = 0;
		}
		else if (!pTag->m_name.Compare(TAG_PUBLISHINFO))
		{
			if (uFromKadVersion >= KADEMLIA_VERSION6_49aBETA)
			{
				// we don't keep this as tag, but as a member property of the searchfile, as we only need its informations
				// in the search list and don't want to carry the tag over when downloading the file (and maybe even wrongly publishing it)
				uPublishInfo = (uint32)pTag->GetInt();
/*#ifdef _DEBUG
				uint32 byDifferentNames = (uPublishInfo & 0xFF000000) >> 24;
				uint32 byPublishersKnown = (uPublishInfo & 0x00FF0000) >> 16;
				uint32 wTrustValue = uPublishInfo & 0x0000FFFF;
				DebugLog(_T("Received PublishInfoTag: %u different names, %u Publishers, %.2f Trustvalue"), byDifferentNames, byPublishersKnown, (float)wTrustValue / 100.0f);  
#endif*/	
			}
			else
				DebugLogWarning(_T("ProcessResultKeyword: Received special pbulish tag (TAG_PUBLISHINFO) from node (version %u, ip: %s) which is not aware of it, filtering")
					, uFromKadVersion, ipstr(ntohl(uFromIP)));
		}
		else if (!pTag->m_name.Compare(TAG_KADAICHHASHRESULT))
		{
			if (uFromKadVersion >= KADEMLIA_VERSION9_50a && pTag->IsBsob())
			{
				CSafeMemFile fileAICHTag(pTag->GetBsob(), pTag->GetBsobSize());
				try
				{
					uint8 byCount = fileAICHTag.ReadUInt8();
					for (uint8 i = 0; i < byCount; i++)
					{
						uint8 byPopularity = fileAICHTag.ReadUInt8();
						if (byPopularity > 0)
						{
							aAICHHashPopularity.Add(byPopularity);
							aAICHHashs.Add(CAICHHash(&fileAICHTag));
						}
					}
				}
				catch (CFileException* pError)
				{
					DebugLogError(_T("ProcessResultKeyword: Corrupt or invalid TAG_KADAICHHASHRESULT received - ip: %s)") , ipstr(ntohl(uFromIP)));
					pError->Delete();
					aAICHHashPopularity.RemoveAll();
					aAICHHashs.RemoveAll();
				}
			}
			else
				DebugLogWarning(_T("ProcessResultKeyword: Received special pbulish tag (TAG_KADAICHHASHRESULT) from node (version %u, ip: %s) which is not aware of it, filtering")
					, uFromKadVersion, ipstr(ntohl(uFromIP)));
		}
		delete pTag;
	}  ///snow:end for  报文中的Taglist信息处理完毕
	delete plistInfo;

	// If we don't have a valid filename or filesize, drop this keyword.
	if( !bFileName || !bFileSize )   ///snow:无效的文件名或文件长度
		return;

	// Check that this result matches original criteria
	WordList listTestWords;
	CSearchManager::GetWords(sName, &listTestWords);   ///snow:对文件名进行分析，存入listTestWords
	CKadTagValueString keyword;
	///snow:CSearchManager::PrepareFindKeywords()中对m_listWords赋值，存储的是用户拟进行搜索的关键字
	for (WordList::const_iterator itWordListWords = m_listWords.begin(); itWordListWords != m_listWords.end(); ++itWordListWords)
	{
		keyword = *itWordListWords;
		bool bInterested = false;
		for (WordList::const_iterator itWordListTestWords = listTestWords.begin(); itWordListTestWords != listTestWords.end(); ++itWordListTestWords)
		{
			if (!KadTagStrCompareNoCase(keyword, *itWordListTestWords))   ///snow:检查返回的关键字是否跟我们拟搜索的关键字是否匹配
			{
				bInterested = true;
				break;
			}
		}
		if (!bInterested)  ///snow:不是我们要搜索的内容，直接返回
			return;
	}

	if (m_pSearchTerm == NULL && m_pucSearchTermsData != NULL && m_uSearchTermsDataSize != 0)
	{
		// we create this to pass on to the searchlist, which will check it against the result to filter bad ones
		CSafeMemFile tmpFile(m_pucSearchTermsData, m_uSearchTermsDataSize);
		m_pSearchTerm = CKademliaUDPListener::CreateSearchExpressionTree(tmpFile, 0);
		ASSERT( m_pSearchTerm != NULL );
	}

	// Inc the number of answers.
	m_uAnswers++;
	// Update the search in the GUI
	theApp.emuledlg->kademliawnd->searchList->SearchRef(this);
	// Send we keyword to searchlist to be processed.
	// This method is still legacy from the multithreaded Kad, maybe this can be changed for better handling.
	theApp.searchlist->KademliaSearchKeyword(m_uSearchID, &uAnswer, sName, uSize, sType, uPublishInfo
		, aAICHHashs, aAICHHashPopularity, m_pSearchTerm, 8,
		    2, TAG_FILEFORMAT, (LPCTSTR)sFormat,
		    2, TAG_MEDIA_ARTIST, (LPCTSTR)sArtist,
		    2, TAG_MEDIA_ALBUM, (LPCTSTR)sAlbum,
		    2, TAG_MEDIA_TITLE, (LPCTSTR)sTitle,
		    3, TAG_MEDIA_LENGTH, uLength,
		    3, TAG_MEDIA_BITRATE, uBitrate,
		    2, TAG_MEDIA_CODEC, (LPCTSTR)sCodec,
		    3, TAG_SOURCES, uAvailability);
}

void CSearch::SendFindValue(CContact* pContact, bool bReAskMore)
{
	// Found a Node that we think has contacts closer to our target.
	///snow:寻找一个接近拟搜索目标的疑似联系人节点
	try
	{
		// Make sure we are not in the process of stopping.
		if(m_bStoping)
			return;
		CSafeMemFile fileIO(33);  ///snow:33个字节：第一个字节是希望返回的联系人数目，第2-17个字节是拟搜索目标hash，第18-33个字节是对方KadID
		// The number of returned contacts is based on the type of search.
		uint8 byContactCount = GetRequestContactCount();
		if (bReAskMore)   ///snow:默认false
		{
			if (pRequestedMoreNodesContact == NULL)
			{
				pRequestedMoreNodesContact = pContact;
				ASSERT( byContactCount == KADEMLIA_FIND_VALUE);
				byContactCount = KADEMLIA_FIND_VALUE_MORE;
			}
			else
				ASSERT( false );
		}
		if (byContactCount > 0)
			fileIO.WriteUInt8(byContactCount);
		else
			return;
		// Put the target we want into the packet.
		fileIO.WriteUInt128(&m_uTarget);
		// Add the ID of the contact we are contacting for sanity checks on the other end.
		fileIO.WriteUInt128(&pContact->GetClientID());
		// Inc the number of packets sent.
		m_uKadPacketSent++;  ///snow:拟发送的KAd包数目+1
		// Update the search for the GUI.
		theApp.emuledlg->kademliawnd->searchList->SearchRef(this);

		///snow:发送数据包，联系人版本低于2的不发送
		if (pContact->GetVersion() >= 2/*47a*/)
		{
			m_pLookupHistory->ContactAskedKad(pContact);
			theApp.emuledlg->kademliawnd->UpdateSearchGraph(m_pLookupHistory);
			if (pContact->GetVersion() >= 6){ /*48b*/  ///snow:之后的版本支持UDPKey
				CUInt128 uClientID = pContact->GetClientID();
				CKademlia::GetUDPListener()->SendPacket(&fileIO, KADEMLIA2_REQ, pContact->GetIPAddress(), pContact->GetUDPPort(), pContact->GetUDPKey(), &uClientID);
			}
			else {    ///snow:不支持UDPKey，一般是版本4
				CKademlia::GetUDPListener()->SendPacket(&fileIO, KADEMLIA2_REQ, pContact->GetIPAddress(), pContact->GetUDPPort(), 0, NULL);
				ASSERT( CKadUDPKey(0) == pContact->GetUDPKey() );
			}
			if (thePrefs.GetDebugClientKadUDPLevel() > 0)
			{
				switch(m_uType)   ///snow:发送的数据不包含m_uType
				{
					case NODE:
						DebugSend("KADEMLIA2_REQ(NODE)", pContact->GetIPAddress(), pContact->GetUDPPort());
						break;
					case NODECOMPLETE:
						DebugSend("KADEMLIA2_REQ(NODECOMPLETE)", pContact->GetIPAddress(), pContact->GetUDPPort());
						break;
					case NODESPECIAL:
						DebugSend("KADEMLIA2_REQ(NODESPECIAL)", pContact->GetIPAddress(), pContact->GetUDPPort());
						break;
					case NODEFWCHECKUDP:
						DebugSend("KADEMLIA2_REQ(NODEFWCHECKUDP)", pContact->GetIPAddress(), pContact->GetUDPPort());
						break;
					case FILE:
						DebugSend("KADEMLIA2_REQ(FILE)", pContact->GetIPAddress(), pContact->GetUDPPort());
						break;
					case KEYWORD:
						DebugSend("KADEMLIA2_REQ(KEYWORD)", pContact->GetIPAddress(), pContact->GetUDPPort());
						break;
					case STOREFILE:
						DebugSend("KADEMLIA2_REQ(STOREFILE)", pContact->GetIPAddress(), pContact->GetUDPPort());
						break;
					case STOREKEYWORD:
						DebugSend("KADEMLIA2_REQ(STOREKEYWORD)", pContact->GetIPAddress(), pContact->GetUDPPort());
						break;
					case STORENOTES:
						DebugSend("KADEMLIA2_REQ(STORENOTES)", pContact->GetIPAddress(), pContact->GetUDPPort());
						break;
					case NOTES:
						DebugSend("KADEMLIA2_REQ(NOTES)", pContact->GetIPAddress(), pContact->GetUDPPort());
						break;
					default:
						DebugSend("KADEMLIA2_REQ()", pContact->GetIPAddress(), pContact->GetUDPPort());
				}
			}
		}
		else
			ASSERT( false );
	}
	catch ( CIOException *ioe )
	{
		AddDebugLogLine( false, _T("Exception in CSearch::SendFindValue (IO error(%i))"), ioe->m_iCause);
		ioe->Delete();
	}
	catch (...)
	{
		AddDebugLogLine(false, _T("Exception in CSearch::SendFindValue"));
	}
}

///snow:在 CSharedFileList::Publish()、 CUpDownClient::TryToConnect()中调用
void CSearch::AddFileID(const CUInt128& uID)
{
	// Add a file hash to the search list.
	// This is used mainly for storing keywords, but was also reused for storing notes.
	m_listFileIDs.push_back(uID);
}

static int GetMetaDataWords(CStringArray& rastrWords, const CString& rstrData)
{
	// Create a list of the 'words' found in 'data'. This is similar but though not equal
	// to the 'CSearchManager::GetWords' function which needs to follow some other rules.
	int iPos = 0;
	CString strWord = rstrData.Tokenize(g_aszInvKadKeywordChars, iPos);
	while (!strWord.IsEmpty())
	{
		rastrWords.Add(strWord);
		strWord = rstrData.Tokenize(g_aszInvKadKeywordChars, iPos);
	}
	return rastrWords.GetSize();
}

static bool IsRedundantMetaData(const CStringArray& rastrFileNameWords, const CString& rstrMetaData)
{
	// Verify if the meta data string 'rstrMetaData' is already contained within the filename.
	if (rstrMetaData.IsEmpty())
		return true;

	int iMetaDataWords = 0;
	int iFoundInFileName = 0;
	int iPos = 0;
	CString strMetaDataWord(rstrMetaData.Tokenize(g_aszInvKadKeywordChars, iPos));
	while (!strMetaDataWord.IsEmpty())
	{
		iMetaDataWords++;
		for (int i = 0; i < rastrFileNameWords.GetSize(); i++)
		{
			// Verified Locale Dependency: Locale dependent string comparison (OK)
			if (rastrFileNameWords.GetAt(i).CompareNoCase(strMetaDataWord) == 0)
			{
				iFoundInFileName++;
				break;
			}
		}
		if (iFoundInFileName < iMetaDataWords)
			return false;
		strMetaDataWord = rstrMetaData.Tokenize(g_aszInvKadKeywordChars, iPos);
	}

	if (iMetaDataWords == 0)
		return true;
	if (iFoundInFileName == iMetaDataWords)
		return true;
	return false;
}

void CSearch::PreparePacketForTags(CByteIO *byIO, CKnownFile *pFile, uint8 byTargetKadVersion)
{
	// We are going to publish a keyword, setup the tag list.
	TagList listTag;
	try
	{
		if (pFile && byIO)
		{
			// Name, Size
			listTag.push_back(new CKadTagStr(TAG_FILENAME, pFile->GetFileName()));
			if (pFile->GetFileSize() > OLD_MAX_EMULE_FILE_SIZE)
			{
				// TODO: As soon as we drop Kad1 support, we should switch to Int64 tags (we could do now already for kad2 nodes only but no advantage in that)
				byte byValue[8];
				*((uint64*)byValue) = pFile->GetFileSize();
				listTag.push_back(new CKadTagBsob(TAG_FILESIZE, byValue, sizeof(byValue)));
			}
			else
				listTag.push_back(new CKadTagUInt(TAG_FILESIZE, pFile->GetFileSize()));

			listTag.push_back(new CKadTagUInt(TAG_SOURCES, pFile->m_nCompleteSourcesCount));

			if (byTargetKadVersion >= KADEMLIA_VERSION9_50a && pFile->GetFileIdentifier().HasAICHHash())
				listTag.push_back(new CKadTagBsob(TAG_KADAICHHASHPUB, pFile->GetFileIdentifier().GetAICHHash().GetRawHashC()
				, (uint8)CAICHHash::GetHashSize()));

			// eD2K file type (Audio, Video, ...)
			// NOTE: Archives and CD-Images are published with file type "Pro"
			CString strED2KFileType(GetED2KFileTypeSearchTerm(GetED2KFileTypeID(pFile->GetFileName())));
			if (!strED2KFileType.IsEmpty())
				listTag.push_back(new CKadTagStr(TAG_FILETYPE, strED2KFileType));

			// file format (filename extension)
			// 21-Sep-2006 []: TAG_FILEFORMAT is no longer explicitly published nor stored as
			// it is already part of the filename.
			//int iExt = pFile->GetFileName().ReverseFind(_T('.'));
			//if (iExt != -1)
			//{
			//	CString strExt(pFile->GetFileName().Mid(iExt));
			//	if (!strExt.IsEmpty())
			//	{
			//		strExt = strExt.Mid(1);
			//		if (!strExt.IsEmpty())
			//			listTag.push_back(new CKadTagStr(TAG_FILEFORMAT, strExt));
			//	}
			//}

			// additional meta data (Artist, Album, Codec, Length, ...)
			// only send verified meta data to nodes
			if (pFile->GetMetaDataVer() > 0)
			{
				static const struct
				{
					uint8 uName;
					uint8 uType;
				}
				_aMetaTags[] =
				{
				    { FT_MEDIA_ARTIST,  TAGTYPE_STRING },
				    { FT_MEDIA_ALBUM,   TAGTYPE_STRING },
				    { FT_MEDIA_TITLE,   TAGTYPE_STRING },
				    { FT_MEDIA_LENGTH,  TAGTYPE_UINT32 },
				    { FT_MEDIA_BITRATE, TAGTYPE_UINT32 },
				    { FT_MEDIA_CODEC,   TAGTYPE_STRING }
				};
				CStringArray astrFileNameWords;
				for (int iIndex = 0; iIndex < ARRSIZE(_aMetaTags); iIndex++)
				{
					const ::CTag* pTag = pFile->GetTag(_aMetaTags[iIndex].uName, _aMetaTags[iIndex].uType);
					if (pTag)
					{
						// skip string tags with empty string values
						if (pTag->IsStr() && pTag->GetStr().IsEmpty())
							continue;
						// skip integer tags with '0' values
						if (pTag->IsInt() && pTag->GetInt() == 0)
							continue;
						char szKadTagName[2];
						szKadTagName[0] = (char)pTag->GetNameID();
						szKadTagName[1] = '\0';
						if (pTag->IsStr())
						{
							bool bIsRedundant = false;
							if (   pTag->GetNameID() == FT_MEDIA_ARTIST
								|| pTag->GetNameID() == FT_MEDIA_ALBUM
								|| pTag->GetNameID() == FT_MEDIA_TITLE)
							{
								if (astrFileNameWords.GetSize() == 0)
									GetMetaDataWords(astrFileNameWords, pFile->GetFileName());
								bIsRedundant = IsRedundantMetaData(astrFileNameWords, pTag->GetStr());
								//if (bIsRedundant)
								//	TRACE(_T("Skipping meta data tag \"%s\" for file \"%s\"\n"), pTag->GetStr(), pFile->GetFileName());
							}
							if (!bIsRedundant)
								listTag.push_back(new CKadTagStr(szKadTagName, pTag->GetStr()));
						}
						else
							listTag.push_back(new CKadTagUInt(szKadTagName, pTag->GetInt()));
					}
				}
			}
			byIO->WriteTagList(listTag);
		}
		else
		{
			//If we get here.. Bad things happen.. Will fix this later if it is a real issue.
			ASSERT(0);
		}
	}
	catch ( CIOException *ioe )
	{
		AddDebugLogLine( false, _T("Exception in CSearch::PreparePacketForTags (IO error(%i))"), ioe->m_iCause);
		ioe->Delete();
	}
	catch (...)
	{
		AddDebugLogLine(false, _T("Exception in CSearch::PreparePacketForTags"));
	}
	for (TagList::const_iterator itTagList = listTag.begin(); itTagList != listTag.end(); ++itTagList)
		delete *itTagList;
}

///snow:取加载的Load节点与有回应的Load节点的比值 不是加载，是回应了Kadmelia2_Publish_source_req时发回的Load值总和
uint32 CSearch::GetNodeLoad() const
{
	// Node load is the average of all node load responses.
	if( m_uTotalLoadResponses == 0 )
	{
		return 0;
	}
	return m_uTotalLoad/m_uTotalLoadResponses;
}

uint32 CSearch::GetSearchID() const
{
	return m_uSearchID;
}
uint32 CSearch::GetSearchTypes() const
{
	return m_uType;
}
void CSearch::SetSearchTypes( uint32 uVal )
{
	m_uType = uVal;
	m_pLookupHistory->SetSearchType(uVal);
}
void CSearch::SetTargetID( CUInt128 uVal )
{
	m_uTarget = uVal;
}
uint32 CSearch::GetAnswers() const
{
	if(m_listFileIDs.size() == 0)
		return m_uAnswers;
	// If we sent more then one packet per node, we have to average the answers for the real count.
	return m_uAnswers/((m_listFileIDs.size()+49)/50);
}
uint32 CSearch::GetKadPacketSent() const
{
	return m_uKadPacketSent;
}
uint32 CSearch::GetRequestAnswer() const
{
	return m_uTotalRequestAnswers;
}

const CKadTagValueString& CSearch::GetGUIName() const
{
	return m_pLookupHistory->GetGUIName();
}
void CSearch::SetGUIName(const CKadTagValueString& sGUIName)
{
	 m_pLookupHistory->SetGUIName(sGUIName);
}
CUInt128 CSearch::GetTarget() const
{
	return m_uTarget;
}
bool CSearch::Stoping() const
{
	return m_bStoping;
}
uint32 CSearch::GetNodeLoadResonse() const
{
	return m_uTotalLoadResponses;
}
uint32 CSearch::GetNodeLoadTotal() const
{
	return m_uTotalLoad;
}
void CSearch::UpdateNodeLoad( uint8 uLoad )
{
	// Since all nodes do not return a load value, keep track of total responses and total load.
	m_uTotalLoad += uLoad;
	m_uTotalLoadResponses++;
}

void CSearch::SetSearchTermData( uint32 uSearchTermDataSize, LPBYTE pucSearchTermsData )
{
	m_uSearchTermsDataSize = uSearchTermDataSize;
	m_pucSearchTermsData = new BYTE[uSearchTermDataSize];
	memcpy(m_pucSearchTermsData, pucSearchTermsData, uSearchTermDataSize);
}

uint8 CSearch::GetRequestContactCount() const
{
	// Returns the amount of contacts we request on routing queries based on the search type
		switch(m_uType)
		{
			case NODE:
			case NODECOMPLETE:
			case NODESPECIAL:
			case NODEFWCHECKUDP:
				return KADEMLIA_FIND_NODE;
				break;
			case FILE:
			case KEYWORD:
			case FINDSOURCE:
			case NOTES:
				return KADEMLIA_FIND_VALUE;
				break;
			case FINDBUDDY:
			case STOREFILE:
			case STOREKEYWORD:
			case STORENOTES:
				return KADEMLIA_STORE;
				break;
			default:
				DebugLogError(false, _T("Invalid search type. (CSearch::GetRequestContactCount())"));
				ASSERT( false );
				return 0;
		}
}
