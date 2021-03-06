/*Copyright (C)2003 Barry Dunne (http://www.emule-project.net)
Copyright (C)2007-2008 Merkur ( strEmail.Format("%s@%s", "devteam", "emule-project.net") / http://www.emule-project.net )
 
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
 
 
This work is based on the java implementation of the Kademlia protocol.
Kademlia: Peer-to-peer routing based on the XOR metric
Copyright (C) 2002  Petar Maymounkov [petar@post.harvard.edu]
http://kademlia.scs.cs.nyu.edu
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

/**
 * The *Zone* is just a node in a binary tree of *Zone*s.
 * Each zone is either an internal node or a leaf node.
 * Internal nodes have "bin == null" and "subZones[i] != null",
 * leaf nodes have "subZones[i] == null" and "bin != null".
 * 
 * All key unique id's are relative to the center (self), which
 * is considered to be 000..000
 */

#include "stdafx.h"
#include <math.h>
#include "./RoutingZone.h"
#include "./RoutingBin.h"
#include "../utils/MiscUtils.h"
#include "../utils/KadUDPKey.h"
#include "../kademlia/Kademlia.h"
#include "../kademlia/Prefs.h"
#include "../kademlia/SearchManager.h"
#include "../kademlia/Defines.h"
#include "../net/KademliaUDPListener.h"
#include "../kademlia/UDPFirewallTester.h"
#include "../../Opcodes.h"
#include "../../emule.h"
#include "../../emuledlg.h"
#include "../../KadContactListCtrl.h"
#include "../../kademliawnd.h"
#include "../../Log.h"
#include "../../ipfilter.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

using namespace Kademlia;

void DebugSend(LPCTSTR pszMsg, uint32 uIP, uint16 uUDPPort);

CString CRoutingZone::m_sFilename;
CUInt128 CRoutingZone::uMe = (ULONG)0;

///snow:CUInt128的位数是从左往右数的，不是从右往左数的！！！

CRoutingZone::CRoutingZone()
{
	// Can only create routing zone after prefs
	// Set our KadID for creating the contact tree
	CKademlia::GetPrefs()->GetKadID(&uMe);
	//theApp.QueueTraceLogLine(TRACE_KAD_BINARY_TREE,_T("My KadID:%s",uMe.ToBinaryString()));
	// Set the preference file name.
	m_sFilename = thePrefs.GetMuleDirectory(EMULE_CONFIGDIR) + _T("nodes.dat");
	// Init our root node.
	Init(NULL, 0, CUInt128((ULONG)0));
}

CRoutingZone::CRoutingZone(LPCSTR szFilename)
{
	// Can only create routing zone after prefs
	// Set our KadID for creating the contact tree
	CKademlia::GetPrefs()->GetKadID(&uMe);
	m_sFilename = szFilename;
	///snow:父结点为NULL，表示为根结点，zoneindex为0
	// Init our root node.
	Init(NULL, 0, CUInt128((ULONG)0));
}

CRoutingZone::CRoutingZone(CRoutingZone *pSuper_zone, int iLevel, const CUInt128 &uZone_index)
{
	// Create a new leaf.  ///snow:建立一个没有子树的叶子结点
	Init(pSuper_zone, iLevel, uZone_index);
	//theApp.QueueTraceLogLine(TRACE_KAD_BINARY_TREE,_T("Parent Index:%s|Parent level:%i|Current Index:%s|Current Level:%i",pSuper_zone->m_uZoneIndex.ToBinaryString(),pSuper_zone->m_uLevel,uZone_index.ToBinaryString(),iLevel));
}

void CRoutingZone::Init(CRoutingZone *pSuper_zone, int iLevel, const CUInt128 &uZone_index)
{
	// Init all Zone vars
	// Set this zones parent
	m_pSuperZone = pSuper_zone;
	// Set this zones level
	m_uLevel = iLevel;
	// Set this zones CUInt128 Index
	m_uZoneIndex = uZone_index;
	///snow:初始化时左右子树均为空，为叶子结点
	// Mark this zone has having now leafs.
	m_pSubZones[0] = NULL;
	m_pSubZones[1] = NULL;
	// Create a new contact bin as this is a leaf.
	m_pBin = new CRoutingBin();

	// Set timer so that zones closer to the root are processed earlier.
	m_tNextSmallTimer = time(NULL) + m_uZoneIndex.Get32BitChunk(3);

	// Start this zone.
	StartTimer();

	///snow:初始化根结点时，读取nodes.dat
	// If we are initializing the root node, read in our saved contact list.
	if ((m_pSuperZone == NULL) && (m_sFilename.GetLength() > 0))
		ReadFile();
}

CRoutingZone::~CRoutingZone()
{
	// Root node is processed first so that we can write our contact list and delete all branches.
	if ((m_pSuperZone == NULL) && (m_sFilename.GetLength() > 0))
	{
		// Hide contacts in the GUI
		theApp.emuledlg->kademliawnd->StopUpdateContacts();
		WriteFile();
	}
	// If this zone is a leaf, delete our contact bin.
	if (IsLeaf())   ///snow:叶子结点，删除m_pBin，非叶结点，删除左右子树
		delete m_pBin;
	else
	{
		// If this zone is branch, delete it's leafs.
		delete m_pSubZones[0];
		delete m_pSubZones[1];
	}
	
	// All branches are deleted, show the contact list in the GUI.
	if (m_pSuperZone == NULL)
		theApp.emuledlg->kademliawnd->StartUpdateContacts();
}

void CRoutingZone::ReadFile(CString strSpecialNodesdate)
{
	if (m_pSuperZone != NULL || (m_sFilename.IsEmpty() && strSpecialNodesdate.IsEmpty())){
		ASSERT( false );
		return;
	}
	bool bDoHaveVerifiedContacts = false;
	// Read in the saved contact list.
	try
	{
		CSafeBufferedFile file;
		CFileException fexp;

/********************************************snow:start*****************************************************************
		00000000h: 00 00 00 00 02 00 00 00 AD 00 00 00 
		                           第一个contact       77 BB 87 00 ; ........?..w粐.
		00000010h: 6A 6F 89 2B BB CF D5 66 8A 58 87 59 E2 BA 2A 79 ; jo?幌說奨嘫夂*y
		00000020h: 7E 41 1B 28 04 00 00 00 00 70 05 3C 04 01 
		                           第二个contact             B1 9F ; ~A.(.....p.<..睙
		00000030h: C2 00 F6 AC E8 5A C7 75 FF 59 32 A0 54 DD 46 F0 ; ?霈鑊莡�Y2燭軫?
		00000040h: 10 97 3C 53 36 12 08 C6 FF 0D F7 70 05 3C 04 01 ; .?S6..?.鱬.<..
		                           第三个contact
		00000050h: 0E F3 75 00 A8 72 F1 79 91 54 8C 97 14 58 64 9D ; .髐.╮駓慣寳.Xd?
		00000060h: DD 89 98 BC 80 44 B4 BC 09 EA 74 F3 1B 70 05 3C ; 輭樇�D醇.阾?p.<
		00000070h: 04 01 
	   第四个contact     98 6F C6 00 75 A3 B6 14 86 DE 6C 07 7A 23 ; ..榦?u６.嗈l.z#
		00000080h: C4 79 EC 25 2D 53 84 FC 85 FC 08 C0 F2 84 EC 70 ; 膟?-S匋咟.莉勳p
		00000090h: 05 3C 04 01 
		第172个contact
		000016c0h:       8D DE CA FF 99 E4 59 0C F2 6C 46 46 E8 2B ; ..嵽?欎Y.騦FF?
		000016d0h: 2A 0C D6 CC 2D 72 28 16 1E 16 08 C0 F2 84 EC 70 ; *.痔-r(....莉勳p
		000016e0h: 05 3C 04 01
		第173个contact         0C 93 4D F6 7D 4D AF 35 28 04 B8 3F ; .<...揗鰙M?(.?
		000016f0h: E8 72 EF 15 57 3D D6 0E 36 27 BB 33 04 00 00 00 ; 鑢?W=?6'?....
		00001700h: 00 70 05 3C 04 00 
*****************************************************snow:end******************************************************/

		if (file.Open(strSpecialNodesdate.IsEmpty() ? m_sFilename : strSpecialNodesdate, CFile::modeRead | CFile::osSequentialScan|CFile::typeBinary|CFile::shareDenyWrite, &fexp))
		{
			setvbuf(file.m_pStream, NULL, _IOFBF, 32768);

			// Get how many contacts in the saved list.
			// NOTE: Older clients put the number of contacts here..
			//       Newer clients always have 0 here to prevent older clients from reading it.
			uint32 uNumContacts = file.ReadUInt32();   ///snow:前4个字节 00 00 00 00 
			uint32 uVersion = 0;
			if (uNumContacts == 0)
			{
				if (file.GetLength() >= 8){
					uVersion = file.ReadUInt32();  ///snow:4个字节的版本号 02 00 00 00
					if (uVersion == 3){
						uint32 nBoostrapEdition = file.ReadUInt32();
						if (nBoostrapEdition == 1){
							// this is a special bootstrap-only nodes.dat, handle it in a seperate reading function
							///snow:bootstrapNodeDat的前12个字节是 00 00 00 00 03 00 00 00 01 00 00 00
							ReadBootstrapNodesDat(file);
							file.Close();
							return;
						}
					}	
					if(uVersion >= 1 && uVersion <= 3) // those version we know, others we ignore
						uNumContacts = file.ReadUInt32();   ///snow:4字节的联系人数 AD 00 00 00  173人
				}
				else
					AddDebugLogLine( false, GetResString(IDS_ERR_KADCONTACTS));
			}
			///snow:2以上版本每个联系人34字节:16字节的ID,4字节的IP,2字节的TCP Port,2字节的UDP Port,1字节的ContactVersion,8字节的 kadUDPKey, 1字节的bVerified=01；2以下低版本的只要25字节！
			///snow:这边有两种情况：1是前四个字节不是00 00 00 00，是旧版本的Nodes.dat,uNumContacts!=0，后边是每个联系人25字节
			///snow:                2是前四个字节是00 00 00 00，经过上面代码的处理，uNumContacts也被赋值了，后边是每个联系人34字节
			if (uNumContacts != 0 && uNumContacts * 25 <= (file.GetLength() - file.GetPosition()))
			{
				// Hide contact list in the GUI
				theApp.emuledlg->kademliawnd->StopUpdateContacts();
				
				uint32 uValidContacts = 0;
				CUInt128 uID;
				while ( uNumContacts )
				{
					file.ReadUInt128(&uID);  ///snow:16字节的iD:77 BB 87 00 6A 6F 89 2B BB CF D5 66 8A 58 87 59
					uint32 uIP = file.ReadUInt32();///snow:IP:E2 BA 2A 79
					uint16 uUDPPort = file.ReadUInt16();///snow:7E 41 
					uint16 uTCPPort = file.ReadUInt16();///snow:1B 28
					byte byType = 0;

					uint8 uContactVersion = 0;
					if(uVersion >= 1)
						uContactVersion = file.ReadUInt8();///snow:04 04版本的没有KadUDPKEy，08，09的有key
					else
						byType = file.ReadUInt8();
					
					CKadUDPKey kadUDPKey;
					bool bVerified = false;
					if(uVersion >= 2){
						kadUDPKey.ReadFromFile(file);///snow:key 00 00 00 00 ip:  70 05 3C 04
						bVerified = file.ReadUInt8() != 0;  ///snow: 01---已验证  00---未验证
						if (bVerified)    ///只要有一个已验证就够了！
							bDoHaveVerifiedContacts = true;
					}
					// IP Appears valid
					if( byType < 4)
					{
						uint32 uhostIP = ntohl(uIP);
						if (::IsGoodIPPort(uhostIP, uUDPPort))
						{
							if (::theApp.ipfilter->IsFiltered(uhostIP))///snow:黑名单
							{
								if (::thePrefs.GetLogFilteredIPs())
									AddDebugLogLine(false, _T("Ignored kad contact (IP=%s:%u)--read known.dat -- - IP filter (%s)") , ipstr(uhostIP), uUDPPort, ::theApp.ipfilter->GetLastHit());
							}
							else if (uUDPPort == 53 && uContactVersion <= KADEMLIA_VERSION5_48a)  /*No DNS Port without encryption*/
							{
								if (::thePrefs.GetLogFilteredIPs())
									AddDebugLogLine(false, _T("Ignored kad contact (IP=%s:%u)--read known.dat") , ipstr(uhostIP), uUDPPort);
							}
							else
							{
								// This was not a dead contact, Inc counter if add was successful
								if (AddUnfiltered(uID, uIP, uUDPPort, uTCPPort, uContactVersion, kadUDPKey, bVerified, false, true, false))
									uValidContacts++;  ///snow:可用联系人+1
							}
						}
					}
					uNumContacts--;
				}
				AddLogLine( false, GetResString(IDS_KADCONTACTSREAD), uValidContacts);
				if (!bDoHaveVerifiedContacts){   ///snow:一个已验证的联系人都没有！
					DebugLogWarning(_T("No verified contacts found in nodes.dat - might be an old file version. Setting all contacts verified for this time to speed up Kad bootstrapping"));
					SetAllContactsVerified();
				}
			}
			file.Close();
		}
		else
			DebugLogWarning(_T("Unable to read Kad file: %s"), m_sFilename);
	}
	catch (CFileException* e)
	{
		e->Delete();
		DebugLogError(_T("CFileException in CRoutingZone::readFile"));
	}
	// Show contact list in GUI
	theApp.emuledlg->kademliawnd->StartUpdateContacts();
}

///snow:引导程序，读取的节点信息存入s_liBootstapList，在CKademlia::Process()中处理
void CRoutingZone::ReadBootstrapNodesDat(CFileDataIO& file){
	// Bootstrap versions of nodes.dat files, are in the style of version 1 nodes.dats. The difference is that
	// they will contain more contacts 500-1000 instead 50, and those contacts are not added into the routingtable
	// but used to sent Bootstrap packets too. The advantage is that on a list with a high ratio of dead nodes,
	// we will be able to bootstrap faster than on a normal nodes.dat and more important, if we would deliver
	// a normal nodes.dat with eMule, those 50 nodes would be kinda DDOSed because everyone adds them to their routing
	// table, while with this style, we don't actually add any of the contacts to our routing table in the end and we
	// ask only one of those 1000 contacts one time (well or more untill we find an alive one).
	if (!CKademlia::s_liBootstapList.IsEmpty()){
		ASSERT( false );
		return;
	}
	uint32 uNumContacts = file.ReadUInt32();
	if (uNumContacts != 0 && uNumContacts * 25 == (file.GetLength() - file.GetPosition()))
	{
		uint32 uValidContacts = 0;
		CUInt128 uID;
		while ( uNumContacts )
		{
			file.ReadUInt128(&uID);
			uint32 uIP = file.ReadUInt32();
			uint16 uUDPPort = file.ReadUInt16();
			uint16 uTCPPort = file.ReadUInt16();
			uint8 uContactVersion = file.ReadUInt8();

			uint32 uhostIP = ntohl(uIP);
			if (::IsGoodIPPort(uhostIP, uUDPPort))
			{
				if (::theApp.ipfilter->IsFiltered(uhostIP))
				{
					if (::thePrefs.GetLogFilteredIPs())
						AddDebugLogLine(false, _T("Ignored kad contact (IP=%s:%u)--read known.dat -- - IP filter (%s)") , ipstr(uhostIP), uUDPPort, ::theApp.ipfilter->GetLastHit());
				}
				else if (uUDPPort == 53 && uContactVersion <= KADEMLIA_VERSION5_48a) 
				{
					if (::thePrefs.GetLogFilteredIPs())
						AddDebugLogLine(false, _T("Ignored kad contact (IP=%s:%u)--read known.dat") , ipstr(uhostIP), uUDPPort);
				}
				else if (uContactVersion > 1) // only kad2 nodes
				{
					// we want the 50 nodes closest to our own ID (provides randomness between different users and gets has good chances to get a bootstrap with close Nodes which is a nice start for our routing table) 
					///snow:取最近的50个联系人，50个联系人按距离由近到远排序
					CUInt128 uDistance = uMe;
					uDistance.Xor(uID);
					uValidContacts++;
					// don't bother if we already have 50 and the farest distance is smaller than this contact
					if (CKademlia::s_liBootstapList.GetCount() < 50 || CKademlia::s_liBootstapList.GetTail()->GetDistance() > uDistance){
						// look were to put this contact into the proper position
						bool bInserted = false;
						CContact* pContact = new CContact(uID, uIP, uUDPPort, uTCPPort, uMe, uContactVersion, 0, false);
						///snow:按距离排序插入
						for (POSITION pos = CKademlia::s_liBootstapList.GetHeadPosition(); pos != NULL; CKademlia::s_liBootstapList.GetNext(pos)){
							if (CKademlia::s_liBootstapList.GetAt(pos)->GetDistance() > uDistance){
								CKademlia::s_liBootstapList.InsertBefore(pos, pContact);
								bInserted = true;
								break;
							}
						}
						if (!bInserted){  ///snow:没有插入成功，则放在队尾
							ASSERT( CKademlia::s_liBootstapList.GetCount() < 50 );
							CKademlia::s_liBootstapList.AddTail(pContact);
						}
						else if (CKademlia::s_liBootstapList.GetCount() > 50)
							delete CKademlia::s_liBootstapList.RemoveTail();
					}
				}
			}
			uNumContacts--;
		}
		AddLogLine( false, GetResString(IDS_KADCONTACTSREAD), CKademlia::s_liBootstapList.GetCount());
		DebugLog(_T("Loaded Bootstrap nodes.dat, selected %u out of %u valid contacts"), CKademlia::s_liBootstapList.GetCount(), uValidContacts);
	}
}

///snow:在析构的时候将KADID写入文件
void CRoutingZone::WriteFile()
{
	// don't overwrite a bootstrap nodes.dat with an empty one, if we didn't finished probing
	if (!CKademlia::s_liBootstapList.IsEmpty() && GetNumContacts() == 0){
		DebugLogWarning(_T("Skipped storing nodes.dat, because we have an unfinished bootstrap of the nodes.dat version and no contacts in our routing table"));
		return;
	}
	try
	{
		// Write a saved contact list.
		CUInt128 uID;
		CSafeBufferedFile file;
		CFileException fexp;
		if (file.Open(m_sFilename, CFile::modeWrite | CFile::modeCreate | CFile::typeBinary|CFile::shareDenyWrite, &fexp))
		{
			setvbuf(file.m_pStream, NULL, _IOFBF, 32768);

			// The bootstrap method gets a very nice sample of contacts to save.
			ContactList listContacts;
			GetBootstrapContacts(&listContacts, 200);
			// Start file with 0 to prevent older clients from reading it.
			file.WriteUInt32(0);
			// Now tag it with a version which happens to be 2 (1 till 0.48a).
			file.WriteUInt32(2);  ///snow:写入版本号
			// file.WriteUInt32(0) // if we would use version >=3, this would mean that this is a normal nodes.dat
			file.WriteUInt32((uint32)listContacts.size());
			for (ContactList::const_iterator itContactList = listContacts.begin(); itContactList != listContacts.end(); ++itContactList)
			{
				CContact* pContact = *itContactList;
				pContact->GetClientID(&uID);
				file.WriteUInt128(&uID);
				file.WriteUInt32(pContact->GetIPAddress());
				file.WriteUInt16(pContact->GetUDPPort());
				file.WriteUInt16(pContact->GetTCPPort());
				file.WriteUInt8(pContact->GetVersion());
				pContact->GetUDPKey().StoreToFile(file);
				file.WriteUInt8(pContact->IsIpVerified() ? 1 : 0);
			}
			file.Close();
			AddDebugLogLine( false, _T("Wrote %ld contact%s to file."), listContacts.size(), ((listContacts.size() == 1) ? _T("") : _T("s")));
		}
		else
			DebugLogError(_T("Unable to store Kad file: %s"), m_sFilename);
	}
	catch (CFileException* e)
	{
		e->Delete();
		AddDebugLogLine(false, _T("CFileException in CRoutingZone::writeFile"));
	}
}

#ifdef _DEBUG
void CRoutingZone::DbgWriteBootstrapFile()
{
	DebugLogWarning(_T("Writing special bootstrap nodes.dat - not intended for normal use"));
	try
	{
		// Write a saved contact list.
		CUInt128 uID;
		CSafeBufferedFile file;
		CFileException fexp;
		if (file.Open(m_sFilename, CFile::modeWrite | CFile::modeCreate | CFile::typeBinary|CFile::shareDenyWrite, &fexp))
		{
			setvbuf(file.m_pStream, NULL, _IOFBF, 32768);

			// The bootstrap method gets a very nice sample of contacts to save.
			ContactMap mapContacts;
			CUInt128 uRandom(CUInt128((ULONG)0), 0);
			CUInt128 uDistance = uRandom;
			uDistance.Xor(uMe);
			GetClosestTo(2, uRandom, uDistance, 1200, &mapContacts, false, false);
			// filter out Kad1 nodes
			///snow:遍历Map，删掉版本号小于2的联系人
			for (ContactMap::iterator itContactMap = mapContacts.begin(); itContactMap != mapContacts.end(); )
			{
				ContactMap::iterator itCurContactMap = itContactMap;
				++itContactMap;
				CContact* pContact = itCurContactMap->second;
				if (pContact->GetVersion() <= 1)
					mapContacts.erase(itCurContactMap);
			}
			// Start file with 0 to prevent older clients from reading it.
			file.WriteUInt32(0);
			// Now tag it with a version which happens to be 2 (1 till 0.48a).
			file.WriteUInt32(3);   ///snow:版本号3，非正常nodes.dat，后面跟的不是联系人数目，而是01 00 00 00
			file.WriteUInt32(1); // if we would use version >=3, this would mean that this is not a normal nodes.dat
			file.WriteUInt32((uint32)mapContacts.size());
			///snow:写入25字节，没有KadUDPKey
			for (ContactMap::const_iterator itContactMap = mapContacts.begin(); itContactMap != mapContacts.end(); ++itContactMap)
			{
				CContact* pContact = itContactMap->second;
				pContact->GetClientID(&uID);
				file.WriteUInt128(&uID);
				file.WriteUInt32(pContact->GetIPAddress());
				file.WriteUInt16(pContact->GetUDPPort());
				file.WriteUInt16(pContact->GetTCPPort());
				file.WriteUInt8(pContact->GetVersion());
			}
			file.Close();
			AddDebugLogLine( false, _T("Wrote %ld contact to bootstrap file."), mapContacts.size());
		}
		else
			DebugLogError(_T("Unable to store Kad file: %s"), m_sFilename);
	}
	catch (CFileException* e)
	{
		e->Delete();
		AddDebugLogLine(false, _T("CFileException in CRoutingZone::writeFile"));
	}

}
#else
void CRoutingZone::DbgWriteBootstrapFile() {}
#endif


bool CRoutingZone::CanSplit() const
{
	// Max levels allowed.
if (m_uLevel >= 127)   ///snow:最大层数127，不能再分割了
		return false;

	// Check if this zone is allowed to split.
if ( (m_uZoneIndex < KK || m_uLevel < KBASE) && m_pBin->GetSize() == K)///snow:后面的条件K桶满了好理解，前面的是条件是什么意思？表示Index为000，001，010，011，110的K桶的分裂不受限制，可以一直分裂到Level=127，而index>5的K桶只能分裂到第4层
		return true;
	return false;
}

// Returns true if a contact was added or updated, false if the routing table was not touched
bool CRoutingZone::Add(const CUInt128 &uID, uint32 uIP, uint16 uUDPPort, uint16 uTCPPort, uint8 uVersion, CKadUDPKey cUDPKey, bool& bIPVerified, bool bUpdate, bool bFromNodesDat, bool bFromHello)
{
	uint32 uhostIP = ntohl(uIP);
	///snow:对IP进行匹配过滤
	if (::IsGoodIPPort(uhostIP, uUDPPort))
	{
		if (!::theApp.ipfilter->IsFiltered(uhostIP) && !(uUDPPort == 53 && uVersion <= KADEMLIA_VERSION5_48a)  /*No DNS Port without encryption*/) {
			return AddUnfiltered(uID, uIP, uUDPPort, uTCPPort, uVersion, cUDPKey, bIPVerified, bUpdate, bFromNodesDat, bFromHello);
		}
		else if (::thePrefs.GetLogFilteredIPs() && !(uUDPPort == 53 && uVersion <= KADEMLIA_VERSION5_48a))
			AddDebugLogLine(false, _T("Ignored kad contact (IP=%s:%u) - IP filter (%s)"), ipstr(uhostIP), uUDPPort, ::theApp.ipfilter->GetLastHit());
		else if (::thePrefs.GetLogFilteredIPs())
			AddDebugLogLine(false, _T("Ignored kad contact (IP=%s:%u)"), ipstr(uhostIP), uUDPPort);

	}
	else if (::thePrefs.GetLogFilteredIPs())
		AddDebugLogLine(false, _T("Ignored kad contact (IP=%s) - Bad IP"), ipstr(uhostIP));
	return false;
}

// Returns true if a contact was added or updated, false if the routing table was not touched
bool CRoutingZone::AddUnfiltered(const CUInt128 &uID, uint32 uIP, uint16 uUDPPort, uint16 uTCPPort, uint8 uVersion, CKadUDPKey cUDPKey, bool& bIPVerified, bool bUpdate, bool /*bFromNodesDat*/, bool bFromHello)
{
	if (uID != uMe && uVersion > 1)   ///snow:uMe在构造函数中赋值：GetPrefs()->GetKadID(&uMe)，不是自身，且版本为2以上版本
	{
		CContact* pContact = new CContact(uID, uIP, uUDPPort, uTCPPort, uVersion, cUDPKey, bIPVerified);
		if (bFromHello)
			pContact->SetReceivedHelloPacket();  ///snow:这里设置的值在Add()中取值判断

		if (Add(pContact, bUpdate, bIPVerified)){
			ASSERT( !bUpdate );
			return true;
		}
		else{
			delete pContact;
			return bUpdate;
		}
	}
	return false;
}

bool CRoutingZone::Add(CContact* pContact, bool& bUpdate, bool& bOutIPVerified)
{
	// If we are not a leaf, call add on the correct branch.
	if (!IsLeaf())
		return m_pSubZones[pContact->GetDistance().GetBitNumber(m_uLevel)]->Add(pContact, bUpdate, bOutIPVerified);
	else  ///snow:当前是叶子结点
	{
		// Do we already have a contact with this KadID?
		CContact* pContactUpdate = m_pBin->GetContact(pContact->GetClientID());
		if (pContactUpdate)   ///snow:已经存在相同KadID的联系人
		{
			if(bUpdate)
			{
				if (pContactUpdate->GetUDPKey().GetKeyValue(theApp.GetPublicIP(false)) != 0
					&& pContactUpdate->GetUDPKey().GetKeyValue(theApp.GetPublicIP(false)) != pContact->GetUDPKey().GetKeyValue(theApp.GetPublicIP(false)))
				{
					///snow:UDPKey!=00(version 4的UDPKey是00）且新要求增加的联系人的UDPKey!=当前已存在的联系人的UDPKey
					// if our existing contact has a UDPSender-Key (which should be the case for all > = 0.49a clients)
					// except if our IP has changed recently, we demand that the key is the same as the key we received
					// from the packet which wants to update this contact in order to make sure this is not a try to
					// hijack this entry
					DebugLogWarning(_T("Kad: Sender (%s) tried to update contact entry but failed to provide the proper sender key (Sent Empty: %s) for the entry (%s) - denying update")
						, ipstr(ntohl(pContact->GetIPAddress())), pContact->GetUDPKey().GetKeyValue(theApp.GetPublicIP(false)) == 0 ? _T("Yes") : _T("No")
						, ipstr(ntohl(pContactUpdate->GetIPAddress())));
					bUpdate = false;
				}
				///snow:版本号在0.46c--0.49abeta之间，且收到了HelloPacket
				else if (pContactUpdate->GetVersion() >= KADEMLIA_VERSION1_46c && pContactUpdate->GetVersion() < KADEMLIA_VERSION6_49aBETA
					&& pContactUpdate->GetReceivedHelloPacket())
				{
					// legacy kad2 contacts are allowed only to update their RefreshTimer to avoid having them hijacked/corrupted by an attacker
					// (kad1 contacts do not have this restriction as they might turn out as kad2 later on)
					// only exception is if we didn't received a HELLO packet from this client yet
					if (pContactUpdate->GetIPAddress() == pContact->GetIPAddress() && pContactUpdate->GetTCPPort() == pContact->GetTCPPort()
						&& pContactUpdate->GetVersion() == pContact->GetVersion() && pContactUpdate->GetUDPPort() == pContact->GetUDPPort())
					{
						ASSERT( !pContact->IsIpVerified() ); // legacy kad2 nodes should be unable to verify their IP on a HELLO
						bOutIPVerified = pContactUpdate->IsIpVerified();
						m_pBin->SetAlive(pContactUpdate);
						theApp.emuledlg->kademliawnd->ContactRef(pContactUpdate);
						DEBUG_ONLY( AddDebugLogLine(DLP_VERYLOW, false, _T("Updated kad contact refreshtimer only for legacy kad2 contact (%s, %u)")
							, ipstr(ntohl(pContactUpdate->GetIPAddress())), pContactUpdate->GetVersion()) );
					}
					else{
						AddDebugLogLine(DLP_DEFAULT, false, _T("Rejected value update for legacy kad2 contact (%s -> %s, %u -> %u)")
							, ipstr(ntohl(pContactUpdate->GetIPAddress())), ipstr(ntohl(pContact->GetIPAddress())), pContactUpdate->GetVersion(), pContact->GetVersion());
						bUpdate = false;
					}
					
				}
				else{
#ifdef _DEBUG
					// just for outlining, get removed anyway
					//debug logging stuff - remove later
					if (pContact->GetUDPKey().GetKeyValue(theApp.GetPublicIP(false)) == 0){
						if (pContact->GetVersion() >= KADEMLIA_VERSION6_49aBETA && pContact->GetType() < 2)
							AddDebugLogLine(DLP_LOW, false, _T("Updating > 0.49a + type < 2 contact without valid key stored %s"), ipstr(ntohl(pContact->GetIPAddress())));
					}
					else
						AddDebugLogLine(DLP_VERYLOW, false, _T("Updating contact, passed key check %s"), ipstr(ntohl(pContact->GetIPAddress())));

					if (pContactUpdate->GetVersion() >= KADEMLIA_VERSION1_46c && pContactUpdate->GetVersion() < KADEMLIA_VERSION6_49aBETA){
						ASSERT( !pContactUpdate->GetReceivedHelloPacket() );
						AddDebugLogLine(DLP_VERYLOW, false, _T("Accepted update for legacy kad2 contact, because of first HELLO (%s -> %s, %u -> %u)")
							, ipstr(ntohl(pContactUpdate->GetIPAddress())), ipstr(ntohl(pContact->GetIPAddress())), pContactUpdate->GetVersion(), pContact->GetVersion());
					}
#endif
					// All other nodes (Kad1, Kad2 > 0.49a with UDPKey checked or not set, first hello updates) are allowed to do full updates
					if (m_pBin->ChangeContactIPAddress(pContactUpdate, pContact->GetIPAddress())   ///snow:函数名起的有点误导，不是Change，而是CanChange
						&& pContact->GetVersion() >= pContactUpdate->GetVersion()) // do not let Kad1 responses overwrite Kad2 ones///snow:新版本的可以替换旧版本的,KAD2可以替换KAD1的，反过来不行
					{
						pContactUpdate->SetUDPPort(pContact->GetUDPPort());
						pContactUpdate->SetTCPPort(pContact->GetTCPPort());
						pContactUpdate->SetVersion(pContact->GetVersion());
						pContactUpdate->SetUDPKey(pContact->GetUDPKey());
						if (!pContactUpdate->IsIpVerified()) // don't unset the verified flag (will clear itself on ipchanges)
							pContactUpdate->SetIpVerified(pContact->IsIpVerified());
						bOutIPVerified = pContactUpdate->IsIpVerified();
						m_pBin->SetAlive(pContactUpdate);
						theApp.emuledlg->kademliawnd->ContactRef(pContactUpdate);
						if (pContact->GetReceivedHelloPacket())
							pContactUpdate->SetReceivedHelloPacket();
					}
					else
						bUpdate = false;
				}
			}
			return false;
		}
		else if (m_pBin->GetRemaining())  ///snow:结点中还有剩余空间，联系人个数未过到K值
		{
			bUpdate = false;

			///snow:add by snow
			theApp.QueueTraceLogLine(TRACE_KAD_BINARY_TREE,_T("Function:%hs|Line:%i|Parent Index:%s|Parent level:%i|Current Index:%s|Current Level:%i|Contact Num:%i"),__FUNCTION__,__LINE__,m_pSuperZone?m_pSuperZone->m_uZoneIndex.ToBinaryString():_T("0-0"),m_pSuperZone?m_pSuperZone->m_uLevel:-1,m_uZoneIndex.ToBinaryString(),m_uLevel,m_pBin->GetSize());

			// This bin is not full, so add the new contact.
			if(m_pBin->AddContact(pContact))
			{
				// Add was successful, add to the GUI and let contact know it's listed in the gui.
				if (theApp.emuledlg->kademliawnd->ContactAdd(pContact))
					pContact->SetGuiRefs(true);
				return true;
			}
			return false;
		}
		else if (CanSplit())///snow:结点中没有空间存放新的联系人了，判断一下是否可以拆分结点
		{

			///snow:add by snow
			theApp.QueueTraceLogLine(TRACE_KAD_BINARY_TREE,_T("Function:%hs|Line:%i|Parent Index:%s|Parent level:%i|Current Index:%s|Current Level:%i|Contact Num:%i"),__FUNCTION__,__LINE__,m_pSuperZone?m_pSuperZone->m_uZoneIndex.ToBinaryString():_T("0-0"),m_pSuperZone?m_pSuperZone->m_uLevel:-1,m_uZoneIndex.ToBinaryString(),m_uLevel,m_pBin->GetSize());

			// This bin was full and split, call add on the correct branch.
			Split();
			return m_pSubZones[pContact->GetDistance().GetBitNumber(m_uLevel)]->Add(pContact, bUpdate, bOutIPVerified);
		}
		else{
			bUpdate = false;
			return false;
		}
	}
}

CContact *CRoutingZone::GetContact(const CUInt128 &uID) const
{
	if (IsLeaf())   ///snow:如果是叶子结点，则调用GetContact()函数
		return m_pBin->GetContact(uID);
	else{     ///snow:如果是分支结点，则根据uDistance中与本zone的m_uLevel对应的位的值，分别调用左子树或右子树，直到叶子结点，最后还是调用叶子结点的GetContact()
		CUInt128 uDistance;
		CKademlia::GetPrefs()->GetKadID(&uDistance); ///snow:将本机KadID赋值给uDistance
		uDistance.Xor(uID);   ///snow:将uID与本机KADID进行异或，得到距离
		return m_pSubZones[uDistance.GetBitNumber(m_uLevel)]->GetContact(uID);
	}
}

CContact* CRoutingZone::GetContact(uint32 uIP, uint16 nPort, bool bTCPPort) const
{
	if (IsLeaf())
		return m_pBin->GetContact(uIP, nPort, bTCPPort);
	else{
		CContact* pContact = m_pSubZones[0]->GetContact(uIP, nPort, bTCPPort);
		return (pContact != NULL) ? pContact : m_pSubZones[1]->GetContact(uIP, nPort, bTCPPort);
	}
}

CContact* CRoutingZone::GetRandomContact(uint32 nMaxType, uint32 nMinKadVersion) const
{
	if (IsLeaf())
		return m_pBin->GetRandomContact(nMaxType, nMinKadVersion);
	else{
		uint32 nZone = GetRandomUInt16() % 2;
		CContact* pContact = m_pSubZones[nZone]->GetRandomContact(nMaxType, nMinKadVersion);
		return (pContact != NULL) ? pContact : m_pSubZones[nZone == 1 ? 0 : 1]->GetRandomContact(nMaxType, nMinKadVersion);
	}
}

///snow:最近的联系人总是与目标结点的位最大程度的一致(从高位往低位匹配(因为CUInt128定义了最高位是0位))，如果本结点是叶子结点，则就是结点中存储的联系人，如果不是，则按位索引分支结点，直到叶子结点
///snow:GetClosestTo()中参数uDistance则代表的是从RoutingZone顶点开始，根据uDistance的值按位索引查找叶子结点
///snow:m_uTarget参数则是为了计算查找出的待定节点与目标节点的距离，然后将距离值作为索引写入ContactMap
void CRoutingZone::GetClosestTo(uint32 uMaxType, const CUInt128 &uTarget, const CUInt128 &uDistance, uint32 uMaxRequired, ContactMap *pmapResult, bool bEmptyFirst, bool bInUse) const
{
	///snow:如果是叶子结点，直接搜索
	// If leaf zone, do it here
	if (IsLeaf())
	{
		m_pBin->GetClosestTo(uMaxType, uTarget, uMaxRequired, pmapResult, bEmptyFirst, bInUse);
		return;
	}

	///snow:uDistancce的作用是按位匹配寻找分支节点
	///snow:按位匹配，寻找相应的分支结点，如果当前分支把返回的结果数较少，再从另一个子树搜索
	// otherwise, recurse in the closer-to-the-target subzone first
	int iCloser = uDistance.GetBitNumber(m_uLevel);
	m_pSubZones[iCloser]->GetClosestTo(uMaxType, uTarget, uDistance, uMaxRequired, pmapResult, bEmptyFirst, bInUse);

	// if still not enough tokens found, recurse in the other subzone too
	if (pmapResult->size() < uMaxRequired)
		m_pSubZones[1-iCloser]->GetClosestTo(uMaxType, uTarget, uDistance, uMaxRequired, pmapResult, false, bInUse);
}

void CRoutingZone::GetAllEntries(ContactList *pmapResult, bool bEmptyFirst)
{
	if (IsLeaf())
		m_pBin->GetEntries(pmapResult, bEmptyFirst);
	else
	{
		m_pSubZones[0]->GetAllEntries(pmapResult, bEmptyFirst);
		m_pSubZones[1]->GetAllEntries(pmapResult, false);///snow:不清空列表，因为存储了左子树的结点
	}
}

void CRoutingZone::TopDepth(int iDepth, ContactList *pmapResult, bool bEmptyFirst)
{
	if (IsLeaf())
		m_pBin->GetEntries(pmapResult, bEmptyFirst);
	else if (iDepth <= 0)
		RandomBin(pmapResult, bEmptyFirst);
	else
	{
		m_pSubZones[0]->TopDepth(iDepth-1, pmapResult, bEmptyFirst);
		m_pSubZones[1]->TopDepth(iDepth-1, pmapResult, false);
	}
}

void CRoutingZone::RandomBin(ContactList *pmapResult, bool bEmptyFirst)
{
	if (IsLeaf())
		m_pBin->GetEntries(pmapResult, bEmptyFirst);
	else
		m_pSubZones[rand()&1]->RandomBin(pmapResult, bEmptyFirst);
}

uint32 CRoutingZone::GetMaxDepth() const
{
	if (IsLeaf())
		return 0;
	///snow:每往下一级，+1
	return 1 + max(m_pSubZones[0]->GetMaxDepth(), m_pSubZones[1]->GetMaxDepth());
}

void CRoutingZone::Split()
{
	StopTimer();

	///snow:构造左右子树
	m_pSubZones[0] = GenSubZone(0);
	m_pSubZones[1] = GenSubZone(1);

	///snow:add by snow
	theApp.QueueTraceLogLine(TRACE_KAD_BINARY_TREE,_T("Function:%hs|Line:%i|Parent Index:%s|Current Index:%s|Current Level:%i"),__FUNCTION__,__LINE__,m_uZoneIndex.ToBinaryString(),m_pSubZones[0]->m_uZoneIndex.ToBinaryString(),m_pSubZones[0]->m_uLevel);
	///snow:add by snow
	theApp.QueueTraceLogLine(TRACE_KAD_BINARY_TREE,_T("Function:%hs|Line:%i|Parent Index:%s|Current Index:%s|Current Level:%i"),__FUNCTION__,__LINE__,m_uZoneIndex.ToBinaryString(),m_pSubZones[1]->m_uZoneIndex.ToBinaryString(),m_pSubZones[1]->m_uLevel);

	///snow:删除叶子结点
	ContactList listEntries;
	m_pBin->GetEntries(&listEntries); ///snow:将原先存储在m_pBin->m_listEntries中的对象的指针复制到listEntries中
	m_pBin->m_bDontDeleteContacts = true;  ///snow:这个参数应该是给CRouteingBin的析构函数用的
	delete m_pBin;
	m_pBin = NULL;	

	///snow:原先存储在m_listEntries中的每个ContactList对象都分配有自己的一段内存，有一个指针指向这个内存，而这个指针就存储在m_listEntries中，
	///snow:实际的ContactList对象是不存储在m_listEntries中的，也就是说m_listEntries实际是个指针集合，所以可以把这些指针拷出来，再删除掉m_pBin对象
	///snow:而不影响ContactList对象，当然，也可以在析构函数中删除掉实际的ContactList对象
	
	///snow:将原先结点中的联系人分配到左右子树中，根据的是m_uDistance中m_uLevel对应的位的值，0则左子树，1则右子树
	for (ContactList::const_iterator itContactList = listEntries.begin(); itContactList != listEntries.end(); ++itContactList)
	{
		int iSuperZone = (*itContactList)->m_uDistance.GetBitNumber(m_uLevel);
		
		///snow:add by snow
		theApp.QueueTraceLogLine(TRACE_KAD_BINARY_TREE,_T("Function:%hs|Line:%i|SubZone :%i|Contact ID:%s"),__FUNCTION__,__LINE__,iSuperZone, (*itContactList)->GetClientID().ToBinaryString());

		if (!m_pSubZones[iSuperZone]->m_pBin->AddContact(*itContactList))  ///snow:AddContact()中添加的也是指针
			delete *itContactList;
	}
}

///snow:合并两个子树
uint32 CRoutingZone::Consolidate()
{
	uint32 uMergeCount = 0;
	if( IsLeaf() )
		return uMergeCount;
	ASSERT(m_pBin==NULL);
	///snow:递归调用Consolidate()，合并子树中的非叶结点
	if( !m_pSubZones[0]->IsLeaf() )
		uMergeCount += m_pSubZones[0]->Consolidate();  
	if( !m_pSubZones[1]->IsLeaf() )
		uMergeCount += m_pSubZones[1]->Consolidate();
	///snow:左右子树都是叶子结点，而且联系人不到1半
	if( m_pSubZones[0]->IsLeaf() && m_pSubZones[1]->IsLeaf() && GetNumContacts() < K/2 )
	{
		m_pBin = new CRoutingBin();
		m_pSubZones[0]->StopTimer();
		m_pSubZones[1]->StopTimer();

		///snow:拷贝原左右子树中的联系人指针
		ContactList list0;
		ContactList list1;
		m_pSubZones[0]->m_pBin->GetEntries(&list0);
		m_pSubZones[1]->m_pBin->GetEntries(&list1);

		m_pSubZones[0]->m_pBin->m_bDontDeleteContacts = true;
		m_pSubZones[1]->m_pBin->m_bDontDeleteContacts = true;
		delete m_pSubZones[0];
		delete m_pSubZones[1];
		m_pSubZones[0] = NULL;
		m_pSubZones[1] = NULL;

		///snow:将原左右子树的联系人指针添加到新叶子结点的联系人列表中
		for (ContactList::const_iterator itContactList = list0.begin(); itContactList != list0.end(); ++itContactList){
			if (!m_pBin->AddContact(*itContactList))
				delete *itContactList;
		}
		for (ContactList::const_iterator itContactList = list1.begin(); itContactList != list1.end(); ++itContactList){
			if (!m_pBin->AddContact(*itContactList))
				delete *itContactList;
		}


		StartTimer();
		uMergeCount++;
	}
	return uMergeCount;
}

bool CRoutingZone::IsLeaf() const
{
	return (m_pBin != NULL);   ///snowL:在split()中，delete m_pBin;m_pBin = NULL;
}

CRoutingZone *CRoutingZone::GenSubZone(int iSide)
{
	CUInt128 uNewIndex(m_uZoneIndex);   ///snow:假设父结点的m_uZoneIndex为0，则新建的叶子结点，左叶子结点m_uZoneIndex=00，右叶子结点m_uZoneIndex为01，依此类推，为010，011，100，101，1000，1001，有点问题呀？不是很对，那0的那支，再怎么左移都是0
	///snow:实际0的叶子结点只有一个，PPT里有详细的分裂过程
	uNewIndex.ShiftLeft(1);
	if (iSide != 0)
		uNewIndex.Add(1);
	return new CRoutingZone(this, m_uLevel+1, uNewIndex); ///snow:this表示新的zone为本zone的子zone
}

///snow:将当前ZOne加入m_mapEvent，在CKademlia::Process()中进行更新处理。在Init()和Consolidate()中调用
void CRoutingZone::StartTimer()
{
	time_t tNow = time(NULL);
	// Start filling the tree, closest bins first.
	m_tNextBigTimer = tNow + SEC(10);
	CKademlia::AddEvent(this);
}

///snow:在Split()和Consolidate()中调用
void CRoutingZone::StopTimer()
{
	CKademlia::RemoveEvent(this);
}

bool CRoutingZone::OnBigTimer()
{
	if ( IsLeaf() && (m_uZoneIndex < KK || m_uLevel < KBASE || m_pBin->GetRemaining() >= (K*.8)))
	{
		RandomLookup();   ///snow:随机查找节点
		return true;
	}

	return false;
}

//This is used when we find a leaf and want to know what this sample looks like.
//We fall back two levels and take a sample to try to minimize any areas of the
//tree that will give very bad results.
uint32 CRoutingZone::EstimateCount()
{
	if( !IsLeaf() )
		return 0;
	if( m_uLevel < KBASE )
		return (UINT)(pow(2.0F, (int)m_uLevel)*K);
	CRoutingZone* pCurZone = m_pSuperZone->m_pSuperZone->m_pSuperZone;
	// Find out how full this part of the tree is.
	float fModify = ((float)pCurZone->GetNumContacts())/(float)(K*2);
	// First calculate users assuming the tree is full.
	// Modify count by bin size.
	// Modify count by how full the tree is.
	
	// LowIDModififier
	// Modify count by assuming 20% of the users are firewalled and can't be a contact for < 0.49b nodes
	// Modify count by actual statistics of Firewalled ratio for >= 0.49b if we are not firewalled ourself
	// Modify count by 40% for >= 0.49b if we are firewalled outself (the actual Firewalled count at this date on kad is 35-55%)
	const float fFirewalledModifyOld = 1.20F;
	float fFirewalledModifyNew = 0;
	if (CUDPFirewallTester::IsFirewalledUDP(true))
		fFirewalledModifyNew = 1.40F; // we are firewalled and get get the real statistic, assume 40% firewalled >=0.49b nodes
	else if (CKademlia::GetPrefs()->StatsGetFirewalledRatio(true) > 0) {
		fFirewalledModifyNew = 1.0F + (CKademlia::GetPrefs()->StatsGetFirewalledRatio(true)); // apply the firewalled ratio to the modify
		ASSERT( fFirewalledModifyNew > 1.0F && fFirewalledModifyNew < 1.90F );
	}
	float fNewRatio = CKademlia::GetPrefs()->StatsGetKadV8Ratio();
	float fFirewalledModifyTotal = 0;
	if (fNewRatio > 0 && fFirewalledModifyNew > 0) // weigth the old and the new modifier based on how many new contacts we have
		fFirewalledModifyTotal = (fNewRatio * fFirewalledModifyNew) + ((1 - fNewRatio) * fFirewalledModifyOld); 
	else
		fFirewalledModifyTotal = fFirewalledModifyOld;
	ASSERT( fFirewalledModifyTotal > 1.0F && fFirewalledModifyTotal < 1.90F );
	

	return (UINT)((pow(2.0F, (int)m_uLevel-2))*(float)K*fModify*fFirewalledModifyTotal);
}

void CRoutingZone::OnSmallTimer()
{
	if (!IsLeaf())
		return;

	CContact *pContact = NULL;
	time_t tNow = time(NULL);
	ContactList listEntries;
	// Remove dead entries
	m_pBin->GetEntries(&listEntries);
	for (ContactList::iterator itContactList = listEntries.begin(); itContactList != listEntries.end(); ++itContactList)
	{
		pContact = *itContactList;
		if ( pContact->GetType() == 4)
		{
			if (((pContact->m_tExpires > 0) && (pContact->m_tExpires <= tNow)))
			{
				if(!pContact->InUse())
				{
					m_pBin->RemoveContact(pContact);
					delete pContact;
				}
				continue;
			}
		}
		if(pContact->m_tExpires == 0)
			pContact->m_tExpires = tNow;
	}
	pContact = m_pBin->GetOldest();
	if( pContact != NULL )
	{
		if ( pContact->m_tExpires >= tNow || pContact->GetType() == 4)
		{
			m_pBin->PushToBottom(pContact);
			pContact = NULL;
		} 
	}
	if(pContact != NULL)
	{
		pContact->CheckingType();
		if (pContact->GetVersion() >= 6){ /*48b*/
			if (thePrefs.GetDebugClientKadUDPLevel() > 0)
				DebugSend("KADEMLIA2_HELLO_REQ", pContact->GetIPAddress(), pContact->GetUDPPort());
			CUInt128 uClientID = pContact->GetClientID();
			CKademlia::GetUDPListener()->SendMyDetails(KADEMLIA2_HELLO_REQ, pContact->GetIPAddress(), pContact->GetUDPPort(), pContact->GetVersion(), pContact->GetUDPKey(), &uClientID, false);
			if (pContact->GetVersion() >= KADEMLIA_VERSION8_49b){
				// FIXME:
				// This is a bit of a work arround for statistic values. Normally we only count values from incoming HELLO_REQs for
				// the firewalled statistics in order to get numbers from nodes which have us on their routing table,
				// however if we send a HELLO due to the timer, the remote node won't send a HELLO_REQ itself anymore (but
				// a HELLO_RES which we don't count), so count those statistics here. This isn't really accurate, but it should
				// do fair enough. Maybe improve it later for example by putting a flag into the contact and make the answer count
				CKademlia::GetPrefs()->StatsIncUDPFirewalledNodes(false);
				CKademlia::GetPrefs()->StatsIncTCPFirewalledNodes(false);
			}
		}
		else if (pContact->GetVersion() >= 2/*47a*/){
			if (thePrefs.GetDebugClientKadUDPLevel() > 0)
				DebugSend("KADEMLIA2_HELLO_REQ", pContact->GetIPAddress(), pContact->GetUDPPort());
			CKademlia::GetUDPListener()->SendMyDetails(KADEMLIA2_HELLO_REQ, pContact->GetIPAddress(), pContact->GetUDPPort(), pContact->GetVersion(), 0, NULL, false);
			ASSERT( CKadUDPKey(0) == pContact->GetUDPKey() );
		}
		else
			ASSERT( false );
	}
}

void CRoutingZone::RandomLookup()
{
	// Look-up a random client in this zone
	CUInt128 uPrefix(m_uZoneIndex);
	uPrefix.ShiftLeft(128 - m_uLevel);
	CUInt128 uRandom(uPrefix, m_uLevel);
	uRandom.Xor(uMe);
	CSearchManager::FindNode(uRandom, false);
}

uint32 CRoutingZone::GetNumContacts() const
{
	if (IsLeaf())
		return m_pBin->GetSize();
	else
		return m_pSubZones[0]->GetNumContacts() + m_pSubZones[1]->GetNumContacts();
}

void CRoutingZone::GetNumContacts(uint32& nInOutContacts, uint32& nInOutFilteredContacts, uint8 byMinVersion) const
{
	if (IsLeaf())
		m_pBin->GetNumContacts(nInOutContacts, nInOutFilteredContacts, byMinVersion);
	else{
		m_pSubZones[0]->GetNumContacts(nInOutContacts, nInOutFilteredContacts, byMinVersion);
		m_pSubZones[1]->GetNumContacts(nInOutContacts, nInOutFilteredContacts, byMinVersion);
	}
}

uint32 CRoutingZone::GetBootstrapContacts(ContactList *plistResult, uint32 uMaxRequired)
{
	ASSERT(m_pSuperZone == NULL);
	plistResult->clear();
	uint32 uRetVal = 0;
	try
	{
		ContactList top;
		TopDepth(LOG_BASE_EXPONENT, &top);
		if (top.size() > 0)
		{
			for (ContactList::const_iterator itContactList = top.begin(); itContactList != top.end(); ++itContactList)
			{
				plistResult->push_back(*itContactList);
				uRetVal++;
				if (uRetVal == uMaxRequired)
					break;
			}
		}
	}
	catch (...)
	{
		AddDebugLogLine(false, _T("Exception in CRoutingZone::getBoostStrapContacts"));
	}
	return uRetVal;
}

bool CRoutingZone::VerifyContact(const CUInt128 &uID, uint32 uIP){
	CContact* pContact = GetContact(uID);
	if (pContact == NULL){
		return false;
	}
	else if (uIP != pContact->GetIPAddress())
		return false;
	else {
		if (pContact->IsIpVerified())
			DebugLogWarning(_T("Kad: VerifyContact: Sender already verified (sender: %s)"), ipstr(ntohl(uIP)));
		else{
			pContact->SetIpVerified(true);
			theApp.emuledlg->kademliawnd->ContactRef(pContact);
		}
		return true;
	}
}

void CRoutingZone::SetAllContactsVerified(){
	if (IsLeaf())
		m_pBin->SetAllContactsVerified();
	else{
		m_pSubZones[0]->SetAllContactsVerified();
		m_pSubZones[1]->SetAllContactsVerified();
	}
}

bool CRoutingZone::IsAcceptableContact(const CContact* pToCheck) const
{
	// Check if we know a conact with the same ID or IP but notmatching IP/ID and other limitations, similar checks like when adding a node to the table except allowing duplicates
	// we use this to check KADEMLIA_RES routing answers on searches
	if (pToCheck->GetVersion() <= 1)	// No Kad1 Contacts allowed
		return false;
	CContact* pDuplicate = GetContact(pToCheck->GetClientID());
	if (pDuplicate != NULL)
	{
		if (pDuplicate->IsIpVerified() 
			&& (pDuplicate->GetIPAddress() != pToCheck->GetIPAddress() || pDuplicate->GetUDPPort() != pToCheck->GetUDPPort()))
		{
			// already existing verfied node with different IP
			return false;
		}
		else
			return true; // node exists already in our routing table, thats fine
	}
	// if the node is not yet know, check if we out IP limitations would hit
#ifdef _DEBUG
	return CRoutingBin::CheckGlobalIPLimits(pToCheck->GetIPAddress(), pToCheck->GetUDPPort(), true);
#else
	return CRoutingBin::CheckGlobalIPLimits(pToCheck->GetIPAddress(), pToCheck->GetUDPPort(), false);
#endif
}

bool CRoutingZone::HasOnlyLANNodes() const
{
	if (IsLeaf())
		return m_pBin->HasOnlyLANNodes();
	else
		return m_pSubZones[0]->HasOnlyLANNodes() && m_pSubZones[1]->HasOnlyLANNodes();
}