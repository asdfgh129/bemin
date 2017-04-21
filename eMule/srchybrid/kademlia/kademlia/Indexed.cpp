/*
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
#include "./Indexed.h"
#include "./Kademlia.h"
#include "./Entry.h"
#include "./Prefs.h"
#include "../net/KademliaUDPListener.h"
#include "../utils/MiscUtils.h"
#include "../io/BufferedFileIO.h"
#include "../io/IOException.h"
#include "../io/ByteIO.h"
#include "../../Preferences.h"
#include "../../Log.h"
#include "../utils/KadUDPKey.h"

#include "../../emule.h"  ///snow:by snow



#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

using namespace Kademlia;

void DebugSend(LPCTSTR pszMsg, uint32 uIP, uint16 uPort);

CString CIndexed::m_sKeyFileName;
CString CIndexed::m_sSourceFileName;
CString CIndexed::m_sLoadFileName;

CIndexed::CIndexed()
{
	m_mapKeyword.InitHashTable(1031);
	m_mapNotes.InitHashTable(1031);
	m_mapLoad.InitHashTable(1031);
	m_mapSources.InitHashTable(1031);
	m_sSourceFileName = thePrefs.GetMuleDirectory(EMULE_CONFIGDIR) + _T("src_index.dat");
	m_sKeyFileName = thePrefs.GetMuleDirectory(EMULE_CONFIGDIR) + _T("key_index.dat");
	m_sLoadFileName = thePrefs.GetMuleDirectory(EMULE_CONFIGDIR) + _T("load_index.dat");
	m_tLastClean = time(NULL) + (60*30);
	m_uTotalIndexSource = 0;
	m_uTotalIndexKeyword = 0;
	m_uTotalIndexNotes = 0;
	m_uTotalIndexLoad = 0;
	m_bAbortLoading = false;
	m_bDataLoaded = false;
	ReadFile();   ///snow:����һ�����̣߳���ȡ�����ļ�
}

void CIndexed::ReadFile(void)
{
	m_bAbortLoading = false;
	CLoadDataThread* pLoadDataThread = (CLoadDataThread*) AfxBeginThread(RUNTIME_CLASS(CLoadDataThread), THREAD_PRIORITY_BELOW_NORMAL,0, CREATE_SUSPENDED);
	pLoadDataThread->SetValues(this);
	pLoadDataThread->ResumeThread();
}

CIndexed::~CIndexed()
{ 
if (!m_bDataLoaded){   ///snow:������ļ��е�����û�м�����ϣ�ֱ��ɾ��������map�и�Entry�ѷ���Ĵ洢�ռ�
		// the user clicked on disconnect/close just after he started kad (on probably just before posting in the forum the emule doenst works :P )
		// while the loading thread is still busy. First tell the thread to abort its loading, afterwards wait for it to terminate
		// and then delete all loaded items without writing them to the files (as they are incomplete and unchanged)
		DebugLogWarning(_T("Kad stopping while still loading CIndexed data, waiting for abort"));
		m_bAbortLoading = true;
		CSingleLock sLock(&m_mutSync);
		sLock.Lock(); // wait
		ASSERT( m_bDataLoaded );

		// cleanup without storing
		POSITION pos1 = m_mapSources.GetStartPosition();
		while( pos1 != NULL )
		{
			CCKey key1;
			SrcHash* pCurrSrcHash;
			m_mapSources.GetNextAssoc( pos1, key1, pCurrSrcHash );
			CKadSourcePtrList* keyHashSrcMap = &pCurrSrcHash->ptrlistSource;
			POSITION pos2 = keyHashSrcMap->GetHeadPosition();
			while( pos2 != NULL )
			{
				Source* pCurrSource = keyHashSrcMap->GetNext(pos2);
				CKadEntryPtrList* srcEntryList = &pCurrSource->ptrlEntryList;
				for(POSITION pos3 = srcEntryList->GetHeadPosition(); pos3 != NULL; )
				{
					CEntry* pCurrName = srcEntryList->GetNext(pos3);
					delete pCurrName;
				}
				delete pCurrSource;
			}
			delete pCurrSrcHash;
		}

		pos1 = m_mapKeyword.GetStartPosition();
		while( pos1 != NULL )
		{
			CCKey key1;
			KeyHash* pCurrKeyHash;
			m_mapKeyword.GetNextAssoc( pos1, key1, pCurrKeyHash );
			CSourceKeyMap* keySrcKeyMap = &pCurrKeyHash->mapSource;
			POSITION pos2 = keySrcKeyMap->GetStartPosition();
			while( pos2 != NULL )
			{
				Source* pCurrSource;
				CCKey key2;
				keySrcKeyMap->GetNextAssoc( pos2, key2, pCurrSource );
				CKadEntryPtrList* srcEntryList = &pCurrSource->ptrlEntryList;
				for(POSITION pos3 = srcEntryList->GetHeadPosition(); pos3 != NULL; )
				{
					CKeyEntry* pCurrName = (CKeyEntry*)srcEntryList->GetNext(pos3);
					ASSERT( pCurrName->IsKeyEntry() );
					pCurrName->DirtyDeletePublishData();
					delete pCurrName;
				}
				delete pCurrSource;
			}
			delete pCurrKeyHash;
		}
		CKeyEntry::ResetGlobalTrackingMap();
	}
	else {  ///snow:�����Ѽ�����ϣ���map�еĸ���Ŀд�ش����ļ���
		// standart cleanup with sotring
		try
		{
			uint32 uTotalSource = 0;
			uint32 uTotalKey = 0;
			uint32 uTotalLoad = 0;

			CBufferedFileIO fileLoad;
			if(fileLoad.Open(m_sLoadFileName, CFile::modeWrite | CFile::modeCreate | CFile::typeBinary | CFile::shareDenyWrite))
			{
				setvbuf(fileLoad.m_pStream, NULL, _IOFBF, 32768);
				uint32 uVersion = 1;
				fileLoad.WriteUInt32(uVersion);
				fileLoad.WriteUInt32(time(NULL));
				fileLoad.WriteUInt32(m_mapLoad.GetCount());
				POSITION pos1 = m_mapLoad.GetStartPosition();
				while( pos1 != NULL )
				{
					Load* pLoad;
					CCKey key1;
					m_mapLoad.GetNextAssoc( pos1, key1, pLoad );
					fileLoad.WriteUInt128(pLoad->uKeyID);
					fileLoad.WriteUInt32(pLoad->uTime);
					uTotalLoad++;
					delete pLoad;
				}
				fileLoad.Close();
			}
			else
				DebugLogError(_T("Unable to store Kad file: %s"), m_sLoadFileName);

			CBufferedFileIO fileSource;
			if (fileSource.Open(m_sSourceFileName, CFile::modeWrite | CFile::modeCreate | CFile::typeBinary | CFile::shareDenyWrite))
			{
				setvbuf(fileSource.m_pStream, NULL, _IOFBF, 32768);
				uint32 uVersion = 2;
				fileSource.WriteUInt32(uVersion);
				fileSource.WriteUInt32(time(NULL)+KADEMLIAREPUBLISHTIMES);
				fileSource.WriteUInt32(m_mapSources.GetCount());
				POSITION pos1 = m_mapSources.GetStartPosition();
				while( pos1 != NULL )
				{
					CCKey key1;
					SrcHash* pCurrSrcHash;
					m_mapSources.GetNextAssoc( pos1, key1, pCurrSrcHash );
					fileSource.WriteUInt128(pCurrSrcHash->uKeyID);
					CKadSourcePtrList* keyHashSrcMap = &pCurrSrcHash->ptrlistSource;
					fileSource.WriteUInt32(keyHashSrcMap->GetCount());
					POSITION pos2 = keyHashSrcMap->GetHeadPosition();
					while( pos2 != NULL )
					{
						Source* pCurrSource = keyHashSrcMap->GetNext(pos2);
						fileSource.WriteUInt128(pCurrSource->uSourceID);
						CKadEntryPtrList* srcEntryList = &pCurrSource->ptrlEntryList;
						fileSource.WriteUInt32(srcEntryList->GetCount());
						for(POSITION pos3 = srcEntryList->GetHeadPosition(); pos3 != NULL; )
						{
							CEntry* pCurrName = srcEntryList->GetNext(pos3);
							fileSource.WriteUInt32(pCurrName->m_tLifetime);
							pCurrName->WriteTagList(&fileSource);
							delete pCurrName;
							uTotalSource++;
						}
						delete pCurrSource;
					}
					delete pCurrSrcHash;
				}
				fileSource.Close();
			}
			else
				DebugLogError(_T("Unable to store Kad file: %s"), m_sSourceFileName);

			CBufferedFileIO fileKey;
			if (fileKey.Open(m_sKeyFileName, CFile::modeWrite | CFile::modeCreate | CFile::typeBinary | CFile::shareDenyWrite))
			{
				setvbuf(fileKey.m_pStream, NULL, _IOFBF, 32768);
				uint32 uVersion = 4;
				fileKey.WriteUInt32(uVersion);
				fileKey.WriteUInt32(time(NULL)+KADEMLIAREPUBLISHTIMEK);
				fileKey.WriteUInt128(Kademlia::CKademlia::GetPrefs()->GetKadID());
				fileKey.WriteUInt32(m_mapKeyword.GetCount());
				POSITION pos1 = m_mapKeyword.GetStartPosition();
				while( pos1 != NULL )
				{
					CCKey key1;
					KeyHash* pCurrKeyHash;
					m_mapKeyword.GetNextAssoc( pos1, key1, pCurrKeyHash );
					fileKey.WriteUInt128(pCurrKeyHash->uKeyID);
					CSourceKeyMap* keySrcKeyMap = &pCurrKeyHash->mapSource;
					fileKey.WriteUInt32(keySrcKeyMap->GetCount());
					POSITION pos2 = keySrcKeyMap->GetStartPosition();
					while( pos2 != NULL )
					{
						Source* pCurrSource;
						CCKey key2;
						keySrcKeyMap->GetNextAssoc( pos2, key2, pCurrSource );
						fileKey.WriteUInt128(pCurrSource->uSourceID);
						CKadEntryPtrList* srcEntryList = &pCurrSource->ptrlEntryList;
						fileKey.WriteUInt32(srcEntryList->GetCount());
						for(POSITION pos3 = srcEntryList->GetHeadPosition(); pos3 != NULL; )
						{
							CKeyEntry* pCurrName = (CKeyEntry*)srcEntryList->GetNext(pos3);
							ASSERT( pCurrName->IsKeyEntry() );
							fileKey.WriteUInt32(pCurrName->m_tLifetime);
							pCurrName->WritePublishTrackingDataToFile(&fileKey);
							pCurrName->WriteTagList(&fileKey);
							pCurrName->DirtyDeletePublishData();
							delete pCurrName;
							uTotalKey++;
						}
						delete pCurrSource;
					}
					delete pCurrKeyHash;
				}
				CKeyEntry::ResetGlobalTrackingMap();
				fileKey.Close();
			}
			else
				DebugLogError(_T("Unable to store Kad file: %s"), m_sKeyFileName);

			AddDebugLogLine( false, _T("Wrote %u source, %u keyword, and %u load entries"), uTotalSource, uTotalKey, uTotalLoad);


		}
		catch ( CIOException *ioe )
		{
			AddDebugLogLine( false, _T("Exception in CIndexed::~CIndexed (IO error(%i))"), ioe->m_iCause);
			ioe->Delete();
		}
		catch (...)
		{
			AddDebugLogLine(false, _T("Exception in CIndexed::~CIndexed"));
		}
	}

	// leftover cleanup (same for both variants)
	POSITION pos1 = m_mapNotes.GetStartPosition();
	while( pos1 != NULL )
	{
		CCKey key1;
		SrcHash* pCurrNoteHash;
		m_mapNotes.GetNextAssoc( pos1, key1, pCurrNoteHash );
		CKadSourcePtrList* keyHashNoteMap = &pCurrNoteHash->ptrlistSource;
		POSITION pos2 = keyHashNoteMap->GetHeadPosition();
		while( pos2 != NULL )
		{
			Source* pCurrNote = keyHashNoteMap->GetNext(pos2);
			CKadEntryPtrList* noteEntryList = &pCurrNote->ptrlEntryList;
			for(POSITION pos3 = noteEntryList->GetHeadPosition(); pos3 != NULL; )
			{
				delete noteEntryList->GetNext(pos3);
			}
			delete pCurrNote;
		}
		delete pCurrNoteHash;
	}
}

void CIndexed::Clean(void)
{

	try
	{
		if( m_tLastClean > time(NULL) )
			return;

		uint32 uRemovedKey = 0;
		uint32 uRemovedSource = 0;
		uint32 uTotalSource = 0;
		uint32 uTotalKey = 0;
		time_t tNow = time(NULL);

		{
			POSITION pos1 = m_mapKeyword.GetStartPosition();
			while( pos1 != NULL )
			{
				CCKey key1;
				KeyHash* pCurrKeyHash;
				m_mapKeyword.GetNextAssoc( pos1, key1, pCurrKeyHash );
				POSITION pos2 = pCurrKeyHash->mapSource.GetStartPosition();
				while( pos2 != NULL )
				{
					CCKey key2;
					Source* pCurrSource;
					pCurrKeyHash->mapSource.GetNextAssoc( pos2, key2, pCurrSource );
					for(POSITION pos3 = pCurrSource->ptrlEntryList.GetHeadPosition(); pos3 != NULL; )
					{
						POSITION pos4 = pos3;
						CKeyEntry* pCurrName = (CKeyEntry*)pCurrSource->ptrlEntryList.GetNext(pos3);
						ASSERT( pCurrName->IsKeyEntry() );
						uTotalKey++;
						if( !pCurrName->m_bSource && pCurrName->m_tLifetime < tNow)
						{
							uRemovedKey++;
							pCurrSource->ptrlEntryList.RemoveAt(pos4);
							delete pCurrName;
						}
						else if (pCurrName->m_bSource)
							ASSERT( false );
						else
							pCurrName->CleanUpTrackedPublishers(); // intern cleanup
					}
					if( pCurrSource->ptrlEntryList.IsEmpty())
					{
						pCurrKeyHash->mapSource.RemoveKey(key2);
						delete pCurrSource;
					}
				}
				if( pCurrKeyHash->mapSource.IsEmpty())
				{
					m_mapKeyword.RemoveKey(key1);
					delete pCurrKeyHash;
				}
			}
		}
		{
			POSITION pos1 = m_mapSources.GetStartPosition();
			while( pos1 != NULL )
			{
				CCKey key1;
				SrcHash* pCurrSrcHash;
				m_mapSources.GetNextAssoc( pos1, key1, pCurrSrcHash );
				for(POSITION pos2 = pCurrSrcHash->ptrlistSource.GetHeadPosition(); pos2 != NULL; )
				{
					POSITION pos3 = pos2;
					Source* pCurrSource = pCurrSrcHash->ptrlistSource.GetNext(pos2);
					for(POSITION pos4 = pCurrSource->ptrlEntryList.GetHeadPosition(); pos4 != NULL; )
					{
						POSITION pos5 = pos4;
						CEntry* pCurrName = pCurrSource->ptrlEntryList.GetNext(pos4);
						uTotalSource++;
						if( pCurrName->m_tLifetime < tNow)
						{
							uRemovedSource++;
							pCurrSource->ptrlEntryList.RemoveAt(pos5);
							delete pCurrName;
						}
					}
					if( pCurrSource->ptrlEntryList.IsEmpty())
					{
						pCurrSrcHash->ptrlistSource.RemoveAt(pos3);
						delete pCurrSource;
					}
				}
				if( pCurrSrcHash->ptrlistSource.IsEmpty())
				{
					m_mapSources.RemoveKey(key1);
					delete pCurrSrcHash;
				}
			}
		}

		m_uTotalIndexSource = uTotalSource;
		m_uTotalIndexKeyword = uTotalKey;
		AddDebugLogLine( false, _T("Removed %u keyword out of %u and %u source out of %u"), uRemovedKey, uTotalKey, uRemovedSource, uTotalSource);
		m_tLastClean = time(NULL) + MIN2S(30);
	}
	catch(...)
	{
		AddDebugLogLine(false, _T("Exception in CIndexed::clean"));
		ASSERT(0);
	}
}

///snow:��һ������Ǵ�m_mapKeyword�ж�ȡ����һ���Ǵ�Kad���н�����KADEMLIA2_PUBLISH_KEY_REQ�룬��CKademliaUDPListener::Process_KADEMLIA2_PUBLISH_KEY_REQ()�д���
bool CIndexed::AddKeyword(const CUInt128& uKeyID, const CUInt128& uSourceID, Kademlia::CKeyEntry* pEntry, uint8& uLoad, bool bIgnoreThreadLock)
{
	// do not access any data while the loading thread is busy;
	// bIgnoreThreadLock should be only used by CLoadDataThread itself
	if (!bIgnoreThreadLock && !m_bDataLoaded) {
		DEBUG_ONLY( DebugLogWarning(_T("CIndexed Memberfunction call failed because the dataloading still in progress")) );
		return false;
	}

	if( !pEntry )
		return false;

	if (!pEntry->IsKeyEntry()){
		ASSERT( false );
		return false;
	}

	if( m_uTotalIndexKeyword > KADEMLIAMAXENTRIES )  ///snow:�����洢�Ĺؼ��ֳ���60000
	{
		uLoad = 100;
		return false;
	}

	if( pEntry->m_uSize == 0 || pEntry->GetCommonFileName().IsEmpty() || pEntry->GetTagCount() == 0 || pEntry->m_tLifetime < time(NULL))
		return false;

	KeyHash* pCurrKeyHash;
	if(!m_mapKeyword.Lookup(CCKey(uKeyID.GetData()), pCurrKeyHash))   ///snow:map��δ������ͬkey����Ŀ
	{
		Source* pCurrSource = new Source;
		pCurrSource->uSourceID.SetValue(uSourceID);
		pEntry->MergeIPsAndFilenames(NULL); //IpTracking init
		pCurrSource->ptrlEntryList.AddHead(pEntry);
		pCurrKeyHash = new KeyHash;
		pCurrKeyHash->uKeyID.SetValue(uKeyID);
		pCurrKeyHash->mapSource.SetAt(CCKey(pCurrSource->uSourceID.GetData()), pCurrSource);
		m_mapKeyword.SetAt(CCKey(pCurrKeyHash->uKeyID.GetData()), pCurrKeyHash);
		uLoad = 1;
		m_uTotalIndexKeyword++;
		return true;
	}
	else   ///snow:�Ѵ���ͬһID��Key��Ŀ
	{
		uint32 uIndexTotal = pCurrKeyHash->mapSource.GetCount();
		if ( uIndexTotal > KADEMLIAMAXINDEX )   ///snow:��ǰ�ؼ����´洢���ļ�Դ����50000
		{
			uLoad = 100;
			//Too many entries for this Keyword..
			return false;
		}
		Source* pCurrSource;
		if(pCurrKeyHash->mapSource.Lookup(CCKey(uSourceID.GetData()), pCurrSource))  ///snow:key���Ƿ����ͬһSourceID����Ŀ
		{
			if (pCurrSource->ptrlEntryList.GetCount() > 0)
			{
				if( uIndexTotal > KADEMLIAMAXINDEX - 5000 )   ///snow:����45000
				{
					uLoad = 100;
					//We are in a hot node.. If we continued to update all the publishes
					//while this index is full, popular files will be the only thing you index.
					return false;
				}
				// also check for size match
				CKeyEntry* pOldEntry = NULL;
				for (POSITION pos = pCurrSource->ptrlEntryList.GetHeadPosition(); pos != NULL; pCurrSource->ptrlEntryList.GetNext(pos)){
					CKeyEntry* pCurEntry = (CKeyEntry*)pCurrSource->ptrlEntryList.GetAt(pos);
					ASSERT( pCurEntry->IsKeyEntry() );
					if (pCurEntry->m_uSize == pEntry->m_uSize){
						pOldEntry = pCurEntry;
						pCurrSource->ptrlEntryList.RemoveAt(pos);
						break;
					}
				}
				pEntry->MergeIPsAndFilenames(pOldEntry); // pOldEntry can be NULL, thats ok and we still need todo this call in this case
				if (pOldEntry == NULL){
					m_uTotalIndexKeyword++;
					DebugLogWarning(_T("Kad: Indexing: Keywords: Multiple sizes published for file %s"), pEntry->m_uSourceID.ToHexString());
				}
				DEBUG_ONLY( AddDebugLogLine(DLP_VERYLOW, false, _T("Indexed file %s"), pEntry->m_uSourceID.ToHexString()) );
				delete pOldEntry;
				pOldEntry = NULL;
			}
			else{
				m_uTotalIndexKeyword++;
				pEntry->MergeIPsAndFilenames(NULL); //IpTracking init
			}
			uLoad = (uint8)((uIndexTotal*100)/KADEMLIAMAXINDEX);
			pCurrSource->ptrlEntryList.AddHead(pEntry);
			return true;
		}
		else   ///snow:��������SourceID��ͬ����Ŀ
		{
			pCurrSource = new Source;
			pCurrSource->uSourceID.SetValue(uSourceID);
			pEntry->MergeIPsAndFilenames(NULL); //IpTracking init
			pCurrSource->ptrlEntryList.AddHead(pEntry);
			pCurrKeyHash->mapSource.SetAt(CCKey(pCurrSource->uSourceID.GetData()), pCurrSource);
			m_uTotalIndexKeyword++;
			uLoad = (uint8)((uIndexTotal*100)/KADEMLIAMAXINDEX);
			return true;
		}
	}
}

bool CIndexed::AddSources(const CUInt128& uKeyID, const CUInt128& uSourceID, Kademlia::CEntry* pEntry, uint8& uLoad, bool bIgnoreThreadLock)
{
	// do not access any data while the loading thread is busy;
	// bIgnoreThreadLock should be only used by CLoadDataThread itself
	if (!bIgnoreThreadLock && !m_bDataLoaded) {
		DEBUG_ONLY( DebugLogWarning(_T("CIndexed Memberfunction call failed because the dataloading still in progress")) );
		return false;
	}

	if( !pEntry )
		return false;
	if( pEntry->m_uIP == 0 || pEntry->m_uTCPPort == 0 || pEntry->m_uUDPPort == 0 || pEntry->GetTagCount() == 0 || pEntry->m_tLifetime < time(NULL))
		return false;

	SrcHash* pCurrSrcHash;
	if(!m_mapSources.Lookup(CCKey(uKeyID.GetData()), pCurrSrcHash))   ///snow:������ͬID��Source��Ŀ
	{
		Source* pCurrSource = new Source;
		pCurrSource->uSourceID.SetValue(uSourceID);
		pCurrSource->ptrlEntryList.AddHead(pEntry);
		pCurrSrcHash = new SrcHash;
		pCurrSrcHash->uKeyID.SetValue(uKeyID);
		pCurrSrcHash->ptrlistSource.AddHead(pCurrSource);
		m_mapSources.SetAt(CCKey(pCurrSrcHash->uKeyID.GetData()), pCurrSrcHash);
		m_uTotalIndexSource++;
		uLoad = 1;      ///snow:���ļ���uLoad =1
		return true;
	}
	else   ///snow:�Ѵ���ͬID��Source��Ŀ
	{
		uint32 uSize = pCurrSrcHash->ptrlistSource.GetSize();
		for(POSITION pos1 = pCurrSrcHash->ptrlistSource.GetHeadPosition(); pos1 != NULL; )
		{
			Source* pCurrSource = pCurrSrcHash->ptrlistSource.GetNext(pos1);
			if( pCurrSource->ptrlEntryList.GetSize() )   ///snow:ptrlEntryList�е�Entry��Ŀ��Ϊ0
			{
				CEntry* pCurrEntry = pCurrSource->ptrlEntryList.GetHead();
				ASSERT(pCurrEntry!=NULL);
				if( pCurrEntry->m_uIP == pEntry->m_uIP && ( pCurrEntry->m_uTCPPort == pEntry->m_uTCPPort || pCurrEntry->m_uUDPPort == pEntry->m_uUDPPort ))   ///snow:IP��Port��UDPPort��һ��
				{
					delete pCurrSource->ptrlEntryList.RemoveHead();
					pCurrSource->ptrlEntryList.AddHead(pEntry);
					uLoad = (uint8)((uSize*100)/KADEMLIAMAXSOUCEPERFILE);   ///snow:ÿ�ļ����1000��Դ��uLoad=���ļ�Դ��*0.1
					return true;
				}
			}
			else
			{
				//This should never happen!
				pCurrSource->ptrlEntryList.AddHead(pEntry);
				ASSERT(0);
				uLoad = (uint8)((uSize*100)/KADEMLIAMAXSOUCEPERFILE);
				m_uTotalIndexSource++;
				return true;
			}
		}

		///snow:IP��Port��UDPPort����һ��
		if( uSize > KADEMLIAMAXSOUCEPERFILE )
		{
			Source* pCurrSource = pCurrSrcHash->ptrlistSource.RemoveTail();
			delete pCurrSource->ptrlEntryList.RemoveTail();
			pCurrSource->uSourceID.SetValue(uSourceID);
			pCurrSource->ptrlEntryList.AddHead(pEntry);
			pCurrSrcHash->ptrlistSource.AddHead(pCurrSource);
			uLoad = 100;   ///snow:ÿ�ļ����1000��Դ�����ļ�Դ��>1000��uLoad=100�����ֵ��
			return true;
		}
		else
		{
			Source* pCurrSource = new Source;
			pCurrSource->uSourceID.SetValue(uSourceID);
			pCurrSource->ptrlEntryList.AddHead(pEntry);
			pCurrSrcHash->ptrlistSource.AddHead(pCurrSource);
			m_uTotalIndexSource++;
			uLoad = (uint8)((uSize*100)/KADEMLIAMAXSOUCEPERFILE);
			return true;
		}
	}
}

bool CIndexed::AddNotes(const CUInt128& uKeyID, const CUInt128& uSourceID, Kademlia::CEntry* pEntry, uint8& uLoad, bool bIgnoreThreadLock)
{
	// do not access any data while the loading thread is busy;
	// bIgnoreThreadLock should be only used by CLoadDataThread itself
	if (!bIgnoreThreadLock && !m_bDataLoaded) {
		DEBUG_ONLY( DebugLogWarning(_T("CIndexed Memberfunction call failed because the dataloading still in progress")) );
		return false;
	}

	if( !pEntry )
		return false;
	if( pEntry->m_uIP == 0 || pEntry->GetTagCount() == 0 )
		return false;

	SrcHash* pCurrNoteHash;
	if(!m_mapNotes.Lookup(CCKey(uKeyID.GetData()), pCurrNoteHash))
	{
		Source* pCurrNote = new Source;
		pCurrNote->uSourceID.SetValue(uSourceID);
		pCurrNote->ptrlEntryList.AddHead(pEntry);
		SrcHash* pCurrNoteHash = new SrcHash;
		pCurrNoteHash->uKeyID.SetValue(uKeyID);
		pCurrNoteHash->ptrlistSource.AddHead(pCurrNote);
		m_mapNotes.SetAt(CCKey(pCurrNoteHash->uKeyID.GetData()), pCurrNoteHash);
		uLoad = 1;
		m_uTotalIndexNotes++;
		return true;
	}
	else
	{
		uint32 uSize = pCurrNoteHash->ptrlistSource.GetSize();
		for(POSITION pos1 = pCurrNoteHash->ptrlistSource.GetHeadPosition(); pos1 != NULL; )
		{
			Source* pCurrNote = pCurrNoteHash->ptrlistSource.GetNext(pos1);
			if( pCurrNote->ptrlEntryList.GetSize() )
			{
				CEntry* pCurrEntry = pCurrNote->ptrlEntryList.GetHead();
				if(pCurrEntry->m_uIP == pEntry->m_uIP || pCurrEntry->m_uSourceID == pEntry->m_uSourceID)
				{
					delete pCurrNote->ptrlEntryList.RemoveHead();
					pCurrNote->ptrlEntryList.AddHead(pEntry);
					uLoad = (uint8)((uSize*100)/KADEMLIAMAXNOTESPERFILE);
					return true;
				}
			}
			else
			{
				//This should never happen!
				pCurrNote->ptrlEntryList.AddHead(pEntry);
				ASSERT(0);
				uLoad = (uint8)((uSize*100)/KADEMLIAMAXNOTESPERFILE);
				m_uTotalIndexKeyword++;
				return true;
			}
		}
		if( uSize > KADEMLIAMAXNOTESPERFILE )
		{
			Source* pCurrNote = pCurrNoteHash->ptrlistSource.RemoveTail();
			delete pCurrNote->ptrlEntryList.RemoveTail();
			pCurrNote->uSourceID.SetValue(uSourceID);
			pCurrNote->ptrlEntryList.AddHead(pEntry);
			pCurrNoteHash->ptrlistSource.AddHead(pCurrNote);
			uLoad = 100;
			return true;
		}
		else
		{
			Source* pCurrNote = new Source;
			pCurrNote->uSourceID.SetValue(uSourceID);
			pCurrNote->ptrlEntryList.AddHead(pEntry);
			pCurrNoteHash->ptrlistSource.AddHead(pCurrNote);
			uLoad = (uint8)((uSize*100)/KADEMLIAMAXNOTESPERFILE);
			m_uTotalIndexKeyword++;
			return true;
		}
	}
}

///snow:���Load�ڵ㵽m_mapLoad�У���CLoadDataThread::Run()�е��ã�д��load_index.dat�еĴ洢�ڵ���Ϣ��������CSearch::~CSearch()�е�SearchType==CSearch::STOREKEYWORDʱд��Ŀ��ڵ���Ϣ��
bool CIndexed::AddLoad(const CUInt128& uKeyID, uint32 uTime, bool bIgnoreThreadLock)
{
	// do not access any data while the loading thread is busy;
	// bIgnoreThreadLock should be only used by CLoadDataThread itself
	if (!bIgnoreThreadLock && !m_bDataLoaded) {
		DEBUG_ONLY( DebugLogWarning(_T("CIndexed Memberfunction call failed because the dataloading still in progress")) );
		return false;
	}

	//This is needed for when you restart the client.
	if((uint32)time(NULL)>uTime)   ///snow:uTime��Ҫ���ڵ�ǰʱ�䣿�ǵģ���Ϊ���ʱ���ʾ���������´���ʹ������ڵ��ʱ�䣬���Ա�����ڵ�ǰʱ�䣬������ǣ����������
		return false;

	Load* pLoad;
	if(m_mapLoad.Lookup(CCKey(uKeyID.GetData()), pLoad))
		return false;

	pLoad = new Load();
	pLoad->uKeyID.SetValue(uKeyID);
	pLoad->uTime = uTime;
	m_mapLoad.SetAt(CCKey(pLoad->uKeyID.GetData()), pLoad);
	m_uTotalIndexLoad++;
	return true;
}

///snow: CKademliaUDPListener::Process_KADEMLIA2_SEARCH_KEY_REQ()�е���
void CIndexed::SendValidKeywordResult(const CUInt128& uKeyID, const SSearchTerm* pSearchTerms, uint32 uIP, uint16 uPort, bool bOldClient, uint16 uStartPosition, CKadUDPKey senderUDPKey)
{
	// do not access any data while the loading thread is busy;
	if (!m_bDataLoaded) {
		DEBUG_ONLY( DebugLogWarning(_T("CIndexed Memberfunction call failed because the dataloading still in progress")) );
		return;
	}

	///snow:�ȴ�m_mapKeyword�в����Ƿ������uKeyIDֵ��ͬ����Ŀ������ҵ����������Key��Ӧ��mapSource�����ÿ��mapSource��Ŀ���ٱ���mapSource�еĸ���Entry����Entry�������Ƿ������������������ʽ��SourceID�����û�ҵ���ִ��clean()��
	KeyHash* pCurrKeyHash;
	if(m_mapKeyword.Lookup(CCKey(uKeyID.GetData()), pCurrKeyHash))  ///snow:���ڶ�Ӧ��Key��Ŀ
	{
		byte byPacket[1024*5];   ///snow:5K
		byte bySmallBuffer[2048];///snow:2K

		CByteIO byIO(byPacket,sizeof(byPacket));///snow:5K
		byIO.WriteByte(OP_KADEMLIAHEADER);   ///snow:Э��
		byIO.WriteByte(KADEMLIA2_SEARCH_RES);  ///snow:ָ��
		byIO.WriteUInt128(Kademlia::CKademlia::GetPrefs()->GetKadID());   ///snow:����kadid
		byIO.WriteUInt128(uKeyID);   ///snow:keyid
		
		byte* pbyCountPos = byPacket + byIO.GetUsed();
		ASSERT( byPacket+18+16 == pbyCountPos || byPacket+18 == pbyCountPos);
		byIO.WriteUInt16(0);

		const uint16 uMaxResults = 300;
		int iCount = 0-uStartPosition;
		int iUnsentCount = 0;
		CByteIO byIOTmp(bySmallBuffer, sizeof(bySmallBuffer));///snow:2K
		// we do 2 loops: In the first one we ignore all results which have a trustvalue below 1
		// in the second one we then also consider those. That way we make sure our 300 max results are not full
		// of spam entries. We could also sort by trustvalue, but we would risk to only send popular files this way
		// on very hot keywords
		bool bOnlyTrusted = true;
		uint32 dbgResultsTrusted = 0;
		uint32 dbgResultsUntrusted = 0;
		do{
			POSITION pos1 = pCurrKeyHash->mapSource.GetStartPosition();
			while( pos1 != NULL )
			{
				CCKey key1;
				Source* pCurrSource;
				pCurrKeyHash->mapSource.GetNextAssoc( pos1, key1, pCurrSource );
				for(POSITION pos2 = pCurrSource->ptrlEntryList.GetHeadPosition(); pos2 != NULL; )
				{
					CKeyEntry* pCurrName = (CKeyEntry*)pCurrSource->ptrlEntryList.GetNext(pos2);
					ASSERT( pCurrName->IsKeyEntry() );
					///snow:������㣬bOnlyTrusted��TrustValue<1��ͬʱΪ���ͬʱΪ�٣���bOnlyTrusted != (TrustValue<1)
					///snow:��һ��ѭ������TrustValue<1�Ľ�������ѭ���������������Ľ����С��uMaxResults��300��������bOnlyTrusted = false;��ʼ��һ��ѭ��
					if ( (bOnlyTrusted ^ (pCurrName->GetTrustValue() < 1.0f)) && (!pSearchTerms || pCurrName->StartSearchTermsMatch(pSearchTerms)) )///snow:���ڷ��������ؼ��������Ŀ
					{
						if( iCount < 0 )   ///snow:�������ʲô���أ�������uStartPosition�й�
							iCount++;
						else if( (uint16)iCount < uMaxResults )
						{
							if((!bOldClient || pCurrName->m_uSize <= OLD_MAX_EMULE_FILE_SIZE))
							{
								iCount++;
								if (bOnlyTrusted)
									dbgResultsTrusted++;
								else
									dbgResultsUntrusted++;
								byIOTmp.WriteUInt128(pCurrName->m_uSourceID);
								pCurrName->WriteTagListWithPublishInfo(&byIOTmp); ///snow:д��TagList
								
								if( byIO.GetUsed() + byIOTmp.GetUsed() > UDP_KAD_MAXFRAGMENT && iUnsentCount > 0)   ///snow:byIO��byIOTmp�����ݼ�����������1420���ֽڣ����֡���ȣ�������SendPacket()����byPacket��Ϣ��
								{
									uint32 uLen = sizeof(byPacket)-byIO.GetAvailable();
									PokeUInt16(pbyCountPos, (uint16)iUnsentCount);
									CKademlia::GetUDPListener()->SendPacket(byPacket, uLen, uIP, uPort, senderUDPKey, NULL);
									///snow:��һ��packet�Ѿ����ͣ�׼����һ��packet
									byIO.Reset();
									byIO.WriteByte(OP_KADEMLIAHEADER);
									if (thePrefs.GetDebugClientKadUDPLevel() > 0)
										DebugSend("KADEMLIA2_SEARCH_RES", uIP, uPort);
									byIO.WriteByte(KADEMLIA2_SEARCH_RES);
									byIO.WriteUInt128(Kademlia::CKademlia::GetPrefs()->GetKadID());
                                    byIO.WriteUInt128(uKeyID);     
									byIO.WriteUInt16(0);
									DEBUG_ONLY(DebugLog(_T("Sent %u keyword search results in one packet to avoid fragmentation"), iUnsentCount)); 
									iUnsentCount = 0;   ///snow:packet��ȫ������
								}
								ASSERT( byIO.GetUsed() + byIOTmp.GetUsed() <= UDP_KAD_MAXFRAGMENT );
								byIO.WriteArray(bySmallBuffer, byIOTmp.GetUsed());   ///snow:byIO��byIOTmp�����ݼ�����û����1420���ֽڣ����֡���ȣ�����byIOTmpд��byIO
								byIOTmp.Reset();
								iUnsentCount++;  ///snow:��ǰbyPacketû�з��ͣ�����ִ��forѭ����д����һSource��Ŀ
							}
						}
						else
						{
							pos1 = NULL;
							break;
						}
					}///snow:end fi(bOnlyTrusted....)
				}///snow end of for
			}///snow:end while(pos1!=NULL)
			if (bOnlyTrusted && iCount < (int)uMaxResults)  ///snow:���������δ�ﵽ�������
				bOnlyTrusted = false;
			else
				break;
		} while (!bOnlyTrusted);

		// LOGTODO: Remove Log
		//DebugLog(_T("Kad Keyword search Result Request: Send %u trusted and %u untrusted results"), dbgResultsTrusted, dbgResultsUntrusted);

		if(iUnsentCount > 0)   ///��δ���͵�packet�����һ�������ֽ�����δ�ﵽ���֡�ֽ��������Ѿ�û�����������
		{
			uint32 uLen = sizeof(byPacket)-byIO.GetAvailable();
			PokeUInt16(pbyCountPos, (uint16)iUnsentCount);
			if(thePrefs.GetDebugClientKadUDPLevel() > 0)
			{
				DebugSend("KADEMLIA2_SEARCH_RES", uIP, uPort);
			}
			CKademlia::GetUDPListener()->SendPacket(byPacket, uLen, uIP, uPort, senderUDPKey, NULL);
			DEBUG_ONLY(DebugLog(_T("Sent %u keyword search results in last packet to avoid fragmentation"), iUnsentCount));
		}
		else if (iCount > 0)
			ASSERT( false );
	}
	Clean();
}

void CIndexed::SendValidSourceResult(const CUInt128& uKeyID, uint32 uIP, uint16 uPort, uint16 uStartPosition, uint64 uFileSize, CKadUDPKey senderUDPKey)
{
	// do not access any data while the loading thread is busy;
	if (!m_bDataLoaded) {
		DEBUG_ONLY( DebugLogWarning(_T("CIndexed Memberfunction call failed because the dataloading still in progress")) );
		return;
	}

	SrcHash* pCurrSrcHash;
	if(m_mapSources.Lookup(CCKey(uKeyID.GetData()), pCurrSrcHash))
	{
		byte byPacket[1024*5];
		byte bySmallBuffer[2048];
		CByteIO byIO(byPacket,sizeof(byPacket));
		byIO.WriteByte(OP_KADEMLIAHEADER);
		byIO.WriteByte(KADEMLIA2_SEARCH_RES);
		byIO.WriteUInt128(Kademlia::CKademlia::GetPrefs()->GetKadID());

		byIO.WriteUInt128(uKeyID);
		byte* pbyCountPos = byPacket + byIO.GetUsed();
		ASSERT( byPacket+18+16 == pbyCountPos || byPacket+18 == pbyCountPos);
		byIO.WriteUInt16(0);
		
		int iUnsentCount = 0;
		CByteIO byIOTmp(bySmallBuffer, sizeof(bySmallBuffer));

		uint16 uMaxResults = 300;
		int iCount = 0-uStartPosition;
		for(POSITION pos1 = pCurrSrcHash->ptrlistSource.GetHeadPosition(); pos1 != NULL; )
		{
			Source* pCurrSource = pCurrSrcHash->ptrlistSource.GetNext(pos1);
			if( pCurrSource->ptrlEntryList.GetSize() )
			{
				CEntry* pCurrName = pCurrSource->ptrlEntryList.GetHead();
				if( iCount < 0 )
					iCount++;
				else if( (uint16)iCount < uMaxResults )
				{
					if( !uFileSize || !pCurrName->m_uSize || pCurrName->m_uSize == uFileSize )
					{
						byIOTmp.WriteUInt128(pCurrName->m_uSourceID);
						pCurrName->WriteTagList(&byIOTmp);
						iCount++;
						if( byIO.GetUsed() + byIOTmp.GetUsed() > UDP_KAD_MAXFRAGMENT && iUnsentCount > 0)
						{
							uint32 uLen = sizeof(byPacket)-byIO.GetAvailable();
							PokeUInt16(pbyCountPos, (uint16)iUnsentCount);
							///snow:һ����¼һ��packet
							CKademlia::GetUDPListener()->SendPacket(byPacket, uLen, uIP, uPort, senderUDPKey, NULL);
							byIO.Reset();
							byIO.WriteByte(OP_KADEMLIAHEADER);
							if (thePrefs.GetDebugClientKadUDPLevel() > 0)
								DebugSend("KADEMLIA2_SEARCH_RES", uIP, uPort);
							byIO.WriteByte(KADEMLIA2_SEARCH_RES);
							byIO.WriteUInt128(Kademlia::CKademlia::GetPrefs()->GetKadID());
							byIO.WriteUInt128(uKeyID);
							byIO.WriteUInt16(0);
							//DEBUG_ONLY(DebugLog(_T("Sent %u source search results in one packet to avoid fragmentation"), iUnsentCount)); 
							iUnsentCount = 0;
						}
						ASSERT( byIO.GetUsed() + byIOTmp.GetUsed() <= UDP_KAD_MAXFRAGMENT );
						byIO.WriteArray(bySmallBuffer, byIOTmp.GetUsed());
						byIOTmp.Reset();
						iUnsentCount++;
					}
				}
				else
				{
					break;
				}
			}
		}

		if(iUnsentCount > 0)
		{
			uint32 uLen = sizeof(byPacket)-byIO.GetAvailable();
			PokeUInt16(pbyCountPos, (uint16)iUnsentCount);
			if(thePrefs.GetDebugClientKadUDPLevel() > 0)
			{
				DebugSend("KADEMLIA2_SEARCH_RES", uIP, uPort);
			}
			CKademlia::GetUDPListener()->SendPacket(byPacket, uLen, uIP, uPort, senderUDPKey, NULL);
			//DEBUG_ONLY(DebugLog(_T("Sent %u source search results in last packet to avoid fragmentation"), iUnsentCount));
		}
		else if (iCount > 0)
			ASSERT( false );
	}
	Clean();
}

void CIndexed::SendValidNoteResult(const CUInt128& uKeyID, uint32 uIP, uint16 uPort, uint64 uFileSize, CKadUDPKey senderUDPKey)
{
	// do not access any data while the loading thread is busy;
	if (!m_bDataLoaded) {
		DEBUG_ONLY( DebugLogWarning(_T("CIndexed Memberfunction call failed because the dataloading still in progress")) );
		return;
	}

	try
	{
		SrcHash* pCurrNoteHash;
		if(m_mapNotes.Lookup(CCKey(uKeyID.GetData()), pCurrNoteHash))
		{
			byte byPacket[1024*5];
			byte bySmallBuffer[2048];
			CByteIO byIO(byPacket,sizeof(byPacket));
			byIO.WriteByte(OP_KADEMLIAHEADER);
			byIO.WriteByte(KADEMLIA2_SEARCH_RES);
			byIO.WriteUInt128(Kademlia::CKademlia::GetPrefs()->GetKadID());
			byIO.WriteUInt128(uKeyID);

			byte* pbyCountPos = byPacket + byIO.GetUsed();
			ASSERT( byPacket+18+16 == pbyCountPos || byPacket+18 == pbyCountPos);
			byIO.WriteUInt16(0);

			int iUnsentCount = 0;
			CByteIO byIOTmp(bySmallBuffer, sizeof(bySmallBuffer));
			uint16 uMaxResults = 150;
			uint16 uCount = 0;
			for(POSITION pos1 = pCurrNoteHash->ptrlistSource.GetHeadPosition(); pos1 != NULL; )
			{
				Source* pCurrNote = pCurrNoteHash->ptrlistSource.GetNext(pos1);
				if( pCurrNote->ptrlEntryList.GetSize() )
				{
					CEntry* pCurrName = pCurrNote->ptrlEntryList.GetHead();
					if( uCount < uMaxResults )
					{
						if( !uFileSize || !pCurrName->m_uSize || uFileSize == pCurrName->m_uSize )
						{
							byIOTmp.WriteUInt128(pCurrName->m_uSourceID);
							pCurrName->WriteTagList(&byIOTmp);
							uCount++;
							if( byIO.GetUsed() + byIOTmp.GetUsed() > UDP_KAD_MAXFRAGMENT && iUnsentCount > 0)
							{
								uint32 uLen = sizeof(byPacket)-byIO.GetAvailable();
								PokeUInt16(pbyCountPos, (uint16)iUnsentCount);
								CKademlia::GetUDPListener()->SendPacket(byPacket, uLen, uIP, uPort, senderUDPKey, NULL);
								byIO.Reset();
								byIO.WriteByte(OP_KADEMLIAHEADER);
								if (thePrefs.GetDebugClientKadUDPLevel() > 0)
									DebugSend("KADEMLIA2_SEARCH_RES", uIP, uPort);
								byIO.WriteByte(KADEMLIA2_SEARCH_RES);
								byIO.WriteUInt128(Kademlia::CKademlia::GetPrefs()->GetKadID());
								byIO.WriteUInt128(uKeyID);
								byIO.WriteUInt16(0);
								DEBUG_ONLY(DebugLog(_T("Sent %u keyword search results in one packet to avoid fragmentation"), iUnsentCount)); 
								iUnsentCount = 0;
							}
							ASSERT( byIO.GetUsed() + byIOTmp.GetUsed() <= UDP_KAD_MAXFRAGMENT );
							byIO.WriteArray(bySmallBuffer, byIOTmp.GetUsed());
							byIOTmp.Reset();
							iUnsentCount++;
						}
					}
					else
					{
						break;
					}
				}
			}
			if(iUnsentCount > 0)
			{
				uint32 uLen = sizeof(byPacket)-byIO.GetAvailable();
				PokeUInt16(pbyCountPos, (uint16)iUnsentCount);
				if(thePrefs.GetDebugClientKadUDPLevel() > 0)
				{
					DebugSend("KADEMLIA2_SEARCH_RES", uIP, uPort);
				}
				CKademlia::GetUDPListener()->SendPacket(byPacket, uLen, uIP, uPort, senderUDPKey, NULL);
				DEBUG_ONLY(DebugLog(_T("Sent %u note search results in last packet to avoid fragmentation"), iUnsentCount));
			}
			else if (uCount > 0)
				ASSERT( false );
		}
	}
	catch(...)
	{
		AddDebugLogLine(false, _T("Exception in CIndexed::SendValidNoteResult"));
	}
}

///snow:����ֵ�������������Send�ˣ���˼Ӧ���Ƿ����˴洢keyword����
///snow:��CSearchManager::PrepareLookup()�е��ã�
bool CIndexed::SendStoreRequest(const CUInt128& uKeyID)
{
	// do not access any data while the loading thread is busy;
	if (!m_bDataLoaded) {
		DEBUG_ONLY( DebugLogWarning(_T("CIndexed Memberfunction call failed because the dataloading still in progress")) );
		return true; // don't report overloaded with a false
	}

	Load* pLoad;
	if(m_mapLoad.Lookup(CCKey(uKeyID.GetData()), pLoad))   ///snow:m_mapLoad�д�������ڵ�
	{
		if(pLoad->uTime < (uint32)time(NULL))  ///snow:ʹ������ڵ�����޹���
		{
			m_mapLoad.RemoveKey(CCKey(uKeyID.GetData()));  ///snow:ɾ������ڵ�
			m_uTotalIndexLoad--;                           ///snow:Load�ڵ�����1
			delete pLoad;
			return true;
		}
		return false;    ///snow:�洢��m_mapLoad�еĽڵ�û����
	}
	return true;    ///snow:m_mapLoad�в���������ڵ�
}

uint32 CIndexed::GetFileKeyCount()
{
	// do not access any data while the loading thread is busy;
	if (!m_bDataLoaded) {
		DEBUG_ONLY( DebugLogWarning(_T("CIndexed Memberfunction call failed because the dataloading still in progress")) );
		return 0;
	}

	return m_mapKeyword.GetCount();
}

SSearchTerm::SSearchTerm()
{
	m_type = AND;
	m_pTag = NULL;
	m_pLeft = NULL;
	m_pRight = NULL;
}

SSearchTerm::~SSearchTerm()
{
	if (m_type == String)
		delete m_pastr;
	delete m_pTag;
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////
/// CIndexed::CLoadDataThread Implementation
typedef CIndexed::CLoadDataThread CLoadDataThread;
IMPLEMENT_DYNCREATE(CLoadDataThread, CWinThread)

CIndexed::CLoadDataThread::CLoadDataThread()
{
	m_pOwner = NULL;
}

BOOL CIndexed::CLoadDataThread::InitInstance()
{
	InitThreadLocale();
	return TRUE;
}

int CIndexed::CLoadDataThread::Run()
{
	DbgSetThreadName("Kademlia Indexed Load Data");
	if ( !m_pOwner )
		return 0;

	ASSERT( m_pOwner->m_bDataLoaded == false );
	CSingleLock sLock(&m_pOwner->m_mutSync);
	sLock.Lock();

	try
	{
		uint32 uTotalLoad = 0;
		uint32 uTotalSource = 0;
		uint32 uTotalKeyword = 0;
		CUInt128 uKeyID, uID, uSourceID;
		
		if (!m_pOwner->m_bAbortLoading)
		{ 
			///snow:����load_index.dat��ʾ����01 00 00 00 09 35 CA 58 01 00 00 00 17 7E D7 1A 51 A4 6C 77 CB 28 15 65 F9 B8 89 EA 2E 41 CB 58
			CBufferedFileIO fileLoad;
			if(fileLoad.Open(m_sLoadFileName, CFile::modeRead | CFile::typeBinary | CFile::shareDenyWrite))
			{
				setvbuf(fileLoad.m_pStream, NULL, _IOFBF, 32768);
				uint32 uVersion = fileLoad.ReadUInt32();    ///snow:ǰ�ĸ��ֽ��ǰ汾��  01 00 00 00
				if(uVersion<2)                              ///snow:�汾��С��2��ֻ����1
				{
					/*time_t tSaveTime = */fileLoad.ReadUInt32();  ///snow:����ʱ�� 09 35 CA 58
					uint32 uNumLoad = fileLoad.ReadUInt32();      ///snow:��Ŀ��  01 00 00 00
					while(uNumLoad && !m_pOwner->m_bAbortLoading)
					{
						fileLoad.ReadUInt128(&uKeyID);           ///snow:16���ֽ�uKeyID:17 7E D7 1A 51 A4 6C 77 CB 28 15 65 F9 B8 89 EA
						if(m_pOwner->AddLoad(uKeyID, fileLoad.ReadUInt32(), true))   ///snow:4�ֽڵļ���ʱ��  2E 41 CB 58
							uTotalLoad++;
						uNumLoad--;
					}
				}
				fileLoad.Close();
			}
			else
				DebugLogWarning(_T("Unable to load Kad file: %s"), m_sLoadFileName);
		}

		if (!m_pOwner->m_bAbortLoading)
		{
			/**************************************snow:start**********************************************************
			//            snow:����key_index.dat��ʾ����
			//              00000000h: 04 00 00 00 89 86 CB 58 C6 FD 41 06 70 7F E5 80 ; ....���X��A.p�
			//				00000010h: B1 33 64 6D F2 73 50 F2 A9 00 00 00
			//              Key:��1��
			//                                                             1F EE 40 06 ; ?dm�sP�....�@.
			//				00000020h: 1E 15 A3 CD 12 0D 9A 6B 78 C8 F3 D6 2D 00 00 00 ; ..��..�kx��?...
			
			//              Soure:��1��   
			//				00000030h: BA 33 6D D8 B5 2A D0 CE 89 91 FE BF F8 C2 38 C5 ; ?mص*�Ή�����8?
			//				00000040h: 01 00 00 00 3B 65 CB 58 01 00 1E 57 5D D0 2B AB ; ....;e�X...W]??
			//				00000050h: 23 A0 AF CF 9C E5 7B B7 F3 8D 3B 0C 4F F7 01 00 ; #��Ϝ�{��?.O?.
			//				00000060h: 00 00 57 00 53 69 65 72 72 61 2C 20 4A 61 76 69 ; ..W.Sierra, Javi
			//				00000070h: 65 72 20 26 20 43 61 6C 6C 65 6A 6F 2C 20 4A 65 ; er & Callejo, Je
			//				00000080h: 73 C3 BA 73 5F 5F 4C 41 20 45 53 50 41 C3 91 41 ; sús__LA ESPAÑA
			//				00000090h: 20 45 58 54 52 41 C3 91 41 20 5B 31 39 39 37 5D ;  EXTRAÑA [1997]
			//				000000a0h: 20 28 4D 69 73 74 65 72 69 6F 2C 20 53 75 73 70 ;  (Misterio, Susp
			//				000000b0h: 65 6E 73 65 29 2B 2E 65 70 75 62 01 00 00 00 01 ; ense)+.epub.....
			//				000000c0h: 00 00 00 DC BE AF 3E BB 13 CA 58 00 00 03 02 01 ; ...ܾ??�X.....
			//				000000d0h: 00 01 57 00 53 69 65 72 72 61 2C 20 4A 61 76 69 ; ..W.Sierra, Javi
			//				000000e0h: 65 72 20 26 20 43 61 6C 6C 65 6A 6F 2C 20 4A 65 ; er & Callejo, Je
			//				000000f0h: 73 C3 BA 73 5F 5F 4C 41 20 45 53 50 41 C3 91 41 ; sús__LA ESPAÑA
			//				00000100h: 20 45 58 54 52 41 C3 91 41 20 5B 31 39 39 37 5D ;  EXTRAÑA [1997]
			//				00000110h: 20 28 4D 69 73 74 65 72 69 6F 2C 20 53 75 73 70 ;  (Misterio, Susp
			//				00000120h: 65 6E 73 65 29 2B 2E 65 70 75 62 03 01 00 02 E2 ; ense)+.epub....?
			//				00000130h: 13 2C 00 09 01 00 15 01 
			
			//                                                 DC 65 05 3A 3E F6 0E C4 ; .,......�e.:>??
			//				00000140h: FA 14 D1 BA CE 01 14 E3 01 00 00 00 F1 7C CB 58 ; ?Ѻ?.?...�|�X
			//				00000150h: 01 00 28 CF D0 9A 86 6B 17 5F 3C B6 13 9F 02 C8 ; ..(�К�k._<???
			//				00000160h: 6E 99 8F 55 6F 96 01 00 00 00 7D 00 41 75 64 69 ; n��Uo?...}.Audi
			//				00000170h: 6F 6C 69 62 72 6F 20 2D 20 52 6F 73 61 20 44 65 ; olibro - Rosa De
			//				00000180h: 20 4C 6F 73 20 56 69 65 6E 74 6F 73 20 2D 20 4C ;  Los Vientos - L
			//				00000190h: 6F 73 20 53 65 63 72 65 74 6F 73 20 4D 65 64 69 ; os Secretos Medi
			//				000001a0h: 65 76 61 6C 65 73 20 28 4C 69 62 72 6F 20 44 65 ; evales (Libro De
			//				000001b0h: 20 4A 65 73 C3 BA 73 20 43 61 6C 6C 65 6A 6F 29 ;  Jesús Callejo)
							000001c0h: 20 2D 20 4D 6F 6E 6F 67 72 C3 A1 66 69 63 6F 73 ;  - Monográficos
							000001d0h: 20 5A 6F 6E 61 20 43 65 72 6F 20 2D 20 50 6F 72 ;  Zona Cero - Por
							000001e0h: 20 4C 75 6B 79 2E 6D 70 33 02 00 00 00 02 00 00 ;  Luky.mp3.......
							000001f0h: 00 DD 8B 2B 3E 0B EE C8 58 00 00 D4 45 3D A7 71 ; .݋+>.��X..�E=�q
							00000200h: 2B CA 58 00 00 04 02 01 00 01 7D 00 41 75 64 69 ; +�X.......}.Audi
							00000210h: 6F 6C 69 62 72 6F 20 2D 20 52 6F 73 61 20 44 65 ; olibro - Rosa De
							00000220h: 20 4C 6F 73 20 56 69 65 6E 74 6F 73 20 2D 20 4C ;  Los Vientos - L
							00000230h: 6F 73 20 53 65 63 72 65 74 6F 73 20 4D 65 64 69 ; os Secretos Medi
							00000240h: 65 76 61 6C 65 73 20 28 4C 69 62 72 6F 20 44 65 ; evales (Libro De
							00000250h: 20 4A 65 73 C3 BA 73 20 43 61 6C 6C 65 6A 6F 29 ;  Jesús Callejo)
							00000260h: 20 2D 20 4D 6F 6E 6F 67 72 C3 A1 66 69 63 6F 73 ;  - Monográficos
							00000270h: 20 5A 6F 6E 61 20 43 65 72 6F 20 2D 20 50 6F 72 ;  Zona Cero - Por
							00000280h: 20 4C 75 6B 79 2E 6D 70 33 03 01 00 02 70 31 D0 ;  Luky.mp3....p1?
							00000290h: 00 09 01 00 15 01 02 01 00 03 05 00 
							
							41 75 64 69 ; ............Audi
							000002a0h: 6F 63 82 51 43 D5 80 86 21 57 CE D2 28 1E 3B 77 ; oc�QCՀ?W��(.;w
			****************************************snow:end********************************************************/
			CBufferedFileIO fileKey;
			if (fileKey.Open(m_sKeyFileName, CFile::modeRead | CFile::typeBinary | CFile::shareDenyWrite))
			{
				setvbuf(fileKey.m_pStream, NULL, _IOFBF, 32768);

				uint32 uVersion = fileKey.ReadUInt32();   ///snow:ǰ�ĸ��ֽ��ǰ汾��  04 00 00 00
				if( uVersion < 5)                    ///snow:�汾��С��5
				{
				time_t tSaveTime = fileKey.ReadUInt32();   ///snow:4�ֽڱ���ʱ�䣺89 86 CB 58  �Ǵ��ʱ�䣬��Ч��24Сʱ
					if( tSaveTime > time(NULL) )
					{
					fileKey.ReadUInt128(&uID);     ///snow:16�ֽ�ID:C6 FD 41 06 70 7F E5 80 B1 33 64 6D F2 73 50 F2
						if( Kademlia::CKademlia::GetPrefs()->GetKadID() == uID )
						{
						uint32 uNumKeys = fileKey.ReadUInt32();   ///snow:Key��Ŀ A9 00 00 00 169��
							while( uNumKeys && !m_pOwner->m_bAbortLoading )
							{
							fileKey.ReadUInt128(&uKeyID);     ///snow:16�ֽڵ�KeyID��1F EE 40 06 1E 15 A3 CD 12 0D 9A 6B 78 C8 F3 D6
							uint32 uNumSource = fileKey.ReadUInt32();  ///snow:4�ֽڵ�source��Ŀ  2D 00 00 00  45��
								while( uNumSource && !m_pOwner->m_bAbortLoading )
								{
								fileKey.ReadUInt128(&uSourceID);   ///snow:16�ֽڵ�SourceID: BA 33 6D D8 B5 2A D0 CE 89 91 FE BF F8 C2 38 C5
								uint32 uNumName = fileKey.ReadUInt32();   ///snow:4�ֽڵ�Name��Ŀ��01 00 00 00  ͬһhash������ͬ�ļ���
									while( uNumName && !m_pOwner->m_bAbortLoading)
									{
										CKeyEntry* pToAdd = new Kademlia::CKeyEntry();
										pToAdd->m_uKeyID.SetValue(uKeyID);
										pToAdd->m_uSourceID.SetValue(uSourceID);									
										pToAdd->m_bSource = false;
										pToAdd->m_tLifetime = fileKey.ReadUInt32();   ///snow:4�ֽڵĴ��ʱ�䣺3B 65 CB 58
										if (uVersion >= 3)   ///snow:�汾4������AICH��Ϣ���汾3������
											///snow:��ȡAICH��Ϣ��2���ֽڵ�AICH��Ŀ��01 00  1��
											///snow:��ʾ�����ܹ���ȡ��110���ֽ�:��0000005eh����ȡ��000000cch�� 01 00 00 00 57 00 53...(�˴�ʡ��97�ֽڣ�...BB 13 CA 58 00 00
											pToAdd->ReadPublishTrackingDataFromFile(&fileKey, uVersion >= 4);   ///��src_index.dat��Ĳ���
										///snow:1�ֽڵ�Tag������03
										uint32 uTotalTags = fileKey.ReadByte();
										///snow:��1��tag:��ȡ��02 01 00 01 57 00 53 69 65 72 72 61 2C 20 4A 61 76 69....65 29 2B 2E 65 70 75 62
										///snow:  02 type=TAGTYPE_STRING, 01 00 name len, 01 pcName=TAG_FILENAME ,57 00 ,filenameLen,�ļ���...87�ֽ�
										///snow:��2��tag:��ȡ��03 01 00 02 E2 13 2C 00
										///snow:03 type=TAGTYPE_UINT32,01 00 name len, 02 pcName=TAG_FILESIZE,value:E2 13 2C 00
										///snow:��3��tag:��ȡ��09 01 00 15 01 DC 65 05 3A 3E F6 0E C4
										///snow:09 type=TAGTYPE_UINT8,01 00 name len, 15 pcName=TAG_SOURCES,value:01
										while( uTotalTags )
										{
										CKadTag* pTag = fileKey.ReadTag();  
											if(pTag)
											{
												if (!pTag->m_name.Compare(TAG_FILENAME))
												{
													if (pToAdd->GetCommonFileName().IsEmpty())
														pToAdd->SetFileName(pTag->GetStr());
													delete pTag;
												}
												else if (!pTag->m_name.Compare(TAG_FILESIZE))
												{
													pToAdd->m_uSize = pTag->GetInt();
													delete pTag;
												}
												else if (!pTag->m_name.Compare(TAG_SOURCEIP))
												{
													pToAdd->m_uIP = (uint32)pTag->GetInt();
													pToAdd->AddTag(pTag);
												}
												else if (!pTag->m_name.Compare(TAG_SOURCEPORT))
												{
													pToAdd->m_uTCPPort = (uint16)pTag->GetInt();
													pToAdd->AddTag(pTag);
												}
												else if (!pTag->m_name.Compare(TAG_SOURCEUPORT))
												{
													pToAdd->m_uUDPPort = (uint16)pTag->GetInt();
													pToAdd->AddTag(pTag);
												}
												else
												{
													pToAdd->AddTag(pTag);
												}
											}
											uTotalTags--;
										}
										uint8 uLoad;
										///snow:��Key_index.dat�е�������Ŀ��ӵ�m_mapKeyword
										if(m_pOwner->AddKeyword(uKeyID, uSourceID, pToAdd, uLoad, true))
											uTotalKeyword++;
										else
											delete pToAdd;
										uNumName--;
									}
									uNumSource--;
								}
								uNumKeys--;
							}
						}
					}
				}
				fileKey.Close();
			}
			else
				DebugLogWarning(_T("Unable to load Kad file: %s"), m_sKeyFileName);
		}


		///snow:add by snow
		PrintCheckIndexData();

		if (!m_pOwner->m_bAbortLoading)
		{ 
/***********************************************snow:start*******************************************
		///snow:����src_index.dat
		00000000h: 02 00 00 00 59 7B CA 58 5D 03 00 00 1B 8E 41 06 ; ....Y{�X]....�A.
		00000010h: CD 8C 99 43 75 9B 4B 66 49 8B 1C B1 01 00 00 00 ; ͌�Cu�KfI??...
		00000020h: 61 9E 6D 07 F4 CB 0E 6E 42 8D 72 0A 11 6F C4 02 ; a�m.��.nB�r..o?
		00000030h: 01 00 00 00 71 69 CA 58 06 03 01 00 02 00 C0 9A ; ....qi�X......��
		00000040h: 2B 03 01 00 FE A8 3A 39 53 09 01 00 FF 01 08 01 ; +...��:9S...�...
		00000050h: 00 FD 9E 1B 08 01 00 FC DB 06 09 01 00 F3 03    ; .��....��....?.
*********************************************snow:end***************************************************/
			CBufferedFileIO fileSource;
			if (fileSource.Open(m_sSourceFileName, CFile::modeRead | CFile::typeBinary | CFile::shareDenyWrite))
			{
				setvbuf(fileSource.m_pStream, NULL, _IOFBF, 32768);

				uint32 uVersion = fileSource.ReadUInt32();   ///snow:�汾�ţ�02 00 00 00
				if( uVersion < 3 )
				{
				time_t tSaveTime = fileSource.ReadUInt32();   ///snow:����ʱ�䣺59 7B CA 58 Ӧ�ò��Ǳ���ʱ�䣬�Ǵ������
					if( tSaveTime > time(NULL) )
					{
					uint32 uNumKeys = fileSource.ReadUInt32();   ///snow:Key��Ŀ��5D 03 00 00   861��
						while( uNumKeys && !m_pOwner->m_bAbortLoading )
						{
						fileSource.ReadUInt128(&uKeyID);    ///snow:16�ֽڵ�keyid:1B 8E 41 06 CD 8C 99 43 75 9B 4B 66 49 8B 1C B1
						uint32 uNumSource = fileSource.ReadUInt32();   ///snow:4�ֽڵ�SourceNum ��01 00 00 00
							while( uNumSource && !m_pOwner->m_bAbortLoading )
							{
							fileSource.ReadUInt128(&uSourceID);   ///snow:16�ֽڵ�sourceid:61 9E 6D 07 F4 CB 0E 6E 42 8D 72 0A 11 6F C4 02
							uint32 uNumName = fileSource.ReadUInt32();   ///snow:4�ֽڵ�NameNum: 01 00 00 00
								while( uNumName && !m_pOwner->m_bAbortLoading )
								{
									CEntry* pToAdd = new Kademlia::CEntry();
									pToAdd->m_bSource = true;
									pToAdd->m_tLifetime = fileSource.ReadUInt32();   ///snow:4�ֽڵĴ��ʱ�䣺71 69 CA 58
									uint32 uTotalTags = fileSource.ReadByte();    ///snow:1�ֽڵ�tag�� 06
									///snow:03 01 00 02 00 C0 9A 2B  UINT32 TAG_FILESIZE
									///snow:03 01 00 FE A8 3A 39 53  UINT32 TAG_SOURCEIP
									///snow:09 01 00 FF 01           UINT8  TAG_SOURCETYPE
									///snow:08 01 00 FD 9E 1B        UINT16 TAG_SOURCEPORT
									///snow:08 01 00 FC DB 06        UINT16 TAG_SOURCEUPORT
									///snow:09 01 00 F3 03           UIN8   TAG_ENCRYPTION 
									while( uTotalTags )
									{
										CKadTag* pTag = fileSource.ReadTag();
										if(pTag)
										{
											if (!pTag->m_name.Compare(TAG_SOURCEIP))
											{
												pToAdd->m_uIP = (uint32)pTag->GetInt();
												pToAdd->AddTag(pTag);
											}
											else if (!pTag->m_name.Compare(TAG_SOURCEPORT))
											{
												pToAdd->m_uTCPPort = (uint16)pTag->GetInt();
												pToAdd->AddTag(pTag);
											}
											else if (!pTag->m_name.Compare(TAG_SOURCEUPORT))
											{
												pToAdd->m_uUDPPort = (uint16)pTag->GetInt();
												pToAdd->AddTag(pTag);
											}
											else
											{
												pToAdd->AddTag(pTag);
											}
										}
										uTotalTags--;
									}
									pToAdd->m_uKeyID.SetValue(uKeyID);
									pToAdd->m_uSourceID.SetValue(uSourceID);
									uint8 uLoad;
									if(m_pOwner->AddSources(uKeyID, uSourceID, pToAdd, uLoad, true))
										uTotalSource++;
									else
										delete pToAdd;
									uNumName--;
								}
								uNumSource--;
							}
							uNumKeys--;
						}
					}
				}
				fileSource.Close();

				m_pOwner->m_uTotalIndexSource = uTotalSource;
				m_pOwner->m_uTotalIndexKeyword = uTotalKeyword;
				m_pOwner->m_uTotalIndexLoad = uTotalLoad;
				AddDebugLogLine( false, _T("Read %u source, %u keyword, and %u load entries"), uTotalSource, uTotalKeyword, uTotalLoad);
			}
			else
				DebugLogWarning(_T("Unable to load Kad file: %s"), m_sSourceFileName);
		}

		///snow:add by snow
		PrintCheckSourceIndexData();
	}
	catch ( CIOException *ioe )
	{
		AddDebugLogLine( false, _T("CIndexed::CLoadDataThread::Run (IO error(%i))"), ioe->m_iCause);
		ioe->Delete();
	}
	catch (...)
	{
		AddDebugLogLine(false, _T("Exception in CIndexed::CLoadDataThread::Run"));
		ASSERT( false );
	}
	if (m_pOwner->m_bAbortLoading)
		AddDebugLogLine(false, _T("Terminating CIndexed::CLoadDataThread - early abort requested"));
	else
		AddDebugLogLine(false, _T("Terminating CIndexed::CLoadDataThread - finished loading data"));

	m_pOwner->m_bDataLoaded = true;
	return 0;
}

///snow:<----------------------------------------------------------------------------





void CIndexed::CLoadDataThread::PrintCheckIndexData()
{
	CBufferedFileIO fileKey;
	CUInt128 uKeyID, uID, uSourceID;
	if (fileKey.Open(m_sKeyFileName, CFile::modeRead | CFile::typeBinary | CFile::shareDenyWrite))
	{
		setvbuf(fileKey.m_pStream, NULL, _IOFBF, 32768);

		theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("FileName:%s\r\n"),m_sKeyFileName.GetBuffer(0));

		uint32 uVersion = fileKey.ReadUInt32();   ///snow:ǰ�ĸ��ֽ��ǰ汾��  04 00 00 00
		theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("Version:%i"),uVersion);

		time_t tSaveTime = fileKey.ReadUInt32();   ///snow:4�ֽڱ���ʱ�䣺89 86 CB 58  �Ǵ��ʱ�䣬��Ч��24Сʱ
		theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("LiftTime:%s"),FormatTime(tSaveTime).GetBuffer(0));

		fileKey.ReadUInt128(&uID);     ///snow:16�ֽ�ID:C6 FD 41 06 70 7F E5 80 B1 33 64 6D F2 73 50 F2
		theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("����KadID(ǰ32λ):%s(%iλ),Hex:%x"),binary(uID.Get32BitChunk(0)).GetBuffer(0),binary(uID.Get32BitChunk(0)).GetLength(),uID.Get32BitChunk(0));

		//if( Kademlia::CKademlia::GetPrefs()->GetKadID() == uID )
		//	{
		uint32 uNumKeys = fileKey.ReadUInt32();   ///snow:Key��Ŀ A9 00 00 00 169��
		theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("Key����:%i\r\n"),uNumKeys);

		uint32 uTotalNumkeys,uTotalNumSources,uTotalEntrys;
		uTotalNumkeys = uNumKeys;

		while( uNumKeys)
		{
			theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("\r\n	Key�� %i ��:"),uTotalNumkeys-uNumKeys+1);
			fileKey.ReadUInt128(&uKeyID);     ///snow:16�ֽڵ�KeyID��1F EE 40 06 1E 15 A3 CD 12 0D 9A 6B 78 C8 F3 D6
			theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("	File ID(ǰ32λ):%s(%iλ),Hex:%x"),binary(uKeyID.Get32BitChunk(0)).GetBuffer(0),binary(uKeyID.Get32BitChunk(0)).GetLength(),uKeyID.Get32BitChunk(0));

			CUInt128 uDistance(uID);
			uDistance.Xor(uKeyID);
			theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("	Distance(ǰ32λ):%s(%iλ),Dec:%d,����ֵ:16777216(%s)"),binary(uDistance.Get32BitChunk(0)).GetBuffer(0),binary(uDistance.Get32BitChunk(0)).GetLength(),uDistance.Get32BitChunk(0),binary(16777216).GetBuffer(0));

			uint32 uNumSource = fileKey.ReadUInt32();  ///snow:4�ֽڵ�source��Ŀ  2D 00 00 00  45��
			theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("	Source����:%i\r\n"),uNumSource);

			uTotalNumSources=uNumSource;
			while( uNumSource)
			{
				theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("		Source�� %i ��:"),uTotalNumSources-uNumSource+1);
				fileKey.ReadUInt128(&uSourceID);   ///snow:16�ֽڵ�SourceID: BA 33 6D D8 B5 2A D0 CE 89 91 FE BF F8 C2 38 C5
				theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("		Source ID(ǰ32λ):%s"),binary(uSourceID.Get32BitChunk(0)).GetBuffer(0));

				uint32 uNumName = fileKey.ReadUInt32();   ///snow:4�ֽڵ�Name��Ŀ��01 00 00 00  ͬһhash������ͬ�ļ���
				theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("		Entry��:%i"),uNumName);

				uTotalEntrys=uNumName;
				while( uNumName)
				{
					theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Entry�� %i ��:"),uTotalEntrys-uNumName+1);
					CKeyEntry* pToAdd = new Kademlia::CKeyEntry();
					pToAdd->m_uKeyID.SetValue(uKeyID);
					pToAdd->m_uSourceID.SetValue(uSourceID);									
					pToAdd->m_bSource = false;
					pToAdd->m_tLifetime = fileKey.ReadUInt32();   ///snow:4�ֽڵĴ��ʱ�䣺3B 65 CB 58
					theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			LiftTime:%s"),FormatTime(pToAdd->m_tLifetime).GetBuffer(0));

					if (uVersion >= 3)   ///snow:�汾4������AICH��Ϣ���汾3������
						///snow:��ȡAICH��Ϣ��2���ֽڵ�AICH��Ŀ��01 00  1��
						///snow:��ʾ�����ܹ���ȡ��110���ֽ�:��0000005eh����ȡ��000000cch�� 01 00 00 00 57 00 53...(�˴�ʡ��97�ֽڣ�...BB 13 CA 58 00 00  �μ�ReadPublishTrackingDataFromFile()ע��
						pToAdd->ReadPublishTrackingDataFromFile(&fileKey, uVersion >= 4);   ///��src_index.dat��Ĳ���
					///snow:1�ֽڵ�Tag������03
					uint32 uTotalTags = fileKey.ReadByte();
					theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("		Tag��:%i"),uTotalTags);
					///snow:��1��tag:��ȡ��02 01 00 01 57 00 53 69 65 72 72 61 2C 20 4A 61 76 69....65 29 2B 2E 65 70 75 62
					///snow:  02 type=TAGTYPE_STRING, 01 00 name len, 01 pcName=TAG_FILENAME ,57 00 ,filenameLen,�ļ���...87�ֽ�
					///snow:��2��tag:��ȡ��03 01 00 02 E2 13 2C 00
					///snow:03 type=TAGTYPE_UINT32,01 00 name len, 02 pcName=TAG_FILESIZE,value:E2 13 2C 00
					///snow:��3��tag:��ȡ��09 01 00 15 01 DC 65 05 3A 3E F6 0E C4
					///snow:09 type=TAGTYPE_UINT8,01 00 name len, 15 pcName=TAG_SOURCES,value:01
					while( uTotalTags )
					{
						CKadTag* pTag = fileKey.ReadTag();  
						if(pTag)
						{
							if (!pTag->m_name.Compare(TAG_FILENAME))
							{
								//if (pToAdd->GetCommonFileName().IsEmpty())
								//{
								//	pToAdd->SetFileName(pTag->GetStr());
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:FileName:%s"),pTag->GetStr().GetBuffer(0));
								//}
								//delete pTag;
								}
							else if (!pTag->m_name.Compare(TAG_FILESIZE))
								{
								//pToAdd->m_uSize = pTag->GetInt();
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:Size:%i"),pTag->GetInt());
								//delete pTag;
								}
							else if (!pTag->m_name.Compare(TAG_SOURCEIP))
								{
								//pToAdd->m_uIP = (uint32)pTag->GetInt();
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:IP:%s"),ipstr((UINT32)pTag->GetInt()));
								//pToAdd->AddTag(pTag);
								}
							else if (!pTag->m_name.Compare(TAG_SOURCEPORT))
								{
								//pToAdd->m_uTCPPort = (uint16)pTag->GetInt();
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:Port:%i"),pTag->GetInt());
								//pToAdd->AddTag(pTag);
								}
							else if (!pTag->m_name.Compare(TAG_SOURCEUPORT))
								{
								//pToAdd->m_uUDPPort = (uint16)pTag->GetInt();
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:UDP Port:%i"),pTag->GetInt());
								//pToAdd->AddTag(pTag);
								}
							else if (!pTag->m_name.Compare(TAG_BUDDYHASH))
								{
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:BUDDYHASH:%i"),pTag->GetInt());
								}
							else if (!pTag->m_name.Compare(TAG_CLIENTLOWID))
								{
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:CLIENTLOWID:%i"),pTag->GetInt());
								}
							else if (!pTag->m_name.Compare(TAG_COLLECTION))
								{
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:COLLECTION:%i"),pTag->GetInt());
								}
							else if (!pTag->m_name.Compare(TAG_COMPLETE_SOURCES))
								{
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:COMPLETE_SOURCES:%i"),pTag->GetInt());
								}
							else if (!pTag->m_name.Compare(TAG_ENCRYPTION))
								{
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:ENCRYPTION:%i"),pTag->GetInt());
								}
							else if (!pTag->m_name.Compare(TAG_FILE_COUNT))
								{
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:FILE_COUNT:%i"),pTag->GetInt());
								}
							else if (!pTag->m_name.Compare(TAG_FILECOMMENT))
								{
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:FILECOMMENT:%i"),pTag->GetInt());
								}
							else if (!pTag->m_name.Compare(TAG_FILEFORMAT))
								{
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:FILEFORMAT:%s"),pTag->GetStr().GetBuffer(0));
								}
							//else if (!pTag->m_name.Compare(TAG_FILENAME))
							//	{
							//	theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:FILENAME:%i"),pTag->GetInt());
							//	}
							else if (!pTag->m_name.Compare(TAG_FILERATING))
								{
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:FILERATING:%i"),pTag->GetInt());
								}
							//else if (!pTag->m_name.Compare(TAG_FILESIZE))
							//	{
							//	theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:FILESIZE:%i"),pTag->GetInt());
							//	}
							else if (!pTag->m_name.Compare(TAG_FILESIZE_HI))
								{
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:FILESIZE_HI:%i"),pTag->GetInt());
								}
							else if (!pTag->m_name.Compare(TAG_FILETYPE))
								{
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:FILETYPE:%s"),pTag->GetStr().GetBuffer(0));
								}
							else if (!pTag->m_name.Compare(TAG_IP_ADDRESS))
								{
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:IP_ADDRESS:%i"),pTag->GetInt());
								}
							else if (!pTag->m_name.Compare(TAG_KADAICHHASHRESULT))
								{
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:KADAICHHASHRESULT:%i"),pTag->GetInt());
								}
							else if (!pTag->m_name.Compare(TAG_KADMISCOPTIONS))
								{
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:KADMISCOPTIONS:%i"),pTag->GetInt());
								}
							else if (!pTag->m_name.Compare(TAG_PARTFILENAME))
								{
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:PARTFILENAME:%s"),pTag->GetStr().GetBuffer(0));
								}
							else if (!pTag->m_name.Compare(TAG_PARTS))
								{
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:PARTS:%i"),pTag->GetInt());
								}
							else if (!pTag->m_name.Compare(TAG_PERMISSIONS))
								{
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:PERMISSIONS:%i"),pTag->GetInt());
								}
							else if (!pTag->m_name.Compare(TAG_PORT))
								{
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:PORT:%i"),pTag->GetInt());
								}
							else if (!pTag->m_name.Compare(TAG_PRIORITY))
								{
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:PRIORITY:%i"),pTag->GetInt());
								}
							else if (!pTag->m_name.Compare(TAG_PUBLISHINFO))
								{
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:PUBLISHINFO:%i"),pTag->GetInt());
								}
							else if (!pTag->m_name.Compare(TAG_SERVERIP))
								{
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:SERVERIP:%s"),ipstr(pTag->GetInt()));
								}
							else if (!pTag->m_name.Compare(TAG_SERVERPORT))
								{
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:SERVERPORT:%i"),pTag->GetInt());
								}
							//else if (!pTag->m_name.Compare(TAG_SOURCEIP))
							//	{
							//	theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:SOURCEIP:%i"),pTag->GetInt());
							//	}
							//else if (!pTag->m_name.Compare(TAG_SOURCEPORT))
							//	{
							//	theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:SOURCEPORT:%i"),pTag->GetInt());
							//	}
							else if (!pTag->m_name.Compare(TAG_SOURCES))
								{
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:SOURCES:%i"),pTag->GetInt());
								}
							else if (!pTag->m_name.Compare(TAG_SOURCETYPE))
								{
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:SOURCETYPE:%i"),pTag->GetInt());
								}
							//else if (!pTag->m_name.Compare(TAG_SOURCEUPORT))
							//	{
							//	theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:SOURCEUPORT:%i"),pTag->GetInt());
							//	}
							else if (!pTag->m_name.Compare(TAG_STATUS))
								{
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:STATUS:%i"),pTag->GetInt());
								}
							else if (!pTag->m_name.Compare(TAG_USER_COUNT))
								{
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:USER_COUNT:%i"),pTag->GetInt());
								}
							else if (!pTag->m_name.Compare(TAG_VERSION))
								{
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:VERSION:%i"),pTag->GetInt());
								}
							else if (!pTag->m_name.Compare(TAG_DESCRIPTION))
								{
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:DESCRIPTION:%i"),pTag->GetInt());
								}
							else if (!pTag->m_name.Compare(TAG_FAIL))
								{
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:FAIL:%i"),pTag->GetInt());
								}
							else if (!pTag->m_name.Compare(TAG_GAPEND))
								{
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:GAPEND:%i"),pTag->GetInt());
								}
							else if (!pTag->m_name.Compare(TAG_GAPSTART))
								{
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:GAPSTART:%i"),pTag->GetInt());
								}
							else if (!pTag->m_name.Compare(TAG_KADAICHHASHPUB))
								{
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:KADAICHHASHPUB:%i"),pTag->GetInt());
								}
							else if (!pTag->m_name.Compare(TAG_MEDIA_ALBUM))
								{
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:MEDIA_ALBUM:%s"),pTag->GetStr().GetBuffer(0));
								}
							else if (!pTag->m_name.Compare(TAG_MEDIA_ARTIST))
								{
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:MEDIA_ARTIST:%s"),pTag->GetStr().GetBuffer(0));
								}
							else if (!pTag->m_name.Compare(TAG_MEDIA_BITRATE))
								{
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:MEDIA_BITRATE:%i"),pTag->GetInt());
								}
							else if (!pTag->m_name.Compare(TAG_MEDIA_CODEC))
								{
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:MEDIA_CODEC:%s"),pTag->GetStr().GetBuffer(0));
								}
							else if (!pTag->m_name.Compare(TAG_MEDIA_LENGTH))
								{
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:MEDIA_LENGTH:%i"),pTag->GetInt());
								}
							else if (!pTag->m_name.Compare(TAG_MEDIA_TITLE))
								{
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:MEDIA_TITLE:%s"),pTag->GetStr().GetBuffer(0));
								}
							else if (!pTag->m_name.Compare(TAG_PART_HASH))
								{
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:PART_HASH:%i"),pTag->GetInt());
								}
							else if (!pTag->m_name.Compare(TAG_PART_PATH))
								{
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:PART_PATH:%i"),pTag->GetInt());
								}
							else if (!pTag->m_name.Compare(TAG_PING))
								{
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:PING:%i"),pTag->GetInt());
								}
							else if (!pTag->m_name.Compare(TAG_PREFERENCE))
								{
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:PREFERENCE:%i"),pTag->GetInt());
								}
							else if (!pTag->m_name.Compare(TAG_TRANSFERRED))
								{
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:TRANSFERRED:%i"),pTag->GetInt());
								}

							else
								{
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:Other type:%s"),ByteToHexStr((uchar*)pTag->m_name.GetBuffer(0),pTag->m_name.GetLength()).GetBuffer(0));
								//pToAdd->AddTag(pTag);
								}
							delete pTag;
							}
						uTotalTags--;
						}

					delete pToAdd;
					uNumName--;
					}
				uNumSource--;
				}
			uNumKeys--;
			}

		fileKey.Close();
		}
	else
		DebugLogWarning(_T("Unable to load Kad file: %s"), m_sKeyFileName);
}

void CIndexed::CLoadDataThread::PrintCheckSourceIndexData()
{
	CBufferedFileIO fileSource;
	CUInt128 uKeyID, uID, uSourceID;
	if (fileSource.Open(m_sSourceFileName, CFile::modeRead | CFile::typeBinary | CFile::shareDenyWrite))
	{
		setvbuf(fileSource.m_pStream, NULL, _IOFBF, 32768);

		theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("FileName:%s\r\n"),m_sSourceFileName.GetBuffer(0));

		uint32 uVersion = fileSource.ReadUInt32();   ///snow:�汾�ţ�02 00 00 00
		theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("Version:%i"),uVersion);


		time_t tSaveTime = fileSource.ReadUInt32();   ///snow:����ʱ�䣺59 7B CA 58 Ӧ�ò��Ǳ���ʱ�䣬�Ǵ������
		theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("LiftTime:%s"),FormatTime(tSaveTime).GetBuffer(0));

		uint32 uNumKeys = fileSource.ReadUInt32();   ///snow:Key��Ŀ��5D 03 00 00   861��
		theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("Key����:%i\r\n"),uNumKeys);

		uint32 uTotalNumkeys,uTotalNumSources,uTotalEntrys;
		uTotalNumkeys = uNumKeys;

		while( uNumKeys)
		{
			theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("\r\n	Key�� %i ��:"),uTotalNumkeys-uNumKeys+1);
			fileSource.ReadUInt128(&uKeyID);    ///snow:16�ֽڵ�keyid:1B 8E 41 06 CD 8C 99 43 75 9B 4B 66 49 8B 1C B1
			theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("	File ID(ǰ32λ):%s(%iλ),Hex:%x"),binary(uKeyID.Get32BitChunk(0)).GetBuffer(0),binary(uKeyID.Get32BitChunk(0)).GetLength(),uKeyID.Get32BitChunk(0));

			uint32 uNumSource = fileSource.ReadUInt32();   ///snow:4�ֽڵ�SourceNum ��01 00 00 00
			//theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("Key����:%i\r\n"),uNumKeys);
			theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("	Source����:%i\r\n"),uNumSource);

			uTotalNumSources=uNumSource;
			while( uNumSource)
			{
				theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("		Source�� %i ��:"),uTotalNumSources-uNumSource+1);
				fileSource.ReadUInt128(&uSourceID);   ///snow:16�ֽڵ�sourceid:61 9E 6D 07 F4 CB 0E 6E 42 8D 72 0A 11 6F C4 02
				theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("		Source ID(ǰ32λ):%s"),binary(uSourceID.Get32BitChunk(0)).GetBuffer(0));

				uint32 uNumName = fileSource.ReadUInt32();   ///snow:4�ֽڵ�NameNum: 01 00 00 00
				theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("		Entry��:%i"),uNumName);

				uTotalEntrys=uNumName;
				while( uNumName)
				{
					theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Entry�� %i ��:"),uTotalEntrys-uNumName+1);
					CEntry* pToAdd = new Kademlia::CEntry();
					pToAdd->m_bSource = true;
					pToAdd->m_tLifetime = fileSource.ReadUInt32();   ///snow:4�ֽڵĴ��ʱ�䣺71 69 CA 58
					theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			LiftTime:%s"),FormatTime(pToAdd->m_tLifetime).GetBuffer(0));
					uint32 uTotalTags = fileSource.ReadByte();    ///snow:1�ֽڵ�tag�� 06
					theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("		Tag��:%i"),uTotalTags);
					///snow:03 01 00 02 00 C0 9A 2B  UINT32 TAG_FILESIZE
					///snow:03 01 00 FE A8 3A 39 53  UINT32 TAG_SOURCEIP
					///snow:09 01 00 FF 01           UINT8  TAG_SOURCETYPE
					///snow:08 01 00 FD 9E 1B        UINT16 TAG_SOURCEPORT
					///snow:08 01 00 FC DB 06        UINT16 TAG_SOURCEUPORT
					///snow:09 01 00 F3 03           UIN8   TAG_ENCRYPTION 
					while( uTotalTags )
					{
						CKadTag* pTag = fileSource.ReadTag();
						if(pTag)
						{
							if (!pTag->m_name.Compare(TAG_SOURCEIP))
							{
								//pToAdd->m_uIP = (uint32)pTag->GetInt();
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:IP:%s"),ipstr(pTag->GetInt()));
								//pToAdd->AddTag(pTag);
							}
							else if (!pTag->m_name.Compare(TAG_SOURCEPORT))
							{
								//pToAdd->m_uTCPPort = (uint16)pTag->GetInt();
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:Port:%i"),pTag->GetInt());
								//pToAdd->AddTag(pTag);
							}
							else if (!pTag->m_name.Compare(TAG_SOURCEUPORT))
							{
								//pToAdd->m_uUDPPort = (uint16)pTag->GetInt();
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:UDP Port:%i"),pTag->GetInt());
								//pToAdd->AddTag(pTag);
							}
							else if (!pTag->m_name.Compare(TAG_BUDDYHASH))
								{
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:BUDDYHASH:%s"),pTag->GetStr().GetBuffer(0));
								}
							else if (!pTag->m_name.Compare(TAG_CLIENTLOWID))
								{
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:CLIENTLOWID:%i"),pTag->GetInt());
								}
							else if (!pTag->m_name.Compare(TAG_COLLECTION))
								{
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:COLLECTION:%i"),pTag->GetInt());
								}
							else if (!pTag->m_name.Compare(TAG_COMPLETE_SOURCES))
								{
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:COMPLETE_SOURCES:%i"),pTag->GetInt());
								}
							else if (!pTag->m_name.Compare(TAG_ENCRYPTION))
								{
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:ENCRYPTION:%i"),pTag->GetInt());
								}
							else if (!pTag->m_name.Compare(TAG_FILE_COUNT))
								{
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:FILE_COUNT:%i"),pTag->GetInt());
								}
							else if (!pTag->m_name.Compare(TAG_FILECOMMENT))
								{
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:FILECOMMENT:%i"),pTag->GetInt());
								}
							else if (!pTag->m_name.Compare(TAG_FILEFORMAT))
								{
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:FILEFORMAT:%i"),pTag->GetInt());
								}
							else if (!pTag->m_name.Compare(TAG_FILENAME))
								{
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:FILENAME:%s"),pTag->GetStr().GetBuffer(0));
								}
							else if (!pTag->m_name.Compare(TAG_FILERATING))
								{
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:FILERATING:%i"),pTag->GetInt());
								}
							else if (!pTag->m_name.Compare(TAG_FILESIZE))
								{
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:FILESIZE:%i"),pTag->GetInt());
								}
							else if (!pTag->m_name.Compare(TAG_FILESIZE_HI))
								{
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:FILESIZE_HI:%i"),pTag->GetInt());
								}
							else if (!pTag->m_name.Compare(TAG_FILETYPE))
								{
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:FILETYPE:%i"),pTag->GetInt());
								}
							else if (!pTag->m_name.Compare(TAG_IP_ADDRESS))
								{
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:IP_ADDRESS:%i"),pTag->GetInt());
								}
							else if (!pTag->m_name.Compare(TAG_KADAICHHASHRESULT))
								{
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:KADAICHHASHRESULT:%i"),pTag->GetInt());
								}
							else if (!pTag->m_name.Compare(TAG_KADMISCOPTIONS))
								{
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:KADMISCOPTIONS:%i"),pTag->GetInt());
								}
							else if (!pTag->m_name.Compare(TAG_PARTFILENAME))
								{
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:PARTFILENAME:%i"),pTag->GetInt());
								}
							else if (!pTag->m_name.Compare(TAG_PARTS))
								{
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:PARTS:%i"),pTag->GetInt());
								}
							else if (!pTag->m_name.Compare(TAG_PERMISSIONS))
								{
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:PERMISSIONS:%i"),pTag->GetInt());
								}
							else if (!pTag->m_name.Compare(TAG_PORT))
								{
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:PORT:%i"),pTag->GetInt());
								}
							else if (!pTag->m_name.Compare(TAG_PRIORITY))
								{
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:PRIORITY:%i"),pTag->GetInt());
								}
							else if (!pTag->m_name.Compare(TAG_PUBLISHINFO))
								{
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:PUBLISHINFO:%i"),pTag->GetInt());
								}
							else if (!pTag->m_name.Compare(TAG_SERVERIP))
								{
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:SERVERIP:%s"),ipstr(pTag->GetInt()));
								}
							else if (!pTag->m_name.Compare(TAG_SERVERPORT))
								{
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:SERVERPORT:%i"),pTag->GetInt());
								}
							//else if (!pTag->m_name.Compare(TAG_SOURCEIP))
							//	{
							//	theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:SOURCEIP:%i"),pTag->GetInt());
							//	}
							//else if (!pTag->m_name.Compare(TAG_SOURCEPORT))
							//	{
							//	theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:SOURCEPORT:%i"),pTag->GetInt());
							//	}
							else if (!pTag->m_name.Compare(TAG_SOURCES))
								{
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:SOURCES:%i"),pTag->GetInt());
								}
							else if (!pTag->m_name.Compare(TAG_SOURCETYPE))
								{
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:SOURCETYPE:%i"),pTag->GetInt());
								}
							//else if (!pTag->m_name.Compare(TAG_SOURCEUPORT))
							//	{
							//	theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:SOURCEUPORT:%i"),pTag->GetInt());
							//	}
							else if (!pTag->m_name.Compare(TAG_STATUS))
								{
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:STATUS:%i"),pTag->GetInt());
								}
							else if (!pTag->m_name.Compare(TAG_USER_COUNT))
								{
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:USER_COUNT:%i"),pTag->GetInt());
								}
							else if (!pTag->m_name.Compare(TAG_VERSION))
								{
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:VERSION:%i"),pTag->GetInt());
								}
							else if (!pTag->m_name.Compare(TAG_DESCRIPTION))
								{
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:DESCRIPTION:%i"),pTag->GetInt());
								}
							else if (!pTag->m_name.Compare(TAG_FAIL))
								{
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:FAIL:%i"),pTag->GetInt());
								}
							else if (!pTag->m_name.Compare(TAG_GAPEND))
								{
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:GAPEND:%i"),pTag->GetInt());
								}
							else if (!pTag->m_name.Compare(TAG_GAPSTART))
								{
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:GAPSTART:%i"),pTag->GetInt());
								}
							else if (!pTag->m_name.Compare(TAG_KADAICHHASHPUB))
								{
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:KADAICHHASHPUB:%i"),pTag->GetInt());
								}
							else if (!pTag->m_name.Compare(TAG_MEDIA_ALBUM))
								{
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:MEDIA_ALBUM:%i"),pTag->GetInt());
								}
							else if (!pTag->m_name.Compare(TAG_MEDIA_ARTIST))
								{
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:MEDIA_ARTIST:%i"),pTag->GetInt());
								}
							else if (!pTag->m_name.Compare(TAG_MEDIA_BITRATE))
								{
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:MEDIA_BITRATE:%i"),pTag->GetInt());
								}
							else if (!pTag->m_name.Compare(TAG_MEDIA_CODEC))
								{
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:MEDIA_CODEC:%i"),pTag->GetInt());
								}
							else if (!pTag->m_name.Compare(TAG_MEDIA_LENGTH))
								{
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:MEDIA_LENGTH:%i"),pTag->GetInt());
								}
							else if (!pTag->m_name.Compare(TAG_MEDIA_TITLE))
								{
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:MEDIA_TITLE:%i"),pTag->GetInt());
								}
							else if (!pTag->m_name.Compare(TAG_PART_HASH))
								{
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:PART_HASH:%i"),pTag->GetInt());
								}
							else if (!pTag->m_name.Compare(TAG_PART_PATH))
								{
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:PART_PATH:%i"),pTag->GetInt());
								}
							else if (!pTag->m_name.Compare(TAG_PING))
								{
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:PING:%i"),pTag->GetInt());
								}
							else if (!pTag->m_name.Compare(TAG_PREFERENCE))
								{
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:PREFERENCE:%i"),pTag->GetInt());
								}
							else if (!pTag->m_name.Compare(TAG_TRANSFERRED))
								{
								theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:TRANSFERRED:%i"),pTag->GetInt());
								}
							else
							{
								//pToAdd->AddTag(pTag);
							theApp.QueueTraceLogLine(TRACE_INDEX_DATA,_T("			Tag:Other type:%s"),ByteToHexStr((uchar*)pTag->m_name.GetBuffer(0),pTag->m_name.GetLength()).GetBuffer(0));
							}
							delete pTag;
						}
						uTotalTags--;
					}
					//pToAdd->m_uKeyID.SetValue(uKeyID);
					//pToAdd->m_uSourceID.SetValue(uSourceID);
					delete pToAdd;
					uNumName--;
				}
				uNumSource--;
			}
			uNumKeys--;
		}


		fileSource.Close();

	}
	else
		DebugLogWarning(_T("Unable to load Kad file: %s"), m_sSourceFileName);

}

///snow:--------------------------------------------------------------------------->by snow