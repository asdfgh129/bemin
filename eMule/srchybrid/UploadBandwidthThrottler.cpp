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
#include <math.h>
#include <Mmsystem.h>
#include "emule.h"
#include "UploadBandwidthThrottler.h"
#include "EMSocket.h"
#include "opcodes.h"
#include "LastCommonRouteFinder.h"
#include "OtherFunctions.h"
#include "emuledlg.h"
#include "uploadqueue.h"
#include "preferences.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif


/**
 * The constructor starts the thread.
 */
UploadBandwidthThrottler::UploadBandwidthThrottler(void) {
	m_SentBytesSinceLastCall = 0;
	m_SentBytesSinceLastCallOverhead = 0;
	m_highestNumberOfFullyActivatedSlots = 0;   ///snow:��ʲô�ã�û������ʲô��

	threadEndedEvent = new CEvent(0, 1);
	pauseEvent = new CEvent(TRUE, TRUE);

	doRun = true;
	AfxBeginThread(RunProc, (LPVOID)this);
}

/**
 * The destructor stops the thread. If the thread has already stoppped, destructor does nothing.
 */
UploadBandwidthThrottler::~UploadBandwidthThrottler(void) {
	EndThread();
	delete threadEndedEvent;
	delete pauseEvent;
}

/**
 * Find out how many bytes that has been put on the sockets since the last call to this
 * method. Includes overhead of control packets.
 * ///snow:��ȡ���ε��÷����ֽ���������
 * @return the number of bytes that has been put on the sockets since the last call
 */
uint64 UploadBandwidthThrottler::GetNumberOfSentBytesSinceLastCallAndReset() {
	sendLocker.Lock();

	uint64 numberOfSentBytesSinceLastCall = m_SentBytesSinceLastCall;
	m_SentBytesSinceLastCall = 0;

	sendLocker.Unlock();

	return numberOfSentBytesSinceLastCall;
}

/**
 * Find out how many bytes that has been put on the sockets since the last call to this
 * method. Excludes overhead of control packets.
 * ///snow:OverHeadָʲô��
 * @return the number of bytes that has been put on the sockets since the last call
 */
uint64 UploadBandwidthThrottler::GetNumberOfSentBytesOverheadSinceLastCallAndReset() {
	sendLocker.Lock();

	uint64 numberOfSentBytesSinceLastCall = m_SentBytesSinceLastCallOverhead;
	m_SentBytesSinceLastCallOverhead = 0;

	sendLocker.Unlock();

	return numberOfSentBytesSinceLastCall;
}

/**
 * Find out the highest number of slots that has been fed data in the normal standard loop
 * of the thread since the last call of this method. This means all slots that haven't
 * been in the trickle state during the entire time since the last call.
 * ///snow:ȡ��߻�Ծ��������ζ�����е�Solt��û�д��ڵι�״̬
 * @return the highest number of fully activated slots during any loop since last call
 */
uint32 UploadBandwidthThrottler::GetHighestNumberOfFullyActivatedSlotsSinceLastCallAndReset() {
    sendLocker.Lock();
    
    //if(m_highestNumberOfFullyActivatedSlots > (uint32)m_StandardOrder_list.GetSize()) {
    //    theApp.QueueDebugLogLine(true, _T("UploadBandwidthThrottler: Throttler wants new slot when get-method called. m_highestNumberOfFullyActivatedSlots: %i m_StandardOrder_list.GetSize(): %i tick: %i"), m_highestNumberOfFullyActivatedSlots, m_StandardOrder_list.GetSize(), ::GetTickCount());
    //}

    uint32 highestNumberOfFullyActivatedSlots = m_highestNumberOfFullyActivatedSlots;
    m_highestNumberOfFullyActivatedSlots = 0;

    sendLocker.Unlock();

    return highestNumberOfFullyActivatedSlots;
}

/**
 * Add a socket to the list of sockets that have upload slots. The main thread will
 * continously call send on these sockets, to give them chance to work off their queues.
 * The sockets are called in the order they exist in the list, so the top socket (index 0)
 * will be given a chance first to use bandwidth, and then the next socket (index 1) etc.
 *
 * It is possible to add a socket several times to the list without removing it inbetween,
 * but that should be avoided.
 * ///snow:��Socket�ӵ���׼�б�
 * @param index insert the socket at this place in the list. An index that is higher than the
 *              current number of sockets in the list will mean that the socket should be inserted
 *              last in the list.
 *
 * @param socket the address to the socket that should be added to the list. If the address is NULL,
 *               this method will do nothing.
 */
void UploadBandwidthThrottler::AddToStandardList(uint32 index, ThrottledFileSocket* socket) {
	if(socket != NULL) {
		sendLocker.Lock();

		RemoveFromStandardListNoLock(socket);
		if(index > (uint32)m_StandardOrder_list.GetSize()) {  ///snow:��ӵ���׼�б�ĩβ��m_StandardOrder_list�д洢���Ǹ��������е�Socket������Packet��һ��socket����һ��slot
			index = m_StandardOrder_list.GetSize();
        }
		m_StandardOrder_list.InsertAt(index, socket);

		sendLocker.Unlock();
//	} else {
//		if (thePrefs.GetVerbose())
//			theApp.AddDebugLogLine(true,"Tried to add NULL socket to UploadBandwidthThrottler Standard list! Prevented.");
	}
}

/**
 * Remove a socket from the list of sockets that have upload slots.
 *
 * If the socket has mistakenly been added several times to the list, this method
 * will return all of the entries for the socket.
 *
 * @param socket the address of the socket that should be removed from the list. If this socket
 *               does not exist in the list, this method will do nothing.
 */
bool UploadBandwidthThrottler::RemoveFromStandardList(ThrottledFileSocket* socket) {
    bool returnValue;
	sendLocker.Lock();

	returnValue = RemoveFromStandardListNoLock(socket);

	sendLocker.Unlock();

    return returnValue;
}

/**
 * Remove a socket from the list of sockets that have upload slots. NOT THREADSAFE!
 * This is an internal method that doesn't take the necessary lock before it removes
 * the socket. This method should only be called when the current thread already owns
 * the sendLocker lock!
 * ///snow:���̰߳�ȫ��������Ϊ���ڲ�������ֻ��sendLocker������������±�����
 * @param socket address of the socket that should be removed from the list. If this socket
 *               does not exist in the list, this method will do nothing.
 */
bool UploadBandwidthThrottler::RemoveFromStandardListNoLock(ThrottledFileSocket* socket) {
	// Find the slot
	int slotCounter = 0;
	bool foundSocket = false;
	while(slotCounter < m_StandardOrder_list.GetSize() && foundSocket == false) {  ///snow:����m_StandardOrder_list���Ƿ����socket������ɾ��
		if(m_StandardOrder_list.GetAt(slotCounter) == socket) {
			// Remove the slot
			m_StandardOrder_list.RemoveAt(slotCounter);
			foundSocket = true;
		} else {
			slotCounter++;
        }
	}

	if(foundSocket && m_highestNumberOfFullyActivatedSlots > (uint32)m_StandardOrder_list.GetSize()) {    ///snow:����з���socket(��Ϊ��ɾ�����б�ı䣩��m_highestNumberOfFullyActivatedSlots����m_StandardOrder_list����
		///snow:m_highestNumberOfFullyActivatedSlots>m_StandardOrder_list.GetSize()������������������δ���û���������£�
		///snow:m_highestNumberOfFullyActivatedSlots = m_StandardOrder_list.GetSize()+1;
        m_highestNumberOfFullyActivatedSlots = m_StandardOrder_list.GetSize();  ///snow:����m_highestNumberOfFullyActivatedSlotsΪm_StandardOrder_list����
    }

    return foundSocket;
}

/**
* Notifies the send thread that it should try to call controlpacket send
* for the supplied socket. It is allowed to call this method several times
* for the same socket, without having controlpacket send called for the socket
* first. The doublette entries are never filtered, since it is incurs less cpu
* overhead to simply call Send() in the socket for each double. Send() will
* already have done its work when the second Send() is called, and will just
* return with little cpu overhead.
* ///snow:��׼�����͵Ŀ��ư�������ʱ�Ŷ��б�
* @param socket address to the socket that requests to have controlpacket send
*               to be called on it
*/
void UploadBandwidthThrottler::QueueForSendingControlPacket(ThrottledControlSocket* socket, bool hasSent) {  ///snow:hasSent����Ƿ����first����
	// Get critical section
	tempQueueLocker.Lock();

	if(doRun) {
        if(hasSent) {
            m_TempControlQueueFirst_list.AddTail(socket);
        } else {
            m_TempControlQueue_list.AddTail(socket);
        }
    }

	// End critical section
	tempQueueLocker.Unlock();
}

/**
 * Remove the socket from all lists and queues. This will make it safe to
 * erase/delete the socket. It will also cause the main thread to stop calling
 * send() for the socket.
 *
 * @param socket address to the socket that should be removed
 */
void UploadBandwidthThrottler::RemoveFromAllQueues(ThrottledControlSocket* socket, bool lock) {
	if(lock) {
		// Get critical section
		sendLocker.Lock();
    }

	///*snow:�ܹ����ĸ����У�m_ControlQueue_list
	///                      m_ControlQueueFirst_list
	///                      m_TempControlQueue_list
	///                      m_TempControlQueueFirst_list 
	///���δ��ĸ�������ɾ����ɾ����socket
	if(doRun) {
        // Remove this socket from control packet queue
        {
            POSITION pos1, pos2;
	        for (pos1 = m_ControlQueue_list.GetHeadPosition();( pos2 = pos1 ) != NULL;) {
		        m_ControlQueue_list.GetNext(pos1);
		        ThrottledControlSocket* socketinQueue = m_ControlQueue_list.GetAt(pos2);

                if(socketinQueue == socket) {
                    m_ControlQueue_list.RemoveAt(pos2);
                }
            }
        }
        
        {
            POSITION pos1, pos2;
	        for (pos1 = m_ControlQueueFirst_list.GetHeadPosition();( pos2 = pos1 ) != NULL;) {
		        m_ControlQueueFirst_list.GetNext(pos1);
		        ThrottledControlSocket* socketinQueue = m_ControlQueueFirst_list.GetAt(pos2);

                if(socketinQueue == socket) {
                    m_ControlQueueFirst_list.RemoveAt(pos2);
                }
            }
        }

		tempQueueLocker.Lock();
        {
            POSITION pos1, pos2;
	        for (pos1 = m_TempControlQueue_list.GetHeadPosition();( pos2 = pos1 ) != NULL;) {
		        m_TempControlQueue_list.GetNext(pos1);
		        ThrottledControlSocket* socketinQueue = m_TempControlQueue_list.GetAt(pos2);

                if(socketinQueue == socket) {
                    m_TempControlQueue_list.RemoveAt(pos2);
                }
            }
        }

        {
            POSITION pos1, pos2;
	        for (pos1 = m_TempControlQueueFirst_list.GetHeadPosition();( pos2 = pos1 ) != NULL;) {
		        m_TempControlQueueFirst_list.GetNext(pos1);
		        ThrottledControlSocket* socketinQueue = m_TempControlQueueFirst_list.GetAt(pos2);

                if(socketinQueue == socket) {
                    m_TempControlQueueFirst_list.RemoveAt(pos2);
                }
            }
        }
		tempQueueLocker.Unlock();
	}

	if(lock) {
		// End critical section
		sendLocker.Unlock();
    }
}
///snow:ͬRemoveFromAllQueues(ThrottledControlSocket* socket)����һ������ControlSocket�����һ��RemoveFromStandardListNoLock(socket);
void UploadBandwidthThrottler::RemoveFromAllQueues(ThrottledFileSocket* socket) {
	// Get critical section
	sendLocker.Lock();

	if(doRun) {
		RemoveFromAllQueues(socket, false);  ///snow : bool lock����ûʲô�ã���ʵ����ȥ����������true������false�����ǵð�����sendLocker.Lock();��sendLocker.UnLock();��

		// And remove it from upload slots
		RemoveFromStandardListNoLock(socket);
	}

	// End critical section
	sendLocker.Unlock();
}

/**
 * Make the thread exit. This method will not return until the thread has stopped
 * looping. This guarantees that the thread will not access the CEMSockets after this
 * call has exited.
 */
void UploadBandwidthThrottler::EndThread() {
	sendLocker.Lock();

	// signal the thread to stop looping and exit.
	doRun = false;

	sendLocker.Unlock();

	Pause(false);  ///snow:SetEvent

	// wait for the thread to signal that it has stopped looping.
	threadEndedEvent->Lock();
}

void UploadBandwidthThrottler::Pause(bool paused) {
	if(paused) {
		pauseEvent->ResetEvent();
	} else {
		pauseEvent->SetEvent();
    }
} 

///snow:solt��������ʲô��solt��ʾ�����ж��ٿͻ����ѽ������ӣ��ж����ļ��ϴ�����ÿһ���ϴ������Ӧһ��socket����һ��socket����һ��solt
///snow:�������������ͬʱ�ϴ���Solt����
uint32 UploadBandwidthThrottler::GetSlotLimit(uint32 currentUpSpeed) {
	uint32 upPerClient = UPLOAD_CLIENT_DATARATE;  ///snow:3K

    // if throttler doesn't require another slot, go with a slightly more restrictive method
	if( currentUpSpeed > 20*1024 )  ///snow :20K
		upPerClient += currentUpSpeed/43;

	if( upPerClient > 7680 )
		upPerClient = 7680;  ///snow:���ޣ�7K

	//now the final check

	uint16 nMaxSlots;
	if (currentUpSpeed > 12*1024)   ///snow:12K
		nMaxSlots = (uint16)(((float)currentUpSpeed) / upPerClient);  ///snow:�����ϴ��ٶ�300K,nMaxSolts=300/7=40
	else if (currentUpSpeed > 7*1024)   ///snow:12K>currentUpSpeed>7K
		nMaxSlots = MIN_UP_CLIENTS_ALLOWED + 2;   ///nMaxSolts = 4
	else if (currentUpSpeed > 3*1024)
		nMaxSlots = MIN_UP_CLIENTS_ALLOWED + 1;
	else
		nMaxSlots = MIN_UP_CLIENTS_ALLOWED;  ///snow:����2��ͬʱ�ϴ�

    return max(nMaxSlots, MIN_UP_CLIENTS_ALLOWED);
}


///snow:consecutiveChange  �����仯��ָʲô�أ�ָnSlotsBusyLevel�仯��Ƶ�ʣ����������ٶȵĵ�������
uint32 UploadBandwidthThrottler::CalculateChangeDelta(uint32 numberOfConsecutiveChanges) const {
    switch(numberOfConsecutiveChanges) {
        case 0: return 50;
        case 1: return 50;
        case 2: return 128;
        case 3: return 256;
        case 4: return 512;
        case 5: return 512+256;
        case 6: return 1*1024;
        case 7: return 1*1024+256;
        default: return 1*1024+512;
    }
}

/**
 * Start the thread. Called from the constructor in this class.
 *
 * @param pParam
 *
 * @return
 */
UINT AFX_CDECL UploadBandwidthThrottler::RunProc(LPVOID pParam) {
	DbgSetThreadName("UploadBandwidthThrottler");
	InitThreadLocale();
	UploadBandwidthThrottler* uploadBandwidthThrottler = (UploadBandwidthThrottler*)pParam;

	return uploadBandwidthThrottler->RunInternal();
}

/**
 * The thread method that handles calling send for the individual sockets.
 *
 * Control packets will always be tried to be sent first. If there is any bandwidth leftover
 * after that, send() for the upload slot sockets will be called in priority order until we have run
 * out of available bandwidth for this loop. Upload slots will not be allowed to go without having sent
 * called for more than a defined amount of time (i.e. two seconds).
 *
 * @return always returns 0.
 */
UINT UploadBandwidthThrottler::RunInternal() {
	DWORD lastLoopTick = timeGetTime();
	sint64 realBytesToSpend = 0;
	uint32 allowedDataRate = 0;
    uint32 rememberedSlotCounter = 0;
    DWORD lastTickReachedBandwidth = timeGetTime();

	uint32 nEstiminatedLimit = 0;
	int nSlotsBusyLevel = 0;
	DWORD nUploadStartTime = 0;
    uint32 numberOfConsecutiveUpChanges = 0;
    uint32 numberOfConsecutiveDownChanges = 0;
    uint32 changesCount = 0;
    uint32 loopsCount = 0;

    bool estimateChangedLog = false;
    bool lotsOfLog = false;
	bool bAlwaysEnableBigSocketBuffers = false;

	while(doRun) {  ///snow:ѭ��һֱִ�У�ֱ��EndThread,��doRun=false
        pauseEvent->Lock();

		DWORD timeSinceLastLoop = timeGetTime() - lastLoopTick;   ///snow:ѭ����ʼ��ʱ��ͳ�Ʊ���ѭ������ʱ�䣬ѭ���ڲ�ͣ���У�����һ�־�ͳ��һ��ʱ��
		///snow:lastLoopTickΪ����ѭ����������ǰ��ʱ��

		// Get current speed from UploadSpeedSense

		allowedDataRate = theApp.lastCommonRouteFinder->GetUpload();   ///snow:û���趨���ٵ�ʱ��allowedDataRate=0xFFFFFFFF(4294967295)==_UI32_MAX������ϴ������ж��壬�����ϴ����٣��趨Ϊ100Kʱ��allowedDataRate=102400

		
        // check busy level for all the slots (WSAEWOULDBLOCK status)
        uint32 cBusy = 0;
        uint32 nCanSend = 0;

        sendLocker.Lock();
		/********************************************* snow:start ************************  
		/*   iС��m_StandardOrder_list���� �� ����������һ������
		/*          1��i<3
		/*          2��i<GetSlotLimit()
		*********************************************snow:end ****************************/
        for (int i = 0; i < m_StandardOrder_list.GetSize() && (i < 3 || (UINT)i < GetSlotLimit(theApp.uploadqueue->GetDatarate())); i++){
            if (m_StandardOrder_list[i] != NULL && m_StandardOrder_list[i]->HasQueues()) {
				nCanSend++;   ///snow:ͳ�ƿ��Է��Ͱ���  ���ˣ������ǰ�������socket����solt������������ͬʱ�ϴ���Socket��

                if(m_StandardOrder_list[i]->IsBusy())
					cBusy++;   ///snow:ͳ����������  ���ˣ������ǰ�������socket����solt�����������ڵȺ��ϴ���socket��
            }
		}
        sendLocker.Unlock();

        // if this is kept, the loop above can be a little optimized (don't count nCanSend, just use nCanSend = GetSlotLimit(theApp.uploadqueue->GetDatarate())
        if(theApp.uploadqueue)
            nCanSend = max(nCanSend, GetSlotLimit(theApp.uploadqueue->GetDatarate()));

        // When no upload limit has been set in options, try to guess a good upload limit.
		bool bUploadUnlimited = (thePrefs.GetMaxUpload() == UNLIMITED);


		/*************************************************snow:start***************************************************************
		/*   ���⣺��preference��û�����������ٶȣ�������������������
		/*   nSoltBusyLevel����æˮƽ������255������-255
		/*   loopsCount    : ͳ��ѭ���Ѿ����м����ˣ�ѭ�����ڲ������еģ�ÿ����һ��,loopsCount�ͼ�1
		/*   changeCount   :ͳ��nSoltBusyLevel������������������ӻ��Ǽ���
		/*   numberOfConsecutiveDownChanges,numberOfConsecutiveUpChanges��������ֵ
        /*   changeDelta   �����ٷ���
		/*   ����æ�ȣ�cBusy/nCanSend��>75% nSlotsBusyLevel���ӣ�����255������æ��<25%ʱ��nSlotsBusyLevel�½����½�-255 ÿѭ��һ�Σ����һ��
		/*   ����æ�ȱ��һ�Σ�changecount������һ��
		/*   �������漸�������������������
		**************************************************snow:end ***************************************************************/
		///snow:û�����ٵ������
		if (bUploadUnlimited) {
            loopsCount++;

            //if(lotsOfLog) theApp.QueueDebugLogLine(false,_T("Throttler: busy: %i/%i nSlotsBusyLevel: %i Guessed limit: %0.5f changesCount: %i loopsCount: %i"), cBusy, nCanSend, nSlotsBusyLevel, (float)nEstiminatedLimit/1024.00f, changesCount, loopsCount);

            if(nCanSend > 0) {
			    float fBusyPercent = ((float)cBusy/(float)nCanSend) * 100;
                if (cBusy > 2 && fBusyPercent > 75.00f && nSlotsBusyLevel < 255){
				    nSlotsBusyLevel++;
                    changesCount++;
                    if(thePrefs.GetVerbose() && lotsOfLog && nSlotsBusyLevel%25==0) theApp.QueueDebugLogLine(false,_T("Throttler: nSlotsBusyLevel: %i Guessed limit: %0.5f changesCount: %i loopsCount: %i"), nSlotsBusyLevel, (float)nEstiminatedLimit/1024.00f, changesCount, loopsCount);
			    }
			    else if ( (cBusy <= 2 || fBusyPercent < 25.00f) && nSlotsBusyLevel > (-255)){
				    nSlotsBusyLevel--;
                    changesCount++;
                    if(thePrefs.GetVerbose() && lotsOfLog && nSlotsBusyLevel%25==0) theApp.QueueDebugLogLine(false,_T("Throttler: nSlotsBusyLevel: %i Guessed limit: %0.5f changesCount %i loopsCount: %i"), nSlotsBusyLevel, (float)nEstiminatedLimit/1024.00f, changesCount, loopsCount);
                }
			}

			 ///snow:׼����ʼ�ϴ�����û��ʼ
			if(nUploadStartTime == 0) 
			{  
				if (m_StandardOrder_list.GetSize() >= 3)   ///snow:��3������socket�ȴ��ϴ���������nUploadStartTime��������ﵽ3����������nUploadStartTime��nUploadStartTime��ȻΪ0��Ϊʲô��
					nUploadStartTime = timeGetTime();      ///snow:Ҳ����˵���ȴ��ϴ�socket��С��3ʱ��nUploadStartTimeһֱΪ0���Ͳ�����ִ��else��֧���е�����
			} 
			///snow:��ʼ�ϴ�����1���ӣ����Կ�ʼ�����ٶ��ˣ�����m_StandardOrder_list�е�socket��С��3ʱ��������
			else if(timeGetTime()- nUploadStartTime > SEC2MS(60)) 
			{   
				if (theApp.uploadqueue){   ///snow:�����ϴ����У����û���ϴ����У��Ͳ�����������
				    if (nEstiminatedLimit == 0){ // no autolimit was set yet  ///snow:nEstiminatedLimit��δ��ֵ����ֵΪ0 ��Estiminated����ΪEstimated�ı���
					    if (nSlotsBusyLevel >= 250){ // sockets indicated that the BW limit has been reached   ///snow:�Ѿ���æ��
							nEstiminatedLimit = theApp.uploadqueue->GetDatarate();  ///snow:��ȡ��ǰ�ϴ����ʣ���������ϴ����ʱȽϣ�ȡСֵ
							allowedDataRate = min(nEstiminatedLimit, allowedDataRate);  ///snow:�����ǰ�ϴ�����û�ﵽ�򳬹�������ϴ����ʣ�����allowedDataRate������nSlotsBusyLevelֵΪ-200
						    nSlotsBusyLevel = -200;
                            if(thePrefs.GetVerbose() && estimateChangedLog) theApp.QueueDebugLogLine(false,_T("Throttler: Set inital estimated limit to %0.5f changesCount: %i loopsCount: %i"), (float)nEstiminatedLimit/1024.00f, changesCount, loopsCount);
							changesCount = 0;  ///snow:�����в���  nSlotsBusyLevel������Ϊ-200��changesCount��loopsCount������Ϊ0
							loopsCount = 0;    ///snow:changesCount,loopsCount��ҪΪ����numberOfConsecutiveDownChanges�ṩ����
					    }
				    }
					else{  ///snow:nEstiminatedLimit ��= 0���Ѿ����������������
						if (nSlotsBusyLevel > 250){  ///snow:��Ҫ��������
							if(changesCount > 500 || changesCount > 300 && loopsCount > 1000 || loopsCount > 2000) {  ///snow:��ѭ�������˺ܶ�Σ�����1000������2000����nSlotsBusyLevel����Ѿ�����300������500����
								numberOfConsecutiveDownChanges = 0;   ///snow:�ѵ������Ƚ�����ͣ���������Ϊ���кܾ��ˣ��Ƚ��ȶ���
                            }
							numberOfConsecutiveDownChanges++;   ///snow:numberOfConsecutiveDownChangesȡֵ��Χ 0---7���ο�CalculateChangeDelta������ȡֵԽ��ÿ���ٶȵĵ�������Խ��
							uint32 changeDelta = CalculateChangeDelta(numberOfConsecutiveDownChanges);  ///snow:ȡֵ��Χ 50-1024+512��changeDelta��ֵΪÿ�ε��ٵķ��ȣ����ÿѭ��һ�ν�1.5K

                            // Don't lower speed below 1 KBytes/s
							if(nEstiminatedLimit < changeDelta + 1024) {   ///snow:������1K
                                if(nEstiminatedLimit > 1024) {
                                    changeDelta = nEstiminatedLimit - 1024;
                                } else {
                                    changeDelta = 0;
                                }
                            }
                            ASSERT(nEstiminatedLimit >= changeDelta + 1024);
							nEstiminatedLimit -= changeDelta;   ///snow:�ϴ��������ٵ���changeDelta

                            if(thePrefs.GetVerbose() && estimateChangedLog) theApp.QueueDebugLogLine(false,_T("Throttler: REDUCED limit #%i with %i bytes to: %0.5f changesCount: %i loopsCount: %i"), numberOfConsecutiveDownChanges, changeDelta, (float)nEstiminatedLimit/1024.00f, changesCount, loopsCount);
							///snow:���������٣��������ĸ�ָ��͹���
                            numberOfConsecutiveUpChanges = 0;
						    nSlotsBusyLevel = 0;
                            changesCount = 0;
                            loopsCount = 0;
					    }
						else if (nSlotsBusyLevel < (-250)){   ///snow:��Ҫ�������٣�ԭ��ͬ����
                            if(changesCount > 500 || changesCount > 300 && loopsCount > 1000 || loopsCount > 2000) {
                                numberOfConsecutiveUpChanges = 0;
                            }
                            numberOfConsecutiveUpChanges++;
                            uint32 changeDelta = CalculateChangeDelta(numberOfConsecutiveUpChanges);

                            // Don't raise speed unless we are under current allowedDataRate
							if(nEstiminatedLimit+changeDelta > allowedDataRate) {    ///snow:��������������
                                if(nEstiminatedLimit < allowedDataRate) {
                                    changeDelta = allowedDataRate - nEstiminatedLimit;
                                } else {
                                    changeDelta = 0;
                                }
                            }
                            ASSERT(nEstiminatedLimit < allowedDataRate && nEstiminatedLimit+changeDelta <= allowedDataRate || nEstiminatedLimit >= allowedDataRate && changeDelta == 0);
                            nEstiminatedLimit += changeDelta;

                            if(thePrefs.GetVerbose() && estimateChangedLog) theApp.QueueDebugLogLine(false,_T("Throttler: INCREASED limit #%i with %i bytes to: %0.5f changesCount: %i loopsCount: %i"), numberOfConsecutiveUpChanges, changeDelta, (float)nEstiminatedLimit/1024.00f, changesCount, loopsCount);
                            ///snow�����������٣��������ĸ�ָ��͹���
                            numberOfConsecutiveDownChanges = 0;
						    nSlotsBusyLevel = 0;
                            changesCount = 0;
                            loopsCount = 0;
					    }

						allowedDataRate = min(nEstiminatedLimit, allowedDataRate);  ///snow:��Ԥ�����ϴ��ٶȻ�������ϴ��ٶ�����֮��ȡСֵ
				    } 
			    }
            }
		}///snow:δ�趨����

		///snow:ȫ�������ˣ������������������ˣ�����nSlotsBusyLevelΪ125
		if(cBusy == nCanSend && m_StandardOrder_list.GetSize() > 0) {   
            allowedDataRate = 0;
            if(nSlotsBusyLevel < 125 && bUploadUnlimited) {
                nSlotsBusyLevel = 125;
                if(thePrefs.GetVerbose() && lotsOfLog) theApp.QueueDebugLogLine(false,_T("Throttler: nSlotsBusyLevel: %i Guessed limit: %0.5f changesCount %i loopsCount: %i (set due to all slots busy)"), nSlotsBusyLevel, (float)nEstiminatedLimit/1024.00f, changesCount, loopsCount);
            }
        }

		uint32 minFragSize = 1300;
        uint32 doubleSendSize = minFragSize*2; // send two packages at a time so they can share an ACK
		if(allowedDataRate < 6*1024) {   ///snow:�����ϴ��ٶȵ���6K������֡����Ϊ536
			minFragSize = 536;
            doubleSendSize = minFragSize; // don't send two packages at a time at very low speeds to give them a smoother load
		}

		///��������ʱ�䣬ֹͣ�ϴ�,ͨ����������ʱ�����ﵽ���ٵ�Ŀ��
#define TIME_BETWEEN_UPLOAD_LOOPS 1
        uint32 sleepTime;
        if(allowedDataRate == _UI32_MAX || realBytesToSpend >= 1000 || allowedDataRate == 0 && nEstiminatedLimit == 0) {
            // we could send at once, but sleep a while to not suck up all cpu
			sleepTime = TIME_BETWEEN_UPLOAD_LOOPS;  ///snow:�������Ҫ���٣�����1ms����ֹռ��ȫ��CPUʱ��
		} else if(allowedDataRate == 0) {  ///snow: nEstiminatedLimit!=0
			sleepTime = max((uint32)ceil(((double)doubleSendSize*1000)/nEstiminatedLimit), TIME_BETWEEN_UPLOAD_LOOPS);  ///snow:ceil()���ش��ڻ��ߵ���ָ�����ʽ����С����
			///snow:����nEstiminatedLimitΪ2048(2K),��sleepTime=max(536*1000/2048,1)=262ms������nEstiminatedLimitΪ6144(6K),��sleepTime=max(2600*1000/6144,1)=424ms��
        } else {
            // sleep for just as long as we need to get back to having one byte to send
			///snow:��Ϊ�ϴ����ˣ�realBytesToSpendΪ��������������300K/S���ϴ�ѭ�����ϴ���2K��
            sleepTime = max((uint32)ceil((double)(-realBytesToSpend + 1000)/allowedDataRate), TIME_BETWEEN_UPLOAD_LOOPS);
			
        }

        if(timeSinceLastLoop < sleepTime) {
			Sleep(sleepTime-timeSinceLastLoop);   ///snow:����һС��
        }

		const DWORD thisLoopTick = timeGetTime();
		timeSinceLastLoop = thisLoopTick - lastLoopTick;

		// Calculate how many bytes we can spend
        sint64 bytesToSpend = 0;

		/********************************* snow:start ***********************************************
		/*   ���������allowedDataRate != _UI32_MAX��
		/*        1��û���������٣������䷱æ�������allowedDataRate��ֱ��Ϊ0����ʾ�������������ϴ�
		/*        2������������
		/********************************* snow:end ************************************************/
		if(allowedDataRate != _UI32_MAX) 
		{   
            // prevent overflow   ///snow:Ԥ��������ν⣿
            if(timeSinceLastLoop == 0)
			{
                // no time has passed, so don't add any bytes. Shouldn't happen.
                bytesToSpend = 0; //realBytesToSpend/1000;
            } 
			else if(_I64_MAX/timeSinceLastLoop > allowedDataRate && _I64_MAX-allowedDataRate*timeSinceLastLoop > realBytesToSpend) 
			{
				if(timeSinceLastLoop > sleepTime + 2000)   ///snow:����2��
				{
			        theApp.QueueDebugLogLine(false,_T("UploadBandwidthThrottler: Time since last loop too long. time: %ims wanted: %ims Max: %ims"), timeSinceLastLoop, sleepTime, sleepTime + 2000);
        
                    timeSinceLastLoop = sleepTime + 2000;
					lastLoopTick = thisLoopTick - timeSinceLastLoop;  ///snow:����ģ��ر������lastLoopTick = thisLoopTick; ����
                }

				realBytesToSpend += allowedDataRate*timeSinceLastLoop;   ///snow:������Ӧ���͵��ֽ������������ϴ�ѭ��û�����999�ֽڣ�����ϴ�ѭ������û���꣬realBytesToSpendֵ����Ϊ999��

				bytesToSpend = realBytesToSpend/1000;  ///snow:��K���㣬���ݵ�ǰ�趨�Ĵ������Է��͵��ֽ���
            } 
			else 
			{
                realBytesToSpend = _I64_MAX;
                bytesToSpend = _I32_MAX;
            }
        } 
		else {
            realBytesToSpend = 0; //_I64_MAX;
			bytesToSpend = _I32_MAX;   ///snow:�ܷ��Ͷ������ݾͷ��Ͷ���
        }

		lastLoopTick = thisLoopTick;  ///snow:�ڷ�������ǰ���µ�ǰʱ�̣���Ϊ��һѭ��ʱ����ʼ�㡣��������Ŀ���Ǳ���ѭ��ͳ�Ƶ�ʱ��ʵ��Ϊ�ϴ�ѭ���������ݵ�ʱ��

		/************************************************** snow:start **************************************
		/* ����ⷢ���ֽ���>=1�����������ϴ��ٶ�==0��������temp�����еİ���ӵ���������ĩβ��
		/*     ������������������ʱ��
		/*        1��bytesToSpend > 0 && spentBytes < (uint64)bytesToSpend �� allowedDataRate == 0 && spentBytes < 500
		/*           ��ʾ�ѷ����ֽ���С���ⷢ���ֽ��� ��  �����ϴ��������Ҳ��ѷ�����С��500    
		/*        2��m_ControlQueueFirst_list��m_ControlQueue_list��Ϊ��
		/*     ���Ϳ��ư�����ͳ�Ʒ��͵��ֽ���
		*************************************************** snow:end **************************************/
		if(bytesToSpend >= 1 || allowedDataRate == 0) {   ///snow:����ʲô��˼���������������ϴ�����ڴ��ϴ������ݣ����ϴ��Ŀ�����⣬allowedDataRate == 0��Ϊʲô�أ�
			uint64 spentBytes = 0;     ///snow:��׼���ֽ���+���ư��ֽ���
			uint64 spentOverhead = 0;  ///snow:ֻͳ�ƿ��ư��ֽ���
    
		    sendLocker.Lock();
    
		    tempQueueLocker.Lock();
    
			///snow:��������Ŀ����ʲô��Ϊʲô��ֱ�Ӿͷ����������У���ô��ʵ�ֱ߷��ͱ�����ˣ�û����
		    // are there any sockets in m_TempControlQueue_list? Move them to normal m_ControlQueue_list;
            while(!m_TempControlQueueFirst_list.IsEmpty()) {
                ThrottledControlSocket* moveSocket = m_TempControlQueueFirst_list.RemoveHead();
                m_ControlQueueFirst_list.AddTail(moveSocket);
            }
		    while(!m_TempControlQueue_list.IsEmpty()) {
			    ThrottledControlSocket* moveSocket = m_TempControlQueue_list.RemoveHead();
			    m_ControlQueue_list.AddTail(moveSocket);
		    }
    
		    tempQueueLocker.Unlock();
    
			///snow:������ư��б��ĸ�����ֻ��ſ��ư���Ϣ
		    // Send any queued up control packets first 
			///snow:���ȷ���First���У�First���з�����ŷ�����������
		    while((bytesToSpend > 0 && spentBytes < (uint64)bytesToSpend || allowedDataRate == 0 && spentBytes < 500) && (!m_ControlQueueFirst_list.IsEmpty() || !m_ControlQueue_list.IsEmpty())) {
			    ThrottledControlSocket* socket = NULL;
    
                if(!m_ControlQueueFirst_list.IsEmpty()) {
                    socket = m_ControlQueueFirst_list.RemoveHead();
                } else if(!m_ControlQueue_list.IsEmpty()) {
                    socket = m_ControlQueue_list.RemoveHead();
                }
    
			    if(socket != NULL) {
					///snow:����bytesToSpend - spentBytes���ֽڣ���allowedDataRate=0ʱ��1���ֽ�1���ֽڷ��͡�ΪʲôҪ1���ֽڷ��ͣ�
                    SocketSentBytes socketSentBytes = socket->SendControlData(allowedDataRate > 0?(UINT)(bytesToSpend - spentBytes):1, minFragSize);
				    uint32 lastSpentBytes = socketSentBytes.sentBytesControlPackets + socketSentBytes.sentBytesStandardPackets;
				    spentBytes += lastSpentBytes;
				    spentOverhead += socketSentBytes.sentBytesControlPackets;
			    }
		    }
			///snow:�����׼�б��ȿɴ�����ư���Ҳ�ɴ����׼��
		    // Check if any sockets haven't gotten data for a long time. Then trickle them a package.
		    for(uint32 slotCounter = 0; slotCounter < (uint32)m_StandardOrder_list.GetSize(); slotCounter++) {
			    ThrottledFileSocket* socket = m_StandardOrder_list.GetAt(slotCounter);
    
			    if(socket != NULL) {
					if(thisLoopTick-socket->GetLastCalledSend() > SEC2MS(1)) {   ///snow:�����ϴε��ó���1���ӣ�����һ��û�������ݵĲŷ���
					    // trickle
						uint32 neededBytes = socket->GetNeededBytes(); ///snow:����neededBytes���ֽ�
    
					    if(neededBytes > 0) {
						    SocketSentBytes socketSentBytes = socket->SendFileAndControlData(neededBytes, minFragSize);
						    uint32 lastSpentBytes = socketSentBytes.sentBytesControlPackets + socketSentBytes.sentBytesStandardPackets;
						    spentBytes += lastSpentBytes;
						    spentOverhead += socketSentBytes.sentBytesControlPackets;

                            if(lastSpentBytes > 0 && slotCounter < m_highestNumberOfFullyActivatedSlots) {
                                m_highestNumberOfFullyActivatedSlots = slotCounter;
                            }
					    }
				    }
			    } else {
				    theApp.QueueDebugLogLine(false,_T("There was a NULL socket in the UploadBandwidthThrottler Standard list (trickle)! Prevented usage. Index: %i Size: %i"), slotCounter, m_StandardOrder_list.GetSize());
                }
		    }

			///snow:ǰ�洦����ǿ��ư����к�m_StandardOrder_list�г�ʱ��û�������ݵ�SOCKET���������ʽ��ʼ����m_StandardOrder_list�е�Socket
						
		    // Equal bandwidth for all slots
            uint32 maxSlot = (uint32)m_StandardOrder_list.GetSize();
			if(maxSlot > 0 && allowedDataRate/maxSlot < UPLOAD_CLIENT_DATARATE) {   ///snow:���ÿsolt�����ʴﲻ��3K������solt��
                maxSlot = allowedDataRate/UPLOAD_CLIENT_DATARATE;
			}   ///snow:��δ��������maxSlot�����ܴ���m_StandardOrder_list.GetSize()

			///snow:�ϴ����ʴ���300K������ÿSolt���ʴ���100Kʱ���ô󻺳���
			// if we are uploading fast, increase the sockets sendbuffers in order to be able to archive faster
			// speeds
			bool bUseBigBuffers = bAlwaysEnableBigSocketBuffers;
			if (maxSlot > 0 && (allowedDataRate == _UI32_MAX || allowedDataRate/maxSlot > 100 * 1024) && theApp.uploadqueue->GetDatarate() > 300 * 1024)
				bUseBigBuffers = true;

            if(maxSlot > m_highestNumberOfFullyActivatedSlots) {
			    m_highestNumberOfFullyActivatedSlots = maxSlot;
            }

            for(uint32 maxCounter = 0; maxCounter < min(maxSlot, (uint32)m_StandardOrder_list.GetSize()) && bytesToSpend > 0 && spentBytes < (uint64)bytesToSpend; maxCounter++) {
                if(rememberedSlotCounter >= (uint32)m_StandardOrder_list.GetSize() ||
                   rememberedSlotCounter >= maxSlot) {
                    rememberedSlotCounter = 0;
				}  ///snow:rememberedSlotCounter��forѭ����ʼʱΪ0��maxSoltһ��С��m_StandardOrder_list.GetSize()������forѭ��ִ�в��ᳬ��maxSolt�Σ�rememberedSlotCounter��ֵ�����ܳ���maxSolt,��rememberedSlotCounter==maxSoltʱ��ѭ��ִ�����ˣ�����������δ�����ɶ���壿������

                ThrottledFileSocket* socket = m_StandardOrder_list.GetAt(rememberedSlotCounter);
				if(socket != NULL) {
					if (bUseBigBuffers)
						socket->UseBigSendBuffer();
					SocketSentBytes socketSentBytes = socket->SendFileAndControlData((UINT)min(doubleSendSize, bytesToSpend-spentBytes), doubleSendSize);
					uint32 lastSpentBytes = socketSentBytes.sentBytesControlPackets + socketSentBytes.sentBytesStandardPackets;

					spentBytes += lastSpentBytes;
					spentOverhead += socketSentBytes.sentBytesControlPackets;
				} else {
					theApp.QueueDebugLogLine(false,_T("There was a NULL socket in the UploadBandwidthThrottler Standard list (equal-for-all)! Prevented usage. Index: %i Size: %i"), rememberedSlotCounter, m_StandardOrder_list.GetSize());
                }

                rememberedSlotCounter++;
            }

			///snow:��spentBytes < (uint64)bytesToSpendʱ������û���꣬�����������ݣ�����Ĵ��뷢�͵��ֽ�����min(doubleSendSize, bytesToSpend-spentBytes)������Ĵ��뷢�͵��ֽ����ǣ�bytesToSpend-spentBytes���������spentBytes��ͬ����������spentBytes����Ϊ����Ĵ����ַ�����Щ���ݣ�����spentBytes��С�ˣ�������������ˣ�����Ĵ���Ͳ���ִ����

		    // Any bandwidth that hasn't been used yet are used first to last.
			for(uint32 slotCounter = 0; slotCounter < (uint32)m_StandardOrder_list.GetSize() && bytesToSpend > 0 && spentBytes < (uint64)bytesToSpend; slotCounter++) {
				ThrottledFileSocket* socket = m_StandardOrder_list.GetAt(slotCounter);

				if(socket != NULL) {
                    uint32 bytesToSpendTemp = (UINT)(bytesToSpend-spentBytes);
					SocketSentBytes socketSentBytes = socket->SendFileAndControlData(bytesToSpendTemp, doubleSendSize);
					uint32 lastSpentBytes = socketSentBytes.sentBytesControlPackets + socketSentBytes.sentBytesStandardPackets;

					spentBytes += lastSpentBytes;
					spentOverhead += socketSentBytes.sentBytesControlPackets;

                    if(slotCounter+1 > m_highestNumberOfFullyActivatedSlots && (lastSpentBytes < bytesToSpendTemp || lastSpentBytes >= doubleSendSize)) { // || lastSpentBytes > 0 && spentBytes == bytesToSpend /*|| slotCounter+1 == (uint32)m_StandardOrder_list.GetSize())*/)) {
                        m_highestNumberOfFullyActivatedSlots = slotCounter+1;
                    }
				} else {
					theApp.QueueDebugLogLine(false,_T("There was a NULL socket in the UploadBandwidthThrottler Standard list (fully activated)! Prevented usage. Index: %i Size: %i"), slotCounter, m_StandardOrder_list.GetSize());
                }
			}
		    realBytesToSpend -= spentBytes*1000;  ///����ѭ��Ӧ�÷��͵��ֽ���-ʵ�ʷ��͵��ֽ���=��δ���͵��ֽ������෢�͵��ֽ�����

			///snow:�����Ķη������ݵĴ��벻�ǲ���ִ�еģ����Ǵ�������˳��ִ�еģ�ֻ�����϶η����ֽ���������ʱ���¶δ���Żᱻִ�С�ÿ�δ��붼����������е�Socket

            // If we couldn't spend all allocated bandwidth this loop, some of it is allowed to be saved
            // and used the next loop
			///snow:realBytesToSpendֵԽС����ʾ�ϴ�Խ�죬�ഫ�͵�����Խ��
		    if(realBytesToSpend < -(((sint64)m_StandardOrder_list.GetSize()+1)*minFragSize)*1000) {   ///����minFragSize=536,����socket����-��2+1��*536*1000=1.5M��
			    sint64 newRealBytesToSpend = -(((sint64)m_StandardOrder_list.GetSize()+1)*minFragSize)*1000;
				///snow:realBytesToSpend=newRealBytesToSpendΪ��ֵ
			    realBytesToSpend = newRealBytesToSpend;
				lastTickReachedBandwidth = thisLoopTick;  ///snow:�ϴδ��������ʱ��,����û����Ļ�������������������ʹ��
            } else {
				uint64 bandwidthSavedTolerance = 0;   ///snow:������δʹ��
				if(realBytesToSpend > 0 && (uint64)realBytesToSpend > 999+bandwidthSavedTolerance) {  ///snow:����ѭ���ϴ����ʲ���������������û������
			        sint64 newRealBytesToSpend = 999+bandwidthSavedTolerance;
			        //theApp.QueueDebugLogLine(false,_T("UploadBandwidthThrottler::RunInternal(): Too high saved bytesToSpend. Limiting value. Old value: %I64i New value: %I64i"), realBytesToSpend, newRealBytesToSpend);
					realBytesToSpend = newRealBytesToSpend;   ///snow:realBytesToSpend=999��δ����1000

					if(thisLoopTick-lastTickReachedBandwidth > max(1000, timeSinceLastLoop*2)) {  ///snow:����ϴδ��������ʱ���ѳ���1����ѳ�������ѭ����ʱ��
						m_highestNumberOfFullyActivatedSlots = m_StandardOrder_list.GetSize()+1;   ///snow:����solt��
                        lastTickReachedBandwidth = thisLoopTick;
                        //theApp.QueueDebugLogLine(false, _T("UploadBandwidthThrottler: Throttler requests new slot due to bw not reached. m_highestNumberOfFullyActivatedSlots: %i m_StandardOrder_list.GetSize(): %i tick: %i"), m_highestNumberOfFullyActivatedSlots, m_StandardOrder_list.GetSize(), thisLoopTick);
                    }
                } else {
                    lastTickReachedBandwidth = thisLoopTick;
                }
            }
		    
            // save info about how much bandwidth we've managed to use since the last time someone polled us about used bandwidth
		    m_SentBytesSinceLastCall += spentBytes;
		    m_SentBytesSinceLastCallOverhead += spentOverhead;
    
            sendLocker.Unlock();
        }
	}

	threadEndedEvent->SetEvent();

	tempQueueLocker.Lock();
	m_TempControlQueue_list.RemoveAll();
	m_TempControlQueueFirst_list.RemoveAll();
	tempQueueLocker.Unlock();

	sendLocker.Lock();

	m_ControlQueue_list.RemoveAll();
	m_StandardOrder_list.RemoveAll();
	sendLocker.Unlock();

	return 0;
}