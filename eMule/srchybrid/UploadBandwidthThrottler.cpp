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
	m_highestNumberOfFullyActivatedSlots = 0;   ///snow:做什么用？没看出有什么用

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
 * ///snow:获取本次调用发送字节数并重置
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
 * ///snow:OverHead指什么？
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
 * ///snow:取最高活跃槽数，意味着所有的Solt都没有处在滴灌状态
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
 * ///snow:将Socket加到标准列表
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
		if(index > (uint32)m_StandardOrder_list.GetSize()) {  ///snow:添加到标准列表末尾，m_StandardOrder_list中存储的是各个连接中的Socket，不是Packet，一个socket就是一个slot
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
 * ///snow:非线程安全函数，因为是内部函数，只在sendLocker已锁定的情况下被调用
 * @param socket address of the socket that should be removed from the list. If this socket
 *               does not exist in the list, this method will do nothing.
 */
bool UploadBandwidthThrottler::RemoveFromStandardListNoLock(ThrottledFileSocket* socket) {
	// Find the slot
	int slotCounter = 0;
	bool foundSocket = false;
	while(slotCounter < m_StandardOrder_list.GetSize() && foundSocket == false) {  ///snow:遍历m_StandardOrder_list，是否存在socket，有则删除
		if(m_StandardOrder_list.GetAt(slotCounter) == socket) {
			// Remove the slot
			m_StandardOrder_list.RemoveAt(slotCounter);
			foundSocket = true;
		} else {
			slotCounter++;
        }
	}

	if(foundSocket && m_highestNumberOfFullyActivatedSlots > (uint32)m_StandardOrder_list.GetSize()) {    ///snow:如果有发现socket(因为被删除，列表改变）且m_highestNumberOfFullyActivatedSlots大于m_StandardOrder_list项数
		///snow:m_highestNumberOfFullyActivatedSlots>m_StandardOrder_list.GetSize()的情况发生在连续两次带宽没用完的情况下：
		///snow:m_highestNumberOfFullyActivatedSlots = m_StandardOrder_list.GetSize()+1;
        m_highestNumberOfFullyActivatedSlots = m_StandardOrder_list.GetSize();  ///snow:设置m_highestNumberOfFullyActivatedSlots为m_StandardOrder_list项数
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
* ///snow:将准备发送的控制包加入临时排队列表
* @param socket address to the socket that requests to have controlpacket send
*               to be called on it
*/
void UploadBandwidthThrottler::QueueForSendingControlPacket(ThrottledControlSocket* socket, bool hasSent) {  ///snow:hasSent标记是否加入first队列
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

	///*snow:总共有四个队列：m_ControlQueue_list
	///                      m_ControlQueueFirst_list
	///                      m_TempControlQueue_list
	///                      m_TempControlQueueFirst_list 
	///依次从四个队列里删除拟删除的socket
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
///snow:同RemoveFromAllQueues(ThrottledControlSocket* socket)函数一样，比ControlSocket多调用一个RemoveFromStandardListNoLock(socket);
void UploadBandwidthThrottler::RemoveFromAllQueues(ThrottledFileSocket* socket) {
	// Get critical section
	sendLocker.Lock();

	if(doRun) {
		RemoveFromAllQueues(socket, false);  ///snow : bool lock参数没什么用，其实可以去掉，无论是true，还是false，还是得包含在sendLocker.Lock();，sendLocker.UnLock();中

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

///snow:solt的作用是什么？solt表示现在有多少客户端已建立连接，有多少文件上传请求，每一个上传请求对应一个socket，而一个socket就是一个solt
///snow:本函数计算可以同时上传的Solt数量
uint32 UploadBandwidthThrottler::GetSlotLimit(uint32 currentUpSpeed) {
	uint32 upPerClient = UPLOAD_CLIENT_DATARATE;  ///snow:3K

    // if throttler doesn't require another slot, go with a slightly more restrictive method
	if( currentUpSpeed > 20*1024 )  ///snow :20K
		upPerClient += currentUpSpeed/43;

	if( upPerClient > 7680 )
		upPerClient = 7680;  ///snow:上限：7K

	//now the final check

	uint16 nMaxSlots;
	if (currentUpSpeed > 12*1024)   ///snow:12K
		nMaxSlots = (uint16)(((float)currentUpSpeed) / upPerClient);  ///snow:假设上传速度300K,nMaxSolts=300/7=40
	else if (currentUpSpeed > 7*1024)   ///snow:12K>currentUpSpeed>7K
		nMaxSlots = MIN_UP_CLIENTS_ALLOWED + 2;   ///nMaxSolts = 4
	else if (currentUpSpeed > 3*1024)
		nMaxSlots = MIN_UP_CLIENTS_ALLOWED + 1;
	else
		nMaxSlots = MIN_UP_CLIENTS_ALLOWED;  ///snow:允许2个同时上传

    return max(nMaxSlots, MIN_UP_CLIENTS_ALLOWED);
}


///snow:consecutiveChange  连续变化，指什么呢？指nSlotsBusyLevel变化的频率，用来控制速度的调整幅度
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

	while(doRun) {  ///snow:循环一直执行，直到EndThread,置doRun=false
        pauseEvent->Lock();

		DWORD timeSinceLastLoop = timeGetTime() - lastLoopTick;   ///snow:循环开始计时，统计本次循环运行时间，循环在不停运行，运行一轮就统计一次时间
		///snow:lastLoopTick为上轮循环发送数据前的时刻

		// Get current speed from UploadSpeedSense

		allowedDataRate = theApp.lastCommonRouteFinder->GetUpload();   ///snow:没有设定限速的时候，allowedDataRate=0xFFFFFFFF(4294967295)==_UI32_MAX，如果上传限速有定义，返回上传限速；设定为100K时，allowedDataRate=102400

		
        // check busy level for all the slots (WSAEWOULDBLOCK status)
        uint32 cBusy = 0;
        uint32 nCanSend = 0;

        sendLocker.Lock();
		/********************************************* snow:start ************************  
		/*   i小于m_StandardOrder_list项数 且 满足下面任一条件：
		/*          1、i<3
		/*          2、i<GetSlotLimit()
		*********************************************snow:end ****************************/
        for (int i = 0; i < m_StandardOrder_list.GetSize() && (i < 3 || (UINT)i < GetSlotLimit(theApp.uploadqueue->GetDatarate())); i++){
            if (m_StandardOrder_list[i] != NULL && m_StandardOrder_list[i]->HasQueues()) {
				nCanSend++;   ///snow:统计可以发送包数  错了！！不是包数，是socket数或solt数，就是允许同时上传的Socket数

                if(m_StandardOrder_list[i]->IsBusy())
					cBusy++;   ///snow:统计阻塞包数  错了！！不是包数，是socket数或solt数，就是正在等候上传的socket数
            }
		}
        sendLocker.Unlock();

        // if this is kept, the loop above can be a little optimized (don't count nCanSend, just use nCanSend = GetSlotLimit(theApp.uploadqueue->GetDatarate())
        if(theApp.uploadqueue)
            nCanSend = max(nCanSend, GetSlotLimit(theApp.uploadqueue->GetDatarate()));

        // When no upload limit has been set in options, try to guess a good upload limit.
		bool bUploadUnlimited = (thePrefs.GetMaxUpload() == UNLIMITED);


		/*************************************************snow:start***************************************************************
		/*   问题：在preference中没有设置限制速度，节流阀是怎样工作的
		/*   nSoltBusyLevel：繁忙水平，上限255，下限-255
		/*   loopsCount    : 统计循环已经运行几轮了，循环是在不断运行的，每运行一轮,loopsCount就加1
		/*   changeCount   :统计nSoltBusyLevel变更次数，无论是增加还是减少
		/*   numberOfConsecutiveDownChanges,numberOfConsecutiveUpChanges，调整阀值
        /*   changeDelta   ：调速幅度
		/*   当繁忙度（cBusy/nCanSend）>75% nSlotsBusyLevel增加，上限255，当繁忙度<25%时，nSlotsBusyLevel下降，下降-255 每循环一次，变更一次
		/*   当繁忙度变更一次，changecount就增加一次
		/*   根据上面几个参数，计算调整幅度
		**************************************************snow:end ***************************************************************/
		///snow:没有限速的情况下
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

			 ///snow:准备开始上传，还没开始
			if(nUploadStartTime == 0) 
			{  
				if (m_StandardOrder_list.GetSize() >= 3)   ///snow:有3个以上socket等待上传，才设置nUploadStartTime，如果不达到3个，不设置nUploadStartTime，nUploadStartTime依然为0，为什么？
					nUploadStartTime = timeGetTime();      ///snow:也就是说当等待上传socket数小于3时，nUploadStartTime一直为0，就不存在执行else分支进行调速了
			} 
			///snow:开始上传超过1秒钟，可以开始调整速度了，但当m_StandardOrder_list中的socket数小于3时，不调整
			else if(timeGetTime()- nUploadStartTime > SEC2MS(60)) 
			{   
				if (theApp.uploadqueue){   ///snow:存在上传队列，如果没有上传队列，就不存在限速了
				    if (nEstiminatedLimit == 0){ // no autolimit was set yet  ///snow:nEstiminatedLimit尚未赋值，初值为0 （Estiminated估计为Estimated的笔误）
					    if (nSlotsBusyLevel >= 250){ // sockets indicated that the BW limit has been reached   ///snow:已经很忙了
							nEstiminatedLimit = theApp.uploadqueue->GetDatarate();  ///snow:获取当前上传速率，跟允许的上传速率比较，取小值
							allowedDataRate = min(nEstiminatedLimit, allowedDataRate);  ///snow:如果当前上传速率没达到或超过允许的上传速率，调低allowedDataRate，调整nSlotsBusyLevel值为-200
						    nSlotsBusyLevel = -200;
                            if(thePrefs.GetVerbose() && estimateChangedLog) theApp.QueueDebugLogLine(false,_T("Throttler: Set inital estimated limit to %0.5f changesCount: %i loopsCount: %i"), (float)nEstiminatedLimit/1024.00f, changesCount, loopsCount);
							changesCount = 0;  ///snow:作用尚不明  nSlotsBusyLevel被重置为-200，changesCount，loopsCount均重置为0
							loopsCount = 0;    ///snow:changesCount,loopsCount主要为计算numberOfConsecutiveDownChanges提供依据
					    }
				    }
					else{  ///snow:nEstiminatedLimit ！= 0，已经计算出估计限速了
						if (nSlotsBusyLevel > 250){  ///snow:需要调降限速
							if(changesCount > 500 || changesCount > 300 && loopsCount > 1000 || loopsCount > 2000) {  ///snow:当循环运行了很多次（大于1000，甚至2000），nSlotsBusyLevel变更已经超过300，甚至500次了
								numberOfConsecutiveDownChanges = 0;   ///snow:把调整幅度降到最低，可能是因为运行很久了，比较稳定了
                            }
							numberOfConsecutiveDownChanges++;   ///snow:numberOfConsecutiveDownChanges取值范围 0---7，参考CalculateChangeDelta（），取值越大，每次速度的调整幅度越大
							uint32 changeDelta = CalculateChangeDelta(numberOfConsecutiveDownChanges);  ///snow:取值范围 50-1024+512，changeDelta的值为每次调速的幅度，最高每循环一次降1.5K

                            // Don't lower speed below 1 KBytes/s
							if(nEstiminatedLimit < changeDelta + 1024) {   ///snow:不低于1K
                                if(nEstiminatedLimit > 1024) {
                                    changeDelta = nEstiminatedLimit - 1024;
                                } else {
                                    changeDelta = 0;
                                }
                            }
                            ASSERT(nEstiminatedLimit >= changeDelta + 1024);
							nEstiminatedLimit -= changeDelta;   ///snow:上传估计限速调低changeDelta

                            if(thePrefs.GetVerbose() && estimateChangedLog) theApp.QueueDebugLogLine(false,_T("Throttler: REDUCED limit #%i with %i bytes to: %0.5f changesCount: %i loopsCount: %i"), numberOfConsecutiveDownChanges, changeDelta, (float)nEstiminatedLimit/1024.00f, changesCount, loopsCount);
							///snow:调整完限速，下面这四个指标就归零
                            numberOfConsecutiveUpChanges = 0;
						    nSlotsBusyLevel = 0;
                            changesCount = 0;
                            loopsCount = 0;
					    }
						else if (nSlotsBusyLevel < (-250)){   ///snow:需要调升限速，原理同调降
                            if(changesCount > 500 || changesCount > 300 && loopsCount > 1000 || loopsCount > 2000) {
                                numberOfConsecutiveUpChanges = 0;
                            }
                            numberOfConsecutiveUpChanges++;
                            uint32 changeDelta = CalculateChangeDelta(numberOfConsecutiveUpChanges);

                            // Don't raise speed unless we are under current allowedDataRate
							if(nEstiminatedLimit+changeDelta > allowedDataRate) {    ///snow:不高于允许速率
                                if(nEstiminatedLimit < allowedDataRate) {
                                    changeDelta = allowedDataRate - nEstiminatedLimit;
                                } else {
                                    changeDelta = 0;
                                }
                            }
                            ASSERT(nEstiminatedLimit < allowedDataRate && nEstiminatedLimit+changeDelta <= allowedDataRate || nEstiminatedLimit >= allowedDataRate && changeDelta == 0);
                            nEstiminatedLimit += changeDelta;

                            if(thePrefs.GetVerbose() && estimateChangedLog) theApp.QueueDebugLogLine(false,_T("Throttler: INCREASED limit #%i with %i bytes to: %0.5f changesCount: %i loopsCount: %i"), numberOfConsecutiveUpChanges, changeDelta, (float)nEstiminatedLimit/1024.00f, changesCount, loopsCount);
                            ///snow：调整完限速，下面这四个指标就归零
                            numberOfConsecutiveDownChanges = 0;
						    nSlotsBusyLevel = 0;
                            changesCount = 0;
                            loopsCount = 0;
					    }

						allowedDataRate = min(nEstiminatedLimit, allowedDataRate);  ///snow:在预估的上传速度或允许的上传速度两者之间取小值
				    } 
			    }
            }
		}///snow:未设定限速

		///snow:全部阻塞了，不能再允许发送数据了，调整nSlotsBusyLevel为125
		if(cBusy == nCanSend && m_StandardOrder_list.GetSize() > 0) {   
            allowedDataRate = 0;
            if(nSlotsBusyLevel < 125 && bUploadUnlimited) {
                nSlotsBusyLevel = 125;
                if(thePrefs.GetVerbose() && lotsOfLog) theApp.QueueDebugLogLine(false,_T("Throttler: nSlotsBusyLevel: %i Guessed limit: %0.5f changesCount %i loopsCount: %i (set due to all slots busy)"), nSlotsBusyLevel, (float)nEstiminatedLimit/1024.00f, changesCount, loopsCount);
            }
        }

		uint32 minFragSize = 1300;
        uint32 doubleSendSize = minFragSize*2; // send two packages at a time so they can share an ACK
		if(allowedDataRate < 6*1024) {   ///snow:允许上传速度低于6K，设置帧长度为536
			minFragSize = 536;
            doubleSendSize = minFragSize; // don't send two packages at a time at very low speeds to give them a smoother load
		}

		///设置休眠时间，停止上传,通过设置休眠时间来达到限速的目的
#define TIME_BETWEEN_UPLOAD_LOOPS 1
        uint32 sleepTime;
        if(allowedDataRate == _UI32_MAX || realBytesToSpend >= 1000 || allowedDataRate == 0 && nEstiminatedLimit == 0) {
            // we could send at once, but sleep a while to not suck up all cpu
			sleepTime = TIME_BETWEEN_UPLOAD_LOOPS;  ///snow:如果不需要限速，休眠1ms，防止占用全部CPU时间
		} else if(allowedDataRate == 0) {  ///snow: nEstiminatedLimit!=0
			sleepTime = max((uint32)ceil(((double)doubleSendSize*1000)/nEstiminatedLimit), TIME_BETWEEN_UPLOAD_LOOPS);  ///snow:ceil()返回大于或者等于指定表达式的最小整数
			///snow:假设nEstiminatedLimit为2048(2K),则sleepTime=max(536*1000/2048,1)=262ms，假设nEstiminatedLimit为6144(6K),则sleepTime=max(2600*1000/6144,1)=424ms，
        } else {
            // sleep for just as long as we need to get back to having one byte to send
			///snow:因为上传快了，realBytesToSpend为负数，假设限速300K/S，上次循环多上传了2K，
            sleepTime = max((uint32)ceil((double)(-realBytesToSpend + 1000)/allowedDataRate), TIME_BETWEEN_UPLOAD_LOOPS);
			
        }

        if(timeSinceLastLoop < sleepTime) {
			Sleep(sleepTime-timeSinceLastLoop);   ///snow:休眠一小会
        }

		const DWORD thisLoopTick = timeGetTime();
		timeSinceLastLoop = thisLoopTick - lastLoopTick;

		// Calculate how many bytes we can spend
        sint64 bytesToSpend = 0;

		/********************************* snow:start ***********************************************
		/*   两种情况下allowedDataRate != _UI32_MAX：
		/*        1、没有设置限速，但传输繁忙，会调整allowedDataRate，直到为0，表示不允许再增加上传
		/*        2、设置限速了
		/********************************* snow:end ************************************************/
		if(allowedDataRate != _UI32_MAX) 
		{   
            // prevent overflow   ///snow:预防溢出，何解？
            if(timeSinceLastLoop == 0)
			{
                // no time has passed, so don't add any bytes. Shouldn't happen.
                bytesToSpend = 0; //realBytesToSpend/1000;
            } 
			else if(_I64_MAX/timeSinceLastLoop > allowedDataRate && _I64_MAX-allowedDataRate*timeSinceLastLoop > realBytesToSpend) 
			{
				if(timeSinceLastLoop > sleepTime + 2000)   ///snow:超过2秒
				{
			        theApp.QueueDebugLogLine(false,_T("UploadBandwidthThrottler: Time since last loop too long. time: %ims wanted: %ims Max: %ims"), timeSinceLastLoop, sleepTime, sleepTime + 2000);
        
                    timeSinceLastLoop = sleepTime + 2000;
					lastLoopTick = thisLoopTick - timeSinceLastLoop;  ///snow:多余的，必被后面的lastLoopTick = thisLoopTick; 覆盖
                }

				realBytesToSpend += allowedDataRate*timeSinceLastLoop;   ///snow:理论上应发送的字节数，包括了上次循环没用完的999字节（如果上次循环带宽没用完，realBytesToSpend值被设为999）

				bytesToSpend = realBytesToSpend/1000;  ///snow:按K计算，根据当前设定的带宽，可以发送的字节数
            } 
			else 
			{
                realBytesToSpend = _I64_MAX;
                bytesToSpend = _I32_MAX;
            }
        } 
		else {
            realBytesToSpend = 0; //_I64_MAX;
			bytesToSpend = _I32_MAX;   ///snow:能发送多少数据就发送多少
        }

		lastLoopTick = thisLoopTick;  ///snow:在发送数据前记下当前时刻，做为下一循环时的起始点。这样做的目的是本次循环统计的时间实际为上次循环发送数据的时间

		/************************************************** snow:start **************************************
		/* 如果拟发送字节数>=1，或者允许上传速度==0，将所有temp队列中的包添加到正常队列末尾，
		/*     当满足下面两个条件时：
		/*        1、bytesToSpend > 0 && spentBytes < (uint64)bytesToSpend 或 allowedDataRate == 0 && spentBytes < 500
		/*           表示已发送字节数小于拟发送字节数 或  允许上传不限速且才已发送数小于500    
		/*        2、m_ControlQueueFirst_list或m_ControlQueue_list不为空
		/*     发送控制包，并统计发送的字节数
		*************************************************** snow:end **************************************/
		if(bytesToSpend >= 1 || allowedDataRate == 0) {   ///snow:代表什么意思？代表不允许增加上传或存在待上传的数据，待上传的可以理解，allowedDataRate == 0是为什么呢？
			uint64 spentBytes = 0;     ///snow:标准包字节数+控制包字节数
			uint64 spentOverhead = 0;  ///snow:只统计控制包字节数
    
		    sendLocker.Lock();
    
		    tempQueueLocker.Lock();
    
			///snow:这样做的目的是什么？为什么不直接就放在正常队列？怎么就实现边发送边添加了？没看懂
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
    
			///snow:处理控制包列表，四个队列只存放控制包信息
		    // Send any queued up control packets first 
			///snow:优先发送First队列，First队列发送完才发送正常队列
		    while((bytesToSpend > 0 && spentBytes < (uint64)bytesToSpend || allowedDataRate == 0 && spentBytes < 500) && (!m_ControlQueueFirst_list.IsEmpty() || !m_ControlQueue_list.IsEmpty())) {
			    ThrottledControlSocket* socket = NULL;
    
                if(!m_ControlQueueFirst_list.IsEmpty()) {
                    socket = m_ControlQueueFirst_list.RemoveHead();
                } else if(!m_ControlQueue_list.IsEmpty()) {
                    socket = m_ControlQueue_list.RemoveHead();
                }
    
			    if(socket != NULL) {
					///snow:发送bytesToSpend - spentBytes个字节，当allowedDataRate=0时，1个字节1个字节发送。为什么要1个字节发送？
                    SocketSentBytes socketSentBytes = socket->SendControlData(allowedDataRate > 0?(UINT)(bytesToSpend - spentBytes):1, minFragSize);
				    uint32 lastSpentBytes = socketSentBytes.sentBytesControlPackets + socketSentBytes.sentBytesStandardPackets;
				    spentBytes += lastSpentBytes;
				    spentOverhead += socketSentBytes.sentBytesControlPackets;
			    }
		    }
			///snow:处理标准列表，既可处理控制包，也可处理标准包
		    // Check if any sockets haven't gotten data for a long time. Then trickle them a package.
		    for(uint32 slotCounter = 0; slotCounter < (uint32)m_StandardOrder_list.GetSize(); slotCounter++) {
			    ThrottledFileSocket* socket = m_StandardOrder_list.GetAt(slotCounter);
    
			    if(socket != NULL) {
					if(thisLoopTick-socket->GetLastCalledSend() > SEC2MS(1)) {   ///snow:距离上次调用超过1秒钟，超过一秒没发送数据的才发送
					    // trickle
						uint32 neededBytes = socket->GetNeededBytes(); ///snow:发送neededBytes个字节
    
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

			///snow:前面处理的是控制包队列和m_StandardOrder_list中长时间没传输数据的SOCKET，下面才正式开始处理m_StandardOrder_list中的Socket
						
		    // Equal bandwidth for all slots
            uint32 maxSlot = (uint32)m_StandardOrder_list.GetSize();
			if(maxSlot > 0 && allowedDataRate/maxSlot < UPLOAD_CLIENT_DATARATE) {   ///snow:如果每solt的速率达不到3K，减少solt数
                maxSlot = allowedDataRate/UPLOAD_CLIENT_DATARATE;
			}   ///snow:这段代码决定了maxSlot不可能大于m_StandardOrder_list.GetSize()

			///snow:上传速率大于300K，或者每Solt速率大于100K时启用大缓冲区
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
				}  ///snow:rememberedSlotCounter在for循环开始时为0，maxSolt一定小于m_StandardOrder_list.GetSize()，所以for循环执行不会超过maxSolt次，rememberedSlotCounter的值不可能超过maxSolt,当rememberedSlotCounter==maxSolt时，循环执行完了，所以上面这段代码有啥意义？看不懂

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

			///snow:当spentBytes < (uint64)bytesToSpend时，带宽还没用完，继续发送数据，上面的代码发送的字节数是min(doubleSendSize, bytesToSpend-spentBytes)，下面的代码发送的字节数是（bytesToSpend-spentBytes），这里的spentBytes不同于上面代码的spentBytes，因为上面的代码又发送了些数据，所以spentBytes变小了，如果带宽用完了，下面的代码就不会执行了

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
		    realBytesToSpend -= spentBytes*1000;  ///本轮循环应该发送的字节数-实际发送的字节数=尚未发送的字节数（多发送的字节数）

			///snow:上面四段发送数据的代码不是并发执行的，而是从上往下顺序执行的，只有在上段发送字节数还不够时，下段代码才会被执行。每段代码都会遍历队列中的Socket

            // If we couldn't spend all allocated bandwidth this loop, some of it is allowed to be saved
            // and used the next loop
			///snow:realBytesToSpend值越小，表示上传越快，多传送的数据越多
		    if(realBytesToSpend < -(((sint64)m_StandardOrder_list.GetSize()+1)*minFragSize)*1000) {   ///假设minFragSize=536,两个socket，则-（2+1）*536*1000=1.5M！
			    sint64 newRealBytesToSpend = -(((sint64)m_StandardOrder_list.GetSize()+1)*minFragSize)*1000;
				///snow:realBytesToSpend=newRealBytesToSpend为负值
			    realBytesToSpend = newRealBytesToSpend;
				lastTickReachedBandwidth = thisLoopTick;  ///snow:上次带宽用完的时刻,带宽没用完的话，可以留下两个周期使用
            } else {
				uint64 bandwidthSavedTolerance = 0;   ///snow:保留，未使用
				if(realBytesToSpend > 0 && (uint64)realBytesToSpend > 999+bandwidthSavedTolerance) {  ///snow:本轮循环上传速率不够，尚余有数据没传送完
			        sint64 newRealBytesToSpend = 999+bandwidthSavedTolerance;
			        //theApp.QueueDebugLogLine(false,_T("UploadBandwidthThrottler::RunInternal(): Too high saved bytesToSpend. Limiting value. Old value: %I64i New value: %I64i"), realBytesToSpend, newRealBytesToSpend);
					realBytesToSpend = newRealBytesToSpend;   ///snow:realBytesToSpend=999，未超过1000

					if(thisLoopTick-lastTickReachedBandwidth > max(1000, timeSinceLastLoop*2)) {  ///snow:如果上次带宽用完的时刻已超过1秒或已超过两个循环的时间
						m_highestNumberOfFullyActivatedSlots = m_StandardOrder_list.GetSize()+1;   ///snow:增加solt数
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