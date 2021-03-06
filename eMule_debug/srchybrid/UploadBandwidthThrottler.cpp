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
    m_highestNumberOfFullyActivatedSlots = 0;

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
 *
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
 *
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
 *
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
 *
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
		if(index > (uint32)m_StandardOrder_list.GetSize()) {
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
 *
 * @param socket address of the socket that should be removed from the list. If this socket
 *               does not exist in the list, this method will do nothing.
 */
bool UploadBandwidthThrottler::RemoveFromStandardListNoLock(ThrottledFileSocket* socket) {
	// Find the slot
	int slotCounter = 0;
	bool foundSocket = false;
	while(slotCounter < m_StandardOrder_list.GetSize() && foundSocket == false) {
		if(m_StandardOrder_list.GetAt(slotCounter) == socket) {
			// Remove the slot
			m_StandardOrder_list.RemoveAt(slotCounter);
			foundSocket = true;
		} else {
			slotCounter++;
        }
	}

    if(foundSocket && m_highestNumberOfFullyActivatedSlots > (uint32)m_StandardOrder_list.GetSize()) {
        m_highestNumberOfFullyActivatedSlots = m_StandardOrder_list.GetSize();
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
*
* @param socket address to the socket that requests to have controlpacket send
*               to be called on it
*/
void UploadBandwidthThrottler::QueueForSendingControlPacket(ThrottledControlSocket* socket, bool hasSent) {
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

void UploadBandwidthThrottler::RemoveFromAllQueues(ThrottledFileSocket* socket) {
	// Get critical section
	sendLocker.Lock();

	if(doRun) {
		RemoveFromAllQueues(socket, false);

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

	Pause(false);

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

uint32 UploadBandwidthThrottler::GetSlotLimit(uint32 currentUpSpeed) {
    uint32 upPerClient = UPLOAD_CLIENT_DATARATE;

    // if throttler doesn't require another slot, go with a slightly more restrictive method
	if( currentUpSpeed > 20*1024 )
		upPerClient += currentUpSpeed/43;

	if( upPerClient > 7680 )
		upPerClient = 7680;

	//now the final check

	uint16 nMaxSlots;
	if (currentUpSpeed > 12*1024)
		nMaxSlots = (uint16)(((float)currentUpSpeed) / upPerClient);
	else if (currentUpSpeed > 7*1024)
		nMaxSlots = MIN_UP_CLIENTS_ALLOWED + 2;
	else if (currentUpSpeed > 3*1024)
		nMaxSlots = MIN_UP_CLIENTS_ALLOWED + 1;
	else
		nMaxSlots = MIN_UP_CLIENTS_ALLOWED;

    return max(nMaxSlots, MIN_UP_CLIENTS_ALLOWED);
}

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
	DWORD time = timeGetTime(); bool record=true;///snow:add to debug
//	//if(record) theApp.QueueTraceLogLine(CAsyncSocketEx_workflow,_T("snow:UploadBandwidthThrottler in line 407: Last loop Tick: %s "), formatTime(lastLoopTick).GetBuffer(0)); ///snow:add to debug
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

	while(doRun) {
        pauseEvent->Lock();
//		//if(record) theApp.QueueTraceLogLine(CAsyncSocketEx_workflow,_T("snow:UploadBandwidthThrottler in line 429"));
		DWORD timeSinceLastLoop = timeGetTime() - lastLoopTick;
//		//if(record) theApp.QueueTraceLogLine(CAsyncSocketEx_workflow,_T("snow:UploadBandwidthThrottler in line 430: timeSinceLastLoop: %s "), formatTime(timeSinceLastLoop).GetBuffer(0)); ///snow:add to debug
		// Get current speed from UploadSpeedSense
		allowedDataRate = theApp.lastCommonRouteFinder->GetUpload();
//		//if(record) theApp.QueueTraceLogLine(CAsyncSocketEx_workflow,_T("snow:UploadBandwidthThrottler in line 434: allowedDataRate : %i "), allowedDataRate); ///snow:add to debug
        // check busy level for all the slots (WSAEWOULDBLOCK status)
        uint32 cBusy = 0;
        uint32 nCanSend = 0;

        sendLocker.Lock();
        for (int i = 0; i < m_StandardOrder_list.GetSize() && (i < 3 || (UINT)i < GetSlotLimit(theApp.uploadqueue->GetDatarate())); i++){
            if (m_StandardOrder_list[i] != NULL && m_StandardOrder_list[i]->HasQueues()) {
                nCanSend++;

//				//if(record) theApp.QueueTraceLogLine(CAsyncSocketEx_workflow,_T("snow:UploadBandwidthThrottler in line 444"));
                if(m_StandardOrder_list[i]->IsBusy())
					cBusy++;
            }
		}
        sendLocker.Unlock();

        // if this is kept, the loop above can be a little optimized (don't count nCanSend, just use nCanSend = GetSlotLimit(theApp.uploadqueue->GetDatarate())
        if(theApp.uploadqueue)
            nCanSend = max(nCanSend, GetSlotLimit(theApp.uploadqueue->GetDatarate()));

        // When no upload limit has been set in options, try to guess a good upload limit.
		bool bUploadUnlimited = (thePrefs.GetMaxUpload() == UNLIMITED);
        if (bUploadUnlimited) {
            loopsCount++;
//			//if(record) theApp.QueueTraceLogLine(CAsyncSocketEx_workflow,_T("snow:UploadBandwidthThrottler in line 458"));///snow
            //if(lotsOfLog) theApp.QueueDebugLogLine(false,_T("Throttler: busy: %i/%i nSlotsBusyLevel: %i Guessed limit: %0.5f changesCount: %i loopsCount: %i"), cBusy, nCanSend, nSlotsBusyLevel, (float)nEstiminatedLimit/1024.00f, changesCount, loopsCount);

            if(nCanSend > 0) {
//				//if(record) theApp.QueueTraceLogLine(CAsyncSocketEx_workflow,_T("snow:UploadBandwidthThrottler in line 463"));///snow
			    float fBusyPercent = ((float)cBusy/(float)nCanSend) * 100;
                if (cBusy > 2 && fBusyPercent > 75.00f && nSlotsBusyLevel < 255){
//					//if(record) theApp.QueueTraceLogLine(CAsyncSocketEx_workflow,_T("snow:UploadBandwidthThrottler in line 465"));
				    nSlotsBusyLevel++;
                    changesCount++;
                    if(thePrefs.GetVerbose() && lotsOfLog && nSlotsBusyLevel%25==0) theApp.QueueDebugLogLine(false,_T("Throttler: nSlotsBusyLevel: %i Guessed limit: %0.5f changesCount: %i loopsCount: %i"), nSlotsBusyLevel, (float)nEstiminatedLimit/1024.00f, changesCount, loopsCount);
			    }
			    else if ( (cBusy <= 2 || fBusyPercent < 25.00f) && nSlotsBusyLevel > (-255)){
//					//if(record) theApp.QueueTraceLogLine(CAsyncSocketEx_workflow,_T("snow:UploadBandwidthThrottler in line 472"));
				    nSlotsBusyLevel--;
                    changesCount++;
                    if(thePrefs.GetVerbose() && lotsOfLog && nSlotsBusyLevel%25==0) theApp.QueueDebugLogLine(false,_T("Throttler: nSlotsBusyLevel: %i Guessed limit: %0.5f changesCount %i loopsCount: %i"), nSlotsBusyLevel, (float)nEstiminatedLimit/1024.00f, changesCount, loopsCount);
                }
			}

            if(nUploadStartTime == 0) {
//				//if(record) theApp.QueueTraceLogLine(CAsyncSocketEx_workflow,_T("snow:UploadBandwidthThrottler in line 480"));
		        if (m_StandardOrder_list.GetSize() >= 3)
			        nUploadStartTime = timeGetTime();
//				//if(record)theApp.QueueTraceLogLine(CAsyncSocketEx_workflow,_T("snow:UploadBandwidthThrottler in line 478: nUploadStartTime. time: %s "), formatTime(nUploadStartTime).GetBuffer(0)); ///snow:add to debug
		// Get current speed from UploadSpeedSense
            } else if(timeGetTime()- nUploadStartTime > SEC2MS(60)) {
//				//if(record) theApp.QueueTraceLogLine(CAsyncSocketEx_workflow,_T("snow:UploadBandwidthThrottler in line 486"));
			    if (theApp.uploadqueue){
				    if (nEstiminatedLimit == 0){ // no autolimit was set yet
//						//if(record) theApp.QueueTraceLogLine(CAsyncSocketEx_workflow,_T("snow:UploadBandwidthThrottler in line 488"));
					    if (nSlotsBusyLevel >= 250){ // sockets indicated that the BW limit has been reached
//							//if(record) theApp.QueueTraceLogLine(CAsyncSocketEx_workflow,_T("snow:UploadBandwidthThrottler in line 491"));
						    nEstiminatedLimit = theApp.uploadqueue->GetDatarate();
//							//if(record)theApp.QueueTraceLogLine(CAsyncSocketEx_workflow,_T("snow:UploadBandwidthThrottler in line 484: nEstiminatedLimit : %i b/s "), nEstiminatedLimit); ///snow:add to debug
						    allowedDataRate = min(nEstiminatedLimit, allowedDataRate);
						    nSlotsBusyLevel = -200;
                            if(thePrefs.GetVerbose() && estimateChangedLog) theApp.QueueDebugLogLine(false,_T("Throttler: Set inital estimated limit to %0.5f changesCount: %i loopsCount: %i"), (float)nEstiminatedLimit/1024.00f, changesCount, loopsCount);
//							//if(record)theApp.QueueTraceLogLine(CAsyncSocketEx_workflow,_T("snow:UploadBandwidthThrottler in line 489: Set inital estimated limit to %0.5f changesCount: %i loopsCount: %i"), (float)nEstiminatedLimit/1024.00f, changesCount, loopsCount);  ///snow:add to debug
                            changesCount = 0;
                            loopsCount = 0;
					    }
				    }
				    else{
                        if (nSlotsBusyLevel > 250){
//							//if(record) theApp.QueueTraceLogLine(CAsyncSocketEx_workflow,_T("snow:UploadBandwidthThrottler in line 504"));
//							//if(record)theApp.QueueTraceLogLine(CAsyncSocketEx_workflow,_T("snow:UploadBandwidthThrottler in line 496: changesCount : %i loopsCount : %i"), changesCount,loopsCount); ///snow:add to debug
                            if(changesCount > 500 || changesCount > 300 && loopsCount > 1000 || loopsCount > 2000) {
                                numberOfConsecutiveDownChanges = 0;
                            }
                            numberOfConsecutiveDownChanges++;
//							//if(record)theApp.QueueTraceLogLine(CAsyncSocketEx_workflow,_T("snow:UploadBandwidthThrottler in line 500: numberOfConsecutiveDownChanges : %i "), numberOfConsecutiveDownChanges); ///snow:add to debug
                            uint32 changeDelta = CalculateChangeDelta(numberOfConsecutiveDownChanges);

                            // Don't lower speed below 1 KBytes/s
                            if(nEstiminatedLimit < changeDelta + 1024) {
                                if(nEstiminatedLimit > 1024) {
                                    changeDelta = nEstiminatedLimit - 1024;
                                } else {
                                    changeDelta = 0;
                                }
                            }
                            ASSERT(nEstiminatedLimit >= changeDelta + 1024);
    						nEstiminatedLimit -= changeDelta;

                            if(thePrefs.GetVerbose() && estimateChangedLog) theApp.QueueDebugLogLine(false,_T("Throttler: REDUCED limit #%i with %i bytes to: %0.5f changesCount: %i loopsCount: %i"), numberOfConsecutiveDownChanges, changeDelta, (float)nEstiminatedLimit/1024.00f, changesCount, loopsCount);
//							//if(record)theApp.QueueTraceLogLine(CAsyncSocketEx_workflow,_T("snow:UploadBandwidthThrottler in line 516: REDUCED limit #%i with %i bytes to: %0.5f changesCount: %i loopsCount: %i"), numberOfConsecutiveDownChanges, changeDelta, (float)nEstiminatedLimit/1024.00f, changesCount, loopsCount); ///snow:add to debug
                            numberOfConsecutiveUpChanges = 0;
						    nSlotsBusyLevel = 0;
                            changesCount = 0;
                            loopsCount = 0;
					    }
                        else if (nSlotsBusyLevel < (-250)){
//							//if(record) theApp.QueueTraceLogLine(CAsyncSocketEx_workflow,_T("snow:UploadBandwidthThrottler in line 532"));
                            if(changesCount > 500 || changesCount > 300 && loopsCount > 1000 || loopsCount > 2000) {
                                numberOfConsecutiveUpChanges = 0;
                            }
                            numberOfConsecutiveUpChanges++;
                            uint32 changeDelta = CalculateChangeDelta(numberOfConsecutiveUpChanges);

                            // Don't raise speed unless we are under current allowedDataRate
                            if(nEstiminatedLimit+changeDelta > allowedDataRate) {
                                if(nEstiminatedLimit < allowedDataRate) {
                                    changeDelta = allowedDataRate - nEstiminatedLimit;
                                } else {
                                    changeDelta = 0;
                                }
                            }
                            ASSERT(nEstiminatedLimit < allowedDataRate && nEstiminatedLimit+changeDelta <= allowedDataRate || nEstiminatedLimit >= allowedDataRate && changeDelta == 0);
                            nEstiminatedLimit += changeDelta;

                            if(thePrefs.GetVerbose() && estimateChangedLog) theApp.QueueDebugLogLine(false,_T("Throttler: INCREASED limit #%i with %i bytes to: %0.5f changesCount: %i loopsCount: %i"), numberOfConsecutiveUpChanges, changeDelta, (float)nEstiminatedLimit/1024.00f, changesCount, loopsCount);
//							theApp.QueueTraceLogLine(CAsyncSocketEx_workflow,_T("snow:UploadBandwidthThrottler in line 541: INCREASED limit #%i with %i bytes to: %0.5f changesCount: %i loopsCount: %i"), numberOfConsecutiveUpChanges, changeDelta, (float)nEstiminatedLimit/1024.00f, changesCount, loopsCount);  ///snow:add to debug


                            numberOfConsecutiveDownChanges = 0;
						    nSlotsBusyLevel = 0;
                            changesCount = 0;
                            loopsCount = 0;
					    }

//						theApp.QueueTraceLogLine(CAsyncSocketEx_workflow,_T("snow:UploadBandwidthThrottler in line 484: allowedDataRate : %i b/s nEstiminatedLimit : %i b/s"), allowedDataRate,nEstiminatedLimit); ///snow:add to debug
					    allowedDataRate = min(nEstiminatedLimit, allowedDataRate);
						
				    } 
			    }
            }
		}

        if(cBusy == nCanSend && m_StandardOrder_list.GetSize() > 0) {
//			//if(record) theApp.QueueTraceLogLine(CAsyncSocketEx_workflow,_T("snow:UploadBandwidthThrottler in line 571"));
            allowedDataRate = 0;
            if(nSlotsBusyLevel < 125 && bUploadUnlimited) {
                nSlotsBusyLevel = 125;
                if(thePrefs.GetVerbose() && lotsOfLog) theApp.QueueDebugLogLine(false,_T("Throttler: nSlotsBusyLevel: %i Guessed limit: %0.5f changesCount %i loopsCount: %i (set due to all slots busy)"), nSlotsBusyLevel, (float)nEstiminatedLimit/1024.00f, changesCount, loopsCount);
//				//if(record)theApp.QueueTraceLogLine(CAsyncSocketEx_workflow,_T("snow:UploadBandwidthThrottler in line 574: nSlotsBusyLevel: %i Guessed limit: %0.5f changesCount %i loopsCount: %i (set due to all slots busy)"), nSlotsBusyLevel, (float)nEstiminatedLimit/1024.00f, changesCount, loopsCount);  ///snow: add to debug
            }
        }

		uint32 minFragSize = 1300;
        uint32 doubleSendSize = minFragSize*2; // send two packages at a time so they can share an ACK
		if(allowedDataRate < 6*1024) {
			minFragSize = 536;
            doubleSendSize = minFragSize; // don't send two packages at a time at very low speeds to give them a smoother load
		}

#define TIME_BETWEEN_UPLOAD_LOOPS 1
        uint32 sleepTime;
        if(allowedDataRate == _UI32_MAX || realBytesToSpend >= 1000 || allowedDataRate == 0 && nEstiminatedLimit == 0) {
//			//if(record) theApp.QueueTraceLogLine(CAsyncSocketEx_workflow,_T("snow:UploadBandwidthThrottler in line 590"));
            // we could send at once, but sleep a while to not suck up all cpu
            sleepTime = TIME_BETWEEN_UPLOAD_LOOPS;
        } else if(allowedDataRate == 0) {
//			//if(record) theApp.QueueTraceLogLine(CAsyncSocketEx_workflow,_T("snow:UploadBandwidthThrottler in line 594"));
            sleepTime = max((uint32)ceil(((double)doubleSendSize*1000)/nEstiminatedLimit), TIME_BETWEEN_UPLOAD_LOOPS);
        } else {
//			//if(record) theApp.QueueTraceLogLine(CAsyncSocketEx_workflow,_T("snow:UploadBandwidthThrottler in line 597"));
            // sleep for just as long as we need to get back to having one byte to send
            sleepTime = max((uint32)ceil((double)(-realBytesToSpend + 1000)/allowedDataRate), TIME_BETWEEN_UPLOAD_LOOPS);
			
        }

//		//if(record)theApp.QueueTraceLogLine(CAsyncSocketEx_workflow,_T("snow:UploadBandwidthThrottler in line 601: timeSinceLastLoop: %s sleepTime:  %s "), formatTime(timeSinceLastLoop).GetBuffer(0), formatTime(sleepTime).GetBuffer(0)); ///snow:add to debug
        if(timeSinceLastLoop < sleepTime) {
//			//if(record) theApp.QueueTraceLogLine(CAsyncSocketEx_workflow,_T("snow:UploadBandwidthThrottler in line 605"));
            Sleep(sleepTime-timeSinceLastLoop);
        }

		const DWORD thisLoopTick = timeGetTime();
		timeSinceLastLoop = thisLoopTick - lastLoopTick;
//		//if(record)theApp.QueueTraceLogLine(CAsyncSocketEx_workflow,_T("snow:UploadBandwidthThrottler in line 609:thisLoopTick: %s timeSinceLastLoop: %s "), formatTime(thisLoopTick).GetBuffer(0),formatTime(timeSinceLastLoop).GetBuffer(0));  ///snow:add to debug

		// Calculate how many bytes we can spend
        sint64 bytesToSpend = 0;

        if(allowedDataRate != _UI32_MAX) {
//			//if(record) theApp.QueueTraceLogLine(CAsyncSocketEx_workflow,_T("snow:UploadBandwidthThrottler in line 617"));
            // prevent overflow
            if(timeSinceLastLoop == 0) {
//				//if(record) theApp.QueueTraceLogLine(CAsyncSocketEx_workflow,_T("snow:UploadBandwidthThrottler in line 620"));
                // no time has passed, so don't add any bytes. Shouldn't happen.
                bytesToSpend = 0; //realBytesToSpend/1000;
            } else if(_I64_MAX/timeSinceLastLoop > allowedDataRate && _I64_MAX-allowedDataRate*timeSinceLastLoop > realBytesToSpend) {
//				//if(record) theApp.QueueTraceLogLine(CAsyncSocketEx_workflow,_T("snow:UploadBandwidthThrottler in line 624"));
                if(timeSinceLastLoop > sleepTime + 2000) {
//					//if(record) theApp.QueueTraceLogLine(CAsyncSocketEx_workflow,_T("snow:UploadBandwidthThrottler in line 626"));
			        theApp.QueueDebugLogLine(false,_T("UploadBandwidthThrottler: Time since last loop too long. time: %s wanted: %s Max: %s"), formatTime(timeSinceLastLoop).GetBuffer(0), formatTime(sleepTime).GetBuffer(0), formatTime(sleepTime + 2000).GetBuffer(0));
        
                    timeSinceLastLoop = sleepTime + 2000;
                    lastLoopTick = thisLoopTick - timeSinceLastLoop;
//					//if(record)theApp.QueueTraceLogLine(CAsyncSocketEx_workflow,_T("snow:UploadBandwidthThrottler in line 629:thisLoopTick: %s timeSinceLastLoop: %s lastLoopTick : %s"), formatTime(thisLoopTick).GetBuffer(0),formatTime(timeSinceLastLoop).GetBuffer(0),formatTime(lastLoopTick).GetBuffer(0));///snow:add to debug
                }

                realBytesToSpend += allowedDataRate*timeSinceLastLoop;


                bytesToSpend = realBytesToSpend/1000;
//				//if(record)theApp.QueueTraceLogLine(CAsyncSocketEx_workflow,_T("snow:UploadBandwidthThrottler in line 636: realBytesToSpend: %i bytesToSpend: %i "), realBytesToSpend,bytesToSpend); ///snow:add to debug
            } else {
//				//if(record) theApp.QueueTraceLogLine(CAsyncSocketEx_workflow,_T("snow:UploadBandwidthThrottler in line 641"));
                realBytesToSpend = _I64_MAX;
                bytesToSpend = _I32_MAX;
            }
        } else {
//			//if(record) theApp.QueueTraceLogLine(CAsyncSocketEx_workflow,_T("snow:UploadBandwidthThrottler in line 645"));
            realBytesToSpend = 0; //_I64_MAX;
            bytesToSpend = _I32_MAX;
        }

		lastLoopTick = thisLoopTick;
//		//if(record)theApp.QueueTraceLogLine(CAsyncSocketEx_workflow,_T("snow:UploadBandwidthThrottler in line 649:thisLoopTick: %s timeSinceLastLoop: %s lastLoopTick : %s"), formatTime(thisLoopTick).GetBuffer(0),formatTime(timeSinceLastLoop).GetBuffer(0),formatTime(lastLoopTick).GetBuffer(0));///snow:add to debug

        if(bytesToSpend >= 1 || allowedDataRate == 0) {
//			//if(record) theApp.QueueTraceLogLine(CAsyncSocketEx_workflow,_T("snow:UploadBandwidthThrottler in line 654"));
		    uint64 spentBytes = 0;
		    uint64 spentOverhead = 0;
    
		    sendLocker.Lock();
    
		    tempQueueLocker.Lock();
    
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


    
		    // Send any queued up control packets first
		    while((bytesToSpend > 0 && spentBytes < (uint64)bytesToSpend || allowedDataRate == 0 && spentBytes < 500) && (!m_ControlQueueFirst_list.IsEmpty() || !m_ControlQueue_list.IsEmpty())) {
//			   //if(record) theApp.QueueTraceLogLine(CAsyncSocketEx_workflow,_T("snow:UploadBandwidthThrottler in line 676:bytesToSpend: %i spentBytes: %i allowedDataRate : %i"), bytesToSpend,spentBytes,allowedDataRate);///snow:add to debug
				
				ThrottledControlSocket* socket = NULL;
    
                if(!m_ControlQueueFirst_list.IsEmpty()) {
                    socket = m_ControlQueueFirst_list.RemoveHead();
                } else if(!m_ControlQueue_list.IsEmpty()) {
                    socket = m_ControlQueue_list.RemoveHead();
                }
    
			    if(socket != NULL) {
                    SocketSentBytes socketSentBytes = socket->SendControlData(allowedDataRate > 0?(UINT)(bytesToSpend - spentBytes):1, minFragSize);
				    uint32 lastSpentBytes = socketSentBytes.sentBytesControlPackets + socketSentBytes.sentBytesStandardPackets;
				    spentBytes += lastSpentBytes;
				    spentOverhead += socketSentBytes.sentBytesControlPackets;
			    }
		    }
    
		    // Check if any sockets haven't gotten data for a long time. Then trickle them a package.
		    for(uint32 slotCounter = 0; slotCounter < (uint32)m_StandardOrder_list.GetSize(); slotCounter++) {
			    ThrottledFileSocket* socket = m_StandardOrder_list.GetAt(slotCounter);
    
			    if(socket != NULL) {
				    if(thisLoopTick-socket->GetLastCalledSend() > SEC2MS(1)) {
//						//if(record) theApp.QueueTraceLogLine(CAsyncSocketEx_workflow,_T("snow:UploadBandwidthThrottler in line 702"));
					    // trickle
					    uint32 neededBytes = socket->GetNeededBytes();
    
					    if(neededBytes > 0) {
						    SocketSentBytes socketSentBytes = socket->SendFileAndControlData(neededBytes, minFragSize);
						    uint32 lastSpentBytes = socketSentBytes.sentBytesControlPackets + socketSentBytes.sentBytesStandardPackets;
						    spentBytes += lastSpentBytes;
						    spentOverhead += socketSentBytes.sentBytesControlPackets;
	
//							//if(record)theApp.QueueTraceLogLine(CAsyncSocketEx_workflow,_T("snow:UploadBandwidthThrottler in line 710:lastSpentBytes: %i slotCounter: %i m_highestNumberOfFullyActivatedSlots : %i"), lastSpentBytes,slotCounter,m_highestNumberOfFullyActivatedSlots);///snow:add to debug

                            if(lastSpentBytes > 0 && slotCounter < m_highestNumberOfFullyActivatedSlots) {
                                m_highestNumberOfFullyActivatedSlots = slotCounter;
                            }
					    }
				    }
			    } else {
				    theApp.QueueDebugLogLine(false,_T("There was a NULL socket in the UploadBandwidthThrottler Standard list (trickle)! Prevented usage. Index: %i Size: %i"), slotCounter, m_StandardOrder_list.GetSize());
                }
		    }

		    // Equal bandwidth for all slots
            uint32 maxSlot = (uint32)m_StandardOrder_list.GetSize();
			//if(record)theApp.QueueTraceLogLine(CAsyncSocketEx_workflow,_T("snow:UploadBandwidthThrottler in line 724:maxSlot: %i "), maxSlot);///snow:add to debug
            if(maxSlot > 0 && allowedDataRate/maxSlot < UPLOAD_CLIENT_DATARATE) {
				//if(record) theApp.QueueTraceLogLine(CAsyncSocketEx_workflow,_T("snow:UploadBandwidthThrottler in line 726"));
                maxSlot = allowedDataRate/UPLOAD_CLIENT_DATARATE;
				//if(record)theApp.QueueTraceLogLine(CAsyncSocketEx_workflow,_T("snow:UploadBandwidthThrottler in line 728:maxSlot: %i "), maxSlot);///snow:add to debug
            }
			// if we are uploading fast, increase the sockets sendbuffers in order to be able to archive faster
			// speeds
			bool bUseBigBuffers = bAlwaysEnableBigSocketBuffers;
			if (maxSlot > 0 && (allowedDataRate == _UI32_MAX || allowedDataRate/maxSlot > 100 * 1024) && theApp.uploadqueue->GetDatarate() > 300 * 1024)
				bUseBigBuffers = true;
			//if(record)theApp.QueueTraceLogLine(CAsyncSocketEx_workflow,_T("snow:UploadBandwidthThrottler in line 735:m_highestNumberOfFullyActivatedSlots: %i "), m_highestNumberOfFullyActivatedSlots);///snow:add to debug
            if(maxSlot > m_highestNumberOfFullyActivatedSlots) {
			    m_highestNumberOfFullyActivatedSlots = maxSlot;
            }

            for(uint32 maxCounter = 0; maxCounter < min(maxSlot, (uint32)m_StandardOrder_list.GetSize()) && bytesToSpend > 0 && spentBytes < (uint64)bytesToSpend; maxCounter++) {
                if(rememberedSlotCounter >= (uint32)m_StandardOrder_list.GetSize() ||
                   rememberedSlotCounter >= maxSlot) {
					   //if(record) theApp.QueueTraceLogLine(CAsyncSocketEx_workflow,_T("snow:UploadBandwidthThrottler in line 745"));
                    rememberedSlotCounter = 0;
                }

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
				//if(record)theApp.QueueTraceLogLine(CAsyncSocketEx_workflow,_T("snow:UploadBandwidthThrottler in line 759:rememberedSlotCounter: %i "), rememberedSlotCounter);///snow:add to debug

                rememberedSlotCounter++;

            }

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
						//if(record)theApp.QueueTraceLogLine(CAsyncSocketEx_workflow,_T("snow:UploadBandwidthThrottler in line 778:m_highestNumberOfFullyActivatedSlots: %i "), m_highestNumberOfFullyActivatedSlots);///snow:add to debug

                    }
				} else {
					theApp.QueueDebugLogLine(false,_T("There was a NULL socket in the UploadBandwidthThrottler Standard list (fully activated)! Prevented usage. Index: %i Size: %i"), slotCounter, m_StandardOrder_list.GetSize());
                }
			}
		    realBytesToSpend -= spentBytes*1000;
			//if(record)theApp.QueueTraceLogLine(CAsyncSocketEx_workflow,_T("snow:UploadBandwidthThrottler in line 787:realBytesToSpend: %i "), realBytesToSpend);///snow:add to debug

            // If we couldn't spend all allocated bandwidth this loop, some of it is allowed to be saved
            // and used the next loop
		    if(realBytesToSpend < -(((sint64)m_StandardOrder_list.GetSize()+1)*minFragSize)*1000) {
				//if(record) theApp.QueueTraceLogLine(CAsyncSocketEx_workflow,_T("snow:UploadBandwidthThrottler in line 794"));
			    sint64 newRealBytesToSpend = -(((sint64)m_StandardOrder_list.GetSize()+1)*minFragSize)*1000;
    
			    realBytesToSpend = newRealBytesToSpend;

				//if(record)theApp.QueueTraceLogLine(CAsyncSocketEx_workflow,_T("snow:UploadBandwidthThrottler in line 797:realBytesToSpend:%i lastTickReachedBandwidth: %i thisLoopTick : %s"), realBytesToSpend,lastTickReachedBandwidth,formatTime(thisLoopTick).GetBuffer(0));///snow:add to debug
                lastTickReachedBandwidth = thisLoopTick;
            } else {
				//if(record) theApp.QueueTraceLogLine(CAsyncSocketEx_workflow,_T("snow:UploadBandwidthThrottler in line 800"));
                uint64 bandwidthSavedTolerance = 0;
                if(realBytesToSpend > 0 && (uint64)realBytesToSpend > 999+bandwidthSavedTolerance) {
					//if(record) theApp.QueueTraceLogLine(CAsyncSocketEx_workflow,_T("snow:UploadBandwidthThrottler in line 803"));
			        sint64 newRealBytesToSpend = 999+bandwidthSavedTolerance;
			        //theApp.QueueDebugLogLine(false,_T("UploadBandwidthThrottler::RunInternal(): Too high saved bytesToSpend. Limiting value. Old value: %I64i New value: %I64i"), realBytesToSpend, newRealBytesToSpend);
			       //if(record)theApp.QueueTraceLogLine(CAsyncSocketEx_workflow,_T("snow:UploadBandwidthThrottler in line 806:realBytesToSpend: %i newRealBytesToSpend : %ims"), realBytesToSpend,newRealBytesToSpend);///snow:add to debug
					realBytesToSpend = newRealBytesToSpend;

                    if(thisLoopTick-lastTickReachedBandwidth > max(1000, timeSinceLastLoop*2)) {
						//if(record) theApp.QueueTraceLogLine(CAsyncSocketEx_workflow,_T("snow:UploadBandwidthThrottler in line 810"));
                        m_highestNumberOfFullyActivatedSlots = m_StandardOrder_list.GetSize()+1;
						//if(record)theApp.QueueTraceLogLine(CAsyncSocketEx_workflow,_T("snow:UploadBandwidthThrottler in line 812:lastTickReachedBandwidth: %i thisLoopTick : %s  m_highestNumberOfFullyActivatedSlots :%i"), lastTickReachedBandwidth,formatTime(thisLoopTick).GetBuffer(0),m_highestNumberOfFullyActivatedSlots);///snow:add to debug
                        lastTickReachedBandwidth = thisLoopTick;
                        //theApp.QueueDebugLogLine(false, _T("UploadBandwidthThrottler: Throttler requests new slot due to bw not reached. m_highestNumberOfFullyActivatedSlots: %i m_StandardOrder_list.GetSize(): %i tick: %i"), m_highestNumberOfFullyActivatedSlots, m_StandardOrder_list.GetSize(), thisLoopTick);
                    }
                } else {
					//if(record) theApp.QueueTraceLogLine(CAsyncSocketEx_workflow,_T("snow:UploadBandwidthThrottler in line 817"));

					//if(record)theApp.QueueTraceLogLine(CAsyncSocketEx_workflow,_T("snow:UploadBandwidthThrottler in line 819:lastTickReachedBandwidth: %i thisLoopTick : %s  "), lastTickReachedBandwidth,formatTime(thisLoopTick).GetBuffer(0));///snow:add to debug
                    lastTickReachedBandwidth = thisLoopTick;
                }
            }
		    
            // save info about how much bandwidth we've managed to use since the last time someone polled us about used bandwidth
		    m_SentBytesSinceLastCall += spentBytes;
		    m_SentBytesSinceLastCallOverhead += spentOverhead;
			//if(record)theApp.QueueTraceLogLine(CAsyncSocketEx_workflow,_T("snow:UploadBandwidthThrottler in line 827:m_SentBytesSinceLastCall: %i m_SentBytesSinceLastCallOverhead : %i"), m_SentBytesSinceLastCall,m_SentBytesSinceLastCallOverhead);///snow:add to debug
    
            sendLocker.Unlock();
        }
		
		if(timeGetTime()-time>SEC2MS(60)) 
		{ 
			record=true;
			time=timeGetTime();
		}
		else record = false;

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