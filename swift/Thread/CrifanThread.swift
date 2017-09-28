//
//  CrifanThread.swift
//  Crifan Li
//  Updated: 2017/09/28
//

import UIKit

let MainThread:DispatchQueue = DispatchQueue.main

let UserInteractiveThread:DispatchQueue = DispatchQueue.global(qos: DispatchQoS.QoSClass.userInteractive)
let UserInitiatedThread:DispatchQueue = DispatchQueue.global(qos: DispatchQoS.QoSClass.userInitiated)
let DefaultThread:DispatchQueue = DispatchQueue.global(qos: DispatchQoS.QoSClass.default)
let UtilityThread:DispatchQueue = DispatchQueue.global(qos: DispatchQoS.QoSClass.utility)
let BackgroundThread:DispatchQueue = DispatchQueue.global(qos: DispatchQoS.QoSClass.background)
let UnspecifiedThread:DispatchQueue = DispatchQueue.global(qos: DispatchQoS.QoSClass.unspecified)


/***************************************************************************
 * GCD/Queue/Thread functions
 ***************************************************************************/

func delayDispatch(_ delayTimeInSec:Double, inThread:DispatchQueue, thingsTodo:@escaping ()->()) {
    let dispatchDelayTime = DispatchTime.now() + Double(Int64(delayTimeInSec * Double(NSEC_PER_SEC))) / Double(NSEC_PER_SEC)
    
    inThread.asyncAfter(deadline: dispatchDelayTime, execute: thingsTodo)
}

func delayDispatchInMainThread(_ delayTimeInSec:Double, thingsTodo:@escaping ()->()) {
    delayDispatch(delayTimeInSec, inThread: MainThread, thingsTodo: thingsTodo)
}

func dispatchMain_sync(_ delayTimeInSec:Double = 0.0, thingsTodo:@escaping ()->()) {
    delayDispatchInMainThread(delayTimeInSec, thingsTodo: thingsTodo)
}

func delayDispatchInBackgroundThread(_ delayTimeInSec:Double, thingsTodo:@escaping ()->()) {
    delayDispatch(delayTimeInSec, inThread: BackgroundThread, thingsTodo: thingsTodo)
}

func dispatchBackground_async(_ thingsTodo:@escaping ()->()) {
    BackgroundThread.async(execute: thingsTodo)
}

func dispatchUserInitiated_async(_ thingsTodo:@escaping ()->()) {
    UserInitiatedThread.async(execute: thingsTodo)
}

func dispatchMain_async(_ thingsTodo:@escaping ()->()) {
    MainThread.async(execute: thingsTodo)
}

