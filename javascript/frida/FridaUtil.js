/*
	File: FridaUtil.js
	Function: crifan's common Frida util related functions
	Author: Crifan Li
	Latest: https://github.com/crifan/crifanLib/blob/master/javascript/frida/FridaUtil.js
	Updated: 20240830
*/

// Frida Common Util
class FridaUtil {

  constructor() {
    console.log("FridaUtil constructor")
  }

  // Frida pointer to UTF-8 string
  static ptrToUtf8Str(curPtr){
    var curUtf8Str = curPtr.readUtf8String()
    // console.log("curUtf8Str=" + curUtf8Str)
    return curUtf8Str
  }

  // Frida pointer to C string
  static ptrToCStr(curPtr){
    // var curCStr = Memory.readCString(curPtr)
    var curCStr = curPtr.readCString()
    // console.log("curCStr=" + curCStr)
    return curCStr
  }

  // print function call and stack, output content type is: address
  static printFunctionCallStack_addr(curContext, prefix=""){
    var backtracerType = Backtracer.ACCURATE
    // var backtracerType = Backtracer.FUZZY
    if (!JsUtil.strIsEmpty(prefix)){
      prefix = prefix + " "
    }
    // const linePrefix = "\n"
    // const linePrefix = "\n\t"
    const linePrefix = "\n  "
    // const linePrefix = "\n "
    // const linePrefix = "\n"
    console.log(prefix + 'Stack:' + linePrefix +
      Thread.backtrace(curContext, backtracerType)
      .map(DebugSymbol.fromAddress).join(linePrefix) + '\n');
  }

  static dumpMemory(toDumpPtr, byteLen=128){
    var buf = toDumpPtr.readByteArray(byteLen)
    var dumpHexStr = hexdump(
      buf,
      {
        offset: 0,
        length: byteLen,
        header: true,
        ansi: true
      }
    )
    console.log("dumpHexStr=\n" + dumpHexStr)
  }

  // Frida Stalker hoo unknown name native function
  static stalkerHookUnnameNative(moduleBaseAddress, funcRelativeStartAddr, functionSize, argNum, hookFuncMap){
    console.log("Frida Stalker hook: module: baseAddress=" + moduleBaseAddress)

    var functionSizeHexStr = JsUtil.intToHexStr(functionSize)
    var funcRelativeStartAddrHexStr = JsUtil.intToHexStr(funcRelativeStartAddr)
    var funcRelativeEndAddr = funcRelativeStartAddr + functionSize
    var funcRelativeEndAddrHexStr = JsUtil.intToHexStr(funcRelativeEndAddr)
    console.log("function: relativeStartAddr=" + funcRelativeStartAddrHexStr + ", size=" + functionSize + "=" + functionSizeHexStr + ", relativeEndAddr=" + funcRelativeEndAddrHexStr)

    const funcRealStartAddr = moduleBaseAddress.add(funcRelativeStartAddr)
    // var funcRealEndAddr = funcRealStartAddr + functionSize
    const funcRealEndAddr = funcRealStartAddr.add(functionSize)
    console.log("funcRealStartAddr=" + funcRealStartAddr + ", funcRealEndAddr=" + funcRealEndAddr)
    var curTid = null
    console.log("curTid=" + curTid)
    Interceptor.attach(funcRealStartAddr, {
      onEnter: function(args) {
        JsUtil.logStr("Trigged addr: relative [" + funcRelativeStartAddrHexStr + "] = real [" + funcRealStartAddr + "]")

        for(var i = 0; i < argNum; i++) {
          var curArg = args[i]
          console.log("arg[" + i  + "]=" + curArg)
        }

        var curTid = Process.getCurrentThreadId()
        console.log("curTid=" + curTid)
        Stalker.follow(curTid, {
            events: {
              call: false, // CALL instructions: yes please            
              ret: true, // RET instructions
              exec: false, // all instructions: not recommended as it's
              block: false, // block executed: coarse execution trace
              compile: false // block compiled: useful for coverage
            },
            // onReceive: Called with `events` containing a binary blob comprised of one or more GumEvent structs. See `gumevent.h` for details about the format. Use `Stalker.parse()` to examine the data.
            onReceive(events) {
              var parsedEvents = Stalker.parse(events)
              // var parsedEventsStr = JSON.stringify(parsedEventsStr)
              // console.log(">>> into onReceive: parsedEvents=" + parsedEvents + ", parsedEventsStr=" + parsedEventsStr);
              console.log(">>> into onReceive: parsedEvents=" + parsedEvents);
            },

            // transform: (iterator: StalkerArm64Iterator) => {
            transform: function (iterator) {
              // https://www.radare.org/doc/frida/interfaces/StalkerArmIterator.html

              // console.log("iterator=" + iterator)
              var instruction = iterator.next()
              const startAddress = instruction.address
              // console.log("+++ into iterator: startAddress=" + startAddress)
              // const isAppCode = startAddress.compare(funcRealStartAddr) >= 0 && startAddress.compare(funcRealEndAddr) === -1
              // const isAppCode = (startAddress.compare(funcRealStartAddr) >= 0) && (startAddress.compare(funcRealEndAddr) < 0)
              const gt_realStartAddr = startAddress.compare(funcRealStartAddr) >= 0
              const lt_realEndAddr = startAddress.compare(funcRealEndAddr) < 0
              var isAppCode = gt_realStartAddr && lt_realEndAddr
              console.log("+++ into iterator: startAddress=" + startAddress + ", isAppCode=" + isAppCode)

              // // for debug
              // isAppCode = true

              // console.log("isAppCode=" + isAppCode + ", gt_realStartAddr=" + gt_realStartAddr + ", lt_realEndAddr=" + lt_realEndAddr)
              do {
                if (isAppCode) {
                  // is origal function code = which we focus on

                  // console.log("instruction: address=" + instruction.address
                  //     + ",next=" + instruction.next()
                  //     + ",size=" + instruction.size
                  //     + ",mnemonic=" + instruction.mnemonic
                  //     + ",opStr=" + instruction.opStr
                  //     + ",operands=" + JSON.stringify(instruction.operands)
                  //     + ",regsAccessed=" + JSON.stringify(instruction.regsAccessed)
                  //     + ",regsRead=" + JSON.stringify(instruction.regsRead)
                  //     + ",regsWritten=" + JSON.stringify(instruction.regsWritten)
                  //     + ",groups=" + JSON.stringify(instruction.groups)
                  //     + ",toString()=" + instruction.toString()
                  //     + ",toJSON()=" + instruction.toJSON()
                  // );

                  var curRealAddr = instruction.address
                  // console.log("curRealAddr=" + curRealAddr)
                  // const isAppCode = curRealAddr.compare(funcRealStartAddr) >= 0 && curRealAddr.compare(funcRealEndAddr) === -1
                  // console.log(curRealAddr + ": isAppCode=" + isAppCode)
                  var curOffsetHexPtr = curRealAddr.sub(funcRealStartAddr)
                  var curOffsetInt = curOffsetHexPtr.toInt32()
                  console.log("current: realAddr=" + curRealAddr + " -> offset: hex=" + curOffsetHexPtr + "=" + curOffsetInt)

                  // var instructionStr = instruction.mnemonic + " " + instruction.opStr
                  var instructionStr = instruction.toString()
                  // console.log("\t" + curRealAddr + ": " + instructionStr);
                  // console.log("\t" + curRealAddr + " <+" + curOffsetHexPtr + ">: " + instructionStr)
                  console.log("\t" + curRealAddr + " <+" + curOffsetInt + ">: " + instructionStr)

                  if (curOffsetInt in hookFuncMap){
                    console.log("offset: " + curOffsetHexPtr + "=" + curOffsetInt)
                    // let curHookFunc = hookFuncMap.get(curOffsetInt)
                    var curHookFunc = hookFuncMap[curOffsetInt]
                    // console.log("curOffsetInt=" + curOffsetInt + " -> curHookFunc=" + curHookFunc)

                    // putCallout -> https://www.radare.org/doc/frida/interfaces/StalkerArmIterator.html#putCallout
                    // StalkerScriptCallout -> https://www.radare.org/doc/frida/types/StalkerScriptCallout.html
                    // CpuContext -> https://www.radare.org/doc/frida/types/CpuContext.html
                    // Arm64CpuContext -> https://www.radare.org/doc/frida/interfaces/Arm64CpuContext.html

                    // work: normal
                    iterator.putCallout(curHookFunc)

                    // var extraDataDict = {
                    //   "curOffsetInt": curOffsetInt
                    // }
                    // Not work: abnormal
                    // iterator.putCallout((context) => {
                    // // iterator.putCallout((context, extraDataDict) => {
                    //   // console.log("match offset: " + curOffsetHexPtr + ", curRealAddr=" + curRealAddr)
                    //   // curHookFunc(context, curOffsetInt, moduleBaseAddress)
                    //   // context.curOffsetInt = curOffsetInt
                    //   // context.curOffsetHexPtr = curOffsetHexPtr
                    //   // context.moduleBaseAddress = moduleBaseAddress
                    //   // context[curOffsetInt] = curOffsetInt
                    //   // context[curOffsetHexPtr] = curOffsetHexPtr
                    //   // context[moduleBaseAddress] = moduleBaseAddress
                    //   // curHookFunc(context, extraDataDict)
                    //   curHookFunc(context)
                    // })
                  }

                }
                iterator.keep()
              } while ((instruction = iterator.next()) !== null)
            }
        });

        // function needDebug(context) {
        //     console.log("into needDebug")
        //     // console.log("into needDebug: context=" + context)
        //     // var contextStr = JSON.stringify(context, null, 2)
        //     // console.log("context=" + contextStr)
        //     // var x9Value1 = context.x9
        //     // var x9Value2 = context["x9"]
        //     // console.log("x9Value1=" + x9Value1 + ", x9Value2=" + x9Value2)
        // }
      },
      onLeave: function(retval) {
        console.log("addr: relative [" + funcRelativeStartAddrHexStr + "] real [" + funcRealStartAddr + "] -> retval=" + retval)
        if (curTid != null) {
          Stalker.unfollow(curTid)
          console.log("Stalker.unfollow curTid=", curTid)
        }
      }
    })
  }


}