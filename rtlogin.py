import pexpect, sys, time, re

def setcommand( s ):
	print "setting the debug command"	
	s.sendline('shelltimeout -1')
	s.expect('DEBUG>', timeout = 90)
	#s.sendline('debug sip-reg-state')
	#s.expect('DEBUG>', timeout = 90)
	#s.sendline('sdump')
	#s.expect( pexpect.EOF, timeout = 60)
	#print s.before
#	s.sendline('debug sip-message')
#	s.expect('DEBUG>', timeout = 90)
#	s.sendline('debug fsm gsm lsm')
#	s.expect('DEBUG>', timeout = 90)
#	s.sendline('debug jvm tftp')
#	s.expect('DEBUG>', timeout = 90)
#	s.sendline('debug jvm http')
#	s.expect('DEBUG>', timeout = 90)

def _startlogin( phone_addr ):
        s = pexpect.spawn('ssh -o MACs=hmac-md5 cisco %s' % phone_addr)
        sshKeyStr = re.escape("(yes/no)?")
	expVal = s.expect(["password:", sshKeyStr], timeout=120)

        if expVal == 1:
                s.sendline('yes')
                expVal = s.expect("password:", timeout=120)

        s.sendline('cisco')
	
        s.expect('\\(none\\) login:')
        s.sendline('debug')

	try:
		s.expect("Password:")
		s.sendline('debug')
		s.expect('DEBUG\\>', timeout = 60)
		print "Login Successfull"
		fout = file( phone_addr, 'w')
		s.logfile = fout
		setcommand( s )
	except pexpect.EOF:
		print "EOF...... %s" % phone_addr
		return fail( s , fout, phone_addr )
	except pexpect.TIMEOUT:
		print "timeout...... %s" % phone_addr
		return fail( s , fout, phone_addr )

	return success( s , fout )

def startlogin( phone_addr ):
        print "attempting to connect to phone %s" % phone_addr
	_startlogin( phone_addr )

def fail( s, fout ):
	s.close()
	fout.close()
        print "Login fail %s" % phone_addr

def success( s, fout ):
	s.close()
	fout.close()
        print "set command successful, and exit."

if __name__ == '__main__':
	fips = open( 'ips', 'r')
	row = 0
	for phone_addr in fips:
		row = row + 1
		print '--------- %d -----------' % row
		startlogin( phone_addr.rstrip('\n') )

