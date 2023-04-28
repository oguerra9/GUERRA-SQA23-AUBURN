'''
Olivia Guerra
May 1, 2023
Code to automatically fuzz 5 python methods
'''
import scanner
import parser

def fuzzValues():
	values = [
		"<a href=\"javascript\\x0A:javascript:alert(1)\" id=\"fuzzelement1\">test</a>",
		"`\"'><img src=xxx:x \\x0Aonerror=javascript:alert(1)>",
		"</textarea><script>alert(123)</script>",
		"<IMG SRC=# onmouseover=\"alert('xxs')\">",
		"<IMG SRC= onmouseover=\"alert('xxs')\">",
		"<IMG onmouseover=\"alert('xxs')\">",
		"<IMG SRC=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;>",
		"<IMG SRC=&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041>",
		"<IMG SRC=&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29>",
		"<IMG SRC=\"jav   ascript:alert('XSS');\">",
		"<IMG SRC=\"jav&#x09;ascript:alert('XSS');\">",
		"<IMG SRC=\"jav&#x0A;ascript:alert('XSS');\">",
		"<IMG SRC=\"jav&#x0D;ascript:alert('XSS');\">",
		"perl -e 'print \"<IMG SRC=java\\0script:alert(\\\"XSS\\\")>\";' > out",
		"<IMG SRC=\" &#14;  javascript:alert('XSS');\">",
		"<SCRIPT/XSS SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>",
		"<BODY onload!#$%&()*~+-_.,:;?@[/|\\]^`=alert(\"XSS\")>",
		"<SCRIPT/SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>",
		"<<SCRIPT>alert(\"XSS\");//<</SCRIPT>",
		"<SCRIPT SRC=http://ha.ckers.org/xss.js?< B >",
		"<SCRIPT SRC=//ha.ckers.org/.j>",
		"<IMG SRC=\"javascript:alert('XSS')\"",
		"<iframe src=http://ha.ckers.org/scriptlet.html <",
		"\\\";alert('XSS');//", "<u oncopy=alert()> Copy me</u>",
		"<i onwheel=alert(1)> Scroll over me </i>", "<plaintext>", "http://a/%%30%30",
		"", "undefined", "undef", "null", "NULL", "(null)", "nil", "NIL",
		"true", "false", "True", "False", "TRUE", "FALSE",
		"None", "hasOwnProperty", "then",
		"\\", "\\\\",
		"0", "1", "1.00", "$1.00", "1/2", "1E2", "1E02", "1E+02", "-1", "-1.00", "-$1.00",
		"-1/2", "-1E2", "-1E02", "-1E+02",
		"1/0", 	"0/0", "-2147483648/-1", "-9223372036854775808/-1",
		"-0", "-0.0", "+0", "+0.0", "0.00", "0..0", ".", "0.0.0", "0,00", "0,,0", ",",
		"0,0,0", "0.0/0", "1.0/0.0", "0.0/0.0", "1,0/0,0", "0,0/0,0", "--1",
		"-", "-.", "-,",
		"999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999",
		"NaN", "Infinity", "-Infinity", "INF", "1#INF", "-1#IND", "1#QNAN", "1#SNAN",
		"1#IND", "0x0", "0xffffffff", "0xffffffffffffffff",
		"0xabad1dea",
		"123456789012345678901234567890123456789",
		"1,000.00", "1 000.00", "1'000.00", "1,000,000.00", "1 000 000.00", "1'000'000.00",
		"1.000,00", "1 000,00", "1'000,00", "1.000.000,00", "1 000 000,00", "1'000'000,00",
		"01000",
		"08",
		"09",
		"2.2250738585072011e-308",
		",./;'[]\\-=",
		"<>?:\"{}|_+",
		"!@#$%^&*()`~",
		"--help",
		"--version",
		"The quic\b\b\b\b\b\bk brown fo\u0007\u0007\u0007\u0007\u0007\u0007\u0007\u0007\u0007\u0007\u0007x... [Beeeep]",
		"() { _; } >_[$($())] { touch /tmp/blns.shellshock2.fail; }",
		"../../../../../../../../../../../etc/passwd%00",
		"File:///",
		"%n",
		"System(\"ls -al /\")",
		"`ls -al /`",
		"Kernel.exec(\"ls -al /\")",
		"Kernel.exit(1)",
		"%x('ls -al /')",
		"<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE foo [ <!ELEMENT foo ANY ><!ENTITY xxe SYSTEM \"file:///etc/passwd\" >]><foo>&xxe;</foo>",
		"$HOME",
		"$ENV{'HOME'}",
		"%d", "%s%s%s%s%s",
		"{0}", "%*.*s", "%@",
		"$USER", "/dev/null; touch /tmp/blns.fail ; echo",
		"`touch /tmp/blns.fail`",
		"$(touch /tmp/blns.fail)",
		"@{[system \"touch /tmp/blns.fail\"]}",
		"eval(\"puts 'hello world'\")"]

	print('scanner.py/isValidUserName()')
	for value in values:
		unOutput = scanner.isValidUserName(value)
		if unOutput != True:
			print('INPUT: ', value)
			print('OUTPUT: ', unOutput)

	print('scanner.py/getYAMLFiles()')
	for value in values:
		output = scanner.getYAMLFiles(value)
		if len(output) > 0:
			print('INPUT: ', value)
			print('OUTPUT: ', output)

	print('scanner.py/isValidPasswordName()')
	for value in values:
		passOutput = scanner.isValidPasswordName(value)
		if passOutput != True:
			print('INPUT: ', value)
			print('OUTPUT: ', passOutput)

	print('scanner.py/isValidKey()')
	for value in values:
		keyOutput = scanner.isValidKey(value)
		if keyOutput != True and keyOutput != False:
			print('INPUT: ', value)
			print('OUTPUT: ', keyOutput)

	'''
	print('scanner.py/scanForOverPrivileges()')
	for value in values:
		privOutput = scanner.scanForOverPrivileges(value)
		print('INPUT: ', value)
		print('OUTPUT: ', privOutput)
	'''

	print('parser.py/checkIfWeirdYAML()')
	for value in values:
		weirdOutput = parser.checkIfWeirdYAML(value)
		if weirdOutput != False:
			print('INPUT: ', value)
			print('OUTPUT: ', weirdOutput)

	print('parser.py/getValuesRecursively()')
	recValuesOutput = parser.getValuesRecursively(values)
	print('OUTPUT: ', recValuesOutput)

	'''
	print('parser.py/checkIfValidK8SYaml()')
	for value in values:
		k8syamlOutput = parser.checkIfValidK8SYaml(value)
		print('INPUT: ', value)
		print('OUTPUT: ', k8syamlOutput)
	'''

	print('parser.py/checkIfValidHelm()')
	for value in values:
		helmOutput = parser.checkIfValidHelm(value)
		if helmOutput != False:
			print('INPUT: ', value)
			print('OUTPUT: ', helmOutput)

	'''
	print('parser.py/readYAMLAsStr()')
	for value in values:
		readOutput = parser.readYAMLAsStr(value)
		print('INPUT: ', value)
		print('OUTPUT: ', readOutput)
	'''

	'''
	print('parser.py/loadMultiYAML()')
	for value in values:
		multiOutput = parser.loadMultiYAML(value)
		print('INPUT: ', value)
		print('OUTPUT: ', multiOutput)
	'''

	print('parser.py/getSingleDict4MultiDocs(lis_dic)')
	predictedOutput = {}
	for value in values:
		singleOutput = parser.getSingleDict4MultiDocs(value)
		if singleOutput != predictedOutput:
			print('INPUT: ', value)
			print('OUTPUT: ', singleOutput)

	print('scanner.py/isValidPasswordName(pName)')
	for value in values:
		passOutput = scanner.isValidPasswordName(value)
		if passOutput != True:
			print('INPUT: ', value)
			print('OUTPUT: ', passOutput)


	print('scanner.py/checkIfValidSecret(single_config_val)')
	for value in values:
		validSecretOutput = scanner.checkIfValidSecret(value)
		if validSecretOutput != True and validSecretOutput != False:
			print('INPUT: ', value)
			print('OUTPUT: ', validSecretOutput)


	print('scanner.py/checkIfValidKeyValue(single_config_val)')
	for value in values:
		validKeyOutput = scanner.checkIfValidKeyValue(value)
		if validKeyOutput != False:
			print('INPUT: ', value)
			print('OUTPUT: ', validKeyOutput)


	print('scanner.py/scanForSecrets(yaml_d)')
	for value in values:
		secOutput = scanner.scanForSecrets(value)
		if secOutput != predictedOutput:
			print('INPUT: ', value)
			print('OUTPUT: ', secOutput)

	'''
	print('scanner.py/scanSingleManifest(path_to_script)')
	for value in values:
		validKeyOutput = scanner.scanSingleManifest(value)
		print('INPUT: ', value)
		print('OUTPUT: ', validKeyOutput)
	'''

	'''
	print('scanner.py/scanForHTTP(path2script)')
	for value in values:
		validKeyOutput = scanner.scanForHTTP(value)
		print('INPUT: ', value)
		print('OUTPUT: ', validKeyOutput)
	'''

	print('scanner.py/runScanner(dir2scan)')
	emptyList = []
	for value in values:
		validKeyOutput = scanner.runScanner(value)
		if validKeyOutput != emptyList:
			print('INPUT: ', value)
			print('OUTPUT: ', validKeyOutput)

def simpleFuzzer():
    fuzzValues()

if __name__=='__main__':
    simpleFuzzer()
