// Package rex provides the ability to execute commands remotely on multiple hosts, in either sequential or concurrent (default) mode.
// In concurrent mode, the output order is by design random, but since every single line is correctly prefixed by a useful string, the output is reusable.
//
// Please set GOMAXPROCS to benefit from actual parallelism.
package rex

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"code.google.com/p/go.crypto/ssh"
)

var (
	streams = [2]string{"out", "err"} // standard output/error string used in prefix
)

// Command represents a command to be executed on a host
// If Sudo is nil, it will be overwritten by Session.Options.Sudo upon execution of Session.RunCommands
type Command struct {
	Cmd  string
	Sudo *bool
}

// NewCommand returns a new Command given a string command and a boolean describing whether the command should be executed with sudo.
// The returned Command is ready to be used with Session.Run.
func NewCommand(cmd string, sudo bool) *Command {
	return &Command{cmd, &sudo}
}

// NewCommands returns a slice of Command objects given a slice of string commands.
// Each command's Sudo field is kept nil.
func NewCommands(cmds []string) []*Command {
	res := make([]*Command, len(cmds))
	for i, cmd := range cmds {
		res[i] = &Command{Cmd: cmd}
	}
	return res
}

// Options records some additional options that are taken into account during Session.RunCommand(s).
type Options struct {
	// If set, will try to use root permission.
	Sudo bool

	// If set, will execute commands on one host at a time.
	// Otherwise, will execute concurrently. However, commands will always be executed sequentially on one given host.
	Sequential bool

	// If set, will use directly the command as is.
	// Otherwise, will escape the command and wrap it around quotes before prepending it by Shell string.
	//
	// Important: it is recommended to keep NoShell false when Sudo is set to true.
	// If both Sudo and NoShell are true, then whoami && whoami will yield root only for the first whoami,
	// since the actual command executed would then be sudo whoami && whoami.
	NoShell bool

	// Shell holds the string prepended to the command to be executed.
	// If NoShell is set, Shell is not used.
	// Otherwise, if Shell is empty, Shell is set to the SHELL environment variable followed by "-l -c"
	//
	// Example: if the command to be executed is echo "hello world" and NoShell is false and Shell == "/bin/bash -l -c",
	// then, assuming Sudo is false, the actual command executed is: /bin/bash -l -c "echo \"hello world\""
	Shell string
}

// Host represents a server running an SSH daemon.
type Host struct {
	Name string
	ch   chan error
}

// errElement is the result object sent from a host through the Session.errors channel
type errElement struct {
	err      error
	hostname string
}

// ClientPassword is a wrapper around ssh.ClientPassword to prevent this package's users to make a useless dependency on package ssh
type ClientPassword interface {
	ssh.ClientPassword
}

// Session represents a Session for remote execution.
type Session struct {
	// ClPass is used when a password is necessary (for sudo)
	// If nil, a panic can happen
	// Note: under normal circumstances, it should be called only once per rex session
	ClPass  ClientPassword
	Hosts   []*Host           // List of Hosts to operate on
	Config  *ssh.ClientConfig // SSH config to use for authentication
	Options Options           // Additional options
	Out     io.Writer         // Output to write to

	password *string          // cache password instead of invoking ClPass
	errors   chan *errElement // holds result channel (buffer size will equal number of Hosts)
}

// NewSession constructs a new Session given a username, an interface value implementing ClientPassword, a list of hostnames and additional options.
func NewSession(username string, clientPassword ClientPassword, hostnames []string, options *Options) (*Session, error) {

	// health checks
	if username == "" {
		return nil, errors.New("No username provided")
	}
	if clientPassword == nil {
		return nil, errors.New("No clientPassword provided")
	}
	if len(hostnames) == 0 {
		return nil, errors.New("No hostnames provided")
	}

	// create hosts
	hosts := make([]*Host, len(hostnames))
	for i := range hosts {
		hosts[i] = &Host{strings.TrimSpace(hostnames[i]), make(chan error)}
	}

	// prepare default options but use given one if provided
	var opts Options
	if options != nil {
		opts = *options
	}

	// if needed, set default Shell string using SHELL environment variable
	if !opts.NoShell && opts.Shell == "" {
		opts.Shell = fmt.Sprintf("%s -l -c", os.Getenv("SHELL"))
	}

	// build ssh authentication methods
	auth := make([]ssh.ClientAuth, 0, 2)
	// try adding ssh-agent
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{os.Getenv("SSH_AUTH_SOCK"), "unix"})
	if err == nil {
		auth = append(auth, ssh.ClientAuthAgent(ssh.NewAgentClient(conn)))
	}

	// password fallback (in case ssh-agent fails, or if sudo password is asked)
	auth = append(auth, ssh.ClientAuthPassword(clientPassword))

	config := &ssh.ClientConfig{
		User: username,
		Auth: auth,
	}

	return &Session{ClPass: clientPassword, Hosts: hosts, Config: config, Options: opts}, nil
}

// runCommandsOnHost will execute all the commands sequentially on the given host and return an error.
// note: every output line is prefixed by a useful string holding the hostname, time, and the stream kind (out/err).
func (s *Session) runCommandsOnHost(host *Host, cmds []*Command) (err error) {

	// health checks
	if host == nil {
		return errors.New("No host provided to runCommandsOnHost")
	}
	if host.Name == "" {
		return errors.New("Hostname is empty")
	}
	if s.Config == nil {
		return errors.New("No SSH authentication config provided")
	}

	// connect to host via ssh using provided configuration
	client, err := ssh.Dial("tcp", host.Name+":22", s.Config)
	if err != nil {
		msg := "ssh: unable to authenticate"
		if strings.HasPrefix(err.Error(), msg) {
			// it is very likely that all the authentication methods in s.Config failed (wrong password/sshagent)
			err = fmt.Errorf("%s with user `%s`", msg, s.Config.User)
		}
		return err
	}
	defer client.Close() // will close connection no matter what

	// create channel to communicate with goroutines responsible for line buffering/prefixing
	//ch := make(chan *errElement, len(cmds))

	// for each command
	for _, cmd := range cmds {

		// open a shell session
		session, err := client.NewSession()
		if err != nil {
			return err
		}
		defer session.Close() // will close shell session no matter what

		var (
			realCmd = cmd.Cmd                                                // realCmd is the string that will effectively be executed; the command is default
			format  = "%s"                                                   // format holds the format string to which realCmd will be applied
			kind    = "run"                                                  // kind holds a string identifying the kind of output (used in prefix)
			bufs    = [2]*bytes.Buffer{new(bytes.Buffer), new(bytes.Buffer)} // resp stdout and stderr buffer
		)

		// link buffers with shell session
		session.Stdout = bufs[0]
		session.Stderr = bufs[1]

		// health check
		if cmd.Sudo == nil {
			return fmt.Errorf("Sudo field not set in Command `%s`", cmd.Cmd)
		}

		if *cmd.Sudo {
			kind = "sudo"

			// get user's password for root permissions
			if s.password == nil {
				if s.ClPass == nil {
					panic("ClPass not set")
				}
				pass, err := s.ClPass.Password(s.Config.User)
				if err != nil {
					panic(err.Error())
				}
				s.password = &pass
			}

			// create stdin stream for sudo from given password
			session.Stdin = strings.NewReader(fmt.Sprintf("%s\n", *s.password))
			if s.Options.NoShell {
				format = "sudo -k -S -p' ' %s"
			} else {
				format = fmt.Sprintf("sudo -k -S -p' ' %s \"%%s\"", s.Options.Shell)
			}
		} else {
			if !s.Options.NoShell {
				format = fmt.Sprintf("%s \"%%s\"", s.Options.Shell)
			}
		}
		
		if !s.Options.NoShell {
			// escape command to be able to wrap into double quotes
			for _, c := range []string{"\"", "$", "`"} {
				realCmd = strings.Replace(realCmd, c, "\\"+c, -1)
			}
		}

		realCmd = fmt.Sprintf(format, realCmd)
		// write the hostname, time and command being run to output
		fmt.Fprintf(s.Out, "[%s:%d] %s: %s\n", host.Name, time.Now().Unix(), kind, cmd.Cmd)

		// execute command
		err = session.Run(realCmd)
		if err != nil {
			return err
		}

		// launch goroutine responsible for buffering/prefixing every line
		//go func(hostname string) {
		for i, b := range bufs {
			buf := bufio.NewReader(b)
			for {
				line, err := buf.ReadString('\n')
				if err == io.EOF {
					break
				} else if err != nil {
					return err
					//ch <- &errElement{err, hostname}
				}
				if line[len(line)-1] == '\n' {
					// write line with prefix (line already has a trailing \n)
					fmt.Fprintf(s.Out, "[%s:%d] %s: %s", host.Name, time.Now().Unix(), streams[i], line)
				} else {
					// ensure \n is added for special case when EOF is encountered and line does not end with \n
					fmt.Fprintf(s.Out, "[%s:%d] %s: %s\n", host.Name, time.Now().Unix(), streams[i], line)
				}
			}
		}
		//ch <- nil
		//}(host.Name)
	}
	/*for _ = range cmds {
		el := <-ch
		if el != nil {
			fmt.Fprintf(os.Stderr, "Error on host `%s`: %v", el.hostname, el.err)
		}
	}
	*/
	fmt.Fprintf(s.Out, "Disconnected from `%s`.\n", host.Name)
	return nil
}

// RunCommands executes multiple commands, one command at a time, on all the hosts either concurrently or sequentially depending on Options.Sequential.
func (s *Session) RunCommands(cmds []*Command) (err error) {

	// Set default output to Stdout if none provided
	if s.Out == nil {
		s.Out = os.Stdout
	}

	// Set default Sudo boolean for all the commands that don't have it set
	for _, cmd := range cmds {
		if cmd.Sudo == nil {
			cmd.Sudo = &s.Options.Sudo
		}
	}

	// closure to call when willing to receive results
	f := func(ch chan *errElement) {
		el := <-ch
		if el != nil {
			fmt.Fprintf(os.Stderr, "Error on host `%s`: %v\n", el.hostname, el.err)
		}
	}

	// s.errors holds a buffer of error results for all hosts
	s.errors = make(chan *errElement, len(s.Hosts))

	// for each host
	for _, host := range s.Hosts {

		// launch a goroutine that will execute the commands on that host in the background
		go func(host *Host) {
			err := s.runCommandsOnHost(host, cmds)
			if err != nil {
				s.errors <- &errElement{err, host.Name}
				return
			}
			s.errors <- nil
		}(host)

		// if in sequential mode, then wait for the goroutine to send its result
		if s.Options.Sequential {
			f(s.errors)
		}
	}

	// if in concurrent mode, retrieve the results in no particular order
	// Note: the reason there is no particular order is because the s.errors channel is buffered with the same size as the number of hosts.
	if !s.Options.Sequential {
		for _ = range s.Hosts {
			f(s.errors)
		}
	}

	fmt.Fprintln(s.Out, "Done.")
	return nil
}

// RunCommand executes a single command on all the hosts either concurrently or sequentially depending on Options.Sequential
func (s *Session) RunCommand(cmd *Command) error {
	return s.RunCommands([]*Command{cmd})
}
