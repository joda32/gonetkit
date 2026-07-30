package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/jfjallid/go-smb/dcerpc"
	"github.com/jfjallid/go-smb/dcerpc/msscmr"
	"github.com/jfjallid/go-smb/dcerpc/smbtransport"
	"github.com/jfjallid/go-smb/smb"

	"github.com/joda32/gonetkit/internal/credentials"
	"github.com/joda32/gonetkit/internal/util"
)

func main() {
	creds := &credentials.Credentials{}

	var share, shellType, serviceName string
	flag.StringVar(&share, "share", "C$", "Share where the output will be grabbed from")
	flag.StringVar(&shellType, "shell-type", "cmd", "Shell type: cmd or powershell")
	flag.StringVar(&serviceName, "service-name", "", "Custom service name (random if empty)")
	creds.RegisterFlags(flag.CommandLine)

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "smbexec - Remote command execution via SCM\n\n")
		fmt.Fprintf(os.Stderr, "Usage: smbexec [options] [[domain/]username[:password]@]<target>\n\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	if flag.NArg() < 1 {
		flag.Usage()
		os.Exit(1)
	}

	creds.ParseTarget(flag.Arg(0))
	creds.PromptPassword()

	if serviceName == "" {
		serviceName = util.RandomServiceName()
	}

	if err := run(creds, share, shellType, serviceName); err != nil {
		fmt.Fprintf(os.Stderr, "[-] %v\n", err)
		os.Exit(1)
	}
}

func run(creds *credentials.Credentials, share, shellType, serviceName string) error {
	opts, err := creds.SMBOptions()
	if err != nil {
		return err
	}

	if creds.Debug {
		fmt.Fprintf(os.Stderr, "[*] Connecting to %s:%d\n", creds.TargetIP, creds.Port)
	}

	session, err := smb.NewConnection(opts)
	if err != nil {
		return fmt.Errorf("SMB connection failed: %w", err)
	}
	defer session.Close()

	if creds.Debug {
		fmt.Fprintf(os.Stderr, "[*] Authenticated as %s\n", session.GetAuthUsername())
	}

	if err := session.TreeConnect("IPC$"); err != nil {
		return fmt.Errorf("IPC$ tree connect failed: %w", err)
	}
	defer session.TreeDisconnect("IPC$")

	pipeFile, err := session.OpenFile("IPC$", "svcctl")
	if err != nil {
		return fmt.Errorf("failed to open svcctl pipe: %w", err)
	}
	defer pipeFile.CloseFile()

	trans, err := smbtransport.NewSMBTransport(pipeFile)
	if err != nil {
		return fmt.Errorf("failed to create SMB transport: %w", err)
	}

	bind, err := dcerpc.Bind(trans, msscmr.MSRPCUuidSvcCtl, msscmr.MSRPCSvcCtlMajorVersion, msscmr.MSRPCSvcCtlMinorVersion, dcerpc.MSRPCUuidNdr)
	if err != nil {
		return fmt.Errorf("SCMR bind failed: %w", err)
	}

	rpc := msscmr.NewRPCCon(bind)

	if err := session.TreeConnect(share); err != nil {
		return fmt.Errorf("failed to connect to share %s: %w", share, err)
	}
	defer session.TreeDisconnect(share)

	shell := &remoteShell{
		session:     session,
		rpc:         rpc,
		share:       share,
		outputFile:  "__output_" + util.RandomName(8),
		serviceName: serviceName,
		shellType:   shellType,
		debug:       creds.Debug,
	}
	defer shell.cleanup()

	return shell.cmdloop()
}

type remoteShell struct {
	session     *smb.Connection
	rpc         *msscmr.RPCCon
	share       string
	outputFile  string
	serviceName string
	shellType   string
	debug       bool
	prompt      string
}

func (s *remoteShell) cleanup() {
	_ = s.session.DeleteFile(s.share, s.outputFile)
	_ = s.rpc.DeleteService(s.serviceName)
}

func (s *remoteShell) cmdloop() error {
	output, err := s.executeRemote("cd", "cmd")
	if err != nil {
		return fmt.Errorf("initial command failed: %w", err)
	}
	s.prompt = strings.TrimSpace(output) + ">"
	if s.shellType == "powershell" {
		s.prompt = "PS " + s.prompt + " "
	}

	fmt.Println("[!] Launching semi-interactive shell - Careful what you execute")

	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print(s.prompt)
		if !scanner.Scan() {
			fmt.Println()
			break
		}
		line := scanner.Text()

		switch {
		case line == "exit" || line == "quit":
			return nil
		case line == "":
			continue
		case strings.EqualFold(line, "cd") || strings.HasPrefix(strings.ToLower(line), "cd "):
			args := strings.TrimSpace(line[2:])
			if len(args) > 0 {
				fmt.Println("[!] You can't CD under SMBEXEC. Use full paths.")
				continue
			}
			output, err := s.executeRemote("cd", "cmd")
			if err != nil {
				fmt.Fprintf(os.Stderr, "[-] %v\n", err)
				continue
			}
			s.prompt = strings.TrimSpace(output) + ">"
			if s.shellType == "powershell" {
				s.prompt = "PS " + s.prompt + " "
			}
		default:
			output, err := s.executeRemote(line, s.shellType)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[-] %v\n", err)
				continue
			}
			if output != "" {
				fmt.Print(output)
			}
		}
	}

	return nil
}

func (s *remoteShell) executeRemote(data, shellType string) (string, error) {
	outputPath := `\\%COMPUTERNAME%\` + s.share + `\` + s.outputFile

	if shellType == "powershell" {
		data = `$ProgressPreference="SilentlyContinue";` + data
		data = `powershell.exe -NoP -NoL -sta -NonI -W Hidden -Exec Bypass -Enc ` + util.EncodePowerShell(data)
	}

	batchFile := `%SYSTEMROOT%\` + util.RandomName(8) + ".bat"

	command := `%COMSPEC% /Q /c echo ` + data + ` ^> ` + outputPath + ` 2^>^&1 > ` + batchFile +
		` & %COMSPEC% /Q /c ` + batchFile +
		` & del ` + batchFile

	if s.debug {
		fmt.Fprintf(os.Stderr, "[*] Executing: %s\n", command)
	}

	err := s.rpc.CreateService(
		s.serviceName,
		msscmr.ServiceWin32OwnProcess,
		msscmr.ServiceDemandStart,
		msscmr.ServiceErrorIgnore,
		command,
		"", "", "",
		true,
	)
	if err != nil && s.debug {
		fmt.Fprintf(os.Stderr, "[*] CreateService returned (expected): %v\n", err)
	}

	_ = s.rpc.DeleteService(s.serviceName)

	return s.getOutput()
}

func (s *remoteShell) getOutput() (string, error) {
	var buf bytes.Buffer
	var lastErr error

	for attempt := 0; attempt < 30; attempt++ {
		buf.Reset()
		err := s.session.RetrieveFile(s.share, s.outputFile, 0, func(data []byte) (int, error) {
			return buf.Write(data)
		})
		if err == nil {
			_ = s.session.DeleteFile(s.share, s.outputFile)
			return buf.String(), nil
		}
		lastErr = err
		time.Sleep(500 * time.Millisecond)
	}

	return "", fmt.Errorf("output file not available after retries: %w", lastErr)
}
