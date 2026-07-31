package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/md4" //nolint:staticcheck
	"www.velocidex.com/golang/regparser"

	localcrypto "github.com/joda32/gonetkit/internal/crypto"
)

func DumpLSA(hiveData []byte, bootKey []byte, w outputWriter, history bool) error {
	reg, err := regparser.NewRegistry(bytes.NewReader(hiveData))
	if err != nil {
		return fmt.Errorf("parse SECURITY hive: %w", err)
	}

	lsaKey, isVista, err := getLSAKey(reg, bootKey)
	if err != nil {
		return fmt.Errorf("LSA key: %w", err)
	}

	nlkmKey, err := getNLKMKey(reg, lsaKey, isVista)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] NL$KM key: %v\n", err)
	} else {
		dumpCachedHashes(reg, nlkmKey, isVista, w)
	}

	dumpSecrets(reg, lsaKey, isVista, w, history)

	return nil
}

func getLSAKey(reg *regparser.Registry, bootKey []byte) ([]byte, bool, error) {
	polEK := reg.OpenKey("Policy\\PolEKList")
	if polEK != nil {
		key, err := getLSAKeyVista(polEK, bootKey)
		return key, true, err
	}

	polSE := reg.OpenKey("Policy\\PolSecretEncryptionKey")
	if polSE != nil {
		key, err := getLSAKeyXP(polSE, bootKey)
		return key, false, err
	}

	return nil, false, fmt.Errorf("no LSA encryption key found")
}

func getLSAKeyVista(key *regparser.CM_KEY_NODE, bootKey []byte) ([]byte, error) {
	data := getDefaultValue(key)
	if data == nil {
		return nil, fmt.Errorf("PolEKList default value not found")
	}

	if len(data) < 28+32 {
		return nil, fmt.Errorf("PolEKList too short")
	}

	salt := data[28 : 28+32]
	cipher := data[28+32:]

	decKey := localcrypto.SHA256LSAKey(bootKey, salt)
	plain, err := localcrypto.DecryptAES(decKey, cipher, make([]byte, 16))
	if err != nil {
		return nil, err
	}

	if len(plain) < 16+52+32 {
		return nil, fmt.Errorf("decrypted PolEKList too short (%d bytes)", len(plain))
	}

	lsaKey := plain[16+52 : 16+52+32]
	return lsaKey, nil
}

func getLSAKeyXP(key *regparser.CM_KEY_NODE, bootKey []byte) ([]byte, error) {
	data := getDefaultValue(key)
	if data == nil {
		return nil, fmt.Errorf("PolSecretEncryptionKey default value not found")
	}

	if len(data) < 76 {
		return nil, fmt.Errorf("PolSecretEncryptionKey too short")
	}

	salt := data[60:76]
	rc4Key := localcrypto.MD5LSAKey(bootKey, salt)

	plain, err := localcrypto.DecryptRC4(rc4Key, data[12:60])
	if err != nil {
		return nil, err
	}

	return plain[0x10:0x20], nil
}

func getNLKMKey(reg *regparser.Registry, lsaKey []byte, isVista bool) ([]byte, error) {
	nlkm := reg.OpenKey("Policy\\Secrets\\NL$KM\\CurrVal")
	if nlkm == nil {
		return nil, fmt.Errorf("NL$KM not found")
	}

	data := getDefaultValue(nlkm)
	if data == nil {
		return nil, fmt.Errorf("NL$KM default value not found")
	}

	if isVista {
		return decryptLSASecretVista(lsaKey, data)
	}
	return localcrypto.DecryptLSASecret(lsaKey, data)
}

func dumpCachedHashes(reg *regparser.Registry, nlkmKey []byte, isVista bool, w outputWriter) {
	cacheKey := reg.OpenKey("Cache")
	if cacheKey == nil {
		return
	}

	iterCount := uint32(10240)
	iterKey := reg.OpenKey("Cache")
	if iterKey != nil {
		for _, v := range iterKey.Values() {
			if v.ValueName() == "NL$IterationCount" {
				val := binary.LittleEndian.Uint32(v.ValueData().Data[:4])
				if val > 10240 {
					iterCount = val & 0xfffffc00
				} else if val > 0 {
					iterCount = val * 1024
				}
				break
			}
		}
	}

	for _, v := range cacheKey.Values() {
		name := v.ValueName()
		if !strings.HasPrefix(name, "NL$") || name == "NL$Control" || name == "NL$IterationCount" {
			continue
		}

		data := v.ValueData().Data
		if len(data) < 96 {
			continue
		}

		rec := parseCacheEntry(data)
		if rec.userLen == 0 {
			continue
		}

		var plain []byte
		var err error

		if isVista {
			plain, err = localcrypto.DecryptAES(nlkmKey[16:32], rec.encData, rec.iv)
		} else {
			rc4Key := localcrypto.HMACMD5(nlkmKey, rec.iv)
			plain, err = localcrypto.DecryptRC4(rc4Key, rec.encData)
		}
		if err != nil || len(plain) < 0x48 {
			continue
		}

		cachedHash := hex.EncodeToString(plain[:16])
		userName := utf16ToString(plain[0x48 : 0x48+rec.userLen])
		domainOff := pad4(0x48 + int(rec.userLen))
		domainName := ""
		if domainOff+int(rec.domainLen) <= len(plain) {
			domainName = utf16ToString(plain[domainOff : domainOff+int(rec.domainLen)])
		}

		if isVista {
			w.Write(fmt.Sprintf("%s/%s:$DCC2$%d#%s#%s",
				domainName, userName, iterCount, strings.ToLower(userName), cachedHash))
		} else {
			w.Write(fmt.Sprintf("%s/%s:%s:%s",
				domainName, userName, cachedHash, strings.ToLower(userName)))
		}
	}
}

type cacheEntry struct {
	userLen   uint16
	domainLen uint16
	iv        []byte
	encData   []byte
}

func parseCacheEntry(data []byte) cacheEntry {
	return cacheEntry{
		userLen:   binary.LittleEndian.Uint16(data[0:2]),
		domainLen: binary.LittleEndian.Uint16(data[2:4]),
		iv:        data[64:80],
		encData:   data[96:],
	}
}

func dumpSecrets(reg *regparser.Registry, lsaKey []byte, isVista bool, w outputWriter, history bool) {
	secretsKey := reg.OpenKey("Policy\\Secrets")
	if secretsKey == nil {
		return
	}

	for _, sub := range secretsKey.Subkeys() {
		secretName := sub.Name()
		currVal := reg.OpenKey("Policy\\Secrets\\" + secretName + "\\CurrVal")
		if currVal == nil {
			continue
		}

		data := getDefaultValue(currVal)
		if data == nil || len(data) == 0 {
			continue
		}

		var secret []byte
		var err error
		if isVista {
			secret, err = decryptLSASecretVista(lsaKey, data)
		} else {
			secret, err = localcrypto.DecryptLSASecret(lsaKey, data)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Secret %s: %v\n", secretName, err)
			continue
		}

		printSecret(secretName, secret, w)

		if history {
			oldVal := reg.OpenKey("Policy\\Secrets\\" + secretName + "\\OldVal")
			if oldVal != nil {
				oldData := getDefaultValue(oldVal)
				if oldData != nil && len(oldData) > 0 {
					var oldSecret []byte
					if isVista {
						oldSecret, _ = decryptLSASecretVista(lsaKey, oldData)
					} else {
						oldSecret, _ = localcrypto.DecryptLSASecret(lsaKey, oldData)
					}
					if oldSecret != nil {
						printSecret(secretName+"_history", oldSecret, w)
					}
				}
			}
		}
	}
}

func decryptLSASecretVista(lsaKey, data []byte) ([]byte, error) {
	if len(data) < 28+32 {
		return nil, fmt.Errorf("encrypted secret too short")
	}

	salt := data[28 : 28+32]
	cipher := data[28+32:]

	decKey := localcrypto.SHA256LSAKey(lsaKey, salt)
	plain, err := localcrypto.DecryptAES(decKey, cipher, make([]byte, 16))
	if err != nil {
		return nil, err
	}

	if len(plain) < 16 {
		return nil, fmt.Errorf("decrypted secret too short")
	}

	secretLen := binary.LittleEndian.Uint32(plain[:4])
	if int(secretLen)+16 > len(plain) {
		secretLen = uint32(len(plain) - 16)
	}

	return plain[16 : 16+secretLen], nil
}

func printSecret(name string, secret []byte, w outputWriter) {
	switch {
	case strings.HasPrefix(name, "_SC_"):
		svcName := strings.TrimPrefix(name, "_SC_")
		password := utf16ToString(secret)
		password = strings.TrimRight(password, "\x00")
		w.Write(fmt.Sprintf("%s: %s", svcName, password))

	case name == "$MACHINE.ACC":
		if len(secret) >= 2 {
			h := md4Hash(secret)
			w.Write(fmt.Sprintf("$MACHINE.ACC: aad3b435b51404eeaad3b435b51404ee:%s", hex.EncodeToString(h)))
		}

	case name == "DPAPI_SYSTEM":
		if len(secret) >= 44+20 {
			machineKey := hex.EncodeToString(secret[4:24])
			userKey := hex.EncodeToString(secret[24:44])
			w.Write(fmt.Sprintf("DPAPI_SYSTEM: machine=%s user=%s", machineKey, userKey))
		} else if len(secret) >= 24 {
			w.Write(fmt.Sprintf("DPAPI_SYSTEM: %s", hex.EncodeToString(secret)))
		}

	case name == "NL$KM":
		w.Write(fmt.Sprintf("NL$KM: %s", hex.EncodeToString(secret)))

	default:
		printable := isPrintable(secret)
		if printable {
			s := utf16ToString(secret)
			s = strings.TrimRight(s, "\x00")
			if s != "" {
				w.Write(fmt.Sprintf("%s: %s", name, s))
				return
			}
		}
		w.Write(fmt.Sprintf("%s: %s", name, hex.EncodeToString(secret)))
	}
}

func isPrintable(data []byte) bool {
	if len(data) < 2 || len(data)%2 != 0 {
		return false
	}
	for i := 0; i < len(data); i += 2 {
		r := rune(binary.LittleEndian.Uint16(data[i:]))
		if r == 0 {
			continue
		}
		if r < 0x20 || r > 0x7e {
			return false
		}
	}
	return true
}

func getDefaultValue(key *regparser.CM_KEY_NODE) []byte {
	vals := key.Values()
	for _, v := range vals {
		if v.ValueName() == "" {
			return v.ValueData().Data
		}
	}
	if len(vals) == 1 {
		return vals[0].ValueData().Data
	}
	return nil
}

func pad4(n int) int {
	if n%4 != 0 {
		return n + (4 - n%4)
	}
	return n
}

func md4Hash(data []byte) []byte {
	h := md4.New()
	h.Write(data)
	return h.Sum(nil)
}
