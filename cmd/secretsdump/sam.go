package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"

	"www.velocidex.com/golang/regparser"

	localcrypto "github.com/joda32/gonetkit/internal/crypto"
)

var (
	samQWERTY = []byte("!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\x00")
	samDIGITS = []byte("0123456789012345678901234567890123456789\x00")
	ntPassword = []byte("NTPASSWORD\x00")
	lmPassword = []byte("LMPASSWORD\x00")
	emptyLM    = "aad3b435b51404eeaad3b435b51404ee"
	emptyNT    = "31d6cfe0d16ae931b73c59d7e0c089c0"
)

func DumpSAM(hiveData []byte, bootKey []byte, w outputWriter, history bool) error {
	reg, err := regparser.NewRegistry(bytes.NewReader(hiveData))
	if err != nil {
		return fmt.Errorf("parse SAM hive: %w", err)
	}

	fKey := reg.OpenKey("SAM\\Domains\\Account")
	if fKey == nil {
		return fmt.Errorf("SAM\\Domains\\Account not found")
	}

	var fData []byte
	for _, v := range fKey.Values() {
		if v.ValueName() == "F" {
			fData = v.ValueData().Data
			break
		}
	}
	if fData == nil {
		return fmt.Errorf("account F value not found")
	}

	hashedBootKey, err := getHBootKey(fData, bootKey)
	if err != nil {
		return fmt.Errorf("hashed boot key: %w", err)
	}

	usersKey := reg.OpenKey("SAM\\Domains\\Account\\Users")
	if usersKey == nil {
		return fmt.Errorf("SAM\\Domains\\Account\\Users not found")
	}

	namesKey := reg.OpenKey("SAM\\Domains\\Account\\Users\\Names")
	ridMap := make(map[uint32]string)
	if namesKey != nil {
		for _, sub := range namesKey.Subkeys() {
			for _, v := range sub.Values() {
				rid := v.Type()
				ridMap[rid] = sub.Name()
				break
			}
		}
	}

	for _, sub := range usersKey.Subkeys() {
		name := sub.Name()
		if name == "Names" {
			continue
		}

		rid64, err := strconv.ParseUint(name, 16, 32)
		if err != nil {
			continue
		}
		rid := uint32(rid64)

		var vData []byte
		for _, v := range sub.Values() {
			if v.ValueName() == "V" {
				vData = v.ValueData().Data
				break
			}
		}
		if vData == nil {
			continue
		}

		userName := ridMap[rid]
		if userName == "" {
			userName = getUserName(vData)
		}
		if userName == "" {
			userName = fmt.Sprintf("(unknown-%d)", rid)
		}

		ntHash, lmHash, err := decryptUserHashes(vData, rid, hashedBootKey)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] %s (RID %d): %v\n", userName, rid, err)
			continue
		}

		lmStr := emptyLM
		if lmHash != nil {
			lmStr = hex.EncodeToString(lmHash)
		}
		ntStr := emptyNT
		if ntHash != nil {
			ntStr = hex.EncodeToString(ntHash)
		}

		w.Write(fmt.Sprintf("%s:%d:%s:%s:::", userName, rid, lmStr, ntStr))
	}

	return nil
}

func getHBootKey(fData []byte, bootKey []byte) ([]byte, error) {
	if len(fData) < 104+32 {
		return nil, fmt.Errorf("F value too short (%d bytes)", len(fData))
	}

	keyData := fData[104:]
	revision := keyData[0]

	switch revision {
	case 0x01:
		return getHBootKeyRC4(keyData, bootKey)
	case 0x02:
		return getHBootKeyAES(keyData, bootKey)
	default:
		return nil, fmt.Errorf("unknown SAM key revision: 0x%02x", revision)
	}
}

func getHBootKeyRC4(keyData []byte, bootKey []byte) ([]byte, error) {
	if len(keyData) < 64 {
		return nil, fmt.Errorf("SAM_KEY_DATA too short")
	}

	salt := keyData[8:24]
	key := keyData[24:40]
	checksum := keyData[40:56]

	rc4Key := localcrypto.MD5Hash(salt, samQWERTY, bootKey, samDIGITS)
	hashedBootKey, err := localcrypto.DecryptRC4(rc4Key, append(key, checksum...))
	if err != nil {
		return nil, err
	}

	verify := localcrypto.MD5Hash(hashedBootKey[:16], samDIGITS, hashedBootKey[:16], samQWERTY)
	if !bytes.Equal(verify, hashedBootKey[16:]) {
		return nil, fmt.Errorf("hashed boot key checksum mismatch")
	}

	return hashedBootKey[:16], nil
}

func getHBootKeyAES(keyData []byte, bootKey []byte) ([]byte, error) {
	if len(keyData) < 32 {
		return nil, fmt.Errorf("SAM_KEY_DATA_AES too short")
	}

	dataLen := binary.LittleEndian.Uint32(keyData[12:16])
	salt := keyData[16:32]
	data := keyData[32 : 32+dataLen]

	hashedBootKey, err := localcrypto.DecryptAES(bootKey, data, salt)
	if err != nil {
		return nil, err
	}

	return hashedBootKey[:16], nil
}

func decryptUserHashes(vData []byte, rid uint32, hashedBootKey []byte) (ntHash, lmHash []byte, err error) {
	if len(vData) < 204 {
		return nil, nil, fmt.Errorf("V data too short (%d bytes)", len(vData))
	}

	ntOffset := binary.LittleEndian.Uint32(vData[168:172]) + 204
	ntLen := binary.LittleEndian.Uint32(vData[172:176])
	lmOffset := binary.LittleEndian.Uint32(vData[156:160]) + 204
	lmLen := binary.LittleEndian.Uint32(vData[160:164])

	if ntLen > 0 {
		ntHash, err = decryptSingleHash(vData[ntOffset:ntOffset+ntLen], rid, hashedBootKey, ntPassword)
		if err != nil {
			return nil, nil, fmt.Errorf("NT hash: %w", err)
		}
	}

	if lmLen > 0 {
		lmHash, err = decryptSingleHash(vData[lmOffset:lmOffset+lmLen], rid, hashedBootKey, lmPassword)
		if err != nil {
			lmHash = nil
		}
	}

	return ntHash, lmHash, nil
}

func decryptSingleHash(data []byte, rid uint32, hashedBootKey []byte, constant []byte) ([]byte, error) {
	if len(data) < 4 {
		return nil, nil
	}

	revision := binary.LittleEndian.Uint16(data[2:4])

	var intermediate []byte
	var err error

	switch {
	case revision == 1 && len(data) >= 20:
		hash := data[4:20]
		rc4Key := localcrypto.MD5Hash(hashedBootKey, binary.LittleEndian.AppendUint32(nil, rid), constant)
		intermediate, err = localcrypto.DecryptRC4(rc4Key, hash)
		if err != nil {
			return nil, err
		}
	case revision == 2 && len(data) >= 24:
		salt := data[8:24]
		encHash := data[24:]
		intermediate, err = localcrypto.DecryptAES(hashedBootKey, encHash, salt)
		if err != nil {
			return nil, err
		}
		intermediate = intermediate[:16]
	default:
		return nil, nil
	}

	k1, k2 := localcrypto.DeriveKey(rid)
	d1, err := localcrypto.DecryptDESECB(k1, intermediate[:8])
	if err != nil {
		return nil, err
	}
	d2, err := localcrypto.DecryptDESECB(k2, intermediate[8:16])
	if err != nil {
		return nil, err
	}

	result := append(d1, d2...)

	allEmpty := true
	for _, b := range result {
		if b != 0 {
			allEmpty = false
			break
		}
	}
	if allEmpty {
		return nil, nil
	}

	return result, nil
}

func getUserName(vData []byte) string {
	if len(vData) < 204 {
		return ""
	}
	nameOffset := binary.LittleEndian.Uint32(vData[12:16]) + 204
	nameLen := binary.LittleEndian.Uint32(vData[16:20])
	if int(nameOffset+nameLen) > len(vData) {
		return ""
	}
	nameBytes := vData[nameOffset : nameOffset+nameLen]
	return strings.TrimRight(utf16ToString(nameBytes), "\x00")
}

func utf16ToString(b []byte) string {
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	runes := make([]rune, len(b)/2)
	for i := 0; i < len(b); i += 2 {
		runes[i/2] = rune(binary.LittleEndian.Uint16(b[i:]))
	}
	return string(runes)
}
