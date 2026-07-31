package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rc4"
	"crypto/sha256"
	"encoding/binary"
)

func TransformKey(in []byte) []byte {
	out := make([]byte, 8)
	out[0] = in[0] >> 1
	out[1] = ((in[0] & 0x01) << 6) | (in[1] >> 2)
	out[2] = ((in[1] & 0x03) << 5) | (in[2] >> 3)
	out[3] = ((in[2] & 0x07) << 4) | (in[3] >> 4)
	out[4] = ((in[3] & 0x0F) << 3) | (in[4] >> 5)
	out[5] = ((in[4] & 0x1F) << 2) | (in[5] >> 6)
	out[6] = ((in[5] & 0x3F) << 1) | (in[6] >> 7)
	out[7] = in[6] & 0x7F
	for i := range out {
		out[i] = (out[i] << 1) & 0xFE
	}
	return out
}

func DeriveKey(rid uint32) ([]byte, []byte) {
	key := make([]byte, 4)
	binary.LittleEndian.PutUint32(key, rid)
	k1 := TransformKey([]byte{key[0], key[1], key[2], key[3], key[0], key[1], key[2]})
	k2 := TransformKey([]byte{key[3], key[0], key[1], key[2], key[3], key[0], key[1]})
	return k1, k2
}

func DecryptDESECB(key, data []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(data))
	for i := 0; i < len(data); i += des.BlockSize {
		block.Decrypt(out[i:i+des.BlockSize], data[i:i+des.BlockSize])
	}
	return out, nil
}

func DecryptRC4(key, data []byte) ([]byte, error) {
	c, err := rc4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(data))
	c.XORKeyStream(out, data)
	return out, nil
}

func DecryptAES(key, data, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(data)%aes.BlockSize != 0 {
		padded := make([]byte, len(data)+aes.BlockSize-len(data)%aes.BlockSize)
		copy(padded, data)
		data = padded
	}
	out := make([]byte, len(data))
	if isZero(iv) {
		for i := 0; i < len(data); i += aes.BlockSize {
			zeroIV := make([]byte, aes.BlockSize)
			mode := cipher.NewCBCDecrypter(block, zeroIV)
			mode.CryptBlocks(out[i:i+aes.BlockSize], data[i:i+aes.BlockSize])
		}
	} else {
		mode := cipher.NewCBCDecrypter(block, iv)
		mode.CryptBlocks(out, data)
	}
	return out, nil
}

func isZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

func MD5Hash(data ...[]byte) []byte {
	h := md5.New()
	for _, d := range data {
		h.Write(d)
	}
	return h.Sum(nil)
}

func HMACMD5(key, data []byte) []byte {
	h := hmac.New(md5.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func SHA256LSAKey(bootKey, salt []byte) []byte {
	h := sha256.New()
	h.Write(bootKey)
	for i := 0; i < 1000; i++ {
		h.Write(salt)
	}
	return h.Sum(nil)
}

func MD5LSAKey(bootKey, salt []byte) []byte {
	h := md5.New()
	h.Write(bootKey)
	for i := 0; i < 1000; i++ {
		h.Write(salt)
	}
	return h.Sum(nil)
}

func DecryptLSASecret(lsaKey, data []byte) ([]byte, error) {
	encSize := binary.LittleEndian.Uint32(data[:4])
	cipherText := data[len(data)-int(encSize):]
	keyPos := 0
	var plain []byte
	for i := 0; i < len(cipherText); i += 8 {
		end := i + 8
		if end > len(cipherText) {
			break
		}
		remaining := len(lsaKey) - keyPos
		if remaining < 7 {
			chunk := make([]byte, 7)
			copy(chunk, lsaKey[keyPos:])
			copy(chunk[remaining:], lsaKey[:7-remaining])
			keyPos = 7 - remaining
			desKey := TransformKey(chunk)
			dec, err := DecryptDESECB(desKey, cipherText[i:end])
			if err != nil {
				return nil, err
			}
			plain = append(plain, dec...)
		} else {
			desKey := TransformKey(lsaKey[keyPos : keyPos+7])
			keyPos += 7
			dec, err := DecryptDESECB(desKey, cipherText[i:end])
			if err != nil {
				return nil, err
			}
			plain = append(plain, dec...)
		}
	}
	return plain, nil
}
