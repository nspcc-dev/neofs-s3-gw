package layer

import (
	"encoding/hex"
	"strconv"
	"testing"

	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	"github.com/stretchr/testify/require"
)

const (
	aes256Key = "1234567890qwertyuiopasdfghjklzxc"
)

func getAES256Key() AES256Key {
	var key AES256Key
	copy(key[:], aes256Key)
	return key
}

func TestHMAC(t *testing.T) {
	encParam := NewEncryptionParams(getAES256Key())

	hmacKey, hmacSalt, err := encParam.HMAC()
	require.NoError(t, err)

	encInfo := data.EncryptionInfo{
		Enabled:   true,
		Algorithm: "",
		HMACKey:   hex.EncodeToString(hmacKey),
		HMACSalt:  hex.EncodeToString(hmacSalt),
	}

	err = encParam.MatchObjectEncryption(encInfo)
	require.NoError(t, err)
}

const (
	objSize     = 30 * 1024 * 1024
	partNum     = 6
	partSize    = 5 * 1024 * 1024
	encObjSize  = 31472640 // objSize + enc headers
	encPartSize = 5245440  // partSize + enc headers
)

func getDecrypter() *decrypter {
	parts := make([]EncryptedPart, partNum)
	for i := range parts {
		parts[i] = EncryptedPart{
			Part: Part{
				PartNumber: i + 1,
				Size:       int64(partSize),
			},
			EncryptedSize: encPartSize,
		}
	}
	return &decrypter{
		parts:      parts,
		encryption: NewEncryptionParams(getAES256Key()),
	}
}

func TestDecrypterInitParams(t *testing.T) {
	decReader := getDecrypter()

	for i, tc := range []struct {
		rng                                       *RangeParams
		expSkipLen, expLn, expOff, expSeqNumber   uint64
		expDecLen, expDataRemain, expEncPartRange int64
	}{
		{
			rng:             &RangeParams{End: objSize - 1},
			expSkipLen:      0,
			expLn:           encObjSize,
			expOff:          0,
			expSeqNumber:    0,
			expDecLen:       objSize,
			expDataRemain:   partSize,
			expEncPartRange: encPartSize,
		},
		{
			rng:             &RangeParams{End: 999999},
			expSkipLen:      0,
			expLn:           1049088,
			expOff:          0,
			expSeqNumber:    0,
			expDecLen:       1000000,
			expDataRemain:   1000000,
			expEncPartRange: 1049088,
		},
		{
			rng:             &RangeParams{Start: 1000000, End: 1999999},
			expSkipLen:      16960,
			expLn:           1049088,
			expOff:          983520,
			expSeqNumber:    15,
			expDecLen:       1000000,
			expDataRemain:   1000000,
			expEncPartRange: 1049088,
		},
	} {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			decReader.rangeParam = tc.rng
			decReader.initRangeParams()
			require.Equal(t, tc.expSkipLen, decReader.skipLen)
			require.Equal(t, tc.expDecLen, decReader.decLen)
			require.Equal(t, tc.expLn, decReader.ln)
			require.Equal(t, tc.expOff, decReader.off)
			require.Equal(t, tc.expDataRemain, decReader.partDataRemain)
			require.Equal(t, tc.expEncPartRange, decReader.encPartRangeLen)
			require.Equal(t, tc.expSeqNumber, decReader.seqNumber)
		})
	}
}
