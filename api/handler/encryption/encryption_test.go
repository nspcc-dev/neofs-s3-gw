package encryption

import (
	"encoding/hex"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	aes256Key = "1234567890qwertyuiopasdfghjklzxc"
)

func getAES256Key() []byte {
	key := make([]byte, 32)
	copy(key[:], aes256Key)
	return key
}

func TestHMAC(t *testing.T) {
	encParam, err := NewParams(getAES256Key())
	require.NoError(t, err)

	hmacKey, hmacSalt, err := encParam.HMAC()
	require.NoError(t, err)

	encInfo := ObjectEncryption{
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

func getDecrypter(t *testing.T) *Decrypter {
	parts := make([]encryptedPart, partNum)
	for i := range parts {
		parts[i] = encryptedPart{
			size:          partSize,
			encryptedSize: encPartSize,
		}
	}

	params, err := NewParams(getAES256Key())
	require.NoError(t, err)

	return &Decrypter{
		parts:      parts,
		encryption: *params,
	}
}

func TestDecrypterInitParams(t *testing.T) {
	decReader := getDecrypter(t)

	for i, tc := range []struct {
		rng                                       *Range
		expSkipLen, expLn, expOff, expSeqNumber   uint64
		expDecLen, expDataRemain, expEncPartRange uint64
	}{
		{
			rng:             &Range{End: objSize - 1},
			expSkipLen:      0,
			expLn:           encObjSize,
			expOff:          0,
			expSeqNumber:    0,
			expDecLen:       objSize,
			expDataRemain:   partSize,
			expEncPartRange: encPartSize,
		},
		{
			rng:             &Range{End: 999999},
			expSkipLen:      0,
			expLn:           1049088,
			expOff:          0,
			expSeqNumber:    0,
			expDecLen:       1000000,
			expDataRemain:   1000000,
			expEncPartRange: 1049088,
		},
		{
			rng:             &Range{Start: 1000000, End: 1999999},
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
			require.Equal(t, tc.expLn, decReader.length)
			require.Equal(t, tc.expOff, decReader.offset)
			require.Equal(t, tc.expDataRemain, decReader.partDataRemain)
			require.Equal(t, tc.expEncPartRange, decReader.encPartRangeLen)
			require.Equal(t, tc.expSeqNumber, decReader.seqNumber)
		})
	}
}
