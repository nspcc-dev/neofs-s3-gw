package v4

import (
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"hash"
	"hash/crc32"

	"github.com/minio/crc64nvme"
)

type (
	checksumType int
)

const (
	checksumNone checksumType = iota
	checksumCRC32
	checksumCRC32C
	checksumSHA1
	checksumSHA256
	checksumCRC64NVMe
)

func (ca checksumType) String() string {
	switch ca {
	case checksumCRC32:
		return "CRC32"
	case checksumCRC32C:
		return "CRC32C"
	case checksumCRC64NVMe:
		return "CRC64NVMe"
	case checksumSHA1:
		return "SHA1"
	case checksumSHA256:
		return "SHA256"
	case checksumNone:
		return ""
	}
	return ""
}

func checksumWriter(algo checksumType) hash.Hash {
	switch algo {
	case checksumCRC32:
		return crc32.NewIEEE()
	case checksumCRC32C:
		return crc32.New(crc32.MakeTable(crc32.Castagnoli))
	case checksumCRC64NVMe:
		return crc64nvme.New()
	case checksumSHA1:
		return sha1.New()
	case checksumSHA256:
		return sha256.New()
	default:
		return nil
	}
}

func detectChecksumType(amzTrailerHeader string) (checksumType, error) {
	switch amzTrailerHeader {
	case "x-amz-checksum-crc32":
		return checksumCRC32, nil
	case "x-amz-checksum-crc32c":
		return checksumCRC32C, nil
	case "x-amz-checksum-crc64nvme":
		return checksumCRC64NVMe, nil
	case "x-amz-checksum-sha1":
		return checksumSHA1, nil
	case "x-amz-checksum-sha256":
		return checksumSHA256, nil
	case "":
		return checksumNone, nil
	default:
		return checksumNone, fmt.Errorf("unsupported: %s", amzTrailerHeader)
	}
}
