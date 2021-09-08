package eacloverlay

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/minio/minio-go/v7/pkg/set"
	"github.com/nspcc-dev/neofs-api-go/pkg/acl/eacl"
	cid "github.com/nspcc-dev/neofs-api-go/pkg/container/id"
	"github.com/nspcc-dev/neofs-api-go/pkg/object"
)

func getFilter(fs []*eacl.Filter, name string) *eacl.Filter {
	for _, f := range fs {
		if f.Key() == name {
			return f
		}
	}
	return nil
}

func s3CanonicalIDToTarget(ids ...string) (*eacl.Target, error) {
	var users [][]byte
	for _, id := range ids {
		u, err := hex.DecodeString(id)
		if err != nil {
			return nil, fmt.Errorf("%w: %s", ErrInvalidCanonicalID, id)
		}
		users = append(users, u)
	}

	tgt := eacl.NewTarget()
	tgt.SetBinaryKeys(users)
	return tgt, nil
}

func s3ResourceToIDList(res set.StringSet) (*cid.ID, []*object.ID, error) {
	var lst []*object.ID
	var cntID *cid.ID
	for _, r := range res.ToSlice() {
		if strings.IndexByte(r, '/') >= 0 { // this is an object address
			addr := object.NewAddress()
			if err := addr.Parse(r); err != nil {
				return nil, nil, err
			}
			lst = append(lst, addr.ObjectID())
		} else {
			cntID = cid.New()
			if err := cntID.Parse(r); err != nil {
				return nil, nil, err
			}
		}
	}
	return cntID, lst, nil
}
