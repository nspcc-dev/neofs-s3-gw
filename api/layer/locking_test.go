package layer

import (
	"testing"
	"time"

	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
	"github.com/stretchr/testify/require"
)

func TestObjectLockAttributes(t *testing.T) {
	tc := prepareContext(t)
	err := tc.layer.PutBucketSettings(tc.ctx, &PutSettingsParams{
		BktInfo:  tc.bktInfo,
		Settings: &data.BucketSettings{VersioningEnabled: true},
	})
	require.NoError(t, err)

	obj := tc.putObject([]byte("content obj1 v1"))

	_, err = tc.layer.PutSystemObject(tc.ctx, &PutSystemObjectParams{
		BktInfo:  tc.bktInfo,
		ObjName:  obj.RetentionObject(),
		Metadata: make(map[string]string),
		Lock: &data.ObjectLock{
			Until:   time.Now(),
			Objects: []oid.ID{obj.ID},
		},
	})
	require.NoError(t, err)

	lockObj := tc.getSystemObject(obj.RetentionObject())
	require.NotNil(t, lockObj)

	expEpoch := false
	for _, attr := range lockObj.Attributes() {
		if attr.Key() == AttributeExpirationEpoch {
			expEpoch = true
		}
	}

	require.Truef(t, expEpoch, "system header __NEOFS__EXPIRATION_EPOCH presence")
}
