package layer

import (
	"testing"
	"time"

	"github.com/nspcc-dev/neofs-s3-gw/api/data"
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

	p := &ObjectVersion{
		BktInfo:    tc.bktInfo,
		ObjectName: obj.Name,
		VersionID:  obj.Version(),
	}

	lock := &data.ObjectLock{
		Retention: &data.RetentionLock{
			Until: time.Now(),
		},
	}

	err = tc.layer.PutLockInfo(tc.ctx, p, lock)
	require.NoError(t, err)

	foundLock, err := tc.layer.GetLockInfo(tc.ctx, p)
	require.NoError(t, err)

	lockObj := tc.getObjectByID(*foundLock.RetentionOID)
	require.NotNil(t, lockObj)

	expEpoch := false
	for _, attr := range lockObj.Attributes() {
		if attr.Key() == AttributeExpirationEpoch {
			expEpoch = true
		}
	}

	require.Truef(t, expEpoch, "system header __NEOFS__EXPIRATION_EPOCH presence")
}
