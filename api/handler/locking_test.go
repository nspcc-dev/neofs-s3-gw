package handler

import (
	"bytes"
	"context"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	apiErrors "github.com/nspcc-dev/neofs-s3-gw/api/errors"
	"github.com/nspcc-dev/neofs-s3-gw/api/layer"
	"github.com/stretchr/testify/require"
)

const defaultURL = "http://localhost/"

func TestFormObjectLock(t *testing.T) {
	for _, tc := range []struct {
		name          string
		bktInfo       *data.BucketInfo
		config        *data.ObjectLockConfiguration
		header        http.Header
		expectedError bool
		expectedLock  *data.ObjectLock
	}{
		{
			name:    "default days",
			bktInfo: &data.BucketInfo{ObjectLockEnabled: true},
			config: &data.ObjectLockConfiguration{Rule: &data.ObjectLockRule{
				DefaultRetention: &data.DefaultRetention{Mode: complianceMode, Days: 1}}},
			expectedLock: &data.ObjectLock{IsCompliance: true, Until: time.Now().Add(24 * time.Hour)},
		},
		{
			name:    "default years",
			bktInfo: &data.BucketInfo{ObjectLockEnabled: true},
			config: &data.ObjectLockConfiguration{Rule: &data.ObjectLockRule{
				DefaultRetention: &data.DefaultRetention{Mode: governanceMode, Years: 1}}},
			expectedLock: &data.ObjectLock{Until: time.Now().Add(365 * 24 * time.Hour)},
		},
		{
			name:    "basic override",
			bktInfo: &data.BucketInfo{ObjectLockEnabled: true},
			config:  &data.ObjectLockConfiguration{Rule: &data.ObjectLockRule{DefaultRetention: &data.DefaultRetention{Mode: complianceMode, Days: 1}}},
			header: map[string][]string{
				api.AmzObjectLockRetainUntilDate: {time.Now().Format(time.RFC3339)},
				api.AmzObjectLockMode:            {governanceMode},
				api.AmzObjectLockLegalHold:       {legalHoldOn},
			},
			expectedLock: &data.ObjectLock{Until: time.Now(), LegalHold: true},
		},
		{
			name:          "lock disabled error",
			bktInfo:       &data.BucketInfo{},
			header:        map[string][]string{api.AmzObjectLockLegalHold: {legalHoldOn}},
			expectedError: true,
		},
		{
			name:    "invalid time format error",
			bktInfo: &data.BucketInfo{ObjectLockEnabled: true},
			header: map[string][]string{
				api.AmzObjectLockRetainUntilDate: {time.Now().Format(time.RFC822)},
			},
			expectedError: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			actualObjLock, err := formObjectLock(tc.bktInfo, tc.config, tc.header)
			if tc.expectedError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assertObjectLocks(t, tc.expectedLock, actualObjLock)
		})
	}
}

func TestFormObjectLockFromRetention(t *testing.T) {
	for _, tc := range []struct {
		name          string
		retention     *data.Retention
		header        http.Header
		expectedError bool
		expectedLock  *data.ObjectLock
	}{
		{
			name: "basic compliance",
			retention: &data.Retention{
				Mode:            complianceMode,
				RetainUntilDate: time.Now().Format(time.RFC3339),
			},
			expectedLock: &data.ObjectLock{Until: time.Now(), IsCompliance: true},
		},
		{
			name: "basic governance",
			retention: &data.Retention{
				Mode:            governanceMode,
				RetainUntilDate: time.Now().Format(time.RFC3339),
			},
			header: map[string][]string{
				api.AmzBypassGovernanceRetention: {strconv.FormatBool(true)},
			},
			expectedLock: &data.ObjectLock{Until: time.Now()},
		},
		{
			name: "error invalid mode",
			retention: &data.Retention{
				Mode:            "",
				RetainUntilDate: time.Now().Format(time.RFC3339),
			},
			expectedError: true,
		},
		{
			name: "error invalid date",
			retention: &data.Retention{
				Mode:            governanceMode,
				RetainUntilDate: "",
			},
			expectedError: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			actualObjLock, err := formObjectLockFromRetention(tc.retention, tc.header)
			if tc.expectedError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assertObjectLocks(t, tc.expectedLock, actualObjLock)
		})
	}
}

func assertObjectLocks(t *testing.T, expected, actual *data.ObjectLock) {
	require.Equal(t, expected.LegalHold, actual.LegalHold)
	require.Equal(t, expected.IsCompliance, actual.IsCompliance)
	require.InDelta(t, expected.Until.Unix(), actual.Until.Unix(), 1)
}

func TestCheckLockObject(t *testing.T) {
	for _, tc := range []struct {
		name          string
		isCompliance  bool
		header        http.Header
		expectedError bool
	}{
		{
			name: "error governance bypass",
			header: map[string][]string{
				api.AmzBypassGovernanceRetention: {strconv.FormatBool(false)},
			},
			expectedError: true,
		},
		{
			name: "error invalid governance bypass",
			header: map[string][]string{
				api.AmzBypassGovernanceRetention: {"t r u e"},
			},
			expectedError: true,
		},
		{
			name:          "error failed change compliance mode",
			isCompliance:  true,
			expectedError: true,
		},
		{
			name: "valid",
			header: map[string][]string{
				api.AmzBypassGovernanceRetention: {strconv.FormatBool(true)},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			header := make(map[string]string)
			if tc.isCompliance {
				header[layer.AttributeComplianceMode] = strconv.FormatBool(true)
			}

			lockInfo := &data.ObjectInfo{Headers: header}
			err := checkLockInfo(lockInfo, tc.header)
			if tc.expectedError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
		})
	}
}

func TestLockConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name          string
		configuration *data.ObjectLockConfiguration
		expectedError bool
	}{
		{
			name:          "basic empty",
			configuration: &data.ObjectLockConfiguration{},
		},
		{
			name: "basic compliance",
			configuration: &data.ObjectLockConfiguration{
				ObjectLockEnabled: enabledValue,
				Rule: &data.ObjectLockRule{
					DefaultRetention: &data.DefaultRetention{
						Days: 1,
						Mode: complianceMode,
					},
				},
			},
		},
		{
			name: "basic governance",
			configuration: &data.ObjectLockConfiguration{
				Rule: &data.ObjectLockRule{
					DefaultRetention: &data.DefaultRetention{
						Mode:  governanceMode,
						Years: 1,
					},
				},
			},
		},
		{
			name: "error invalid enabled",
			configuration: &data.ObjectLockConfiguration{
				ObjectLockEnabled: "false",
			},
			expectedError: true,
		},
		{
			name: "error invalid mode",
			configuration: &data.ObjectLockConfiguration{
				Rule: &data.ObjectLockRule{
					DefaultRetention: &data.DefaultRetention{
						Mode: "",
					},
				},
			},
			expectedError: true,
		},
		{
			name: "error no duration",
			configuration: &data.ObjectLockConfiguration{
				Rule: &data.ObjectLockRule{
					DefaultRetention: &data.DefaultRetention{
						Mode: governanceMode,
					},
				},
			},
			expectedError: true,
		},
		{
			name: "error both durations",
			configuration: &data.ObjectLockConfiguration{
				Rule: &data.ObjectLockRule{
					DefaultRetention: &data.DefaultRetention{
						Days:  1,
						Mode:  governanceMode,
						Years: 1,
					},
				},
			},
			expectedError: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := checkLockConfiguration(tc.configuration)
			if tc.expectedError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
		})
	}
}

func TestPutBucketLockConfigurationHandler(t *testing.T) {
	ctx := context.Background()
	hc := prepareHandlerContext(t)

	bktLockDisabled := "bucket-lock-disabled"
	createTestBucket(ctx, t, hc, bktLockDisabled)

	bktLockEnabled := "bucket-lock-enabled"
	createTestBucketWithLock(ctx, t, hc, bktLockEnabled, nil)

	bktLockEnabledWithOldConfig := "bucket-lock-enabled-old-conf"
	createTestBucketWithLock(ctx, t, hc, bktLockEnabledWithOldConfig,
		&data.ObjectLockConfiguration{
			Rule: &data.ObjectLockRule{
				DefaultRetention: &data.DefaultRetention{
					Days: 1,
					Mode: complianceMode,
				},
			},
		})

	for _, tc := range []struct {
		name          string
		bucket        string
		expectedError apiErrors.Error
		noError       bool
		configuration *data.ObjectLockConfiguration
	}{
		{
			name:          "bkt not found",
			expectedError: apiErrors.GetAPIError(apiErrors.ErrNoSuchBucket),
		},
		{
			name:          "bkt lock disabled",
			bucket:        bktLockDisabled,
			expectedError: apiErrors.GetAPIError(apiErrors.ErrObjectLockConfigurationNotAllowed),
		},
		{
			name:          "invalid configuration",
			bucket:        bktLockEnabled,
			expectedError: apiErrors.GetAPIError(apiErrors.ErrInternalError),
			configuration: &data.ObjectLockConfiguration{ObjectLockEnabled: "dummy"},
		},
		{
			name:          "basic",
			bucket:        bktLockEnabled,
			noError:       true,
			configuration: &data.ObjectLockConfiguration{},
		},
		{
			name:    "basic override",
			bucket:  bktLockEnabledWithOldConfig,
			noError: true,
			configuration: &data.ObjectLockConfiguration{
				Rule: &data.ObjectLockRule{
					DefaultRetention: &data.DefaultRetention{
						Mode:  governanceMode,
						Years: 1,
					},
				},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body, err := xml.Marshal(tc.configuration)
			require.NoError(t, err)

			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPut, defaultURL, bytes.NewReader(body))
			r = r.WithContext(api.SetReqInfo(r.Context(), api.NewReqInfo(w, r, api.ObjectRequest{Bucket: tc.bucket})))

			hc.Handler().PutBucketObjectLockConfigHandler(w, r)

			if !tc.noError {
				assertS3Error(t, w, tc.expectedError)
				return
			}

			bktInfo, err := hc.Layer().GetBucketInfo(ctx, tc.bucket)
			require.NoError(t, err)
			bktSettings, err := hc.Layer().GetBucketSettings(ctx, bktInfo)
			require.NoError(t, err)
			actualConf := bktSettings.LockConfiguration
			require.True(t, bktSettings.VersioningEnabled)
			require.Equal(t, tc.configuration.ObjectLockEnabled, actualConf.ObjectLockEnabled)
			require.Equal(t, tc.configuration.Rule, actualConf.Rule)
		})
	}
}

func TestGetBucketLockConfigurationHandler(t *testing.T) {
	ctx := context.Background()
	hc := prepareHandlerContext(t)

	bktLockDisabled := "bucket-lock-disabled"
	createTestBucket(ctx, t, hc, bktLockDisabled)

	bktLockEnabled := "bucket-lock-enabled"
	createTestBucketWithLock(ctx, t, hc, bktLockEnabled, nil)

	oldConfig := &data.ObjectLockConfiguration{
		Rule: &data.ObjectLockRule{
			DefaultRetention: &data.DefaultRetention{
				Days: 1,
				Mode: complianceMode,
			},
		},
	}
	bktLockEnabledWithOldConfig := "bucket-lock-enabled-old-conf"
	createTestBucketWithLock(ctx, t, hc, bktLockEnabledWithOldConfig, oldConfig)

	for _, tc := range []struct {
		name          string
		bucket        string
		expectedError apiErrors.Error
		noError       bool
		expectedConf  *data.ObjectLockConfiguration
	}{
		{
			name:          "bkt not found",
			expectedError: apiErrors.GetAPIError(apiErrors.ErrNoSuchBucket),
		},
		{
			name:          "bkt lock disabled",
			bucket:        bktLockDisabled,
			expectedError: apiErrors.GetAPIError(apiErrors.ErrObjectLockConfigurationNotFound),
		},
		{
			name:         "bkt lock enabled empty default",
			bucket:       bktLockEnabled,
			noError:      true,
			expectedConf: &data.ObjectLockConfiguration{ObjectLockEnabled: enabledValue},
		},
		{
			name:         "bkt lock enabled",
			bucket:       bktLockEnabledWithOldConfig,
			noError:      true,
			expectedConf: oldConfig,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPut, defaultURL, bytes.NewReader(nil))
			r = r.WithContext(api.SetReqInfo(r.Context(), api.NewReqInfo(w, r, api.ObjectRequest{Bucket: tc.bucket})))

			hc.Handler().GetBucketObjectLockConfigHandler(w, r)

			if !tc.noError {
				assertS3Error(t, w, tc.expectedError)
				return
			}

			actualConf := &data.ObjectLockConfiguration{}
			err := xml.NewDecoder(w.Result().Body).Decode(actualConf)
			require.NoError(t, err)

			require.Equal(t, tc.expectedConf.ObjectLockEnabled, actualConf.ObjectLockEnabled)
			require.Equal(t, tc.expectedConf.Rule, actualConf.Rule)
		})
	}
}

func assertS3Error(t *testing.T, w *httptest.ResponseRecorder, expectedError apiErrors.Error) {
	actualErrorResponse := &api.ErrorResponse{}
	err := xml.NewDecoder(w.Result().Body).Decode(actualErrorResponse)
	require.NoError(t, err)

	require.Equal(t, expectedError.HTTPStatusCode, w.Code)
	require.Equal(t, expectedError.Code, actualErrorResponse.Code)

	if expectedError.ErrCode != apiErrors.ErrInternalError {
		require.Equal(t, expectedError.Description, actualErrorResponse.Message)
	}
}

func TestObjectLegalHold(t *testing.T) {
	ctx := context.Background()
	hc := prepareHandlerContext(t)

	bktName := "bucket-lock-enabled"
	bktInfo := createTestBucketWithLock(ctx, t, hc, bktName, nil)

	objName := "obj-for-legal-hold"
	createTestObject(ctx, t, hc, bktInfo, objName)

	w, r := prepareTestRequest(t, bktName, objName, nil)
	hc.Handler().GetObjectLegalHoldHandler(w, r)
	assertLegalHold(t, w, legalHoldOff)

	w, r = prepareTestRequest(t, bktName, objName, &data.LegalHold{Status: legalHoldOn})
	hc.Handler().PutObjectLegalHoldHandler(w, r)
	require.Equal(t, http.StatusOK, w.Code)

	w, r = prepareTestRequest(t, bktName, objName, nil)
	hc.Handler().GetObjectLegalHoldHandler(w, r)
	assertLegalHold(t, w, legalHoldOn)

	// to make sure put hold is an idempotent operation
	w, r = prepareTestRequest(t, bktName, objName, &data.LegalHold{Status: legalHoldOn})
	hc.Handler().PutObjectLegalHoldHandler(w, r)
	require.Equal(t, http.StatusOK, w.Code)

	w, r = prepareTestRequest(t, bktName, objName, &data.LegalHold{Status: legalHoldOff})
	hc.Handler().PutObjectLegalHoldHandler(w, r)
	require.Equal(t, http.StatusOK, w.Code)

	w, r = prepareTestRequest(t, bktName, objName, nil)
	hc.Handler().GetObjectLegalHoldHandler(w, r)
	assertLegalHold(t, w, legalHoldOff)

	// to make sure put hold is an idempotent operation
	w, r = prepareTestRequest(t, bktName, objName, &data.LegalHold{Status: legalHoldOff})
	hc.Handler().PutObjectLegalHoldHandler(w, r)
	require.Equal(t, http.StatusOK, w.Code)
}

func assertLegalHold(t *testing.T, w *httptest.ResponseRecorder, status string) {
	actualHold := &data.LegalHold{}
	err := xml.NewDecoder(w.Result().Body).Decode(actualHold)
	require.NoError(t, err)
	require.Equal(t, status, actualHold.Status)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestObjectRetention(t *testing.T) {
	ctx := context.Background()
	hc := prepareHandlerContext(t)

	bktName := "bucket-lock-enabled"
	bktInfo := createTestBucketWithLock(ctx, t, hc, bktName, nil)

	objName := "obj-for-retention"
	createTestObject(ctx, t, hc, bktInfo, objName)

	w, r := prepareTestRequest(t, bktName, objName, nil)
	hc.Handler().GetObjectRetentionHandler(w, r)
	assertS3Error(t, w, apiErrors.GetAPIError(apiErrors.ErrNoSuchKey))

	retention := &data.Retention{Mode: governanceMode, RetainUntilDate: time.Now().Format(time.RFC3339)}
	w, r = prepareTestRequest(t, bktName, objName, retention)
	hc.Handler().PutObjectRetentionHandler(w, r)
	require.Equal(t, http.StatusOK, w.Code)

	w, r = prepareTestRequest(t, bktName, objName, nil)
	hc.Handler().GetObjectRetentionHandler(w, r)
	assertRetention(t, w, retention)

	retention = &data.Retention{Mode: governanceMode, RetainUntilDate: time.Now().Format(time.RFC3339)}
	w, r = prepareTestRequest(t, bktName, objName, retention)
	hc.Handler().PutObjectRetentionHandler(w, r)
	assertS3Error(t, w, apiErrors.GetAPIError(apiErrors.ErrInternalError))

	retention = &data.Retention{Mode: complianceMode, RetainUntilDate: time.Now().Format(time.RFC3339)}
	w, r = prepareTestRequest(t, bktName, objName, retention)
	r.Header.Set(api.AmzBypassGovernanceRetention, strconv.FormatBool(true))
	hc.Handler().PutObjectRetentionHandler(w, r)
	require.Equal(t, http.StatusOK, w.Code)

	w, r = prepareTestRequest(t, bktName, objName, nil)
	hc.Handler().GetObjectRetentionHandler(w, r)
	assertRetention(t, w, retention)

	w, r = prepareTestRequest(t, bktName, objName, retention)
	r.Header.Set(api.AmzBypassGovernanceRetention, strconv.FormatBool(true))
	hc.Handler().PutObjectRetentionHandler(w, r)
	assertS3Error(t, w, apiErrors.GetAPIError(apiErrors.ErrInternalError))
}

func assertRetention(t *testing.T, w *httptest.ResponseRecorder, retention *data.Retention) {
	actualRetention := &data.Retention{}
	err := xml.NewDecoder(w.Result().Body).Decode(actualRetention)
	require.NoError(t, err)
	require.Equal(t, retention.Mode, actualRetention.Mode)
	require.Equal(t, retention.RetainUntilDate, actualRetention.RetainUntilDate)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestPutObjectWithLock(t *testing.T) {
	ctx := context.Background()
	hc := prepareHandlerContext(t)

	bktName := "bucket-lock-enabled"
	lockConfig := &data.ObjectLockConfiguration{
		ObjectLockEnabled: enabledValue,
		Rule: &data.ObjectLockRule{
			DefaultRetention: &data.DefaultRetention{
				Days: 1,
				Mode: governanceMode,
			},
		},
	}
	createTestBucketWithLock(ctx, t, hc, bktName, lockConfig)

	objDefault := "obj-default-retention"

	w, r := prepareTestRequest(t, bktName, objDefault, nil)
	hc.Handler().PutObjectHandler(w, r)
	require.Equal(t, http.StatusOK, w.Code)

	w, r = prepareTestRequest(t, bktName, objDefault, nil)
	hc.Handler().GetObjectRetentionHandler(w, r)
	expectedRetention := &data.Retention{
		Mode:            governanceMode,
		RetainUntilDate: time.Now().Add(24 * time.Hour).Format(time.RFC3339),
	}
	assertRetentionApproximate(t, w, expectedRetention, 1)

	w, r = prepareTestRequest(t, bktName, objDefault, nil)
	hc.Handler().GetObjectLegalHoldHandler(w, r)
	assertLegalHold(t, w, legalHoldOff)

	objOverride := "obj-override-retention"
	w, r = prepareTestRequest(t, bktName, objOverride, nil)
	r.Header.Set(api.AmzObjectLockMode, complianceMode)
	r.Header.Set(api.AmzObjectLockLegalHold, legalHoldOn)
	r.Header.Set(api.AmzObjectLockRetainUntilDate, time.Now().Add(2*24*time.Hour).Format(time.RFC3339))
	hc.Handler().PutObjectHandler(w, r)
	require.Equal(t, http.StatusOK, w.Code)

	w, r = prepareTestRequest(t, bktName, objOverride, nil)
	hc.Handler().GetObjectRetentionHandler(w, r)
	expectedRetention = &data.Retention{
		Mode:            complianceMode,
		RetainUntilDate: time.Now().Add(2 * 24 * time.Hour).Format(time.RFC3339),
	}
	assertRetentionApproximate(t, w, expectedRetention, 1)

	w, r = prepareTestRequest(t, bktName, objOverride, nil)
	hc.Handler().GetObjectLegalHoldHandler(w, r)
	assertLegalHold(t, w, legalHoldOn)
}

func assertRetentionApproximate(t *testing.T, w *httptest.ResponseRecorder, retention *data.Retention, delta float64) {
	actualRetention := &data.Retention{}
	err := xml.NewDecoder(w.Result().Body).Decode(actualRetention)
	require.NoError(t, err)
	require.Equal(t, retention.Mode, actualRetention.Mode)
	require.Equal(t, http.StatusOK, w.Code)

	actualUntil, err := time.Parse(time.RFC3339, actualRetention.RetainUntilDate)
	require.NoError(t, err)

	expectedUntil, err := time.Parse(time.RFC3339, retention.RetainUntilDate)
	require.NoError(t, err)

	require.InDelta(t, expectedUntil.Unix(), actualUntil.Unix(), delta)
}
