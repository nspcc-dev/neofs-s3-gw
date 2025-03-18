package data

import (
	"encoding/xml"
	"fmt"
	"strconv"
	"strings"
	"time"
)

type (
	ObjectLockConfiguration struct {
		XMLName           xml.Name        `xml:"ObjectLockConfiguration" json:"-"`
		ObjectLockEnabled string          `xml:"ObjectLockEnabled" json:"ObjectLockEnabled"`
		Rule              *ObjectLockRule `xml:"Rule" json:"Rule"`
	}

	ObjectLockRule struct {
		DefaultRetention *DefaultRetention `xml:"DefaultRetention" json:"DefaultRetention"`
	}

	DefaultRetention struct {
		Days  int64  `xml:"Days" json:"Days"`
		Mode  string `xml:"Mode" json:"Mode"`
		Years int64  `xml:"Years" json:"Years"`
	}

	LegalHold struct {
		XMLName xml.Name `xml:"LegalHold" json:"-"`
		Status  string   `xml:"Status" json:"Status"`
	}

	Retention struct {
		XMLName         xml.Name `xml:"Retention" json:"-"`
		Mode            string   `xml:"Mode" json:"Mode"`
		RetainUntilDate string   `xml:"RetainUntilDate" json:"RetainUntilDate"`
	}

	ObjectLock struct {
		LegalHold *LegalHoldLock
		Retention *RetentionLock
	}

	LegalHoldLock struct {
		Enabled bool
	}

	RetentionLock struct {
		Until              time.Time
		IsCompliance       bool
		ByPassedGovernance bool
	}
)

// Encode marshal ObjectLockConfiguration to string.
func (conf *ObjectLockConfiguration) Encode() string {
	if conf.Rule == nil || conf.Rule.DefaultRetention == nil {
		return conf.ObjectLockEnabled
	}

	defaults := conf.Rule.DefaultRetention
	return fmt.Sprintf("%s,%d,%s,%d", conf.ObjectLockEnabled, defaults.Days, defaults.Mode, defaults.Years)
}

// Decode unmarshal ObjectLockConfiguration from string.
func (conf *ObjectLockConfiguration) Decode(value string) error {
	if len(value) == 0 {
		return nil
	}

	lockValues := strings.Split(value, ",")
	if len(lockValues) == 0 {
		return fmt.Errorf("invalid lock configuration: %s", value)
	}

	conf.ObjectLockEnabled = lockValues[0]

	if len(lockValues) == 1 {
		return nil
	}

	if len(lockValues) != 4 {
		return fmt.Errorf("invalid lock configuration: %s", value)
	}

	var (
		err         error
		days, years int64
	)

	if len(lockValues[1]) > 0 {
		if days, err = strconv.ParseInt(lockValues[1], 10, 64); err != nil {
			return fmt.Errorf("invalid lock configuration: %s", value)
		}
	}

	if len(lockValues[3]) > 0 {
		if years, err = strconv.ParseInt(lockValues[3], 10, 64); err != nil {
			return fmt.Errorf("invalid lock configuration: %s", value)
		}
	}

	conf.Rule = &ObjectLockRule{
		DefaultRetention: &DefaultRetention{
			Days:  days,
			Mode:  lockValues[2],
			Years: years,
		},
	}

	return nil
}
