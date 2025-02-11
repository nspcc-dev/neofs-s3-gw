package data

import (
	"encoding/xml"
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
