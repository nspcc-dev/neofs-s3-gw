package data

type (
	ObjectLockConfiguration struct {
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
)
