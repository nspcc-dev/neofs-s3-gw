package layer

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFillingPrefixes(t *testing.T) {
	cases := []struct {
		name             string
		list             *ListObjectsInfo
		directories      map[string]bool
		expectedPrefixes []string
		expectedObjects  []*ObjectInfo
	}{
		{
			name: "3 dirs",
			list: &ListObjectsInfo{
				Objects: []*ObjectInfo{{Name: "dir/"}, {Name: "dir2/"}, {Name: "dir3/"}},
			},
			directories:      map[string]bool{"dir/": true, "dir2/": true, "dir3/": true},
			expectedPrefixes: []string{"dir/", "dir2/", "dir3/"},
			expectedObjects:  []*ObjectInfo{},
		},
		{
			name: "1 obj, 3 dirs",
			list: &ListObjectsInfo{
				Objects: []*ObjectInfo{{Name: "dir/"}, {Name: "dir2/"}, {Name: "dir3/"}, {Name: "obj"}},
			},
			directories:      map[string]bool{"dir/": true, "dir2/": true, "dir3/": true},
			expectedPrefixes: []string{"dir/", "dir2/", "dir3/"},
			expectedObjects:  []*ObjectInfo{{Name: "obj"}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fillPrefixes(tc.list, tc.directories)
			require.Equal(t, tc.expectedPrefixes, tc.list.Prefixes)
			require.Equal(t, tc.expectedObjects, tc.list.Objects)
		})
	}
}
