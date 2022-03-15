package layer

import (
	"testing"

	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	"github.com/nspcc-dev/neofs-s3-gw/api/errors"
	"github.com/stretchr/testify/require"
)

func TestCheckRules(t *testing.T) {
	t.Run("correct rules with prefix and suffix", func(t *testing.T) {
		rules := []data.FilterRule{
			{Name: "prefix", Value: "asd"},
			{Name: "suffix", Value: "asd"},
		}
		err := checkRules(rules)
		require.NoError(t, err)
	})

	t.Run("correct rules with prefix", func(t *testing.T) {
		rules := []data.FilterRule{
			{Name: "prefix", Value: "asd"},
		}
		err := checkRules(rules)
		require.NoError(t, err)
	})

	t.Run("correct rules with suffix", func(t *testing.T) {
		rules := []data.FilterRule{
			{Name: "suffix", Value: "asd"},
		}
		err := checkRules(rules)
		require.NoError(t, err)
	})

	t.Run("incorrect rules with wrong name", func(t *testing.T) {
		rules := []data.FilterRule{
			{Name: "prefix", Value: "sdf"},
			{Name: "sfx", Value: "asd"},
		}
		err := checkRules(rules)
		require.ErrorIs(t, err, errors.GetAPIError(errors.ErrFilterNameInvalid))
	})

	t.Run("incorrect rules with repeating suffix", func(t *testing.T) {
		rules := []data.FilterRule{
			{Name: "suffix", Value: "asd"},
			{Name: "suffix", Value: "asdf"},
			{Name: "prefix", Value: "jk"},
		}
		err := checkRules(rules)
		require.ErrorIs(t, err, errors.GetAPIError(errors.ErrFilterNameSuffix))
	})

	t.Run("incorrect rules with repeating prefix", func(t *testing.T) {
		rules := []data.FilterRule{
			{Name: "suffix", Value: "ds"},
			{Name: "prefix", Value: "asd"},
			{Name: "prefix", Value: "asdf"},
		}
		err := checkRules(rules)
		require.ErrorIs(t, err, errors.GetAPIError(errors.ErrFilterNamePrefix))
	})
}
