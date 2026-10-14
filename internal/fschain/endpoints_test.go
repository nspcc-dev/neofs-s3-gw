package fschain

import (
	"context"
	"errors"
	"testing"

	"github.com/nspcc-dev/neo-go/pkg/rpcclient"
	"github.com/nspcc-dev/neo-go/pkg/util"
	"github.com/stretchr/testify/require"
)

func TestNewClientsKeepsUnavailableEndpoints(t *testing.T) {
	endpoints := []string{"http://IR1-down:30333", "http://IR2-up:30333"}

	clients, err := NewClients(context.Background(), endpoints)
	require.NoError(t, err)
	t.Cleanup(func() { CloseClients(clients) })

	require.Len(t, clients, len(endpoints))
	for i, cl := range clients {
		require.Equal(t, endpoints[i], cl.Endpoint())
	}
}

func TestNewClientsFailsForEmptyList(t *testing.T) {
	_, err := NewClients(context.Background(), []string{})
	require.ErrorContains(t, err, "endpoints must be set")
}

func TestFirstSuccessfulContinuesAfterFailure(t *testing.T) {
	clients, err := NewClients(context.Background(), []string{"http://IR1-down:30333", "http://IR2-up:30333", "http://IR3-up:30333"})
	require.NoError(t, err)
	t.Cleanup(func() { CloseClients(clients) })

	var attempted []string

	res, err := FirstSuccessful(clients, func(cl *rpcclient.Client) (util.Uint160, error) {
		attempted = append(attempted, cl.Endpoint())
		if cl.Endpoint() == "http://IR1-down:30333" {
			return util.Uint160{}, errors.New("unavailable")
		}

		return util.Uint160{2}, nil
	})

	require.NoError(t, err)
	require.Equal(t, util.Uint160{2}, res)
	require.Equal(t, []string{"http://IR1-down:30333", "http://IR2-up:30333"}, attempted)
}

func TestFirstSuccessfulFailsWhenAllEndpointsFail(t *testing.T) {
	clients, err := NewClients(context.Background(), []string{"http://IR1-down:30333", "http://IR2-down:30333"})
	require.NoError(t, err)
	t.Cleanup(func() { CloseClients(clients) })

	firstErr := errors.New("first endpoint unavailable")
	secondErr := errors.New("second endpoint unavailable")

	_, err = FirstSuccessful(clients, func(cl *rpcclient.Client) (util.Uint160, error) {
		switch cl.Endpoint() {
		case "http://IR1-down:30333":
			return util.Uint160{}, firstErr
		case "http://IR2-down:30333":
			return util.Uint160{}, secondErr
		default:
			t.Fatalf("unexpected endpoint %q", cl.Endpoint())
			return util.Uint160{}, nil
		}
	})

	require.ErrorContains(t, err, "all RPC endpoints failed")
	require.ErrorIs(t, err, firstErr)
	require.ErrorIs(t, err, secondErr)
}
