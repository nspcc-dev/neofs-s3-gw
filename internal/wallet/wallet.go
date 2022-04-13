package wallet

import (
	"fmt"

	"github.com/nspcc-dev/neo-go/cli/flags"
	"github.com/nspcc-dev/neo-go/cli/input"
	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neo-go/pkg/util"
	"github.com/nspcc-dev/neo-go/pkg/wallet"
	"github.com/spf13/viper"
)

// GetPassword gets the passphrase for a wallet.
func GetPassword(v *viper.Viper, variable string) *string {
	var password *string
	if v.IsSet(variable) {
		pwd := v.GetString(variable)
		password = &pwd
	}
	return password
}

// GetKeyFromPath reads a wallet and gets the private key.
func GetKeyFromPath(walletPath, addrStr string, password *string) (*keys.PrivateKey, error) {
	if len(walletPath) == 0 {
		return nil, fmt.Errorf("wallet path must not be empty")
	}
	w, err := wallet.NewWalletFromFile(walletPath)
	if err != nil {
		return nil, err
	}

	var addr util.Uint160
	if len(addrStr) == 0 {
		addr = w.GetChangeAddress()
	} else {
		addr, err = flags.ParseAddress(addrStr)
		if err != nil {
			return nil, fmt.Errorf("invalid address")
		}
	}

	acc := w.GetAccount(addr)
	if acc == nil {
		return nil, fmt.Errorf("couldn't find wallet account for %s", addrStr)
	}

	if password == nil {
		pwd, err := input.ReadPassword(fmt.Sprintf("Enter password for %s > ", walletPath))
		if err != nil {
			return nil, fmt.Errorf("couldn't read password")
		}
		password = &pwd
	}
	if err := acc.Decrypt(*password, w.Scrypt); err != nil {
		return nil, fmt.Errorf("couldn't decrypt account: %w", err)
	}

	return acc.PrivateKey(), nil
}
