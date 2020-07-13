package layer

import (
	"context"
	"crypto/ecdsa"
	"strings"
	"time"

	minio "github.com/minio/minio/legacy"
	"github.com/minio/minio/neofs/pool"
	"github.com/nspcc-dev/neofs-api-go/object"
	"github.com/nspcc-dev/neofs-api-go/refs"
	"github.com/nspcc-dev/neofs-api-go/service"
	"github.com/nspcc-dev/neofs-api-go/session"
	crypto "github.com/nspcc-dev/neofs-crypto"
)

type (
	tokenParams struct {
		cli   pool.Client
		key   *ecdsa.PrivateKey
		until uint64
	}

	queryParams struct {
		key  *ecdsa.PrivateKey
		addr refs.Address
		verb service.Token_Info_Verb
	}
)

// APIVersion of the neofs
const APIVersion = 1

func userHeaders(h []object.Header) map[string]string {
	result := make(map[string]string, len(h))

	for i := range h {
		switch v := h[i].Value.(type) {
		case *object.Header_UserHeader:
			result[v.UserHeader.Key] = v.UserHeader.Value
		default:
			continue
		}
	}

	return result
}

func objectInfoFromMeta(meta *object.Object) minio.ObjectInfo {
	aws3name := meta.SystemHeader.ID.String()

	userHeaders := userHeaders(meta.Headers)
	if name, ok := userHeaders[AWS3NameHeader]; ok {
		aws3name = name
		delete(userHeaders, name)
	}

	oi := minio.ObjectInfo{
		Bucket:      meta.SystemHeader.CID.String(),
		Name:        aws3name,
		ModTime:     time.Unix(meta.SystemHeader.CreatedAt.UnixTime, 0),
		Size:        int64(meta.SystemHeader.PayloadLength),
		ETag:        "", // ?
		ContentType: "", // ?
		UserDefined: userHeaders,
		UserTags:    "", // ignore it
	}

	return oi
}

func generateToken(ctx context.Context, p tokenParams) (*service.Token, error) {
	owner, err := refs.NewOwnerID(&p.key.PublicKey)
	if err != nil {
		return nil, err
	}

	token := new(service.Token)
	token.SetOwnerID(owner)
	token.SetExpirationEpoch(p.until)
	token.SetOwnerKey(crypto.MarshalPublicKey(&p.key.PublicKey))

	conn, err := p.cli.GetConnection(ctx)
	if err != nil {
		return nil, err
	}

	creator, err := session.NewGRPCCreator(conn, p.key)
	if err != nil {
		return nil, err
	}

	res, err := creator.Create(ctx, token)
	if err != nil {
		return nil, err
	}

	token.SetID(res.GetID())
	token.SetSessionKey(res.GetSessionKey())

	return token, nil
}

func prepareToken(t *service.Token, p queryParams) (*service.Token, error) {
	sig := make([]byte, len(t.Signature))
	copy(sig, t.Signature)

	token := &service.Token{
		Token_Info: service.Token_Info{
			ID:            t.ID,
			OwnerID:       t.OwnerID,
			Verb:          t.Verb,
			Address:       t.Address,
			TokenLifetime: t.TokenLifetime,
			SessionKey:    t.SessionKey,
			OwnerKey:      t.OwnerKey,
		},
		Signature: sig,
	}

	token.SetAddress(p.addr)
	token.SetVerb(p.verb)

	err := service.AddSignatureWithKey(p.key, service.NewSignedSessionToken(token))
	if err != nil {
		return nil, err
	}

	return token, nil
}

func parseUserHeaders(h map[string]string) []object.Header {
	headers := make([]object.Header, 0, len(h))

	for k, v := range h {
		uh := &object.UserHeader{Key: k, Value: v}
		headers = append(headers, object.Header{
			Value: &object.Header_UserHeader{UserHeader: uh},
		})
	}

	return headers
}

func nameFromObject(o *object.Object) (string, string) {
	var (
		name string
		uh   = userHeaders(o.Headers)
	)

	if _, ok := uh[AWS3NameHeader]; !ok {
		name = o.SystemHeader.ID.String()
	} else {
		name = uh[AWS3NameHeader]
	}

	ind := strings.LastIndex(name, SlashSeparator)

	return name[ind+1:], name[:ind+1]
}
