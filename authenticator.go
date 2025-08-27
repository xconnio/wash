package wampshell

import (
	"fmt"

	"github.com/xconnio/wampproto-go/auth"
)

type ServerAuthenticator struct {
	keyStore *KeyStore
}

func NewAuthenticator(keyStore *KeyStore) *ServerAuthenticator {
	return &ServerAuthenticator{keyStore: keyStore}
}

func (a *ServerAuthenticator) Methods() []auth.Method {
	return []auth.Method{auth.MethodCryptoSign}
}

func (a *ServerAuthenticator) Authenticate(request auth.Request) (auth.Response, error) {
	cryptosignRequest, ok := request.(*auth.RequestCryptoSign)
	if !ok {
		return nil, fmt.Errorf("invalid request type: %T", request)
	}

	pubKeyHex := cryptosignRequest.PublicKey()
	for _, pubKey := range a.keyStore.Keys() {
		if pubKey == pubKeyHex {
			return auth.NewResponse("", "anonymous", 0)
		}
	}
	return nil, fmt.Errorf("public key not authorized")
}
