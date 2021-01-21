package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"mime"
	"net/http"
	"strings"

	"github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
)

// B2C provider
type B2C struct {
	BaseURL      string `long:"base-url" env:"BASE_URL" description:"Base URL"`
	ClientID     string `long:"client-id" env:"CLIENT_ID" description:"Client ID"`
	ClientSecret string `long:"client-secret" env:"CLIENT_SECRET" description:"Client Secret" json:"-"`

	OAuthProvider

	verifier *oidc.IDTokenVerifier
}

type B2CUser struct {
	Emails []string `json:"emails"`
}

// Name returns the name of the provider
func (o *B2C) Name() string {
	return "b2c"
}

// Setup performs validation and setup
func (o *B2C) Setup() error {
	// Check parms
	if o.BaseURL == "" || o.ClientID == "" || o.ClientSecret == "" {
		return errors.New("providers.b2c.base-url, providers.b2c.client-id, providers.b2c.client-secret must be set")
	}

	o.ctx = context.Background()

	// create endpoint
	urls, err := ReadOpenIDConfiguration(o.ctx, o.BaseURL)
	if err != nil {
		return err
	}
	endpoint := oauth2.Endpoint{
		AuthURL:  urls.AuthURL,
		TokenURL: urls.TokenURL,
	}

	// Create oauth2 config
	o.Config = &oauth2.Config{
		ClientID:     o.ClientID,
		ClientSecret: o.ClientSecret,
		Endpoint:     endpoint,

		// "openid" is a required scope for OpenID Connect flows.
		// client id scope is required so an access token is returned
		Scopes: []string{oidc.ScopeOpenID, "profile", "email", o.ClientID},
	}

	// Create B2C verifier
	o.verifier = oidc.NewVerifier(
		urls.Issuer,
		oidc.NewRemoteKeySet(o.ctx, urls.JWKSURL),
		&oidc.Config{
			ClientID: o.ClientID,
		},
	)

	return nil
}

// GetLoginURL provides the login url for the given redirect uri and state
func (o *B2C) GetLoginURL(redirectURI, state string) string {
	return o.OAuthGetLoginURL(redirectURI, state)
}

// ExchangeCode exchanges the given redirect uri and code for a token
func (o *B2C) ExchangeCode(redirectURI, code string) (string, error) {
	token, err := o.OAuthExchangeCode(redirectURI, code)
	if err != nil {
		return "", err
	}

	// Extract ID token
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return "", errors.New("Missing id_token")
	}

	return rawIDToken, nil
}

// GetUser uses the given token and returns a complete provider.User object
func (o *B2C) GetUser(token string) (User, error) {
	var user User

	// Parse & Verify ID Token
	idToken, err := o.verifier.Verify(o.ctx, token)
	if err != nil {
		return user, err
	}

	// Extract custom claims
	var b2cUser B2CUser
	if err := idToken.Claims(&b2cUser); err != nil {
		return user, err
	}

	// for B2C email is returned in emails array
	if len(b2cUser.Emails) > 0 {
		user.Email = strings.ToLower(b2cUser.Emails[0])
	}

	return user, nil
}

type providerJSON struct {
	Issuer      string `json:"issuer"`
	AuthURL     string `json:"authorization_endpoint"`
	TokenURL    string `json:"token_endpoint"`
	JWKSURL     string `json:"jwks_uri"`
	UserInfoURL string `json:"userinfo_endpoint"`
}

func ReadOpenIDConfiguration(ctx context.Context, baseUrl string) (*providerJSON, error) {
	wellKnown := strings.TrimSuffix(baseUrl, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequest("GET", wellKnown, nil)
	if err != nil {
		return nil, err
	}
	resp, err := doRequest(ctx, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("unable to read response body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", resp.Status, body)
	}

	var p providerJSON
	err = unmarshalResp(resp, body, &p)
	if err != nil {
		return nil, fmt.Errorf("oidc: failed to decode provider discovery object: %v", err)
	}

	return &p, nil
}

func doRequest(ctx context.Context, req *http.Request) (*http.Response, error) {
	client := http.DefaultClient
	if c, ok := ctx.Value(oauth2.HTTPClient).(*http.Client); ok {
		client = c
	}
	return client.Do(req.WithContext(ctx))
}

func unmarshalResp(r *http.Response, body []byte, v interface{}) error {
	err := json.Unmarshal(body, &v)
	if err == nil {
		return nil
	}
	ct := r.Header.Get("Content-Type")
	mediaType, _, parseErr := mime.ParseMediaType(ct)
	if parseErr == nil && mediaType == "application/json" {
		return fmt.Errorf("got Content-Type = application/json, but could not unmarshal as JSON: %v", err)
	}
	return fmt.Errorf("expected Content-Type = application/json, got %q: %v", ct, err)
}
