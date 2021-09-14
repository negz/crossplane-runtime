/*
Copyright 2021 The Crossplane Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package gke contains utilities for authenticating to GKE clusters.
package gke

import (
	"context"
	"net/http"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/crossplane/crossplane-runtime/pkg/errors"
)

// DefaultScopes for GKE authentication.
var DefaultScopes []string = []string{
	"https://www.googleapis.com/auth/cloud-platform",
	"https://www.googleapis.com/auth/userinfo.email",
}

// NewRESTConfig returns a Kubernetes REST configuration suitable for use with
// a GKE cluster. It ignores any user credentials specified by the supplied
// kubeconfig and instead uses the supplied Google Application Credentials JSON
// to perform OAuth2 authentication.
func NewRESTConfig(ctx context.Context, kubeconfig, credentials []byte, scopes ...string) (*rest.Config, error) {
	creds, err := google.CredentialsFromJSON(ctx, credentials, scopes...)
	if err != nil {
		return nil, errors.Wrap(err, "cannot load Google Application Credentials from JSON")
	}

	tok, err := creds.TokenSource.Token()
	if err != nil {
		return nil, errors.Wrap(err, "cannot request OAuth2 token using Google Application Credentials")
	}

	src := oauth2.ReuseTokenSource(tok, creds.TokenSource)

	kc, err := clientcmd.Load(kubeconfig)
	if err != nil {
		return nil, errors.Wrap(err, "cannot load kubeconfig")
	}

	if kc.CurrentContext == "" {
		return nil, errors.New("currentContext not set in kubeconfig")
	}
	cluster := kc.Clusters[kc.Contexts[kc.CurrentContext].Cluster]
	if cluster == nil {
		return nil, errors.Errorf("cluster for currentContext (%s) not found", kc.CurrentContext)
	}
	user := kc.AuthInfos[kc.Contexts[kc.CurrentContext].AuthInfo]
	if user == nil {
		return nil, errors.Errorf("auth info for currentContext (%s) not found", kc.CurrentContext)
	}

	// We intentionally ignore tokens, basic auth, client certs, etc because
	// we always use oauth2 authentication per the supplied credentials.
	cfg := &rest.Config{
		Host: cluster.Server,
		Impersonate: rest.ImpersonationConfig{
			UserName: user.Impersonate,
			Groups:   user.ImpersonateGroups,
			Extra:    user.ImpersonateUserExtra,
		},
		TLSClientConfig: rest.TLSClientConfig{
			Insecure:   cluster.InsecureSkipTLSVerify,
			ServerName: cluster.TLSServerName,
			CAData:     cluster.CertificateAuthorityData,
		},
		WrapTransport: func(rt http.RoundTripper) http.RoundTripper {
			return &oauth2.Transport{Source: src, Base: rt}
		},
	}

	return cfg, nil
}
