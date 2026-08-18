package resolver

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"oras.land/oras-go/v2/registry/remote/auth"
)

// dockerConfig is the subset of ~/.docker/config.json Assay reads. Scan pods
// mount a pull secret at DOCKER_CONFIG so the resolver can reach private
// registries, including the OpenShift integrated registry.
type dockerConfig struct {
	Auths map[string]struct {
		Auth     string `json:"auth"`
		Username string `json:"username"`
		Password string `json:"password"`
	} `json:"auths"`
}

type credentialStore struct {
	entries map[string]auth.Credential
}

// Get implements auth.CredentialFunc.
func (s *credentialStore) Get(_ context.Context, registry string) (auth.Credential, error) {
	if cred, ok := s.entries[registry]; ok {
		return cred, nil
	}
	// Docker stores docker.io credentials under the legacy index host.
	if registry == "registry-1.docker.io" || registry == "docker.io" {
		for _, key := range []string{"https://index.docker.io/v1/", "index.docker.io", "docker.io"} {
			if cred, ok := s.entries[key]; ok {
				return cred, nil
			}
		}
	}
	return auth.EmptyCredential, nil
}

// dockerConfigStore loads credentials from the mounted Docker config, if any.
func dockerConfigStore() (*credentialStore, error) {
	path := configPath()
	if path == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read docker config %s: %w", path, err)
	}

	var cfg dockerConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("parse docker config %s: %w", path, err)
	}

	store := &credentialStore{entries: map[string]auth.Credential{}}
	for host, entry := range cfg.Auths {
		username, password := entry.Username, entry.Password
		if entry.Auth != "" {
			decoded, err := base64.StdEncoding.DecodeString(entry.Auth)
			if err == nil {
				if user, pass, ok := strings.Cut(string(decoded), ":"); ok {
					username, password = user, pass
				}
			}
		}
		if username == "" && password == "" {
			continue
		}
		store.entries[normalizeHost(host)] = auth.Credential{Username: username, Password: password}
		store.entries[host] = auth.Credential{Username: username, Password: password}
	}
	return store, nil
}

func configPath() string {
	if explicit := os.Getenv("DOCKER_CONFIG"); explicit != "" {
		return strings.TrimSuffix(explicit, "/") + "/config.json"
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return home + "/.docker/config.json"
}

func normalizeHost(host string) string {
	host = strings.TrimPrefix(host, "https://")
	host = strings.TrimPrefix(host, "http://")
	return strings.TrimSuffix(host, "/")
}
