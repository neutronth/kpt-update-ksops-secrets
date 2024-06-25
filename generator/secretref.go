// Copyright 2022 Neutron Soutmun <neutron@neutron.in.th>
// SPDX-License-Identifier: Apache-2.0

package generator

import (
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"

	sdk "github.com/GoogleContainerTools/kpt-functions-sdk/go/fn"
	"github.com/neutronth/kpt-update-ksops-secrets/config"
	"sigs.k8s.io/kustomize/kyaml/yaml"
)

var ErrSecretNotFound = errors.New("secret was not found in the references")

type SecretReference interface {
	Get(key string) (value string, b64encoded bool, err error)
	GetExact(name, key string) (value string, b64encoded bool, err error)
	GetEncryptedFP(name, key string) string
}

type secretReference struct {
	sdk.KubeObjects
}

func sliceContainsString(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}

	return false
}

func listSecretRefsFromConfig(uksConfig *config.UpdateKSopsSecrets) (list []string) {
	list = append(list, uksConfig.Secret.References...)

	for _, r := range uksConfig.Recipients {
		if r.Type == "pgp" && r.PublicKeySecretReference.Name != "" {
			list = append(list, r.PublicKeySecretReference.Name)
		}
	}

	if !sliceContainsString(list, uksConfig.GetName()) {
		list = append(list, uksConfig.GetName())
	}

	return list
}

func getSecretRefNodes(items sdk.KubeObjects, secretrefs []string) (results sdk.KubeObjects) {
	for _, ko := range items {
		if ko.GetAPIVersion() == "v1" && ko.GetKind() == "Secret" {
			if sliceContainsString(secretrefs, ko.GetName()) {
				results = append(results, ko)
			}
		}
	}

	return
}

func encryptedSecretPredicate(expected bool) (f func(ko *sdk.KubeObject) bool) {
	skipcheck, err := regexp.Compile(`generated/secrets\..*\.enc\.yaml`)
	if err != nil {
		return f
	}

	return func(ko *sdk.KubeObject) bool {
		return skipcheck.MatchString(ko.PathAnnotation()) == expected
	}
}

func (sr *secretReference) onlyEncryptedSecrets() (results sdk.KubeObjects) {
	return sr.Where(encryptedSecretPredicate(true))
}

func (sr *secretReference) withoutEncryptedSecrets() (results sdk.KubeObjects) {
	return sr.Where(encryptedSecretPredicate(false))
}

func newSecretReference(items []*yaml.RNode,
	uksConfig *config.UpdateKSopsSecrets) SecretReference {

	var kobjs sdk.KubeObjects

	for _, item := range items {
		ko, err := sdk.NewFromTypedObject(item)
		if err == nil {
			kobjs = append(kobjs, ko)
		}
	}

	return &secretReference{
		getSecretRefNodes(kobjs, listSecretRefsFromConfig(uksConfig)),
	}
}
func (sr *secretReference) Get(key string) (value string, b64encoded bool, err error) {
	return sr.GetExact("", key)
}

func (sr *secretReference) GetExact(name, key string) (value string, b64encoded bool, err error) {
	if val, found := sr.lookup(name, key, "stringData"); found {
		return val, false, nil
	} else if val, found := sr.lookup(name, key, "data"); found {
		if _, err := base64.StdEncoding.DecodeString(val); err != nil {
			return "", false, err
		}
		return val, true, nil
	}
	return "", false, fmt.Errorf("secret: %s, %w", key, ErrSecretNotFound)
}

func (sr *secretReference) lookup(name, key, dataField string) (val string, found bool) {
	for _, ko := range sr.withoutEncryptedSecrets() {
		if name != "" && ko.GetName() != name {
			continue
		}

		if data, found, err := ko.NestedStringMap(dataField); err == nil && found {
			if val, ok := data[key]; ok {
				return val, true
			}
		}
	}
	return "", false
}

func (sr *secretReference) GetEncryptedFP(name, key string) string {
	for _, ko := range sr.onlyEncryptedSecrets() {
		if name != "" && ko.GetName() != name {
			continue
		}

		if data, found, err := ko.NestedStringMap("sops", "encrypted_fp"); err == nil && found {
			if val, ok := data[key]; ok {
				return val
			}
		}
	}

	return ""
}
