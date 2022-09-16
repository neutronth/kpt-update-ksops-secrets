// Copyright 2022 Neutron Soutmun <neutron@neutron.in.th>
// SPDX-License-Identifier: Apache-2.0

package generator

import (
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

	return list
}

func getSecretRefNodes(items sdk.KubeObjects, secretrefs []string) (results sdk.KubeObjects) {
	skipcheck, err := regexp.Compile(`generated/secrets\..*\.enc\.yaml`)
	if err != nil {
		return
	}

	for _, ko := range items {
		if ko.GetAPIVersion() == "v1" && ko.GetKind() == "Secret" {
			if skipcheck.MatchString(ko.PathAnnotation()) {
				continue
			}

			if sliceContainsString(secretrefs, ko.GetName()) {
				results = append(results, ko)
			}
		}
	}

	return
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
		value = val
		b64encoded = false
	} else if val, found := sr.lookup(name, key, "data"); found {
		value = val
		b64encoded = true
	} else {
		err = fmt.Errorf("secret: %s, %w", key, ErrSecretNotFound)
	}

	return
}

func (sr *secretReference) lookup(name, key, dataField string) (val string, found bool) {
	for _, ko := range sr.KubeObjects {
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
