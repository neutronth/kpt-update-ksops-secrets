// Copyright 2022 Neutron Soutmun <neutron@neutron.in.th>
// SPDX-License-Identifier: Apache-2.0

package generator

import (
	"fmt"

	sdk "github.com/GoogleContainerTools/kpt-functions-catalog/thirdparty/kyaml/fnsdk"
	"github.com/neutronth/kpt-update-ksops-secrets/config"
	"sigs.k8s.io/kustomize/kyaml/yaml"
)

type SecretReference interface {
	Get(key string) (value string, b64encoded bool, err error)
	GetExact(name, key string) (value string, b64encoded bool, err error)
}

type secretReference struct {
	secretRefNodes []*yaml.RNode
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

func getSecretRefNodes(items []*yaml.RNode, secretrefs []string) []*yaml.RNode {
	var nodes []*yaml.RNode

	oItems := sdk.NewFromRNodes(items)

	for _, o := range oItems {
		if o.APIVersion() == "v1" && o.Kind() == "Secret" {
			if sliceContainsString(secretrefs, o.Name()) {
				nodes = append(nodes, o.ToRNode())
			}
		}
	}

	return nodes
}

func newSecretReference(items []*yaml.RNode,
	uksConfig *config.UpdateKSopsSecrets) SecretReference {

	return &secretReference{
		secretRefNodes: getSecretRefNodes(items, listSecretRefsFromConfig(uksConfig)),
	}
}
func (sr *secretReference) Get(key string) (value string, b64encoded bool, err error) {
	return sr.GetExact("", key)
}

func (sr *secretReference) GetExact(name, key string) (value string, b64encoded bool, err error) {
	if field := sr.lookup(name, key, "dataString"); field != nil {
		value = yaml.GetValue(field.Value)
		b64encoded = false
	} else if field := sr.lookup(name, key, "data"); field != nil {
		value = yaml.GetValue(field.Value)
		b64encoded = true
	} else {
		err = fmt.Errorf("Secret %s was not found in the references", key)
	}

	return
}

func (sr *secretReference) lookup(name, key, dataField string) (mapnode *yaml.MapNode) {
	for _, rn := range sr.secretRefNodes {
		if name != "" && rn.GetName() != name {
			continue
		}

		n, err := rn.Pipe(yaml.Lookup(dataField))
		if err != nil {
			return nil
		}

		if n == nil {
			continue
		}

		if field := n.Field(key); field != nil {
			return field
		}
	}

	return nil
}
