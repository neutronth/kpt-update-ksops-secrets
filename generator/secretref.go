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
		secretRefNodes: getSecretRefNodes(items, uksConfig.Secret.References),
	}
}

func (sr *secretReference) Get(key string) (value string, b64encoded bool, err error) {
	if field := sr.lookup(key, "dataString"); field != nil {
		value = yaml.GetValue(field.Value)
		b64encoded = false
	} else if field := sr.lookup(key, "data"); field != nil {
		value = yaml.GetValue(field.Value)
		b64encoded = true
	} else {
		err = fmt.Errorf("Secret %s was not found in the references", key)
	}

	return
}

func (sr *secretReference) lookup(key, dataField string) (mapnode *yaml.MapNode) {
	for _, rn := range sr.secretRefNodes {
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
