// Copyright 2022 Neutron Soutmun <neutron@neutron.in.th>
// SPDX-License-Identifier: Apache-2.0

package generator

import (
	"fmt"
	"strings"

	"github.com/neutronth/kpt-update-ksops-secrets/config"
	"sigs.k8s.io/kustomize/kyaml/yaml"
)

const ResultFileBaseSecrets = "secrets.yaml"
const ResultFileKustomization = "kustomization.yaml"
const ResultFileKSopsGenerator = "generated/ksops-generator.yaml"
const ResultFileEncryptedBase = "generated/secrets"

type KSopsGenerator struct{}

func (g *KSopsGenerator) GenerateBaseSecrets(nodes []*yaml.RNode,
	uksConfig *config.UpdateKSopsSecrets,
) ([]*yaml.RNode, error) {
	node, err := NewBaseSecretsNode(
		uksConfig.GetName(),
		uksConfig.GetType(),
		uksConfig.GetAnnotations(),
		uksConfig.GetLabels(),
	)
	if err != nil {
		return nil, err
	}
	var newNodes []*yaml.RNode
	newNodes = append(newNodes, node)

	return newNodes, nil
}

func (g *KSopsGenerator) GenerateKustomization(nodes []*yaml.RNode) (
	[]*yaml.RNode, error) {
	node, err := NewKustomizationNode()
	if err != nil {
		return nil, err
	}
	var newNodes []*yaml.RNode
	newNodes = append(newNodes, node)

	return newNodes, nil
}

func (g *KSopsGenerator) GenerateKSopsGenerator(nodes []*yaml.RNode, uksConfig *config.UpdateKSopsSecrets) (
	[]*yaml.RNode, error) {
	var newNodes []*yaml.RNode

	for _, key := range uksConfig.GetSecretItems() {
		node, err := NewKSopsGeneratorNode(uksConfig.GetName(), key)
		if err != nil {
			return nil, err
		}
		newNodes = append(newNodes, node)
	}

	return newNodes, nil
}

func NewBaseSecretsNode(name, secretType string, annotations, labels map[string]string) (*yaml.RNode, error) {
	n := yaml.MustParse(`
apiVersion: v1
kind: Secret
type: Opaque
data: {}
`)
	if err := n.SetName(name); err != nil {
		return nil, err
	}

	updateAnnotations := map[string]string{}
	if len(annotations) > 0 {
		updateAnnotations = annotations
	}
	updateAnnotations["kustomize.config.k8s.io/behavior"] = "merge"

	if err := n.SetAnnotations(updateAnnotations); err != nil {
		return nil, err
	}

	if len(labels) > 0 {
		if err := n.SetLabels(labels); err != nil {
			return nil, err
		}
	}

	if secretType != "" {
		n, err := n.Pipe(yaml.Lookup("type"))
		if err != nil {
			return nil, err
		}

		n.YNode().Value = secretType
	}

	return n, nil
}

func NewKustomizationNode() (*yaml.RNode, error) {
	n := yaml.MustParse(`
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
- secrets.yaml
generators:
- generated/ksops-generator.yaml
`)

	return n, nil
}

func NewKSopsGeneratorNode(secretName, key string) (*yaml.RNode, error) {
	n := yaml.MustParse(`
apiVersion: viaduct.ai/v1
kind: ksops
files:
`)
	normalizedKey := normalizedKeyName(key)
	if err := n.SetName(fmt.Sprintf("ksops-generator-%s-%s", secretName, normalizedKey)); err != nil {
		return nil, err
	}

	files := yaml.NewListRNode(fmt.Sprintf("generated/secrets.%s.enc.yaml", normalizedKey))
	if _, err := n.Pipe(yaml.Lookup("files"), yaml.Set(files)); err != nil {
		return nil, err
	}

	return n, nil
}

func normalizedKeyName(key string) string {
	return strings.ToLower(key)
}
