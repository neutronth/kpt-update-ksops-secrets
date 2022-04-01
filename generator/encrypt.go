// Copyright 2022 Neutron Soutmun <neutron@neutron.in.th>
// SPDX-License-Identifier: Apache-2.0

package generator

import (
	"encoding/base64"
	"fmt"

	"github.com/neutronth/kpt-update-ksops-secrets/config"
	"github.com/neutronth/kpt-update-ksops-secrets/exec"
	"sigs.k8s.io/kustomize/kyaml/fn/framework"
	"sigs.k8s.io/kustomize/kyaml/kio/kioutil"
	"sigs.k8s.io/kustomize/kyaml/yaml"
)

func (g *KSopsGenerator) GenerateSecretEncryptedFiles(nodes []*yaml.RNode,
	uksConfig *config.UpdateKSopsSecrets,
	secretRef SecretReference,
) ([]*yaml.RNode, []*framework.Result, error) {
	var newNodes []*yaml.RNode
	var results []*framework.Result

	preloadResult, err := preloadGPGKeys(uksConfig.Recipients...)
	results = append(results, preloadResult)

	if err != nil {
		return newNodes, results, err
	}

	for _, key := range uksConfig.GetSecretItems() {
		value, b64encoded, err := secretRef.Get(key)
		if err != nil {
			results = append(results, &framework.Result{
				Message:  fmt.Sprintf("Secret '%s' not found in the secrets references, encryption skipped", key),
				Severity: framework.Warning,
			})
			continue
		}

		encNode, err := NewSecretEncryptedFileNode(
			uksConfig.GetName(),
			key,
			value,
			b64encoded,
			uksConfig.Recipients...,
		)
		if err != nil {
			results = append(results, &framework.Result{
				Message:  err.Error(),
				Severity: framework.Error,
			})
		}

		setFilename([]*yaml.RNode{encNode},
			fmt.Sprintf("%s.%s.enc.yaml", ResultFileEncryptedBase,
				normalizedKeyName(key),
			),
		)
		newNodes = append(newNodes, encNode)
	}

	return newNodes, results, nil
}

func NewSecretEncryptedFileNode(secretName, key, value string,
	b64encoded bool,
	recipients ...config.UpdateKSopsRecipient,
) (*yaml.RNode, error) {
	n := yaml.MustParse(`
apiVersion: v1
kind: Secret
metadata:
  name: secret
type: Opaque
data:
`)

	if err := n.SetName(secretName); err != nil {
		return nil, err
	}

	if _, err := n.Pipe(yaml.SetAnnotation("kustomize.config.k8s.io/behavior", "merge")); err != nil {
		return nil, err
	}

	dataValue := value
	if !b64encoded {
		dataValue = encodeValue(value)
	}

	data := map[string]string{
		key: dataValue,
	}
	n.SetDataMap(data)

	encryptor := exec.NewSopsEncryption()
	output, err := encryptor.Encrypt(n.MustString(), recipients...)
	if err != nil {
		return nil, err
	}

	enc := yaml.MustParse(output)

	// The Sops render the encrypted YAML as a wide sequences indentation
	if _, err := enc.Pipe(yaml.SetAnnotation(kioutil.SeqIndentAnnotation,
		string(yaml.WideSequenceStyle))); err != nil {
		return nil, err
	}

	return enc, nil
}

func preloadGPGKeys(recipients ...config.UpdateKSopsRecipient) (result *framework.Result, err error) {
	var gpgRecipients []string

	for _, r := range recipients {
		if r.Type == "pgp" {
			gpgRecipients = append(gpgRecipients, r.Recipient)
		}
	}

	if len(gpgRecipients) > 0 {
		gpg := exec.NewGPGKeys()
		output, err := gpg.ReceiveKeys(gpgRecipients...)

		if err != nil {
			result = &framework.Result{
				Message:  err.Error(),
				Severity: framework.Error,
			}
			return result, err
		}

		result = &framework.Result{
			Message:  output,
			Severity: framework.Info,
		}
	}

	return result, nil
}

func encodeValue(value string) (enc string) {
	return base64.StdEncoding.EncodeToString([]byte(value))
}
