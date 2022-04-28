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
) (newNodes []*yaml.RNode, results framework.Results) {
	preloadResults := preloadGPGKeys(secretRef, uksConfig.Recipients...)
	results = append(results, preloadResults...)
	if preloadResults.ExitCode() == 1 {
		return nil, results
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
			uksConfig.GetType(),
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

		filename := fmt.Sprintf("%s.%s.enc.yaml", ResultFileEncryptedBase,
			normalizedKeyName(key))
		setFilename([]*yaml.RNode{encNode}, filename)
		newNodes = append(newNodes, encNode)
		results = append(results, &framework.Result{
			Message: fmt.Sprintf("Secret key '%s' => %s encrypted",
				key, filename),
			Severity: framework.Info,
		})
	}

	return newNodes, results
}

func NewSecretEncryptedFileNode(secretName, secretType, key, value string,
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

	if secretType != "" {
		n, err := n.Pipe(yaml.Lookup("type"))
		if err != nil {
			return nil, err
		}

		n.YNode().Value = secretType
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

func selectGPGRecipientsWithPublicKey(gpgRecipients []config.UpdateKSopsRecipient) (selected []config.UpdateKSopsRecipient) {
	for _, gr := range gpgRecipients {
		sr := gr.PublicKeySecretReference
		if sr.Name != "" && sr.Key != "" {
			selected = append(selected, gr)
		}
	}

	return selected
}

func selectGPGRecipientsWithoutPublicKey(gpgRecipients []config.UpdateKSopsRecipient) (selected []config.UpdateKSopsRecipient) {
	for _, gr := range gpgRecipients {
		sr := gr.PublicKeySecretReference
		if sr.Name == "" || sr.Key == "" {
			selected = append(selected, gr)
		}
	}

	return selected
}

func getGPGRecipients(recipients ...config.UpdateKSopsRecipient) (gpgRecipients []config.UpdateKSopsRecipient) {
	for _, r := range recipients {
		if r.Type == "pgp" {
			gpgRecipients = append(gpgRecipients, r)
		}
	}

	return
}

func getGPGPublicKeysData(secretRef SecretReference, name, key string) (data string, err error) {
	value, b64encoded, err := secretRef.GetExact(name, key)

	if err != nil {
		return "", err
	}

	data = value
	if b64encoded {
		decoded, err := decodeValue(data)

		if err != nil {
			return "", err
		}

		data = string(decoded)
	}

	return data, nil
}

func importGPGKeys(secretRef SecretReference, recipients ...config.UpdateKSopsRecipient) (results []*framework.Result) {
	gpg := exec.NewGPGKeys()

	for _, gr := range selectGPGRecipientsWithPublicKey(getGPGRecipients(recipients...)) {
		sr := gr.PublicKeySecretReference
		data, err := getGPGPublicKeysData(secretRef, sr.Name, sr.Key)
		if err != nil {
			results = append(results, &framework.Result{
				Message:  err.Error(),
				Severity: framework.Warning,
			})
			continue
		}

		if _, err = gpg.ImportKey(data); err != nil {
			results = append(results, &framework.Result{
				Message:  err.Error(),
				Severity: framework.Warning,
			})
			continue
		}

		results = append(results, &framework.Result{
			Message:  fmt.Sprintf("PGP/GPG public key %s imported", gr.Recipient),
			Severity: framework.Info,
		})
	}

	return
}

func receiveGPGKeys(recipients ...config.UpdateKSopsRecipient) (results []*framework.Result) {
	gpg := exec.NewGPGKeys()
	for _, gr := range selectGPGRecipientsWithoutPublicKey(getGPGRecipients(recipients...)) {
		if _, err := gpg.ReceiveKeys(gr.Recipient); err != nil {
			results = append(results, &framework.Result{
				Message:  err.Error(),
				Severity: framework.Error,
			})
			return
		}

		results = append(results, &framework.Result{
			Message: fmt.Sprintf("PGP/GPG public key %s received from key server",
				gr.Recipient),
			Severity: framework.Info,
		})
	}

	return
}

func preloadGPGKeys(secretRef SecretReference, recipients ...config.UpdateKSopsRecipient) framework.Results {
	importResults := importGPGKeys(secretRef, recipients...)
	receiveKeysResults := receiveGPGKeys(recipients...)

	return append(importResults, receiveKeysResults...)
}

func encodeValue(value string) (enc string) {
	return base64.StdEncoding.EncodeToString([]byte(value))
}

func decodeValue(value string) (enc []byte, err error) {
	return base64.StdEncoding.DecodeString(value)
}
