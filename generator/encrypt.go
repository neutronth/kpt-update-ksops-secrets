// Copyright 2022 Neutron Soutmun <neutron@neutron.in.th>
// SPDX-License-Identifier: Apache-2.0

package generator

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/neutronth/kpt-update-ksops-secrets/config"
	"github.com/neutronth/kpt-update-ksops-secrets/exec"
	"golang.org/x/crypto/argon2"
	"sigs.k8s.io/kustomize/kyaml/fn/framework"
	"sigs.k8s.io/kustomize/kyaml/kio/kioutil"
	"sigs.k8s.io/kustomize/kyaml/yaml"
)

const (
	gcmStandardNonceSize = 12
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
		shouldSkip := false
		if err == nil && strings.HasPrefix(value, "ENC[AES256_GCM,data:") && strings.HasSuffix(value, ",type:str]") {
			shouldSkip = true
		}

		if err != nil && errors.Unwrap(err) == ErrSecretNotFound || shouldSkip {
			results = append(results, &framework.Result{
				Message:  fmt.Sprintf("Secret '%s' not found in the secrets references, encryption skipped", key),
				Severity: framework.Warning,
			})
			continue
		}
		if err != nil {
			results = append(results, &framework.Result{
				Message:  fmt.Sprintf("Secret '%s' get failure: %s", key, err),
				Severity: framework.Error,
			})
			continue
		}

		encryptedFP := secretRef.GetEncryptedFP(uksConfig.GetName(), key)
		found, encryptedOnceErr := secretFingerprintTryOpen(encryptedFP, uksConfig.GetName(), uksConfig.GetType(), key, value, b64encoded, uksConfig.Recipients...)
		if found {
			results = append(results, &framework.Result{
				Message:  fmt.Sprintf("Secret '%s' has been encrypted and not changed, encryption skipped", key),
				Severity: framework.Warning,
			})
			continue
		}

		if encryptedOnceErr != nil {
			results = append(results, &framework.Result{
				Message:  fmt.Sprintf("Secret '%s' '%s' error %s", key, uksConfig.GetName(), encryptedOnceErr.Error()),
				Severity: framework.Warning,
			})
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

		fpNode, err := NewSecretFingerprintFileNode(
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

		filename = fmt.Sprintf("%s.%s.fp.yaml", ResultFileEncryptedBase,
			normalizedKeyName(key))
		setFilename([]*yaml.RNode{fpNode}, filename)
		newNodes = append(newNodes, fpNode)
		results = append(results, &framework.Result{
			Message: fmt.Sprintf("SecretFingerprint key '%s' => %s updated",
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
		rnType, err := n.Pipe(yaml.Lookup("type"))
		if err != nil {
			return nil, err
		}

		rnType.YNode().Value = secretType
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

func NewSecretFingerprintFileNode(secretName, secretType, key, value string,
	b64encoded bool,
	recipients ...config.UpdateKSopsRecipient,
) (*yaml.RNode, error) {
	n := yaml.MustParse(`
apiVersion: config.kubernetes.io/v1alpha1
kind: SecretFingerprint
metadata:
  name: secret
type: Opaque
data:
`)

	if err := n.SetName(secretName); err != nil {
		return nil, err
	}

	if secretType != "" {
		rnType, err := n.Pipe(yaml.Lookup("type"))
		if err != nil {
			return nil, err
		}

		rnType.YNode().Value = secretType
	}

	dataValue := value
	if !b64encoded {
		dataValue = encodeValue(value)
	}

	// Add the encrypted fingerprint to support the encrypt once consideration
	fingerprintCiphertext, err := secretFingerprintSeal(secretName, secretType, key, dataValue, true, recipients...)
	if err != nil {
		return nil, err
	}

	data := map[string]string{
		key: fingerprintCiphertext,
	}
	n.SetDataMap(data)

	// The Sops render the encrypted YAML as a wide sequences indentation
	if _, err := n.Pipe(yaml.SetAnnotation(kioutil.SeqIndentAnnotation,
		string(yaml.WideSequenceStyle))); err != nil {
		return nil, err
	}

	return n, nil
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

func secretFingerprintIDKey(value, salt []byte) []byte {
	return argon2.IDKey(value, salt, 1, 46*1024, 1, 32)
}

func secretFingerprintObfuscatedValue(value string, salt []byte) []byte {
	sum := secretFingerprintIDKey([]byte(value), salt)
	mod := int(sum[31]) % 16
	if mod == 0 {
		mod = 1
	}

	truncateIndex := 16 + (int(sum[0]) % mod)
	return sum[:truncateIndex]
}

func secretFingerprintCryptoKey(secretName, secretType, key, value string, b64encoded bool,
	salt []byte,
	recipients ...config.UpdateKSopsRecipient,
) []byte {
	var buffer bytes.Buffer

	secretValue := value
	if !b64encoded {
		secretValue = encodeValue(value)
	}

	buffer.Write(secretFingerprintObfuscatedValue(secretName, salt))
	buffer.Write(secretFingerprintObfuscatedValue(secretType, salt))
	buffer.Write(secretFingerprintObfuscatedValue(key, salt))
	buffer.Write(secretFingerprintObfuscatedValue(secretValue, salt))

	for _, recipient := range recipients {
		buffer.Write(secretFingerprintObfuscatedValue(recipient.Type, salt))
		buffer.Write(secretFingerprintObfuscatedValue(recipient.Recipient, salt))
	}

	return secretFingerprintIDKey(buffer.Bytes(), salt)
}

func secretFingerprintSeal(secretName, secretType, key, value string, b64encoded bool,
	recipients ...config.UpdateKSopsRecipient,
) (string, error) {
	nonce := make([]byte, gcmStandardNonceSize)
	_, err := rand.Read(nonce)
	if err != nil {
		return "", fmt.Errorf("Random nonce error: %w", err)
	}

	secretKey := secretFingerprintCryptoKey(secretName, secretType, key, value, b64encoded, nonce, recipients...)

	block, err := aes.NewCipher(secretKey)
	if err != nil {
		return "", fmt.Errorf("AES cipher error: %w", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("GCM cipher error: %w", err)
	}

	// Data does not matter
	data := time.Now().String()

	ciphertext := aesgcm.Seal(nonce, nonce, []byte(data), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func secretFingerprintTryOpen(b64Ciphertext, secretName, secretType, key, value string, b64encoded bool,
	recipients ...config.UpdateKSopsRecipient,
) (found bool, err error) {
	if b64Ciphertext == "" {
		return false, nil
	}

	ciphertext, err := base64.StdEncoding.DecodeString(b64Ciphertext)
	if err != nil {
		return false, fmt.Errorf("Base64 decode error: %w", err)
	}

	nonce, ciphertext := ciphertext[:gcmStandardNonceSize], ciphertext[gcmStandardNonceSize:]

	secretKey := secretFingerprintCryptoKey(secretName, secretType, key, value, b64encoded, nonce, recipients...)

	block, err := aes.NewCipher(secretKey)
	if err != nil {
		return false, fmt.Errorf("AES cipher error: %w", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return false, fmt.Errorf("GCM cipher error: %w", err)
	}

	_, err = aesgcm.Open(nil, nonce, ciphertext, nil)
	return err == nil, nil
}
