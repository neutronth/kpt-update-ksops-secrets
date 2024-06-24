// Copyright 2022 Neutron Soutmun <neutron@neutron.in.th>
// SPDX-License-Identifier: Apache-2.0

package generator

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/neutronth/kpt-update-ksops-secrets/config"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/kustomize/kyaml/yaml"
)

func uksConfigEncryptedSimple() *config.UpdateKSopsSecrets {
	return &config.UpdateKSopsSecrets{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test",
		},
		Secret: config.UpdateKSopsSecretSpec{
			References: []string{"unencrypted-secrets"},
			Items:      []string{"test", "test2", "UPPER_CASE"},
		},
		Recipients: []config.UpdateKSopsRecipient{
			{
				Type:      "age",
				Recipient: "age1x7pzjx4r05ar95pulf20knx0mkscaxa0zhtqr948wza3863fvees8tzaaa",
			},
			{
				Type:      "pgp",
				Recipient: "F532DA10E563EE84440977A19D0470BDA6CDC457",
			},
			{
				Type:      "pgp",
				Recipient: "6DBFDBA2ABED52FDA0E52B960125569F5334AAFA",
				PublicKeySecretReference: config.UpdateKSopsGPGPublicKeyReference{
					Name: "gpg-publickeys",
					Key:  "6DBFDBA2ABED52FDA0E52B960125569F5334AAFA.gpg",
				},
			},
		},
	}
}

type mockSecretReference struct{}

func (sr *mockSecretReference) GetExact(name, key string) (value string, b64encoded bool, err error) {
	value = "T0s="
	b64encoded = true
	err = nil
	return
}

func (sr *mockSecretReference) Get(key string) (value string, b64encoded bool, err error) {
	switch key {
	case "test":
		value = "dGVzdA=="
		b64encoded = true
		err = nil
	case "test2":
		value = "test2"
		b64encoded = false
		err = nil
	case "UPPER_CASE":
		value = "upper_case"
		b64encoded = false
		err = nil
	default:
		err = fmt.Errorf("Key %s not found in the secret reference", key)
	}
	return
}

func (sr *mockSecretReference) GetEncryptedFP(name, key string) string {
	return ""
}

func TestGPGRecipients(t *testing.T) {
	uksConfig := uksConfigEncryptedSimple()

	t.Run("get GPG recipients", func(t *testing.T) {
		expected := []config.UpdateKSopsRecipient{
			uksConfig.Recipients[1],
			uksConfig.Recipients[2],
		}

		actual := getGPGRecipients(uksConfig.Recipients...)

		if !reflect.DeepEqual(expected, actual) {
			t.Errorf("Expect\n%#v\n,got\n%#v", expected, actual)
		}
	})

	t.Run("select GPG recipients without public key data", func(t *testing.T) {
		expected := []config.UpdateKSopsRecipient{
			uksConfig.Recipients[1],
		}

		actual := selectGPGRecipientsWithoutPublicKey(getGPGRecipients(uksConfig.Recipients...))

		if !reflect.DeepEqual(expected, actual) {
			t.Errorf("Expect\n%#v\n,got\n%#v", expected, actual)
		}
	})

	t.Run("select GPG recipients with public key data", func(t *testing.T) {
		expected := []config.UpdateKSopsRecipient{
			uksConfig.Recipients[2],
		}

		actual := selectGPGRecipientsWithPublicKey(getGPGRecipients(uksConfig.Recipients...))

		if !reflect.DeepEqual(expected, actual) {
			t.Errorf("Expect\n%#v\n,got\n%#v", expected, actual)
		}
	})

	t.Run("get GPG recipient public key data", func(t *testing.T) {
		expected := "OK"
		secretRef := &mockSecretReference{}
		actual, _ := getGPGPublicKeysData(secretRef, "test", "test")

		if expected != actual {
			t.Errorf("Expect %s,got %s", expected, actual)
		}
	})
}

func TestGenerateSecretEncryptedFiles(t *testing.T) {
	t.Run("new encrypted file node", func(t *testing.T) {
		testCases := []struct {
			Name       string
			SecretName string
			SecretType string
			Key        string
			Value      string
			B64Encoded bool
		}{
			{
				Name:       "raw value",
				SecretName: "test",
				SecretType: "Opaque",
				Key:        "test",
				Value:      "test",
				B64Encoded: false,
			},
			{
				Name:       "base64 encoded value",
				SecretName: "test",
				SecretType: "Opaque",
				Key:        "test",
				Value:      "dGVzdA==",
				B64Encoded: true,
			},
			{
				Name:       "other scret type",
				SecretName: "test",
				SecretType: "kubernetes.io/dockerconfigjson",
				Key:        "test",
				Value:      "dGVzdA==",
				B64Encoded: true,
			},
		}

		recipients := []config.UpdateKSopsRecipient{
			{
				Type:      "age",
				Recipient: "age1x7pzjx4r05ar95pulf20knx0mkscaxa0zhtqr948wza3863fvees8tzaaa",
			},
			{
				Type:      "pgp",
				Recipient: "F532DA10E563EE84440977A19D0470BDA6CDC457",
			},
			{
				Type:      "pgp",
				Recipient: "6DBFDBA2ABED52FDA0E52B960125569F5334AAFA",
				PublicKeySecretReference: config.UpdateKSopsGPGPublicKeyReference{
					Name: "gpg-publickeys",
					Key:  "6DBFDBA2ABED52FDA0E52B960125569F5334AAFA.gpg",
				},
			},
		}

		for _, tc := range testCases {
			t.Run(tc.Name, func(t *testing.T) {
				output, err := NewSecretEncryptedFileNode(tc.SecretName, tc.SecretType,
					tc.Key, tc.Value, tc.B64Encoded, recipients...)
				if err != nil {
					t.Fatalf("Unexpected error: %v", err)
				}

				n, err := output.Pipe(yaml.Lookup("type"))
				if err != nil {
					t.Errorf("Expect encrypted secret type exist, got none")
				}

				actualSecretType := n.YNode().Value
				if actualSecretType != tc.SecretType {
					t.Errorf("Expect encrypted secret type %s, got %s", tc.SecretType, actualSecretType)
				}

				data := output.GetDataMap()
				for key, value := range data {
					if !strings.HasPrefix(value, "ENC[AES256_GCM,data:") {
						t.Errorf("Expect encrypted data, got %s=%v", key, value)
					}
				}

				if err := assertRecipients(output, recipients); err != nil {
					t.Errorf("Expect encrypted for all recipients, got error %s", err)
				}
			})
		}
	})

	t.Run("generate encrypted files from config", func(t *testing.T) {
		uksConfig := uksConfigEncryptedSimple()
		gen := KSopsGenerator{}
		secretRef := &mockSecretReference{}
		nodes, results := gen.GenerateSecretEncryptedFiles([]*yaml.RNode{}, uksConfig, secretRef)
		if results.ExitCode() != 0 {
			t.Fatalf("unexpected error:\n %s", results.Error())
		}

		for _, node := range nodes {
			data := node.GetDataMap()
			for key, value := range data {
				if !strings.HasPrefix(value, "ENC[AES256_GCM,data:") {
					t.Errorf("Expect encrypted data, got %s=%v", key, value)
				}
			}

			if err := assertRecipients(node, uksConfig.Recipients); err != nil {
				t.Errorf("Expect encrypted for all recipients, got error %s", err)
			}
		}
	})
}

func TestSecretFingerprint(t *testing.T) {
	t.Run("fingerprint seal and try open", func(t *testing.T) {
		recipients := []config.UpdateKSopsRecipient{
			{
				Type:      "age",
				Recipient: "age1x7pzjx4r05ar95pulf20knx0mkscaxa0zhtqr948wza3863fvees8tzaaa",
			},
			{
				Type:      "pgp",
				Recipient: "F532DA10E563EE84440977A19D0470BDA6CDC457",
			},
			{
				Type:      "pgp",
				Recipient: "6DBFDBA2ABED52FDA0E52B960125569F5334AAFA",
				PublicKeySecretReference: config.UpdateKSopsGPGPublicKeyReference{
					Name: "gpg-publickeys",
					Key:  "6DBFDBA2ABED52FDA0E52B960125569F5334AAFA.gpg",
				},
			},
		}

		fp, err := secretFingerprintSeal("secret-name", "Opaque", "test", "secret", false, recipients...)
		if err != nil {
			t.Errorf("Expect no errors got %v", err)
		}

		if fp == "" {
			t.Errorf("Expect non-empty sealed fingerprint, got %s", fp)
		}

		err = secretFingerprintTryOpen(fp, "secret-name", "Opaque", "test", "secret", false, recipients...)
		if err != nil {
			t.Errorf("Expect no errors got %v", err)
		}

		err = secretFingerprintTryOpen(fp, "secret-name", "Opaque", "test", "c2VjcmV0", true, recipients...)
		if err != nil {
			t.Errorf("Expect no errors got %v", err)
		}

		err = secretFingerprintTryOpen(fp, "secret-name", "Opaque", "test", "invalidsecret", false, recipients...)
		if err == nil {
			t.Errorf("Expect errors as invalid/changed secret provided but got %v", err)
		}
	})

	t.Run("generate encrypted files with encrypted_fp added", func(t *testing.T) {
		uksConfig := uksConfigEncryptedSimple()
		gen := KSopsGenerator{}
		secretRef := &mockSecretReference{}
		nodes, results := gen.GenerateSecretEncryptedFiles([]*yaml.RNode{}, uksConfig, secretRef)
		if results.ExitCode() != 0 {
			t.Fatalf("unexpected error:\n %s", results.Error())
		}

		for _, node := range nodes {
			data, err := node.GetFieldValue("sops.encrypted_fp")
			if err != nil {
				t.Fatalf("lookup for sops.encrypted_fp error: %s", err.Error())
			}

			if len(data.(map[string]interface{})) == 0 {
				t.Error("Expect encrypted_fp field exists, got none")
			}
		}
	})
}

func encryptedRecipients(output *yaml.RNode) map[string]bool {
	recipients := make(map[string]bool, 0)
	noRecipients := map[string]bool{}

	sops, err := output.GetFieldValue("sops")
	if err != nil {
		return noRecipients
	}

	sopsValue, ok := sops.(map[string]interface{})
	if !ok {
		return noRecipients
	}

	for recipientType, val := range sopsValue {
		if sopsMetadataList, ok := val.([]interface{}); ok {
			for _, sopsMetadata := range sopsMetadataList {
				if data, ok := sopsMetadata.(map[string]interface{}); ok {
					switch recipientType {
					case "age":
						recipients[fmt.Sprintf("%s:%s", recipientType, data["recipient"])] = true
					case "pgp":
						recipients[fmt.Sprintf("%s:%s", recipientType, data["fp"])] = true
					}
				}
			}
		}
	}

	return recipients
}

func assertRecipients(output *yaml.RNode, recipients []config.UpdateKSopsRecipient) error {
	encRecipients := encryptedRecipients(output)

	for _, recipient := range recipients {
		key := fmt.Sprintf("%s:%s", recipient.Type, recipient.Recipient)
		if ok := encRecipients[key]; !ok {
			return fmt.Errorf("Encrypted for recipient '%s:%s' not found", recipient.Type, recipient.Recipient)
		}
	}

	return nil
}
