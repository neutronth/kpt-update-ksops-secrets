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
			Key        string
			Value      string
			B64Encoded bool
		}{
			{
				Name:       "raw value",
				SecretName: "test",
				Key:        "test",
				Value:      "test",
				B64Encoded: false,
			},
			{
				Name:       "base64 encoded value",
				SecretName: "test",
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
		}

		for _, tc := range testCases {
			t.Run(tc.Name, func(t *testing.T) {
				output, err := NewSecretEncryptedFileNode(tc.SecretName, tc.Key, tc.Value, tc.B64Encoded, recipients...)
				if err != nil {
					t.Fatalf("Unexpected error: %v", err)
				}

				data := output.GetDataMap()
				for key, value := range data {
					if !strings.HasPrefix(value, "ENC[AES256_GCM,data:") {
						t.Errorf("Expect encrypted data, got %s=%v", key, value)
					}
				}
			})
		}
	})

	t.Run("generate encrypted files from config", func(t *testing.T) {
		uksConfig := uksConfigEncryptedSimple()
		gen := KSopsGenerator{}
		secretRef := &mockSecretReference{}
		nodes, _, err := gen.GenerateSecretEncryptedFiles([]*yaml.RNode{}, uksConfig, secretRef)
		if err != nil {
			t.Fatalf("unexpected error %v", err)
		}

		for _, node := range nodes {
			data := node.GetDataMap()
			for key, value := range data {
				if !strings.HasPrefix(value, "ENC[AES256_GCM,data:") {
					t.Errorf("Expect encrypted data, got %s=%v", key, value)
				}
			}
		}
	})
}
