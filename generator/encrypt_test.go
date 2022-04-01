// Copyright 2022 Neutron Soutmun <neutron@neutron.in.th>
// SPDX-License-Identifier: Apache-2.0

package generator

import (
	"fmt"
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
		},
	}
}

type mockSecretReference struct{}

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
