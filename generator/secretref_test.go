// Copyright 2022 Neutron Soutmun <neutron@neutron.in.th>
// SPDX-License-Identifier: Apache-2.0

package generator

import (
	"testing"

	"github.com/neutronth/kpt-update-ksops-secrets/config"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/kustomize/kyaml/yaml"
)

func uksConfigSecretReferenceSimple() *config.UpdateKSopsSecrets {
	return &config.UpdateKSopsSecrets{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test",
		},
		Secret: config.UpdateKSopsSecretSpec{
			References: []string{"unencrypted-secrets", "unencrypted-secrets-config-txt"},
			Items:      []string{"test", "test2", "UPPER_CASE", "config.txt"},
		},
		Recipients: []config.UpdateKSopsRecipient{},
	}
}

func TestSecretReference(t *testing.T) {
	var secretlist []*yaml.RNode

	unencryptedSecrets := []string{`
apiVersion: v1
kind: Secret
metadata:
  name: unencrypted-secrets
type: Opaque
dataString:
  test2: test2
  UPPER_CASE: upper_case
data:
  test: dGVzdA==
`, `
apiVersion: v1
kind: Secret
metadata:
  name: unencrypted-secrets-config-txt
type: Opaque
data:
  config.txt: Y29uZmlnLnR4dAo=
`}

	for _, ref := range unencryptedSecrets {
		secretlist = append(secretlist, yaml.MustParse(ref))
	}

	uksConfig := uksConfigSecretReferenceSimple()
	secretRef := newSecretReference(secretlist, uksConfig)

	testCases := []struct {
		Name               string
		Key                string
		ExpectedValue      string
		ExpectedB64Encoded bool
		ExpectedError      error
	}{
		{
			Name:               "get test",
			Key:                "test",
			ExpectedValue:      "dGVzdA==",
			ExpectedB64Encoded: true,
			ExpectedError:      nil,
		},
		{
			Name:               "get test2",
			Key:                "test2",
			ExpectedValue:      "test2",
			ExpectedB64Encoded: false,
			ExpectedError:      nil,
		},
		{
			Name:               "get UPPER_CASE",
			Key:                "UPPER_CASE",
			ExpectedValue:      "upper_case",
			ExpectedB64Encoded: false,
			ExpectedError:      nil,
		},
		{
			Name:               "get config.txt",
			Key:                "config.txt",
			ExpectedValue:      "Y29uZmlnLnR4dAo=",
			ExpectedB64Encoded: true,
			ExpectedError:      nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			value, b64encoded, err := secretRef.Get(tc.Key)
			if err != tc.ExpectedError {
				t.Fatalf("Expect %v, got %v", tc.ExpectedError, err)
			}

			if value != tc.ExpectedValue {
				t.Errorf("Expect %v, got %v", tc.ExpectedValue, value)
			}

			if b64encoded != tc.ExpectedB64Encoded {
				t.Errorf("Expect %v, got %v", tc.ExpectedB64Encoded, b64encoded)
			}
		})
	}
}
