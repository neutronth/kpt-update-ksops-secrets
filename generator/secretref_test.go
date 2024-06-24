// Copyright 2022 Neutron Soutmun <neutron@neutron.in.th>
// SPDX-License-Identifier: Apache-2.0

package generator

import (
	"errors"
	"reflect"
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
		Recipients: []config.UpdateKSopsRecipient{
			{
				Type:      "age",
				Recipient: "age1x7pzjx4r05ar95pulf20knx0mkscaxa0zhtqr948wza3863fvees8tzaaa",
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

func uksConfigSecretReferenceSameName() *config.UpdateKSopsSecrets {
	return &config.UpdateKSopsSecrets{
		ObjectMeta: metav1.ObjectMeta{
			Name: "samename",
		},
		Secret: config.UpdateKSopsSecretSpec{
			References: []string{"unencrypted-secrets", "samename"},
			Items:      []string{"unencrypted", "samename"},
		},
		Recipients: []config.UpdateKSopsRecipient{
			{
				Type:      "age",
				Recipient: "age1x7pzjx4r05ar95pulf20knx0mkscaxa0zhtqr948wza3863fvees8tzaaa",
			},
		},
	}
}

func uksConfigSecretFingerprint() *config.UpdateKSopsSecrets {
	return &config.UpdateKSopsSecrets{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-update-ksops-secrets",
		},
		Secret: config.UpdateKSopsSecretSpec{
			References: []string{"test-update-ksops-secrets"},
			Items:      []string{"test"},
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
				Recipient: "380024A2AC1D3EBC9402BEE66E38309B4DA30118",
				PublicKeySecretReference: config.UpdateKSopsGPGPublicKeyReference{
					Name: "gpg-publickeys",
					Key:  "380024A2AC1D3EBC9402BEE66E38309B4DA30118.gpg",
				},
			},
		},
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
stringData:
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
`, `
apiVersion: v1
kind: Secret
metadata:
  name: gpg-publickeys
type: Opaque
data:
  380024A2AC1D3EBC9402BEE66E38309B4DA30118.gpg: LS0tLS1CRUdJTiBQR1AgUFVCTElDIEtFWSBCTE9DSy0tLS0tCgptRE1FWWthb21SWUpLd1lCQkFIYVJ3OEJBUWRBalBxK1NNTUptbmVyY1piUlZ0a3hJaXdGTXlWKzBxYWc4QnhuCjdVbGpmeWkwSFV0d2RDQlZjR1JoZEdVZ1MxTlBVRk1nVTJWamNtVjBjeUJVWlhOMGlKUUVFeFlLQUR3V0lRUTQKQUNTaXJCMCt2SlFDdnVadU9EQ2JUYU1CR0FVQ1lrYW9tUUliQXdVTENRZ0hBZ01pQWdFR0ZRb0pDQXNDQkJZQwpBd0VDSGdjQ0Y0QUFDZ2tRYmpnd20wMmpBUmlWZHdFQXF5Y2F1K21rdkMvSW9ZZVY0eWpoUGN2eTVoNTVuamJ6ClNQeHhua3NHZERvQS8zWGRFYitsQTlLdFdPSTltQTJKSXpRQkNxSWRNRHZWOFo4eDZyUDBnZ0VJdURnRVlrYW8KbVJJS0t3WUJCQUdYVlFFRkFRRUhRR3plVWJWTzdCSXlORU5iUVdZMGdwQWpCTERwdnpKSzJSb2syNVpUUFp0MQpBd0VJQjRoNEJCZ1dDZ0FnRmlFRU9BQWtvcXdkUHJ5VUFyN21iamd3bTAyakFSZ0ZBbUpHcUprQ0d3d0FDZ2tRCmJqZ3dtMDJqQVJpb1F3RUF6QlAwQ0REdlkwYkdLa2VZZkpmWVdsTHBzRG9QM3FLamdpN3YyMlpUV0NjQkFKV2oKN1o0T0toVGRLSlRwWjRaei80UzBoT0pFeXJiMkVWdTJhTU52cVVRQQo9WEtwOAotLS0tLUVORCBQR1AgUFVCTElDIEtFWSBCTE9DSy0tLS0tCg==
`}

	for _, ref := range unencryptedSecrets {
		secretlist = append(secretlist, yaml.MustParse(ref))
	}

	uksConfig := uksConfigSecretReferenceSimple()
	secretRef := newSecretReference(secretlist, uksConfig)

	t.Run("list secret refs from config", func(t *testing.T) {
		expected := []string{
			"unencrypted-secrets",
			"unencrypted-secrets-config-txt",
			"gpg-publickeys",
		}

		list := listSecretRefsFromConfig(uksConfig)

		if !reflect.DeepEqual(expected, list) {
			t.Errorf("Expect %#v, got %#v", expected, list)
		}
	})

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

	testExactMatchCases := []struct {
		Name               string
		SecretName         string
		Key                string
		ExpectedValue      string
		ExpectedB64Encoded bool
		ExpectedError      error
	}{
		{
			Name:               "get exact match",
			Key:                "380024A2AC1D3EBC9402BEE66E38309B4DA30118.gpg",
			ExpectedValue:      "LS0tLS1CRUdJTiBQR1AgUFVCTElDIEtFWSBCTE9DSy0tLS0tCgptRE1FWWthb21SWUpLd1lCQkFIYVJ3OEJBUWRBalBxK1NNTUptbmVyY1piUlZ0a3hJaXdGTXlWKzBxYWc4QnhuCjdVbGpmeWkwSFV0d2RDQlZjR1JoZEdVZ1MxTlBVRk1nVTJWamNtVjBjeUJVWlhOMGlKUUVFeFlLQUR3V0lRUTQKQUNTaXJCMCt2SlFDdnVadU9EQ2JUYU1CR0FVQ1lrYW9tUUliQXdVTENRZ0hBZ01pQWdFR0ZRb0pDQXNDQkJZQwpBd0VDSGdjQ0Y0QUFDZ2tRYmpnd20wMmpBUmlWZHdFQXF5Y2F1K21rdkMvSW9ZZVY0eWpoUGN2eTVoNTVuamJ6ClNQeHhua3NHZERvQS8zWGRFYitsQTlLdFdPSTltQTJKSXpRQkNxSWRNRHZWOFo4eDZyUDBnZ0VJdURnRVlrYW8KbVJJS0t3WUJCQUdYVlFFRkFRRUhRR3plVWJWTzdCSXlORU5iUVdZMGdwQWpCTERwdnpKSzJSb2syNVpUUFp0MQpBd0VJQjRoNEJCZ1dDZ0FnRmlFRU9BQWtvcXdkUHJ5VUFyN21iamd3bTAyakFSZ0ZBbUpHcUprQ0d3d0FDZ2tRCmJqZ3dtMDJqQVJpb1F3RUF6QlAwQ0REdlkwYkdLa2VZZkpmWVdsTHBzRG9QM3FLamdpN3YyMlpUV0NjQkFKV2oKN1o0T0toVGRLSlRwWjRaei80UzBoT0pFeXJiMkVWdTJhTU52cVVRQQo9WEtwOAotLS0tLUVORCBQR1AgUFVCTElDIEtFWSBCTE9DSy0tLS0tCg==",
			ExpectedB64Encoded: true,
			ExpectedError:      nil,
		},
	}

	for _, tc := range testExactMatchCases {
		t.Run(tc.Name, func(t *testing.T) {
			value, b64encoded, err := secretRef.GetExact(tc.SecretName, tc.Key)

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

func TestSecretReferenceSameName(t *testing.T) {
	var secretlist []*yaml.RNode

	mixedSecrets := []string{`
apiVersion: v1
kind: Secret
metadata:
  name: unencrypted-secrets
type: Opaque
stringData:
  unencrypted: test
`, `
apiVersion: v1
kind: Secret
metadata:
  name: samename
  annotations:
    internal.config.kubernetes.io/path: generated/secrets.samename_samename.enc.yaml
type: Opaque
data:
  samename: ENC[AES256_GCM,data:ICJgw+sCHuU=,iv:xkWe+zgtT4f4nVKuXvy0uNwu1fVqmq6sCcODFWO3ofs=,tag:yHE6jwn9h69lQ0GOgCNrew==,type:str]
`}

	mixedSecretsWithOverride := []string{`
apiVersion: v1
kind: Secret
metadata:
  name: unencrypted-secrets
type: Opaque
stringData:
  unencrypted: test
`, `
apiVersion: v1
kind: Secret
metadata:
  name: samename
  annotations:
    internal.config.kubernetes.io/path: generated/secrets.samename_samename.enc.yaml
type: Opaque
data:
  samename: ENC[AES256_GCM,data:ICJgw+sCHuU=,iv:xkWe+zgtT4f4nVKuXvy0uNwu1fVqmq6sCcODFWO3ofs=,tag:yHE6jwn9h69lQ0GOgCNrew==,type:str]
`, `
apiVersion: v1
kind: Secret
metadata:
  name: samename
type: Opaque
stringData:
  samename: override
`,
	}

	testCases := []struct {
		Name               string
		Key                string
		ExpectedValue      string
		ExpectedB64Encoded bool
		ExpectedError      error
		SecretsSource      []string
	}{
		{
			Name:               "get unencrypted",
			Key:                "unencrypted",
			ExpectedValue:      "test",
			ExpectedB64Encoded: false,
			ExpectedError:      nil,
			SecretsSource:      mixedSecrets,
		},
		{
			Name:               "get samename",
			Key:                "samename",
			ExpectedValue:      "",
			ExpectedB64Encoded: false,
			ExpectedError:      ErrSecretNotFound,
			SecretsSource:      mixedSecrets,
		},
		{
			Name:               "get samename (override)",
			Key:                "samename",
			ExpectedValue:      "override",
			ExpectedB64Encoded: false,
			ExpectedError:      nil,
			SecretsSource:      mixedSecretsWithOverride,
		},
	}

	for _, tc := range testCases {
		for _, ref := range tc.SecretsSource {
			secretlist = append(secretlist, yaml.MustParse(ref))
		}

		uksConfig := uksConfigSecretReferenceSameName()
		secretRef := newSecretReference(secretlist, uksConfig)

		t.Run(tc.Name, func(t *testing.T) {
			value, b64encoded, err := secretRef.Get(tc.Key)

			if !errors.Is(err, tc.ExpectedError) {
				t.Fatalf("Expect error %v, got %v", tc.ExpectedError, err)
			}

			if value != tc.ExpectedValue {
				t.Errorf("Expect value %v, got %v", tc.ExpectedValue, value)
			}

			if b64encoded != tc.ExpectedB64Encoded {
				t.Errorf("Expect base64 %v, got %v", tc.ExpectedB64Encoded, b64encoded)
			}
		})
	}
}

func TestSecretReferenceUnencodedBase64DataBlock(t *testing.T) {
	data := `
apiVersion: v1
kind: Secret
metadata:
  name: unencoded-b64-data
type: Opaque
data:
  KEY: plaintext
`
	secretlist := []*yaml.RNode{yaml.MustParse(data)}
	uksConfig := uksConfigSecretReferenceSameName()
	uksConfig.Secret.References = []string{"unencoded-b64-data"}
	uksConfig.Secret.Items = []string{"KEY"}

	secretRef := newSecretReference(secretlist, uksConfig)
	v, encoded, err := secretRef.Get("KEY")

	if err == nil {
		t.Fatal("Expected error, got nil")
	}
	if errors.Unwrap(err) == ErrSecretNotFound {
		t.Fatal("Expected err is another error not ErrSecretNotFound.")
	}
	if v != "" {
		t.Fatalf("Expected value to be empty string, got %s", v)
	}
	if encoded {
		t.Fatal("Value is unencoded (false), got true")
	}
}

func TestSecretEncryptedFingerprint(t *testing.T) {
	var secretlist []*yaml.RNode

	secrets := []string{`
apiVersion: v1
kind: Secret
metadata:
  name: test-update-ksops-secrets
type: Opaque
stringData:
  test: test
`, `
apiVersion: v1
kind: Secret
metadata:
  name: test-update-ksops-secrets
  annotations:
    kustomize.config.k8s.io/behavior: merge
    internal.config.kubernetes.io/path: generated/secrets.test-update-ksops-secrets_test.enc.yaml
type: Opaque
data:
  test: ENC[AES256_GCM,data:IUJvrFsCOzM=,iv:WGt9lQnO1VNbFkMN26EDacHUF0xQNvmDZfzPjzp6S8Q=,tag:Y56ZVMB9MIlxv1B/t2VPVQ==,type:str]
sops:
  encrypted_fp:
    test: +OSdrYZqZjj3uQ68dhoHpKqAMCe8gMR4PyDtQ5sVdhViHh6rbhd4mwZeZ5uWFQjkY7S+ISp4wq9ioNmwATnI53EtuZajI5C19oUmCj8HEYobVw==
`}

	for _, ref := range secrets {
		secretlist = append(secretlist, yaml.MustParse(ref))
	}

	uksConfig := uksConfigSecretFingerprint()
	secretRef := newSecretReference(secretlist, uksConfig)

	fp := secretRef.GetEncryptedFP("test-update-ksops-secrets", "test")
	expected := "+OSdrYZqZjj3uQ68dhoHpKqAMCe8gMR4PyDtQ5sVdhViHh6rbhd4mwZeZ5uWFQjkY7S+ISp4wq9ioNmwATnI53EtuZajI5C19oUmCj8HEYobVw=="

	if fp != expected {
		t.Errorf("Expect fingerprint %s, got %s", expected, fp)
	}
}
