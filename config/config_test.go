// Copyright 2022 Neutron Soutmun <neutron@neutron.in.th>
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"reflect"
	"testing"

	sdk "github.com/GoogleContainerTools/kpt-functions-sdk/go/fn"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestConfig(t *testing.T) {
	testCases := []struct {
		TestName       string
		FunctionConfig string
		ExpectedConfig UpdateKSopsSecrets
		ExpectedError  error
	}{
		{
			TestName: "simple",
			FunctionConfig: `
apiVersion: fn.kpt.dev/v1alpha1
kind: UpdateKSopsSecrets
metadata:
  name: test-simple
secret:
  references:
  - unencrypted-secrets
  items:
  - test
  - test2
recipients:
- type: age
  recipient: age1x7pzjx4r05ar95pulf20knx0mkscaxa0zhtqr948wza3863fvees8tzaaa
- type: pgp
  recipient: 380024A2AC1D3EBC9402BEE66E38309B4DA30118
`,
			ExpectedConfig: UpdateKSopsSecrets{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-simple",
				},
				Secret: UpdateKSopsSecretSpec{
					References: []string{"unencrypted-secrets"},
					Items:      []string{"test", "test2"},
				},
				Recipients: []UpdateKSopsRecipient{
					{
						Type:      "age",
						Recipient: "age1x7pzjx4r05ar95pulf20knx0mkscaxa0zhtqr948wza3863fvees8tzaaa",
					},
					{
						Type:      "pgp",
						Recipient: "380024A2AC1D3EBC9402BEE66E38309B4DA30118",
					},
				},
			},
		},
		{
			TestName: "annotations",
			FunctionConfig: `
apiVersion: fn.kpt.dev/v1alpha1
kind: UpdateKSopsSecrets
metadata:
  name: test-annotations
  annotations:
    test: test
    test2: test2
secret:
  references:
  - unencrypted-secrets
  items:
  - test
  - test2
recipients:
- type: age
  recipient: age1x7pzjx4r05ar95pulf20knx0mkscaxa0zhtqr948wza3863fvees8tzaaa
- type: pgp
  recipient: 380024A2AC1D3EBC9402BEE66E38309B4DA30118
`,
			ExpectedConfig: UpdateKSopsSecrets{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-annotations",
					Annotations: map[string]string{
						"test":  "test",
						"test2": "test2",
					},
				},
				Secret: UpdateKSopsSecretSpec{
					References: []string{"unencrypted-secrets"},
					Items:      []string{"test", "test2"},
				},
				Recipients: []UpdateKSopsRecipient{
					{
						Type:      "age",
						Recipient: "age1x7pzjx4r05ar95pulf20knx0mkscaxa0zhtqr948wza3863fvees8tzaaa",
					},
					{
						Type:      "pgp",
						Recipient: "380024A2AC1D3EBC9402BEE66E38309B4DA30118",
					},
				},
			},
		},
		{
			TestName: "labels",
			FunctionConfig: `
apiVersion: fn.kpt.dev/v1alpha1
kind: UpdateKSopsSecrets
metadata:
  name: test-labels
  labels:
    test: test
    test2: test2
secret:
  references:
  - unencrypted-secrets
  items:
  - test
  - test2
recipients:
- type: age
  recipient: age1x7pzjx4r05ar95pulf20knx0mkscaxa0zhtqr948wza3863fvees8tzaaa
- type: pgp
  recipient: 380024A2AC1D3EBC9402BEE66E38309B4DA30118
`,
			ExpectedConfig: UpdateKSopsSecrets{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-labels",
					Labels: map[string]string{
						"test":  "test",
						"test2": "test2",
					},
				},
				Secret: UpdateKSopsSecretSpec{
					References: []string{"unencrypted-secrets"},
					Items:      []string{"test", "test2"},
				},
				Recipients: []UpdateKSopsRecipient{
					{
						Type:      "age",
						Recipient: "age1x7pzjx4r05ar95pulf20knx0mkscaxa0zhtqr948wza3863fvees8tzaaa",
					},
					{
						Type:      "pgp",
						Recipient: "380024A2AC1D3EBC9402BEE66E38309B4DA30118",
					},
				},
			},
		},
		{
			TestName: "annotations and labels",
			FunctionConfig: `
apiVersion: fn.kpt.dev/v1alpha1
kind: UpdateKSopsSecrets
metadata:
  name: test-annotations-labels
  annotations:
    test: test
    test2: test2
  labels:
    test: test
    test2: test2
secret:
  references:
  - unencrypted-secrets
  items:
  - test
  - test2
recipients:
- type: age
  recipient: age1x7pzjx4r05ar95pulf20knx0mkscaxa0zhtqr948wza3863fvees8tzaaa
- type: pgp
  recipient: 380024A2AC1D3EBC9402BEE66E38309B4DA30118
`,
			ExpectedConfig: UpdateKSopsSecrets{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-annotations-labels",
					Annotations: map[string]string{
						"test":  "test",
						"test2": "test2",
					},
					Labels: map[string]string{
						"test":  "test",
						"test2": "test2",
					},
				},
				Secret: UpdateKSopsSecretSpec{
					References: []string{"unencrypted-secrets"},
					Items:      []string{"test", "test2"},
				},
				Recipients: []UpdateKSopsRecipient{
					{
						Type:      "age",
						Recipient: "age1x7pzjx4r05ar95pulf20knx0mkscaxa0zhtqr948wza3863fvees8tzaaa",
					},
					{
						Type:      "pgp",
						Recipient: "380024A2AC1D3EBC9402BEE66E38309B4DA30118",
					},
				},
			},
		},
		{
			TestName: "multiple secrets references",
			FunctionConfig: `
apiVersion: fn.kpt.dev/v1alpha1
kind: UpdateKSopsSecrets
metadata:
  name: test-multiple-secrets-references
secret:
  references:
  - unencrypted-secrets
  - unencrypted-secrets-config-txt
  items:
  - test
  - test2
  - config.txt
recipients:
- type: age
  recipient: age1x7pzjx4r05ar95pulf20knx0mkscaxa0zhtqr948wza3863fvees8tzaaa
- type: pgp
  recipient: 380024A2AC1D3EBC9402BEE66E38309B4DA30118
`,
			ExpectedConfig: UpdateKSopsSecrets{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-multiple-secrets-references",
				},
				Secret: UpdateKSopsSecretSpec{
					References: []string{"unencrypted-secrets", "unencrypted-secrets-config-txt"},
					Items:      []string{"test", "test2", "config.txt"},
				},
				Recipients: []UpdateKSopsRecipient{
					{
						Type:      "age",
						Recipient: "age1x7pzjx4r05ar95pulf20knx0mkscaxa0zhtqr948wza3863fvees8tzaaa",
					},
					{
						Type:      "pgp",
						Recipient: "380024A2AC1D3EBC9402BEE66E38309B4DA30118",
					},
				},
			},
		},
		{
			TestName: "other secret type",
			FunctionConfig: `
apiVersion: fn.kpt.dev/v1alpha1
kind: UpdateKSopsSecrets
metadata:
  name: test-other-secret-type
secret:
  type: kubernetes.io/dockerconfigjson
  references:
  - unencrypted-secrets
  items:
  - .dockerconfigjson
recipients:
- type: age
  recipient: age1x7pzjx4r05ar95pulf20knx0mkscaxa0zhtqr948wza3863fvees8tzaaa
- type: pgp
  recipient: 380024A2AC1D3EBC9402BEE66E38309B4DA30118
`,
			ExpectedConfig: UpdateKSopsSecrets{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-other-secret-type",
				},
				Secret: UpdateKSopsSecretSpec{
					Type:       "kubernetes.io/dockerconfigjson",
					References: []string{"unencrypted-secrets"},
					Items:      []string{".dockerconfigjson"},
				},
				Recipients: []UpdateKSopsRecipient{
					{
						Type:      "age",
						Recipient: "age1x7pzjx4r05ar95pulf20knx0mkscaxa0zhtqr948wza3863fvees8tzaaa",
					},
					{
						Type:      "pgp",
						Recipient: "380024A2AC1D3EBC9402BEE66E38309B4DA30118",
					},
				},
			},
		},
		{
			TestName: "PGP/GPG public key preload",
			FunctionConfig: `
apiVersion: fn.kpt.dev/v1alpha1
kind: UpdateKSopsSecrets
metadata:
  name: test-pgp-gpg-public-key-preload
secret:
  type: kubernetes.io/dockerconfigjson
  references:
  - unencrypted-secrets
  items:
  - .dockerconfigjson
recipients:
- type: age
  recipient: age1x7pzjx4r05ar95pulf20knx0mkscaxa0zhtqr948wza3863fvees8tzaaa
- type: pgp
  recipient: 380024A2AC1D3EBC9402BEE66E38309B4DA30118
  publicKeySecretReference:
    name: gpg-publickeys
    key: 380024A2AC1D3EBC9402BEE66E38309B4DA30118.gpg
`,
			ExpectedConfig: UpdateKSopsSecrets{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-pgp-gpg-public-key-preload",
				},
				Secret: UpdateKSopsSecretSpec{
					Type:       "kubernetes.io/dockerconfigjson",
					References: []string{"unencrypted-secrets"},
					Items:      []string{".dockerconfigjson"},
				},
				Recipients: []UpdateKSopsRecipient{
					{
						Type:      "age",
						Recipient: "age1x7pzjx4r05ar95pulf20knx0mkscaxa0zhtqr948wza3863fvees8tzaaa",
					},
					{
						Type:      "pgp",
						Recipient: "380024A2AC1D3EBC9402BEE66E38309B4DA30118",
						PublicKeySecretReference: UpdateKSopsGPGPublicKeyReference{
							Name: "gpg-publickeys",
							Key:  "380024A2AC1D3EBC9402BEE66E38309B4DA30118.gpg",
						},
					},
				},
			},
		},
		{
			TestName: "invalid functionConfig kind",
			FunctionConfig: `
apiVersion: v1 
kind: ConfigMap 
metadata:
  name: test-invalid-function-config-kind
data:
  test: test
  test2: test2
`,
			ExpectedConfig: UpdateKSopsSecrets{},
			ExpectedError:  fmt.Errorf("the functionConfig must be a %s", fnConfigKind),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.TestName, func(t *testing.T) {
			koConfig, err := sdk.ParseKubeObject([]byte(tc.FunctionConfig))
			if err != nil {
				t.Fatalf("Unexpected error, %v", err)
			}

			uks := UpdateKSopsSecrets{}
			err = uks.Config(koConfig)

			if err == nil {
				if !reflect.DeepEqual(uks, tc.ExpectedConfig) {
					t.Errorf("Expected\n%#v,\ngot \n%#v", tc.ExpectedConfig, uks)
				}
			} else {
				if err.Error() != tc.ExpectedError.Error() {
					t.Fatalf("Unexpected error, %v", err)
				}
			}
		})
	}
}
