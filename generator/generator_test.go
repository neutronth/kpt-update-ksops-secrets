// Copyright 2022 Neutron Soutmun <neutron@neutron.in.th>
// SPDX-License-Identifier: Apache-2.0

package generator

import (
	"testing"

	"github.com/neutronth/kpt-update-ksops-secrets/config"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/kustomize/kyaml/yaml"
	yaml2 "sigs.k8s.io/yaml"
)

func uksConfigSimple() *config.UpdateKSopsSecrets {
	return &config.UpdateKSopsSecrets{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test",
		},
		Secret: config.UpdateKSopsSecretSpec{
			References: []string{"unencrypted-secrets"},
			Items:      []string{"test", "test2", "UPPER_CASE"},
		},
	}
}

func uksConfigAnnotations() *config.UpdateKSopsSecrets {
	return &config.UpdateKSopsSecrets{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test",
			Annotations: map[string]string{
				"test":  "test",
				"test2": "test2",
			},
		},
		Secret: config.UpdateKSopsSecretSpec{
			References: []string{"unencrypted-secrets"},
			Items:      []string{"test", "test2"},
		},
	}
}

func uksConfigLabels() *config.UpdateKSopsSecrets {
	return &config.UpdateKSopsSecrets{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test",
			Labels: map[string]string{
				"test":  "test",
				"test2": "test2",
			},
		},
		Secret: config.UpdateKSopsSecretSpec{
			References: []string{"unencrypted-secrets"},
			Items:      []string{"test", "test2"},
		},
	}
}

func uksConfigAnnotationsLabels() *config.UpdateKSopsSecrets {
	return &config.UpdateKSopsSecrets{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test",
			Annotations: map[string]string{
				"test":  "test",
				"test2": "test2",
			},
			Labels: map[string]string{
				"test":  "test",
				"test2": "test2",
			},
		},
		Secret: config.UpdateKSopsSecretSpec{
			References: []string{"unencrypted-secrets"},
			Items:      []string{"test", "test2"},
		},
	}
}

func uksConfigOtherSecretType() *config.UpdateKSopsSecrets {
	return &config.UpdateKSopsSecrets{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test",
			Annotations: map[string]string{
				"test":  "test",
				"test2": "test2",
			},
			Labels: map[string]string{
				"test":  "test",
				"test2": "test2",
			},
		},
		Secret: config.UpdateKSopsSecretSpec{
			Type:       "kubernetes.io/dockerconfigjson",
			References: []string{"unencrypted-secrets"},
			Items:      []string{".dockerconfigjson"},
		},
	}
}

func TestGenerateBaseSecrets(t *testing.T) {
	testCases := []struct {
		Name     string
		Config   *config.UpdateKSopsSecrets
		Expected string
	}{
		{
			Name:   "simple",
			Config: uksConfigSimple(),
			Expected: `apiVersion: v1
data: {}
kind: Secret
metadata:
  annotations:
    kustomize.config.k8s.io/behavior: merge
  name: test
type: Opaque
`,
		},
		{
			Name:   "with annotations",
			Config: uksConfigAnnotations(),
			Expected: `apiVersion: v1
data: {}
kind: Secret
metadata:
  annotations:
    kustomize.config.k8s.io/behavior: merge
    test: test
    test2: test2
  name: test
type: Opaque
`,
		},
		{
			Name:   "with labels",
			Config: uksConfigLabels(),
			Expected: `apiVersion: v1
data: {}
kind: Secret
metadata:
  annotations:
    kustomize.config.k8s.io/behavior: merge
  labels:
    test: test
    test2: test2
  name: test
type: Opaque
`,
		},
		{
			Name:   "with annotations and labels",
			Config: uksConfigAnnotationsLabels(),
			Expected: `apiVersion: v1
data: {}
kind: Secret
metadata:
  annotations:
    kustomize.config.k8s.io/behavior: merge
    test: test
    test2: test2
  labels:
    test: test
    test2: test2
  name: test
type: Opaque
`,
		},
		{
			Name:   "with other secret type kubernetes.io/dockerconfigjson",
			Config: uksConfigOtherSecretType(),
			Expected: `apiVersion: v1
data: {}
kind: Secret
metadata:
  annotations:
    kustomize.config.k8s.io/behavior: merge
    test: test
    test2: test2
  labels:
    test: test
    test2: test2
  name: test
type: kubernetes.io/dockerconfigjson
`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			gen := KSopsGenerator{}
			outputs, err := gen.GenerateBaseSecrets([]*yaml.RNode{}, tc.Config)
			if err != nil {
				t.Fatalf("unexpected error %v", err)
			}
			if len(outputs) != 1 {
				t.Fatalf("expect to generate 1 rnode, got %v", len(outputs))
			}
			a, _ := outputs[0].MarshalJSON()
			actual, _ := yaml2.JSONToYAML(a)
			if string(actual) != tc.Expected {
				t.Fatalf("\n[expect]\n%v\n[got]\n%v", tc.Expected, string(actual))
			}
		})
	}
}

func TestGenerateKustomization(t *testing.T) {
	expected := `apiVersion: kustomize.config.k8s.io/v1beta1
generators:
- generated/ksops-generator.yaml
kind: Kustomization
resources:
- secrets.yaml
`

	gen := KSopsGenerator{}
	outputs, err := gen.GenerateKustomization([]*yaml.RNode{})
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}
	if len(outputs) != 1 {
		t.Fatalf("expect to generate 1 rnode, got %v", len(outputs))
	}
	a, _ := outputs[0].MarshalJSON()
	actual, _ := yaml2.JSONToYAML(a)
	if string(actual) != expected {
		t.Fatalf("\n[expect]\n%v\n[got]\n%v", expected, string(actual))
	}
}

func TestGenerateKSopsGenerator(t *testing.T) {
	uksConfig := uksConfigSimple()
	expected := []string{
		`apiVersion: viaduct.ai/v1
files:
- generated/secrets.upper_case.enc.yaml
kind: ksops
metadata:
  name: ksops-generator-test-upper_case
`,
		`apiVersion: viaduct.ai/v1
files:
- generated/secrets.test.enc.yaml
kind: ksops
metadata:
  name: ksops-generator-test-test
`,
		`apiVersion: viaduct.ai/v1
files:
- generated/secrets.test2.enc.yaml
kind: ksops
metadata:
  name: ksops-generator-test-test2
`,
	}

	gen := KSopsGenerator{}
	outputs, err := gen.GenerateKSopsGenerator([]*yaml.RNode{}, uksConfig)
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}
	if len(outputs) != 3 {
		t.Fatalf("expect to generate 3 rnode, got %v", len(outputs))
	}

	for idx := range outputs {
		a, _ := outputs[idx].MarshalJSON()
		actual, _ := yaml2.JSONToYAML(a)
		if string(actual) != expected[idx] {
			t.Fatalf("\n[expect]\n%v\n[got]\n%v", expected[idx], string(actual))
		}
	}
}
