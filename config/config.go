// Copyright 2022 Neutron Soutmun <neutron@neutron.in.th>
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"sort"

	sdk "github.com/GoogleContainerTools/kpt-functions-sdk/go/fn"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	fnConfigGroup      = "fn.kpt.dev"
	fnConfigVersion    = "v1alpha1"
	fnConfigAPIVersion = fnConfigGroup + "/" + fnConfigVersion
	fnConfigKind       = "UpdateKSopsSecrets"
)

type UpdateKSopsSecretSpec struct {
	Type       string   `json:"type,omitempty" yaml:"type,omitempty"`
	References []string `json:"references" yaml:"references"`
	Items      []string `json:"items" yaml:"items"`
}

type UpdateKSopsGPGPublicKeyReference struct {
	Name string `json:"name" yaml:"name"`
	Key  string `json:"key" yaml:"key"`
}

type UpdateKSopsRecipient struct {
	Type      string `json:"type" yaml:"type"`
	Recipient string `json:"recipient" yaml:"recipient"`

	PublicKeySecretReference UpdateKSopsGPGPublicKeyReference `json:"publicKeySecretReference,omitempty" yaml:"publicKeySecretReference,omitempty"`
}

type UpdateKSopsSecrets struct {
	ObjectMeta metav1.ObjectMeta
	Secret     UpdateKSopsSecretSpec  `json:"secret" yaml:"secret"`
	Recipients []UpdateKSopsRecipient `json:"recipients" yaml:"recipients"`
}

func validGVK(ko *sdk.KubeObject, apiVersion, kind string) bool {
	return ko.GetAPIVersion() == apiVersion && ko.GetKind() == kind
}

func (uks *UpdateKSopsSecrets) Config(functionConfig *sdk.KubeObject) error {
	switch {
	case validGVK(functionConfig, fnConfigAPIVersion, fnConfigKind):
		if err := functionConfig.As(uks); err != nil {
			return fmt.Errorf("unable to convert functionConfig to %s %s:\n%w",
				fnConfigVersion, fnConfigKind, err)
		}
	default:
		return fmt.Errorf("the functionConfig must be a %s", fnConfigKind)
	}

	uks.ObjectMeta.Name = functionConfig.GetName()

	annotations := functionConfig.GetAnnotations()
	if len(annotations) > 0 {
		uks.ObjectMeta.Annotations = annotations
	}

	labels := functionConfig.GetLabels()
	if len(labels) > 0 {
		uks.ObjectMeta.Labels = labels
	}

	return nil
}

func (uks *UpdateKSopsSecrets) GetName() string {
	return uks.ObjectMeta.GetName()
}

func (uks *UpdateKSopsSecrets) GetAnnotations() map[string]string {
	return uks.ObjectMeta.GetAnnotations()
}

func (uks *UpdateKSopsSecrets) GetLabels() map[string]string {
	return uks.ObjectMeta.GetLabels()
}

func (uks *UpdateKSopsSecrets) GetType() string {
	return uks.Secret.Type
}

func (uks *UpdateKSopsSecrets) GetSecretItems() []string {
	keys := make([]string, len(uks.Secret.Items))

	copy(keys, uks.Secret.Items)
	sort.Strings(keys)

	return keys
}
