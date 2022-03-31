// Copyright 2022 Neutron Soutmun <neutron@neutron.in.th>
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"

	"github.com/neutronth/kpt-update-ksops-secrets/generated"
	"github.com/neutronth/kpt-update-ksops-secrets/generator"
	"sigs.k8s.io/kustomize/kyaml/fn/framework/command"
)

func main() {
	cmd := command.Build(generator.NewProcessor(),
		command.StandaloneEnabled, false)

	cmd.Short = generated.KptUpdateKsopsSecretsShort
	cmd.Long = generated.KptUpdateKsopsSecretsLong
	cmd.Example = generated.KptUpdateKsopsSecretsExamples

	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
