// Copyright 2022 Neutron Soutmun <neutron@neutron.in.th>
// SPDX-License-Identifier: Apache-2.0

package exec

import (
	"fmt"
	"os/exec"
)

type GPGKeysInterface interface {
	ReceiveKeys(fingerprints ...string) (output string, err error)
}

type gpg struct{}

func NewGPGKeys() GPGKeysInterface {
	return &gpg{}
}

func (g *gpg) ReceiveKeys(fingerprints ...string) (output string, err error) {
	cmdOpts := append(
		[]string{
			"--receive-keys",
		},
		fingerprints...,
	)

	cmd := exec.Command("gpg", cmdOpts...)
	out, err := cmd.CombinedOutput()

	if err != nil {
		return "", fmt.Errorf("GPG Error: %s\n", out)
	}

	return string(out), nil
}
