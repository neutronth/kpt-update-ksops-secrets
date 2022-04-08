// Copyright 2022 Neutron Soutmun <neutron@neutron.in.th>
// SPDX-License-Identifier: Apache-2.0

package exec

import (
	"fmt"
	"os/exec"
	"strings"
)

type GPGKeysInterface interface {
	ReceiveKeys(fingerprints ...string) (output string, err error)
	ImportKey(data string) (output string, err error)
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
		return "", fmt.Errorf("the GPG Error: %s", out)
	}

	return string(out), nil
}

func (g *gpg) ImportKey(data string) (output string, err error) {
	cmdOpts := []string{
		"--import",
	}

	cmd := exec.Command("gpg", cmdOpts...)
	cmd.Stdin = strings.NewReader(data)
	out, err := cmd.CombinedOutput()

	if err != nil {
		return "", fmt.Errorf("the GPG Error: %s", out)
	}

	return string(out), nil
}
