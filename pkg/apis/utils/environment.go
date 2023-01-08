package utils

import (
	"fmt"
	"github.com/equinor/radix-operator/pkg/apis/radix/v1"
)

// GetRadixEnvironmentByName Returns the environment with the given name
func GetRadixEnvironmentByName(application *v1.RadixApplication, envName string) (*v1.Environment, error) {
	for _, env := range application.Spec.Environments {
		if env.Name == envName {
			return &env, nil
		}
	}
	return nil, fmt.Errorf("could not find environment %s in RadixApplication", envName)
}
