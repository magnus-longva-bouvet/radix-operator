// +build !ignore_autogenerated

/*
Copyright The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Code generated by deepcopy-gen. DO NOT EDIT.

package v1

import (
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ComponentPort) DeepCopyInto(out *ComponentPort) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ComponentPort.
func (in *ComponentPort) DeepCopy() *ComponentPort {
	if in == nil {
		return nil
	}
	out := new(ComponentPort)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *EnvVars) DeepCopyInto(out *EnvVars) {
	*out = *in
	if in.Variables != nil {
		in, out := &in.Variables, &out.Variables
		*out = make(EnvVarsMap, len(*in))
		for key, val := range *in {
			(*out)[key] = val
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new EnvVars.
func (in *EnvVars) DeepCopy() *EnvVars {
	if in == nil {
		return nil
	}
	out := new(EnvVars)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in EnvVarsMap) DeepCopyInto(out *EnvVarsMap) {
	{
		in := &in
		*out = make(EnvVarsMap, len(*in))
		for key, val := range *in {
			(*out)[key] = val
		}
		return
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new EnvVarsMap.
func (in EnvVarsMap) DeepCopy() EnvVarsMap {
	if in == nil {
		return nil
	}
	out := new(EnvVarsMap)
	in.DeepCopyInto(out)
	return *out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Environment) DeepCopyInto(out *Environment) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Environment.
func (in *Environment) DeepCopy() *Environment {
	if in == nil {
		return nil
	}
	out := new(Environment)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *RadixApplication) DeepCopyInto(out *RadixApplication) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new RadixApplication.
func (in *RadixApplication) DeepCopy() *RadixApplication {
	if in == nil {
		return nil
	}
	out := new(RadixApplication)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *RadixApplication) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *RadixApplicationList) DeepCopyInto(out *RadixApplicationList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	out.ListMeta = in.ListMeta
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]RadixApplication, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new RadixApplicationList.
func (in *RadixApplicationList) DeepCopy() *RadixApplicationList {
	if in == nil {
		return nil
	}
	out := new(RadixApplicationList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *RadixApplicationList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *RadixApplicationSpec) DeepCopyInto(out *RadixApplicationSpec) {
	*out = *in
	if in.Environments != nil {
		in, out := &in.Environments, &out.Environments
		*out = make([]Environment, len(*in))
		copy(*out, *in)
	}
	if in.Components != nil {
		in, out := &in.Components, &out.Components
		*out = make([]RadixComponent, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new RadixApplicationSpec.
func (in *RadixApplicationSpec) DeepCopy() *RadixApplicationSpec {
	if in == nil {
		return nil
	}
	out := new(RadixApplicationSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *RadixComponent) DeepCopyInto(out *RadixComponent) {
	*out = *in
	if in.Ports != nil {
		in, out := &in.Ports, &out.Ports
		*out = make([]ComponentPort, len(*in))
		copy(*out, *in)
	}
	if in.EnvironmentVariables != nil {
		in, out := &in.EnvironmentVariables, &out.EnvironmentVariables
		*out = make([]EnvVars, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.Secrets != nil {
		in, out := &in.Secrets, &out.Secrets
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new RadixComponent.
func (in *RadixComponent) DeepCopy() *RadixComponent {
	if in == nil {
		return nil
	}
	out := new(RadixComponent)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *RadixDeployComponent) DeepCopyInto(out *RadixDeployComponent) {
	*out = *in
	if in.Ports != nil {
		in, out := &in.Ports, &out.Ports
		*out = make([]ComponentPort, len(*in))
		copy(*out, *in)
	}
	if in.EnvironmentVariables != nil {
		in, out := &in.EnvironmentVariables, &out.EnvironmentVariables
		*out = make(EnvVarsMap, len(*in))
		for key, val := range *in {
			(*out)[key] = val
		}
	}
	if in.Secrets != nil {
		in, out := &in.Secrets, &out.Secrets
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new RadixDeployComponent.
func (in *RadixDeployComponent) DeepCopy() *RadixDeployComponent {
	if in == nil {
		return nil
	}
	out := new(RadixDeployComponent)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *RadixDeployment) DeepCopyInto(out *RadixDeployment) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new RadixDeployment.
func (in *RadixDeployment) DeepCopy() *RadixDeployment {
	if in == nil {
		return nil
	}
	out := new(RadixDeployment)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *RadixDeployment) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *RadixDeploymentList) DeepCopyInto(out *RadixDeploymentList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	out.ListMeta = in.ListMeta
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]RadixDeployment, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new RadixDeploymentList.
func (in *RadixDeploymentList) DeepCopy() *RadixDeploymentList {
	if in == nil {
		return nil
	}
	out := new(RadixDeploymentList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *RadixDeploymentList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *RadixDeploymentSpec) DeepCopyInto(out *RadixDeploymentSpec) {
	*out = *in
	if in.Components != nil {
		in, out := &in.Components, &out.Components
		*out = make([]RadixDeployComponent, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new RadixDeploymentSpec.
func (in *RadixDeploymentSpec) DeepCopy() *RadixDeploymentSpec {
	if in == nil {
		return nil
	}
	out := new(RadixDeploymentSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *RadixRegistration) DeepCopyInto(out *RadixRegistration) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new RadixRegistration.
func (in *RadixRegistration) DeepCopy() *RadixRegistration {
	if in == nil {
		return nil
	}
	out := new(RadixRegistration)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *RadixRegistration) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *RadixRegistrationList) DeepCopyInto(out *RadixRegistrationList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	out.ListMeta = in.ListMeta
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]RadixRegistration, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new RadixRegistrationList.
func (in *RadixRegistrationList) DeepCopy() *RadixRegistrationList {
	if in == nil {
		return nil
	}
	out := new(RadixRegistrationList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *RadixRegistrationList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *RadixRegistrationSpec) DeepCopyInto(out *RadixRegistrationSpec) {
	*out = *in
	if in.AdGroups != nil {
		in, out := &in.AdGroups, &out.AdGroups
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new RadixRegistrationSpec.
func (in *RadixRegistrationSpec) DeepCopy() *RadixRegistrationSpec {
	if in == nil {
		return nil
	}
	out := new(RadixRegistrationSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in SecretsMap) DeepCopyInto(out *SecretsMap) {
	{
		in := &in
		*out = make(SecretsMap, len(*in))
		for key, val := range *in {
			(*out)[key] = val
		}
		return
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new SecretsMap.
func (in SecretsMap) DeepCopy() SecretsMap {
	if in == nil {
		return nil
	}
	out := new(SecretsMap)
	in.DeepCopyInto(out)
	return *out
}
