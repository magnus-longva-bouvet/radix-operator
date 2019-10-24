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
func (in *AppAlias) DeepCopyInto(out *AppAlias) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AppAlias.
func (in *AppAlias) DeepCopy() *AppAlias {
	if in == nil {
		return nil
	}
	out := new(AppAlias)
	in.DeepCopyInto(out)
	return out
}

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
func (in *EnvBuild) DeepCopyInto(out *EnvBuild) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new EnvBuild.
func (in *EnvBuild) DeepCopy() *EnvBuild {
	if in == nil {
		return nil
	}
	out := new(EnvBuild)
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
	out.Build = in.Build
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
func (in *ExternalAlias) DeepCopyInto(out *ExternalAlias) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ExternalAlias.
func (in *ExternalAlias) DeepCopy() *ExternalAlias {
	if in == nil {
		return nil
	}
	out := new(ExternalAlias)
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
	in.ListMeta.DeepCopyInto(&out.ListMeta)
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
	out.DNSAppAlias = in.DNSAppAlias
	if in.DNSExternalAlias != nil {
		in, out := &in.DNSExternalAlias, &out.DNSExternalAlias
		*out = make([]ExternalAlias, len(*in))
		copy(*out, *in)
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
func (in *RadixBuildSpec) DeepCopyInto(out *RadixBuildSpec) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new RadixBuildSpec.
func (in *RadixBuildSpec) DeepCopy() *RadixBuildSpec {
	if in == nil {
		return nil
	}
	out := new(RadixBuildSpec)
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
	if in.Secrets != nil {
		in, out := &in.Secrets, &out.Secrets
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.EnvironmentConfig != nil {
		in, out := &in.EnvironmentConfig, &out.EnvironmentConfig
		*out = make([]RadixEnvironmentConfig, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
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
	if in.Replicas != nil {
		in, out := &in.Replicas, &out.Replicas
		*out = new(int)
		**out = **in
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
	if in.DNSExternalAlias != nil {
		in, out := &in.DNSExternalAlias, &out.DNSExternalAlias
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	in.Resources.DeepCopyInto(&out.Resources)
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
func (in *RadixDeployStatus) DeepCopyInto(out *RadixDeployStatus) {
	*out = *in
	in.ActiveFrom.DeepCopyInto(&out.ActiveFrom)
	in.ActiveTo.DeepCopyInto(&out.ActiveTo)
	in.Reconciled.DeepCopyInto(&out.Reconciled)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new RadixDeployStatus.
func (in *RadixDeployStatus) DeepCopy() *RadixDeployStatus {
	if in == nil {
		return nil
	}
	out := new(RadixDeployStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *RadixDeployment) DeepCopyInto(out *RadixDeployment) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
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
	in.ListMeta.DeepCopyInto(&out.ListMeta)
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
func (in *RadixEnvironmentConfig) DeepCopyInto(out *RadixEnvironmentConfig) {
	*out = *in
	if in.Replicas != nil {
		in, out := &in.Replicas, &out.Replicas
		*out = new(int)
		**out = **in
	}
	in.Resources.DeepCopyInto(&out.Resources)
	if in.Variables != nil {
		in, out := &in.Variables, &out.Variables
		*out = make(EnvVarsMap, len(*in))
		for key, val := range *in {
			(*out)[key] = val
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new RadixEnvironmentConfig.
func (in *RadixEnvironmentConfig) DeepCopy() *RadixEnvironmentConfig {
	if in == nil {
		return nil
	}
	out := new(RadixEnvironmentConfig)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *RadixJob) DeepCopyInto(out *RadixJob) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	out.Spec = in.Spec
	in.Status.DeepCopyInto(&out.Status)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new RadixJob.
func (in *RadixJob) DeepCopy() *RadixJob {
	if in == nil {
		return nil
	}
	out := new(RadixJob)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *RadixJob) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *RadixJobList) DeepCopyInto(out *RadixJobList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]RadixJob, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new RadixJobList.
func (in *RadixJobList) DeepCopy() *RadixJobList {
	if in == nil {
		return nil
	}
	out := new(RadixJobList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *RadixJobList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *RadixJobSpec) DeepCopyInto(out *RadixJobSpec) {
	*out = *in
	out.Build = in.Build
	out.Promote = in.Promote
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new RadixJobSpec.
func (in *RadixJobSpec) DeepCopy() *RadixJobSpec {
	if in == nil {
		return nil
	}
	out := new(RadixJobSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *RadixJobStatus) DeepCopyInto(out *RadixJobStatus) {
	*out = *in
	if in.Created != nil {
		in, out := &in.Created, &out.Created
		*out = (*in).DeepCopy()
	}
	if in.Started != nil {
		in, out := &in.Started, &out.Started
		*out = (*in).DeepCopy()
	}
	if in.Ended != nil {
		in, out := &in.Ended, &out.Ended
		*out = (*in).DeepCopy()
	}
	if in.TargetEnvs != nil {
		in, out := &in.TargetEnvs, &out.TargetEnvs
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.Steps != nil {
		in, out := &in.Steps, &out.Steps
		*out = make([]RadixJobStep, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new RadixJobStatus.
func (in *RadixJobStatus) DeepCopy() *RadixJobStatus {
	if in == nil {
		return nil
	}
	out := new(RadixJobStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *RadixJobStep) DeepCopyInto(out *RadixJobStep) {
	*out = *in
	if in.Started != nil {
		in, out := &in.Started, &out.Started
		*out = (*in).DeepCopy()
	}
	if in.Ended != nil {
		in, out := &in.Ended, &out.Ended
		*out = (*in).DeepCopy()
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new RadixJobStep.
func (in *RadixJobStep) DeepCopy() *RadixJobStep {
	if in == nil {
		return nil
	}
	out := new(RadixJobStep)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *RadixPromoteSpec) DeepCopyInto(out *RadixPromoteSpec) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new RadixPromoteSpec.
func (in *RadixPromoteSpec) DeepCopy() *RadixPromoteSpec {
	if in == nil {
		return nil
	}
	out := new(RadixPromoteSpec)
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
	in.ListMeta.DeepCopyInto(&out.ListMeta)
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
func (in ResourceList) DeepCopyInto(out *ResourceList) {
	{
		in := &in
		*out = make(ResourceList, len(*in))
		for key, val := range *in {
			(*out)[key] = val
		}
		return
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ResourceList.
func (in ResourceList) DeepCopy() ResourceList {
	if in == nil {
		return nil
	}
	out := new(ResourceList)
	in.DeepCopyInto(out)
	return *out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ResourceRequirements) DeepCopyInto(out *ResourceRequirements) {
	*out = *in
	if in.Limits != nil {
		in, out := &in.Limits, &out.Limits
		*out = make(ResourceList, len(*in))
		for key, val := range *in {
			(*out)[key] = val
		}
	}
	if in.Requests != nil {
		in, out := &in.Requests, &out.Requests
		*out = make(ResourceList, len(*in))
		for key, val := range *in {
			(*out)[key] = val
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ResourceRequirements.
func (in *ResourceRequirements) DeepCopy() *ResourceRequirements {
	if in == nil {
		return nil
	}
	out := new(ResourceRequirements)
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
