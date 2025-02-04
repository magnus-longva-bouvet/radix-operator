package deployment

import (
	"testing"

	"github.com/equinor/radix-operator/pkg/apis/kube"
	"github.com/equinor/radix-operator/pkg/apis/utils"
	"github.com/stretchr/testify/assert"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func Test_ComponentNameExistsInRD(t *testing.T) {
	rd := utils.ARadixDeployment().
		WithComponents(
			utils.NewDeployComponentBuilder().WithName("component")).
		WithJobComponents(
			utils.NewDeployJobComponentBuilder().WithName("job")).
		BuildRD()

	componentName := RadixComponentName("component")
	assert.True(t, componentName.ExistInDeploymentSpec(rd))
	assert.True(t, componentName.ExistInDeploymentSpecComponentList(rd))
	assert.False(t, componentName.ExistInDeploymentSpecJobList(rd))

	jobName := RadixComponentName("job")
	assert.True(t, jobName.ExistInDeploymentSpec(rd))
	assert.False(t, jobName.ExistInDeploymentSpecComponentList(rd))
	assert.True(t, jobName.ExistInDeploymentSpecJobList(rd))

	nonExistingName := RadixComponentName("nonexisting")
	assert.False(t, nonExistingName.ExistInDeploymentSpec(rd))
	assert.False(t, nonExistingName.ExistInDeploymentSpecComponentList(rd))
	assert.False(t, nonExistingName.ExistInDeploymentSpecJobList(rd))
}

func Test_FindCommonComponentInRD(t *testing.T) {
	rd := utils.ARadixDeployment().
		WithComponents(
			utils.NewDeployComponentBuilder().WithName("component")).
		WithJobComponents(
			utils.NewDeployJobComponentBuilder().WithName("job")).
		BuildRD()

	componentName := RadixComponentName("component")
	comp := componentName.GetCommonDeployComponent(rd)
	assert.NotNil(t, comp)
	assert.Equal(t, "component", comp.GetName())

	jobName := RadixComponentName("job")
	job := jobName.GetCommonDeployComponent(rd)
	assert.NotNil(t, job)
	assert.Equal(t, "job", job.GetName())

	nonExistingName := RadixComponentName("nonexisting")
	nonExisting := nonExistingName.GetCommonDeployComponent(rd)
	assert.Nil(t, nonExisting)

}

func Test_NewRadixComponentNameFromLabels(t *testing.T) {
	nonRadix := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{
				"anylabel": "component",
			},
		},
	}

	radixLabelled := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{
				kube.RadixComponentLabel: "component",
			},
		},
	}

	radixAuxLabelled := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{
				kube.RadixAuxiliaryComponentLabel: "component",
			},
		},
	}

	name, ok := RadixComponentNameFromComponentLabel(radixLabelled)
	assert.True(t, ok)
	assert.Equal(t, RadixComponentName("component"), name)

	name, ok = RadixComponentNameFromAuxComponentLabel(radixAuxLabelled)
	assert.True(t, ok)
	assert.Equal(t, RadixComponentName("component"), name)

	name, ok = RadixComponentNameFromComponentLabel(nonRadix)
	assert.False(t, ok)
	assert.Equal(t, RadixComponentName(""), name)
}
