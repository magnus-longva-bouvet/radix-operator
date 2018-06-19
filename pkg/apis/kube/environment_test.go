package kube

import (
	"fmt"
	"io/ioutil"
	"testing"

	"github.com/statoil/radix-operator/radix-operator/common"

	log "github.com/Sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/client-go/kubernetes/fake"
)

func init() {
	log.SetOutput(ioutil.Discard)
}

func Test_Create_Radix_Environments(t *testing.T) {
	radixRegistration, _ := common.GetRadixRegistrationFromFile(sampleRegistration)
	radixApp, _ := common.GetRadixAppFromFile(sampleApp)
	kubeclient := fake.NewSimpleClientset()
	kubeutil, _ := New(kubeclient)
	label := fmt.Sprintf("radixApp=%s", radixApp.Name)
	t.Run("It can create environments", func(t *testing.T) {
		for _, env := range radixApp.Spec.Environments {
			err := kubeutil.CreateEnvironment(radixRegistration, env.Name)
			assert.NoError(t, err)
		}
		namespaces, _ := kubeclient.CoreV1().Namespaces().List(metav1.ListOptions{
			LabelSelector: label,
		})
		assert.Len(t, namespaces.Items, 2)
		environment, err := kubeclient.CoreV1().Namespaces().Get(fmt.Sprintf("%s-%s", radixApp.Name, radixApp.Spec.Environments[0].Name), metav1.GetOptions{})
		assert.NoError(t, err)
		assert.NotNil(t, environment)
	})

	t.Run("It doesn't fail when re-running creation", func(t *testing.T) {
		for _, env := range radixApp.Spec.Environments {
			err := kubeutil.CreateEnvironment(radixRegistration, env.Name)
			assert.NoError(t, err)
		}
		namespaces, _ := kubeclient.CoreV1().Namespaces().List(metav1.ListOptions{
			LabelSelector: label,
		})
		assert.Len(t, namespaces.Items, 2)
	})
}
