package application

import (
	"encoding/json"
	"testing"

	"github.com/equinor/radix-operator/pkg/apis/kube"
	"github.com/equinor/radix-operator/pkg/apis/test"
	"github.com/equinor/radix-operator/pkg/apis/utils"
	radixclient "github.com/equinor/radix-operator/pkg/client/clientset/versioned"
	fakeradix "github.com/equinor/radix-operator/pkg/client/clientset/versioned/fake"
	informers "github.com/equinor/radix-operator/pkg/client/informers/externalversions"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubeinformers "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/record"
)

const (
	clusterName       = "AnyClusterName"
	dnsZone           = "dev.radix.equinor.com"
	containerRegistry = "any.container.registry"
)

var synced chan bool

func setupTest() (*test.Utils, kubernetes.Interface, radixclient.Interface) {
	client := fake.NewSimpleClientset()
	radixClient := fakeradix.NewSimpleClientset()

	handlerTestUtils := test.NewTestUtils(client, radixClient)
	handlerTestUtils.CreateClusterPrerequisites(clusterName, containerRegistry)
	return &handlerTestUtils, client, radixClient
}

func Test_Controller_Calls_Handler(t *testing.T) {
	anyAppName := "test-app"
	initialAdGroup, _ := json.Marshal([]string{"12345-6789-01234"})

	// Setup
	tu, client, radixClient := setupTest()

	client.CoreV1().Namespaces().Create(&corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: utils.GetAppNamespace(anyAppName),
			Labels: map[string]string{
				kube.RadixAppLabel: anyAppName,
				kube.RadixEnvLabel: "app",
			},
			Annotations: map[string]string{
				kube.AdGroupsAnnotation: string(initialAdGroup),
			},
		},
	})

	stop := make(chan struct{})
	synced := make(chan bool)

	defer close(stop)
	defer close(synced)

	applicationHandler := NewHandler(
		client,
		radixClient,
		func(syncedOk bool) {
			synced <- syncedOk
		},
	)
	go startApplicationController(client, radixClient, applicationHandler, stop)

	// Test

	// Create registration should sync
	tu.ApplyApplication(
		utils.ARadixApplication().
			WithAppName(anyAppName).
			WithEnvironment("dev", "master"))

	op, ok := <-synced
	assert.True(t, ok)
	assert.True(t, op)

	// Update ad group of app namespace should sync
	newAdGroups, _ := json.Marshal([]string{"98765-4321-09876"})
	appNamespace, _ := client.CoreV1().Namespaces().Get(utils.GetAppNamespace(anyAppName), metav1.GetOptions{})
	appNamespace.ResourceVersion = "12345"
	appNamespace.Annotations[kube.AdGroupsAnnotation] = string(newAdGroups)
	client.CoreV1().Namespaces().Update(appNamespace)

	op, ok = <-synced
	assert.True(t, ok)
	assert.True(t, op)
}

func startApplicationController(client kubernetes.Interface, radixClient radixclient.Interface, handler Handler, stop chan struct{}) {

	kubeInformerFactory := kubeinformers.NewSharedInformerFactory(client, 0)
	radixInformerFactory := informers.NewSharedInformerFactory(radixClient, 0)
	eventRecorder := &record.FakeRecorder{}

	controller := NewController(client, radixClient, &handler,
		radixInformerFactory.Radix().V1().RadixApplications(),
		kubeInformerFactory.Core().V1().Namespaces(), eventRecorder)

	kubeInformerFactory.Start(stop)
	radixInformerFactory.Start(stop)
	controller.Run(1, stop)

}
