package job

import (
	"context"
	"os"
	"testing"

	"github.com/equinor/radix-operator/pkg/apis/defaults"
	jobs "github.com/equinor/radix-operator/pkg/apis/job"
	"github.com/equinor/radix-operator/pkg/apis/kube"
	"github.com/equinor/radix-operator/pkg/apis/test"
	"github.com/equinor/radix-operator/pkg/apis/utils"
	radixclient "github.com/equinor/radix-operator/pkg/client/clientset/versioned"
	fakeradix "github.com/equinor/radix-operator/pkg/client/clientset/versioned/fake"
	informers "github.com/equinor/radix-operator/pkg/client/informers/externalversions"
	"github.com/stretchr/testify/assert"
	tektonclientfake "github.com/tektoncd/pipeline/pkg/client/clientset/versioned/fake"
	batchv1 "k8s.io/api/batch/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubeinformers "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/record"
	secretproviderfake "sigs.k8s.io/secrets-store-csi-driver/pkg/client/clientset/versioned/fake"
)

const (
	clusterName       = "AnyClusterName"
	containerRegistry = "any.container.registry"
	egressIps         = "0.0.0.0"
)

func setupTest() (*test.Utils, kubernetes.Interface, *kube.Kube, radixclient.Interface) {
	client := fake.NewSimpleClientset()
	radixClient := fakeradix.NewSimpleClientset()
	secretproviderclient := secretproviderfake.NewSimpleClientset()
	tektonclient := tektonclientfake.NewSimpleClientset()
	kubeUtil, _ := kube.New(client, radixClient, secretproviderclient)
	handlerTestUtils := test.NewTestUtils(client, radixClient, secretproviderclient, tektonclient)
	handlerTestUtils.CreateClusterPrerequisites(clusterName, containerRegistry, egressIps)
	return &handlerTestUtils, client, kubeUtil, radixClient
}

func teardownTest() {
	os.Unsetenv(defaults.OperatorRollingUpdateMaxUnavailable)
	os.Unsetenv(defaults.OperatorRollingUpdateMaxSurge)
	os.Unsetenv(defaults.OperatorReadinessProbeInitialDelaySeconds)
	os.Unsetenv(defaults.OperatorReadinessProbePeriodSeconds)
}

func Test_Controller_Calls_Handler(t *testing.T) {
	anyAppName := "test-app"

	// Setup
	tu, client, kubeUtil, radixClient := setupTest()
	stop := make(chan struct{})
	synced := make(chan bool)

	defer close(stop)
	defer close(synced)

	kubeInformerFactory := kubeinformers.NewSharedInformerFactory(client, 0)
	radixInformerFactory := informers.NewSharedInformerFactory(radixClient, 0)

	jobHandler := NewHandler(
		client,
		kubeUtil,
		radixClient,
		func(syncedOk bool) {
			synced <- syncedOk
		},
	)
	go startJobController(client, radixClient, radixInformerFactory, kubeInformerFactory, jobHandler, stop)

	// Test

	// Create job should sync
	rj, _ := tu.ApplyJob(
		utils.ARadixBuildDeployJob().
			WithAppName(anyAppName))

	op, ok := <-synced
	assert.True(t, ok)
	assert.True(t, op)

	// Update  radix job should sync. Controller will skip if an update
	// changes nothing, except for spec or metadata, labels or annotations
	rj.Spec.Stop = true
	radixClient.RadixV1().RadixJobs(rj.ObjectMeta.Namespace).Update(context.TODO(), rj, metav1.UpdateOptions{})

	op, ok = <-synced
	assert.True(t, ok)
	assert.True(t, op)

	// Child job should sync
	childJob := batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			OwnerReferences: jobs.GetOwnerReference(rj),
		},
	}

	// Only update of Kubernetes Job is something that the job-controller handles
	client.BatchV1().Jobs(rj.ObjectMeta.Namespace).Create(context.TODO(), &childJob, metav1.CreateOptions{})
	childJob.ObjectMeta.ResourceVersion = "1234"
	client.BatchV1().Jobs(rj.ObjectMeta.Namespace).Update(context.TODO(), &childJob, metav1.UpdateOptions{})

	op, ok = <-synced
	assert.True(t, ok)
	assert.True(t, op)

	teardownTest()
}

func startJobController(
	client kubernetes.Interface,
	radixClient radixclient.Interface,
	radixInformerFactory informers.SharedInformerFactory,
	kubeInformerFactory kubeinformers.SharedInformerFactory,
	handler Handler, stop chan struct{}) {

	eventRecorder := &record.FakeRecorder{}

	waitForChildrenToSync := false
	controller := NewController(
		client, radixClient, &handler,
		kubeInformerFactory,
		radixInformerFactory,
		waitForChildrenToSync,
		eventRecorder)

	kubeInformerFactory.Start(stop)
	radixInformerFactory.Start(stop)
	controller.Run(1, stop)

}
