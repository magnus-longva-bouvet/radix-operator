package application

import (
	"github.com/equinor/radix-operator/pkg/apis/kube"
	v1 "github.com/equinor/radix-operator/pkg/apis/radix/v1"
	radixclient "github.com/equinor/radix-operator/pkg/client/clientset/versioned"
	log "github.com/sirupsen/logrus"
	"k8s.io/client-go/kubernetes"
)

var logger *log.Entry

// Application Instance variables
type Application struct {
	kubeclient   kubernetes.Interface
	radixclient  radixclient.Interface
	kubeutil     *kube.Kube
	registration *v1.RadixRegistration
}

// NewApplication Constructor
func NewApplication(
	kubeclient kubernetes.Interface,
	radixclient radixclient.Interface,
	registration *v1.RadixRegistration) (Application, error) {
	kubeutil, err := kube.New(kubeclient)
	if err != nil {
		return Application{}, err
	}

	return Application{
		kubeclient,
		radixclient,
		kubeutil,
		registration}, nil
}

// OnRegistered called when an application is registered (new RadixRegistration in cluster)
func (app Application) OnRegistered() {
	radixRegistration := app.registration
	logger = logger.WithFields(log.Fields{"registrationName": radixRegistration.ObjectMeta.Name, "registrationNamespace": radixRegistration.ObjectMeta.Namespace})

	err := app.kubeutil.CreateEnvironment(radixRegistration, "app")
	if err != nil {
		logger.Errorf("Failed to create app namespace. %v", err)
	} else {
		logger.Infof("App namespace created")
	}

	err = app.ApplySecretsForPipelines() // create deploy key in app namespace
	if err != nil {
		logger.Errorf("Failed to apply secrets needed by pipeline. %v", err)
	} else {
		logger.Infof("Applied secrets needed by pipelines")
	}

	pipelineServiceAccount, err := app.ApplyPipelineServiceAccount()
	if err != nil {
		logger.Errorf("Failed to apply service account needed by pipeline. %v", err)
	} else {
		logger.Infof("Applied service account needed by pipelines")
	}

	err = app.ApplyRbacRadixRegistration()
	if err != nil {
		logger.Errorf("Failed to set access on RadixRegistration: %v", err)
	} else {
		logger.Infof("Applied access permissions to RadixRegistration")
	}

	err = app.GrantAccessToCICDLogs()
	if err != nil {
		logger.Errorf("Failed to grant access to ci/cd logs: %v", err)
	} else {
		logger.Infof("Applied access to ci/cd logs")
	}

	err = app.ApplyRbacOnPipelineRunner(pipelineServiceAccount)
	if err != nil {
		logger.Errorf("Failed to set access permissions needed by pipeline: %v", err)
	} else {
		logger.Infof("Applied access permissions needed by pipeline")
	}
}
