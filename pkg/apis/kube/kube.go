package kube

import (
	log "github.com/sirupsen/logrus"
	"k8s.io/client-go/kubernetes"
)

// Radix Labels
const (
	RadixAppLabel                = "radix-app"
	RadixEnvLabel                = "radix-env"
	RadixComponentLabel          = "radix-component"
	RadixJobNameLabel            = "radix-job-name"
	RadixBuildLabel              = "radix-build"
	RadixCommitLabel             = "radix-commit"
	RadixImageTagLabel           = "radix-image-tag"
	RadixBranchLabel             = "radix-branch"
	RadixJobTypeLabel            = "radix-job-type"
	RadixJobTypeBuild            = "build"
	RadixAppAliasLabel           = "radix-app-alias"
	RadixExternalAliasLabel      = "radix-app-external-alias"
	RadixActiveClusterAliasLabel = "radix-app-active-cluster-alias"
)

// Kube  Stuct for accessing lower level kubernetes functions
type Kube struct {
	kubeClient kubernetes.Interface
}

var logger *log.Entry

func init() {
	logger = log.WithFields(log.Fields{"radixOperatorComponent": "kube-api"})
}

// New Constructor
func New(client kubernetes.Interface) (*Kube, error) {
	kube := &Kube{
		kubeClient: client,
	}
	return kube, nil
}
