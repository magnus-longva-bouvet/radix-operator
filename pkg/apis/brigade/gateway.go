package brigade

import (
	log "github.com/Sirupsen/logrus"
	radix_v1 "github.com/statoil/radix-operator/pkg/apis/radix/v1"
	"k8s.io/client-go/kubernetes"
)

type BrigadeGateway struct {
	clientset kubernetes.Interface
}

func (b *BrigadeGateway) EnsureProject(app *radix_v1.RadixApplication) {
	log.Infof("Creating/Updating application %s", app.ObjectMeta.Name)
}

func (b *BrigadeGateway) DeleteProject(key string) {
	log.Infof("Removing project %s", key)
}
