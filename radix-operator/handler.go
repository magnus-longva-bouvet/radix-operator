package main

import (
	"strings"

	log "github.com/Sirupsen/logrus"
	"github.com/statoil/radix-operator/pkg/apis/brigade"
	"github.com/statoil/radix-operator/pkg/apis/radix/v1"
	"k8s.io/client-go/kubernetes"
)

type Handler interface {
	Init() error
	ObjectCreated(obj interface{})
	ObjectDeleted(key string)
	ObjectUpdated(objOld, objNew interface{})
}

type RadixAppHandler struct {
	clientset kubernetes.Interface
	brigade   *brigade.BrigadeGateway
}

// Init handles any handler initialization
func (t *RadixAppHandler) Init() error {
	log.Info("RadixAppHandler.Init")
	return nil
}

// ObjectCreated is called when an object is created
func (t *RadixAppHandler) ObjectCreated(obj interface{}) {
	log.Info("RadixAppHandler.ObjectCreated")
	radixApp, ok := obj.(*v1.RadixApplication)
	if !ok {
		log.Errorf("Provided object was not a valid Radix Application; instead was %v", obj)
		return
	}
	t.brigade.EnsureProject(radixApp)
}

// ObjectDeleted is called when an object is deleted
func (t *RadixAppHandler) ObjectDeleted(key string) {
	log.Info("RadixAppHandler.ObjectDeleted")
	str := strings.Split(key, "/")
	t.brigade.DeleteProject(str[1], str[0])
}

// ObjectUpdated is called when an object is updated
func (t *RadixAppHandler) ObjectUpdated(objOld, objNew interface{}) {
	log.Info("RadixAppHandler.ObjectUpdated")
	err := t.brigade.EnsureProject(objNew.(*v1.RadixApplication))
	if err != nil {
		log.Errorf("Failed to create/update project: %v", err)
	}
}
