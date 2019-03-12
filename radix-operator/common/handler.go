package common

import "k8s.io/client-go/tools/record"

// HasSynced Handler to function to report back on sync
type HasSynced func(bool)

// Handler Common handler interface
type Handler interface {
	Sync(namespace, name string, eventRecorder record.EventRecorder) error
}
