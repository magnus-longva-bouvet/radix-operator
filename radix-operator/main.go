package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	log "github.com/Sirupsen/logrus"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	radixclient "github.com/statoil/radix-operator/pkg/client/clientset/versioned"
	"github.com/statoil/radix-operator/radix-operator/application"
	"github.com/statoil/radix-operator/radix-operator/deployment"
	"github.com/statoil/radix-operator/radix-operator/registration"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

func main() {
	client, radixClient := getKubernetesClient()

	stop := make(chan struct{})
	defer close(stop)

	go startMetricsServer(stop)

	startRegistrationController(client, radixClient, stop)
	startApplicationController(client, radixClient, stop)
	startDeploymentController(client, radixClient, stop)

	sigTerm := make(chan os.Signal, 1)
	signal.Notify(sigTerm, syscall.SIGTERM)
	signal.Notify(sigTerm, syscall.SIGINT)
	<-sigTerm
}

func startRegistrationController(client kubernetes.Interface, radixClient radixclient.Interface, stop <-chan struct{}) {
	handler := registration.NewRegistrationHandler(client)
	registrationController := registration.NewController(client, radixClient, &handler)

	go registrationController.Run(stop)
}

func startApplicationController(client kubernetes.Interface, radixClient radixclient.Interface, stop <-chan struct{}) {
	applicationController := application.NewController(client, radixClient)

	go applicationController.Run(stop)
}

func startDeploymentController(client kubernetes.Interface, radixClient radixclient.Interface, stop <-chan struct{}) {
	deployHandler := deployment.NewDeployHandler(client, radixClient)

	deployController := deployment.NewDeployController(client, radixClient, &deployHandler)
	go deployController.Run(stop)
}

func startMetricsServer(stop <-chan struct{}) {
	srv := &http.Server{Addr: ":9000"}
	http.Handle("/metrics", promhttp.Handler())
	http.Handle("/healthz", http.HandlerFunc(Healthz))
	go func() {
		if err := srv.ListenAndServe(); err != nil {
			log.Printf("MetricServer: ListenAndServe() error: %s", err)
		}
	}()
	<-stop
	if err := srv.Shutdown(nil); err != nil {
		panic(err)
	}
}

type HealthStatus struct {
	Status int
}

func Healthz(writer http.ResponseWriter, r *http.Request) {
	health := HealthStatus{
		Status: http.StatusOK,
	}

	response, err := json.Marshal(health)

	if err != nil {
		http.Error(writer, "Error while retrieving HealthStatus", http.StatusInternalServerError)
		log.Errorf("Could not serialize HealthStatus: %v", err)
		return
	}

	fmt.Fprintf(writer, "%s", response)
}

func getKubernetesClient() (kubernetes.Interface, radixclient.Interface) {
	kubeConfigPath := os.Getenv("HOME") + "/.kube/config"
	config, err := clientcmd.BuildConfigFromFlags("", kubeConfigPath)
	if err != nil {
		config, err = rest.InClusterConfig()
		if err != nil {
			log.Fatalf("getClusterConfig InClusterConfig: %v", err)
		}
	}

	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatalf("getClusterConfig k8s client: %v", err)
	}

	radixClient, err := radixclient.NewForConfig(config)
	if err != nil {
		log.Fatalf("getClusterConfig radix client: %v", err)
	}

	log.Print("Successfully constructed k8s client")
	return client, radixClient
}
