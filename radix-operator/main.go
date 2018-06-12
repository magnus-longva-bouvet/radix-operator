package main

import (
	"net/http"
	"os"
	"os/signal"
	"syscall"

	log "github.com/Sirupsen/logrus"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/statoil/radix-operator/pkg/apis/brigade"
	radixclient "github.com/statoil/radix-operator/pkg/client/clientset/versioned"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

func main() {
	client, radixClient := getKubernetesClient()

	stop := make(chan struct{})
	defer close(stop)

	go startMetricsServer(stop)

	brigadeGateway, err := brigade.New(client)
	if err != nil {
		log.Fatalf("Could not create Brigade gateway: %v", err)
	}

	appHandler := &RadixAppHandler{
		clientset: client,
		brigade:   brigadeGateway,
	}

	appController := NewAppController(client, radixClient, appHandler)
	go appController.Run(stop)

	deployHandler := &RadixDeployHandler{
		clientset: client,
	}

	deployController := NewDeployController(client, radixClient, deployHandler)
	go deployController.Run(stop)

	sigTerm := make(chan os.Signal, 1)
	signal.Notify(sigTerm, syscall.SIGTERM)
	signal.Notify(sigTerm, syscall.SIGINT)
	<-sigTerm
}

func startMetricsServer(stop <-chan struct{}) {
	srv := &http.Server{Addr: ":9000"}
	http.Handle("/metrics", promhttp.Handler())
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
