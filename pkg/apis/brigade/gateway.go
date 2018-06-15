package brigade

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"

	log "github.com/Sirupsen/logrus"
	"github.com/prometheus/client_golang/prometheus"
	radix_v1 "github.com/statoil/radix-operator/pkg/apis/radix/v1"
	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
)

var projectPrefix = "Statoil/"

const namespace = "default"

var projectCounter = prometheus.NewCounter(prometheus.CounterOpts{
	Name: "project_created",
	Help: "Number of projects created by the Radix Operator",
})

type BrigadeGateway struct {
	client kubernetes.Interface
}

func init() {
	prometheus.MustRegister(projectCounter)
}

func New(clientset kubernetes.Interface) (*BrigadeGateway, error) {
	if clientset == nil {
		return nil, fmt.Errorf("Missing client")
	}

	gw := &BrigadeGateway{
		client: clientset,
	}
	return gw, nil
}

func (b *BrigadeGateway) EnsureProject(app *radix_v1.RadixRegistration) error {
	create := false
	if b.client == nil {
		return fmt.Errorf("No k8s client available")
	}

	secretName := fmt.Sprintf("brigade-%s", shortSHA(projectPrefix+app.Name))
	log.Infof("Creating/Updating application %s", app.ObjectMeta.Name)
	project, _ := b.getExistingBrigadeProject(secretName)
	if project == nil {
		project = createNewProject(secretName, app.Name, app.UID)
		create = true
	}

	secretsJSON, _ := json.Marshal(app.Spec.Secrets)
	project.StringData = map[string]string{
		"repository":        app.Spec.Repository,
		"sharedSecret":      app.Spec.SharedSecret,
		"cloneURL":          app.Spec.CloneURL,
		"sshKey":            strings.Replace(app.Spec.DeployKey, "\n", "$", -1),
		"initGitSubmodules": "false",
		"defaultScript":     app.Spec.DefaultScript,
		"defaultScriptName": "",
		"secrets":           string(secretsJSON),
	}

	if create {
		createdSecret, err := b.client.CoreV1().Secrets(namespace).Create(project)
		if err != nil {
			return fmt.Errorf("Failed to create Brigade project: %v", err)
		}

		log.Infof("Created: %s", createdSecret.Name)
		projectCounter.Inc()
	} else {
		_, err := b.client.CoreV1().Secrets(namespace).Update(project)
		if err != nil {
			log.Errorf("Failed to update registration: %v", err)
			return err
		}
	}

	return nil
}

func (b *BrigadeGateway) DeleteProject(appName, namespace string) error {
	return nil
}

func (b *BrigadeGateway) AddAppConfigToProject(app *radix_v1.RadixApplication) {
	log.Infof("Updating Brigade project with recent values from RadixApplication %s", app.Name)
	secret, err := b.client.CoreV1().Secrets(namespace).Get(fmt.Sprintf("brigade-%s", shortSHA(projectPrefix+app.Name)), metav1.GetOptions{})
	if err != nil {
		log.Errorf("Failed to retrieve Brigade project: %v", err)
		return
	}

	spec, _ := json.Marshal(app.Spec.Components)
	specJson := strings.Replace(string(spec), "\"", "'", -1)
	secret.Data["secrets"] = []byte(fmt.Sprintf("{\"app\": \"%s\"}", specJson))
	_, err = b.client.CoreV1().Secrets(namespace).Update(secret)
	if err != nil {
		log.Errorf("Failed to update Brigade project: %v", err)
	}
}

func shortSHA(input string) string {
	sum := sha256.Sum256([]byte(input))
	return fmt.Sprintf("%x", sum)[0:54]
}

func (b *BrigadeGateway) getExistingBrigadeProject(name string) (*v1.Secret, error) {
	secret, err := b.client.CoreV1().Secrets(namespace).Get(name, metav1.GetOptions{})
	if secret != nil {
		secret.ObjectMeta.Name = name
	}

	if errors.IsNotFound(err) {
		return nil, nil
	}

	return secret, err
}

func createNewProject(name, appName string, ownerID types.UID) *v1.Secret {
	trueVar := true

	project := &v1.Secret{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Secret",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Labels: map[string]string{
				"app":       "brigade",
				"component": "project",
				"radixApp":  appName,
			},
			Annotations: map[string]string{
				"projectName": projectPrefix + appName,
			},
			OwnerReferences: []metav1.OwnerReference{
				metav1.OwnerReference{
					APIVersion: "radix.equinor.com/v1", //need to hardcode these values for now - seems they are missing from the CRD in k8s 1.8
					Kind:       "RadixRegistration",
					Name:       appName,
					UID:        ownerID,
					Controller: &trueVar,
				},
			},
		},
		Type: "brigade.sh/project",
	}
	return project
}
