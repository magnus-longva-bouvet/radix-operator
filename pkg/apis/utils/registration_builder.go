package utils

import (
	"strings"

	"github.com/statoil/radix-operator/pkg/apis/radix/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// RegistrationBuilder Handles construction of RR or applicationRegistation
type RegistrationBuilder interface {
	WithName(name string) RegistrationBuilder
	WithRepository(string) RegistrationBuilder
	WithSharedSecret(string) RegistrationBuilder
	WithAdGroups([]string) RegistrationBuilder
	WithPublicKey(string) RegistrationBuilder
	WithPrivateKey(string) RegistrationBuilder
	WithCloneURL(string) RegistrationBuilder
	WithRadixRegistration(*v1.RadixRegistration) RegistrationBuilder
	BuildRR() *v1.RadixRegistration
}

// RegistrationBuilderStruct Instance variables
type RegistrationBuilderStruct struct {
	name         string
	repository   string
	sharedSecret string
	adGroups     []string
	publicKey    string
	privateKey   string
	cloneURL     string
}

func (rb *RegistrationBuilderStruct) WithRadixRegistration(radixRegistration *v1.RadixRegistration) RegistrationBuilder {
	rb.WithName(radixRegistration.Name)
	rb.WithCloneURL(radixRegistration.Spec.CloneURL)
	rb.WithSharedSecret(radixRegistration.Spec.SharedSecret)
	rb.WithAdGroups(radixRegistration.Spec.AdGroups)
	rb.WithPublicKey(radixRegistration.Spec.DeployKeyPublic)
	rb.WithPrivateKey(radixRegistration.Spec.DeployKey)
	return rb
}

func (rb *RegistrationBuilderStruct) WithName(name string) RegistrationBuilder {
	rb.name = name
	return rb
}

func (rb *RegistrationBuilderStruct) WithRepository(repository string) RegistrationBuilder {
	rb.repository = repository
	return rb
}

func (rb *RegistrationBuilderStruct) WithCloneURL(cloneURL string) RegistrationBuilder {
	rb.cloneURL = cloneURL
	return rb
}

func (rb *RegistrationBuilderStruct) WithSharedSecret(sharedSecret string) RegistrationBuilder {
	rb.sharedSecret = sharedSecret
	return rb
}

func (rb *RegistrationBuilderStruct) WithAdGroups(adGroups []string) RegistrationBuilder {
	rb.adGroups = adGroups
	return rb
}

func (rb *RegistrationBuilderStruct) WithPublicKey(publicKey string) RegistrationBuilder {
	rb.publicKey = strings.TrimSuffix(publicKey, "\n")
	return rb
}

func (rb *RegistrationBuilderStruct) WithPrivateKey(privateKey string) RegistrationBuilder {
	rb.privateKey = privateKey
	return rb
}

func (rb *RegistrationBuilderStruct) BuildRR() *v1.RadixRegistration {
	cloneURL := rb.cloneURL
	if cloneURL == "" {
		cloneURL = GetGithubCloneURLFromRepo(rb.repository)
	}

	radixRegistration := &v1.RadixRegistration{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "radix.equinor.com/v1",
			Kind:       "RadixRegistration",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      rb.name,
			Namespace: corev1.NamespaceDefault,
		},
		Spec: v1.RadixRegistrationSpec{
			CloneURL:        cloneURL,
			SharedSecret:    rb.sharedSecret,
			DeployKey:       rb.privateKey,
			DeployKeyPublic: rb.publicKey,
			AdGroups:        rb.adGroups,
		},
	}
	return radixRegistration
}

// NewRegistrationBuilder Constructor for registration builder
func NewRegistrationBuilder() RegistrationBuilder {
	return &RegistrationBuilderStruct{}
}

// ARadixRegistration Constructor for registration builder containing test data
func ARadixRegistration() RegistrationBuilder {
	builder := NewRegistrationBuilder().
		WithName("anyapp").
		WithCloneURL("git@github.com:Statoil/anyapp").
		WithSharedSecret("NotSoSecret")

	return builder
}
