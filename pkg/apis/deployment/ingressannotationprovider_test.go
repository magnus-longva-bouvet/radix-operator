package deployment

import (
	"errors"
	"testing"

	maputils "github.com/equinor/radix-common/utils/maps"
	"github.com/equinor/radix-operator/pkg/apis/defaults"
	v1 "github.com/equinor/radix-operator/pkg/apis/radix/v1"
	"github.com/equinor/radix-operator/pkg/apis/utils"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

func Test_NewForceSslRedirectAnnotationProvider(t *testing.T) {
	sut := NewForceSslRedirectAnnotationProvider()
	assert.IsType(t, &forceSslRedirectAnnotationProvider{}, sut)
}

func Test_NewIngressConfigurationAnnotationProvider(t *testing.T) {
	cfg := IngressConfiguration{[]AnnotationConfiguration{{Name: "test"}}}
	sut := NewIngressConfigurationAnnotationProvider(cfg)
	assert.IsType(t, &ingressConfigurationAnnotationProvider{}, sut)
	sutReal := sut.(*ingressConfigurationAnnotationProvider)
	assert.Equal(t, cfg, sutReal.config)
}

func Test_NewClientCertificateAnnotationProvider(t *testing.T) {
	sut := NewClientCertificateAnnotationProvider("anynamespace")
	assert.IsType(t, &clientCertificateAnnotationProvider{}, sut)
	sutReal := sut.(*clientCertificateAnnotationProvider)
	assert.Equal(t, "anynamespace", sutReal.namespace)
}

func Test_NewOAuth2AnnotationProvider(t *testing.T) {
	cfg := defaults.MockOAuth2Config{}
	sut := NewOAuth2AnnotationProvider(&cfg)
	assert.IsType(t, &oauth2AnnotationProvider{}, sut)
	sutReal := sut.(*oauth2AnnotationProvider)
	assert.Equal(t, &cfg, sutReal.oauth2DefaultConfig)
}

func Test_ForceSslRedirectAnnotations(t *testing.T) {
	sslAnnotations := forceSslRedirectAnnotationProvider{}
	expected := map[string]string{"nginx.ingress.kubernetes.io/force-ssl-redirect": "true"}
	actual, err := sslAnnotations.GetAnnotations(&v1.RadixDeployComponent{})
	assert.Nil(t, err)
	assert.Equal(t, expected, actual)
}

func Test_IngressConfigurationAnnotations(t *testing.T) {
	config := IngressConfiguration{
		AnnotationConfigurations: []AnnotationConfiguration{
			{Name: "ewma", Annotations: map[string]string{"ewma1": "x", "ewma2": "y"}},
			{Name: "socket", Annotations: map[string]string{"socket1": "x", "socket2": "y", "socket3": "z"}},
			{Name: "round-robin", Annotations: map[string]string{"round-robin1": "1"}},
		},
	}
	componentIngress := ingressConfigurationAnnotationProvider{config: config}

	annotations, err := componentIngress.GetAnnotations(&v1.RadixDeployComponent{IngressConfiguration: []string{"socket"}})
	assert.Nil(t, err)
	assert.Equal(t, 3, len(annotations))
	assert.Equal(t, config.AnnotationConfigurations[1].Annotations, annotations)

	annotations, err = componentIngress.GetAnnotations(&v1.RadixDeployComponent{IngressConfiguration: []string{"socket", "round-robin"}})
	assert.Nil(t, err)
	assert.Equal(t, 4, len(annotations))
	assert.Equal(t, maputils.MergeMaps(config.AnnotationConfigurations[1].Annotations, config.AnnotationConfigurations[2].Annotations), annotations)

	annotations, err = componentIngress.GetAnnotations(&v1.RadixDeployComponent{IngressConfiguration: []string{"non-existing"}})
	assert.Nil(t, err)
	assert.Equal(t, 0, len(annotations))
}

func Test_ClientCertificateAnnotations(t *testing.T) {
	verification := v1.VerificationTypeOptional

	expect1 := make(map[string]string)
	expect1["nginx.ingress.kubernetes.io/auth-tls-pass-certificate-to-upstream"] = "true"
	expect1["nginx.ingress.kubernetes.io/auth-tls-verify-client"] = string(v1.VerificationTypeOff)
	expect1["nginx.ingress.kubernetes.io/auth-tls-secret"] = utils.GetComponentClientCertificateSecretName("ns/name")

	expect2 := make(map[string]string)
	expect2["nginx.ingress.kubernetes.io/auth-tls-pass-certificate-to-upstream"] = "false"
	expect2["nginx.ingress.kubernetes.io/auth-tls-verify-client"] = string(v1.VerificationTypeOff)

	expect3 := make(map[string]string)
	expect3["nginx.ingress.kubernetes.io/auth-tls-pass-certificate-to-upstream"] = "false"
	expect3["nginx.ingress.kubernetes.io/auth-tls-verify-client"] = string(verification)
	expect3["nginx.ingress.kubernetes.io/auth-tls-secret"] = utils.GetComponentClientCertificateSecretName("ns/name")

	config1 := &v1.Authentication{
		ClientCertificate: &v1.ClientCertificate{
			PassCertificateToUpstream: utils.BoolPtr(true),
		},
	}

	config2 := &v1.Authentication{
		ClientCertificate: &v1.ClientCertificate{
			PassCertificateToUpstream: utils.BoolPtr(false),
		},
	}

	config3 := &v1.Authentication{
		ClientCertificate: &v1.ClientCertificate{
			Verification: &verification,
		},
	}

	ingressAnnotations := clientCertificateAnnotationProvider{namespace: "ns"}
	result, err := ingressAnnotations.GetAnnotations(&v1.RadixDeployComponent{Name: "name", Authentication: config1})
	assert.Nil(t, err)
	assert.Equal(t, expect1, result)

	result, err = ingressAnnotations.GetAnnotations(&v1.RadixDeployComponent{Name: "name", Authentication: config2})
	assert.Nil(t, err)
	assert.Equal(t, expect2, result)

	result, err = ingressAnnotations.GetAnnotations(&v1.RadixDeployComponent{Name: "name", Authentication: config3})
	assert.Nil(t, err)
	assert.Equal(t, expect3, result)

	result, err = ingressAnnotations.GetAnnotations(&v1.RadixDeployComponent{Name: "name"})
	assert.Nil(t, err)
	assert.Empty(t, result, "Expected Annotations to be empty")
}

type OAuth2AnnotationsTestSuite struct {
	suite.Suite
	oauth2Config *defaults.MockOAuth2Config
	ctrl         *gomock.Controller
}

func TestOAuth2AnnotationsTestSuite(t *testing.T) {
	suite.Run(t, new(OAuth2AnnotationsTestSuite))
}

func (s *OAuth2AnnotationsTestSuite) SetupTest() {
	s.ctrl = gomock.NewController(s.T())
	s.oauth2Config = defaults.NewMockOAuth2Config(s.ctrl)
}

func (s *OAuth2AnnotationsTestSuite) TearDownTest() {
	s.ctrl.Finish()
}

func (s *OAuth2AnnotationsTestSuite) Test_NonPublicComponent() {
	s.oauth2Config.EXPECT().MergeWith(gomock.Any()).Times(0)
	sut := oauth2AnnotationProvider{oauth2DefaultConfig: s.oauth2Config}
	actual, err := sut.GetAnnotations(&v1.RadixDeployComponent{Authentication: &v1.Authentication{OAuth2: &v1.OAuth2{ClientID: "1234"}}})
	s.Nil(err)
	s.Len(actual, 0)
}

func (s *OAuth2AnnotationsTestSuite) Test_PublicComponentNoOAuth() {
	s.oauth2Config.EXPECT().MergeWith(gomock.Any()).Times(0)
	sut := oauth2AnnotationProvider{oauth2DefaultConfig: s.oauth2Config}
	actual, err := sut.GetAnnotations(&v1.RadixDeployComponent{PublicPort: "http", Authentication: &v1.Authentication{}})
	s.Nil(err)
	s.Len(actual, 0)
}

func (s *OAuth2AnnotationsTestSuite) Test_ComponentOAuthPassedToOAuth2Config() {
	oauth := &v1.OAuth2{ClientID: "1234"}
	s.oauth2Config.EXPECT().MergeWith(oauth).Times(1).Return(&v1.OAuth2{}, nil)
	sut := oauth2AnnotationProvider{oauth2DefaultConfig: s.oauth2Config}
	sut.GetAnnotations(&v1.RadixDeployComponent{PublicPort: "http", Authentication: &v1.Authentication{OAuth2: oauth}})
}

func (s *OAuth2AnnotationsTestSuite) Test_AuthSigninAndUrlAnnotations() {
	s.oauth2Config.EXPECT().MergeWith(gomock.Any()).Times(1).Return(&v1.OAuth2{ProxyPrefix: "/anypath"}, nil)
	expected := map[string]string{
		"nginx.ingress.kubernetes.io/auth-signin": "https://$host/anypath/start?rd=$escaped_request_uri",
		"nginx.ingress.kubernetes.io/auth-url":    "https://$host/anypath/auth",
	}
	sut := oauth2AnnotationProvider{oauth2DefaultConfig: s.oauth2Config}
	actual, err := sut.GetAnnotations(&v1.RadixDeployComponent{PublicPort: "http", Authentication: &v1.Authentication{OAuth2: &v1.OAuth2{}}})
	s.Nil(err)
	s.Equal(expected, actual)
}

func (s *OAuth2AnnotationsTestSuite) Test_AuthResponseHeaderAnnotations_All() {
	s.oauth2Config.EXPECT().MergeWith(gomock.Any()).Times(1).Return(&v1.OAuth2{SetXAuthRequestHeaders: utils.BoolPtr(true), SetAuthorizationHeader: utils.BoolPtr(true)}, nil)
	sut := oauth2AnnotationProvider{oauth2DefaultConfig: s.oauth2Config}
	actual, err := sut.GetAnnotations(&v1.RadixDeployComponent{PublicPort: "http", Authentication: &v1.Authentication{OAuth2: &v1.OAuth2{}}})
	s.Nil(err)
	s.Equal("X-Auth-Request-Access-Token,X-Auth-Request-User,X-Auth-Request-Groups,X-Auth-Request-Email,X-Auth-Request-Preferred-Username,Authorization", actual["nginx.ingress.kubernetes.io/auth-response-headers"])
}

func (s *OAuth2AnnotationsTestSuite) Test_AuthResponseHeaderAnnotations_XAuthHeadersOnly() {
	s.oauth2Config.EXPECT().MergeWith(gomock.Any()).Times(1).Return(&v1.OAuth2{SetXAuthRequestHeaders: utils.BoolPtr(true), SetAuthorizationHeader: utils.BoolPtr(false)}, nil)
	sut := oauth2AnnotationProvider{oauth2DefaultConfig: s.oauth2Config}
	actual, err := sut.GetAnnotations(&v1.RadixDeployComponent{PublicPort: "http", Authentication: &v1.Authentication{OAuth2: &v1.OAuth2{}}})
	s.Nil(err)
	s.Equal("X-Auth-Request-Access-Token,X-Auth-Request-User,X-Auth-Request-Groups,X-Auth-Request-Email,X-Auth-Request-Preferred-Username", actual["nginx.ingress.kubernetes.io/auth-response-headers"])
}

func (s *OAuth2AnnotationsTestSuite) Test_AuthResponseHeaderAnnotations_AuthorizationHeaderOnly() {
	s.oauth2Config.EXPECT().MergeWith(gomock.Any()).Times(1).Return(&v1.OAuth2{SetXAuthRequestHeaders: utils.BoolPtr(false), SetAuthorizationHeader: utils.BoolPtr(true)}, nil)
	sut := oauth2AnnotationProvider{oauth2DefaultConfig: s.oauth2Config}
	actual, err := sut.GetAnnotations(&v1.RadixDeployComponent{PublicPort: "http", Authentication: &v1.Authentication{OAuth2: &v1.OAuth2{}}})
	s.Nil(err)
	s.Equal("Authorization", actual["nginx.ingress.kubernetes.io/auth-response-headers"])
}

func (s *OAuth2AnnotationsTestSuite) Test_OAuthConfig_ApplyTo_ReturnError() {
	s.oauth2Config.EXPECT().MergeWith(gomock.Any()).Times(1).Return(&v1.OAuth2{SetXAuthRequestHeaders: utils.BoolPtr(false), SetAuthorizationHeader: utils.BoolPtr(true)}, errors.New("any error"))
	sut := oauth2AnnotationProvider{oauth2DefaultConfig: s.oauth2Config}
	actual, err := sut.GetAnnotations(&v1.RadixDeployComponent{PublicPort: "http", Authentication: &v1.Authentication{OAuth2: &v1.OAuth2{}}})
	s.Error(err)
	s.Nil(actual)
}
