package steps

import (
	"context"
	"fmt"
	"strings"
	"testing"

	application "github.com/equinor/radix-operator/pkg/apis/applicationconfig"
	"github.com/equinor/radix-operator/pkg/apis/kube"
	v1 "github.com/equinor/radix-operator/pkg/apis/radix/v1"
	"github.com/equinor/radix-operator/pkg/apis/utils"
	"github.com/equinor/radix-operator/pkg/apis/utils/numbers"
	monitoring "github.com/prometheus-operator/prometheus-operator/pkg/client/versioned"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/equinor/radix-operator/pipeline-runner/model"
	"github.com/equinor/radix-operator/pkg/apis/test"
)

func TestPromote_ErrorScenarios_ErrorIsReturned(t *testing.T) {
	anyApp1 := "any-app-1"
	anyApp2 := "any-app-2"
	anyApp4 := "any-app-4"
	anyApp5 := "any-app-5"
	anyDeployment1 := "1"
	anyDeployment2 := "2"
	anyDeployment3 := "3"
	anyDeployment4 := "4"
	anyDeployment5 := "5"
	anyProdEnvironment := "prod"
	anyDevEnvironment := "dev"
	anyQAEnvironment := "qa"
	anyImageTag := "abcdef"
	anyJobName := "radix-pipeline-abcdef"
	nonExistingComponent := "non-existing-comp"
	nonExistingJobComponent := "non-existing-job"

	// Setup
	kubeclient, kube, radixclient, commonTestUtils, env := setupTest(t)

	commonTestUtils.ApplyDeployment(utils.
		ARadixDeployment().
		WithDeploymentName(anyDeployment1).
		WithAppName(anyApp1).
		WithEnvironment(anyProdEnvironment).
		WithImageTag(anyImageTag))

	commonTestUtils.ApplyDeployment(utils.
		ARadixDeployment().
		WithDeploymentName(anyDeployment2).
		WithAppName(anyApp1).
		WithEnvironment(anyDevEnvironment).
		WithImageTag(anyImageTag))

	commonTestUtils.ApplyDeployment(utils.
		ARadixDeployment().
		WithDeploymentName(anyDeployment3).
		WithAppName(anyApp2).
		WithEnvironment(anyDevEnvironment).
		WithImageTag(anyImageTag))

	commonTestUtils.ApplyDeployment(utils.
		ARadixDeployment().
		WithDeploymentName(anyDeployment4).
		WithAppName(anyApp4).
		WithEnvironment(anyDevEnvironment).
		WithImageTag(anyImageTag).
		WithComponent(utils.
			NewDeployComponentBuilder().
			WithName(nonExistingComponent)))

	commonTestUtils.ApplyDeployment(utils.
		ARadixDeployment().
		WithDeploymentName(anyDeployment5).
		WithAppName(anyApp5).
		WithEnvironment(anyDevEnvironment).
		WithImageTag(anyImageTag).
		WithJobComponent(utils.
			NewDeployJobComponentBuilder().
			WithName(nonExistingJobComponent)))

	test.CreateEnvNamespace(kubeclient, anyApp2, anyProdEnvironment)

	var testScenarios = []struct {
		name            string
		appName         string
		fromEnvironment string
		imageTag        string
		jobName         string
		toEnvironment   string
		deploymentName  string
		expectedError   error
	}{
		{"empty from environment", anyApp1, "", anyImageTag, anyJobName, anyProdEnvironment, anyDeployment2, EmptyArgument("From environment")},
		{"empty to environment", anyApp1, anyDevEnvironment, anyImageTag, anyJobName, "", anyDeployment2, EmptyArgument("To environment")},
		{"empty image tag", anyApp1, anyDevEnvironment, "", anyJobName, anyProdEnvironment, anyDeployment2, EmptyArgument("Image tag")},
		{"empty job name", anyApp1, anyDevEnvironment, anyImageTag, "", anyProdEnvironment, anyDeployment2, EmptyArgument("Job name")},
		{"empty deployment name", anyApp1, anyDevEnvironment, anyImageTag, anyJobName, anyProdEnvironment, "", EmptyArgument("Deployment name")},
		{"promote from non-existing environment", anyApp1, anyQAEnvironment, anyImageTag, anyJobName, anyProdEnvironment, anyDeployment2, NonExistingFromEnvironment(anyQAEnvironment)},
		{"promote to non-existing environment", anyApp1, anyDevEnvironment, anyImageTag, anyJobName, anyQAEnvironment, anyDeployment2, NonExistingToEnvironment(anyQAEnvironment)},
		{"promote non-existing deployment", anyApp2, anyDevEnvironment, "nopqrst", anyJobName, anyProdEnvironment, "non-existing", NonExistingDeployment("non-existing")},
		{"promote deployment with non-existing component", anyApp4, anyDevEnvironment, anyImageTag, anyJobName, anyDevEnvironment, anyDeployment4, NonExistingComponentName(anyApp4, nonExistingComponent)},
		{"promote deployment with non-existing job component", anyApp5, anyDevEnvironment, anyImageTag, anyJobName, anyDevEnvironment, anyDeployment5, NonExistingComponentName(anyApp5, nonExistingJobComponent)},
	}

	for _, scenario := range testScenarios {
		t.Run(scenario.name, func(t *testing.T) {
			rr, _ := radixclient.RadixV1().RadixRegistrations().Get(context.TODO(), scenario.appName, metav1.GetOptions{})

			cli := NewPromoteStep()
			cli.Init(kubeclient, radixclient, kube, &monitoring.Clientset{}, rr, env)

			pipelineInfo := &model.PipelineInfo{
				PipelineArguments: model.PipelineArguments{
					FromEnvironment: scenario.fromEnvironment,
					ToEnvironment:   scenario.toEnvironment,
					DeploymentName:  scenario.deploymentName,
					JobName:         scenario.jobName,
					ImageTag:        scenario.imageTag,
					CommitID:        anyCommitID,
				},
			}

			err := cli.Run(pipelineInfo)
			assert.Error(t, err)

			if scenario.expectedError != nil {
				assert.Equal(t, scenario.expectedError.Error(), err.Error())
			}
		})
	}
}

func TestPromote_PromoteToOtherEnvironment_NewStateIsExpected(t *testing.T) {
	anyApp := "any-app"
	anyDeploymentName := "deployment-1"
	anyImageTag := "abcdef"
	anyBuildDeployJobName := "any-build-deploy-job"
	anyPromoteJobName := "any-promote-job"
	anyProdEnvironment := "prod"
	anyDevEnvironment := "dev"
	anyDNSAlias := "a-dns-alias"
	prodNode := v1.RadixNode{Gpu: "prod-gpu", GpuCount: "2"}

	// Setup
	kubeclient, kubeUtil, radixclient, commonTestUtils, env := setupTest(t)

	secretType := v1.RadixAzureKeyVaultObjectTypeSecret
	keyType := v1.RadixAzureKeyVaultObjectTypeKey
	commonTestUtils.ApplyDeployment(
		utils.NewDeploymentBuilder().
			WithComponent(
				utils.NewDeployComponentBuilder().
					WithName("app").
					WithSecrets([]string{"DEPLOYAPPSECRET"}).
					WithNodeGpu("dev-gpu").
					WithNodeGpuCount("1"),
			).
			WithJobComponent(
				utils.NewDeployJobComponentBuilder().
					WithName("job").
					WithSecrets([]string{"DEPLOYJOBSECRET"}),
			).
			WithRadixApplication(
				utils.NewRadixApplicationBuilder().
					WithRadixRegistration(
						utils.ARadixRegistration().
							WithName(anyApp)).
					WithAppName(anyApp).
					WithEnvironment(anyDevEnvironment, "master").
					WithEnvironment(anyProdEnvironment, "").
					WithDNSAppAlias(anyProdEnvironment, "app").
					WithDNSExternalAlias(anyDNSAlias, anyProdEnvironment, "app").
					WithComponents(
						utils.AnApplicationComponent().
							WithName("app").
							WithSecrets("APPSECRET1", "APPSECRET2").
							WithCommonEnvironmentVariable("DB_TYPE", "mysql").
							WithCommonEnvironmentVariable("DB_NAME", "my-db").
							WithSecretRefs(v1.RadixSecretRefs{AzureKeyVaults: []v1.RadixAzureKeyVault{{
								Name: "TestKeyVault2",
								Items: []v1.RadixAzureKeyVaultItem{
									{
										Name:   "Secret2",
										EnvVar: "SECRET_2",
										Type:   &secretType,
									},
									{
										Name:   "Key2",
										EnvVar: "KEY_2",
										Type:   &keyType,
									},
								},
							}}}).
							WithEnvironmentConfigs(
								utils.AnEnvironmentConfig().
									WithEnvironment(anyDevEnvironment).
									WithReplicas(test.IntPtr(2)).
									WithEnvironmentVariable("DB_HOST", "db-dev").
									WithEnvironmentVariable("DB_PORT", "1234"),
								utils.AnEnvironmentConfig().
									WithEnvironment(anyProdEnvironment).
									WithReplicas(test.IntPtr(4)).
									WithEnvironmentVariable("DB_HOST", "db-prod").
									WithEnvironmentVariable("DB_PORT", "5678").
									WithEnvironmentVariable("DB_NAME", "my-db-prod").
									WithNode(prodNode))).
					WithJobComponents(
						utils.AnApplicationJobComponent().
							WithName("job").
							WithSchedulerPort(numbers.Int32Ptr(8888)).
							WithPayloadPath(utils.StringPtr("/path")).
							WithSecrets("JOBSECRET1", "JOBSECRET2").
							WithCommonEnvironmentVariable("COMMON1", "common1").
							WithCommonEnvironmentVariable("COMMON2", "common2").
							WithSecretRefs(v1.RadixSecretRefs{AzureKeyVaults: []v1.RadixAzureKeyVault{{
								Name: "TestKeyVault",
								Items: []v1.RadixAzureKeyVaultItem{
									{
										Name:   "Secret1",
										EnvVar: "SECRET_1",
										Type:   &secretType,
									},
									{
										Name:   "Key1",
										EnvVar: "KEY_1",
										Type:   &keyType,
									},
								},
							}}}).
							WithEnvironmentConfigs(
								utils.AJobComponentEnvironmentConfig().
									WithEnvironment(anyDevEnvironment).
									WithEnvironmentVariable("COMMON1", "dev1").
									WithEnvironmentVariable("COMMON2", "dev2"),
								utils.AJobComponentEnvironmentConfig().
									WithEnvironment(anyProdEnvironment).
									WithEnvironmentVariable("COMMON1", "prod1").
									WithEnvironmentVariable("PROD3", "prod3"),
							),
					)).
			WithAppName(anyApp).
			WithDeploymentName(anyDeploymentName).
			WithEnvironment(anyDevEnvironment).
			WithImageTag(anyImageTag).
			WithLabel(kube.RadixJobNameLabel, anyBuildDeployJobName))

	// Create prod environment without any deployments
	test.CreateEnvNamespace(kubeclient, anyApp, anyProdEnvironment)

	rr, _ := radixclient.RadixV1().RadixRegistrations().Get(context.TODO(), anyApp, metav1.GetOptions{})
	ra, _ := radixclient.RadixV1().RadixApplications(utils.GetAppNamespace(anyApp)).Get(context.TODO(), anyApp, metav1.GetOptions{})

	cli := NewPromoteStep()
	cli.Init(kubeclient, radixclient, kubeUtil, &monitoring.Clientset{}, rr, env)

	pipelineInfo := &model.PipelineInfo{
		PipelineArguments: model.PipelineArguments{
			FromEnvironment: anyDevEnvironment,
			ToEnvironment:   anyProdEnvironment,
			DeploymentName:  anyDeploymentName,
			JobName:         anyPromoteJobName,
			ImageTag:        anyImageTag,
			CommitID:        anyCommitID,
		},
	}

	applicationConfig, _ := application.NewApplicationConfig(kubeclient, kubeUtil, radixclient, rr, ra)
	gitCommitHash := pipelineInfo.GitCommitHash
	gitTags := pipelineInfo.GitTags
	pipelineInfo.SetApplicationConfig(applicationConfig)
	pipelineInfo.SetGitAttributes(gitCommitHash, gitTags)
	err := cli.Run(pipelineInfo)
	assert.NoError(t, err)

	rds, _ := radixclient.RadixV1().RadixDeployments(utils.GetEnvironmentNamespace(anyApp, anyProdEnvironment)).List(context.TODO(), metav1.ListOptions{})
	assert.Equal(t, 1, len(rds.Items))
	assert.True(t, strings.HasPrefix(rds.Items[0].Name, fmt.Sprintf("%s-%s-", anyProdEnvironment, anyImageTag)))
	assert.Equal(t, anyProdEnvironment, rds.Items[0].Labels[kube.RadixEnvLabel])
	assert.Equal(t, anyImageTag, rds.Items[0].Labels[kube.RadixImageTagLabel])
	assert.Equal(t, anyPromoteJobName, rds.Items[0].Labels[kube.RadixJobNameLabel])
	assert.Equal(t, 4, *rds.Items[0].Spec.Components[0].Replicas)
	assert.Equal(t, "db-prod", rds.Items[0].Spec.Components[0].EnvironmentVariables["DB_HOST"])
	assert.Equal(t, "5678", rds.Items[0].Spec.Components[0].EnvironmentVariables["DB_PORT"])
	assert.Equal(t, "mysql", rds.Items[0].Spec.Components[0].EnvironmentVariables["DB_TYPE"])
	assert.Equal(t, "my-db-prod", rds.Items[0].Spec.Components[0].EnvironmentVariables["DB_NAME"])
	assert.Equal(t, anyDNSAlias, rds.Items[0].Spec.Components[0].DNSExternalAlias[0])
	assert.True(t, rds.Items[0].Spec.Components[0].DNSAppAlias)
	assert.Len(t, rds.Items[0].Spec.Components[0].Secrets, 1)
	assert.Equal(t, "DEPLOYAPPSECRET", rds.Items[0].Spec.Components[0].Secrets[0])
	assert.Len(t, rds.Items[0].Spec.Components[0].SecretRefs.AzureKeyVaults, 1)
	assert.Len(t, rds.Items[0].Spec.Components[0].SecretRefs.AzureKeyVaults[0].Items, 2)
	assert.Equal(t, "TestKeyVault2", rds.Items[0].Spec.Components[0].SecretRefs.AzureKeyVaults[0].Name)
	assert.Equal(t, "Secret2", rds.Items[0].Spec.Components[0].SecretRefs.AzureKeyVaults[0].Items[0].Name)
	assert.Equal(t, "SECRET_2", rds.Items[0].Spec.Components[0].SecretRefs.AzureKeyVaults[0].Items[0].EnvVar)
	assert.Equal(t, "secret", string(*rds.Items[0].Spec.Components[0].SecretRefs.AzureKeyVaults[0].Items[0].Type))
	assert.Equal(t, "Key2", rds.Items[0].Spec.Components[0].SecretRefs.AzureKeyVaults[0].Items[1].Name)
	assert.Equal(t, "KEY_2", rds.Items[0].Spec.Components[0].SecretRefs.AzureKeyVaults[0].Items[1].EnvVar)
	assert.Equal(t, "key", string(*rds.Items[0].Spec.Components[0].SecretRefs.AzureKeyVaults[0].Items[1].Type))
	assert.Equal(t, prodNode, rds.Items[0].Spec.Components[0].Node)

	assert.Equal(t, 1, len(rds.Items[0].Spec.Jobs))
	assert.Equal(t, 3, len(rds.Items[0].Spec.Jobs[0].EnvironmentVariables))
	assert.Equal(t, "prod1", rds.Items[0].Spec.Jobs[0].EnvironmentVariables["COMMON1"])
	assert.Equal(t, "common2", rds.Items[0].Spec.Jobs[0].EnvironmentVariables["COMMON2"])
	assert.Equal(t, "prod3", rds.Items[0].Spec.Jobs[0].EnvironmentVariables["PROD3"])
	assert.Equal(t, numbers.Int32Ptr(8888), rds.Items[0].Spec.Jobs[0].SchedulerPort)
	assert.Equal(t, "/path", rds.Items[0].Spec.Jobs[0].Payload.Path)
	assert.Len(t, rds.Items[0].Spec.Jobs[0].Secrets, 1)
	assert.Equal(t, "DEPLOYJOBSECRET", rds.Items[0].Spec.Jobs[0].Secrets[0])
	assert.Len(t, rds.Items[0].Spec.Jobs[0].SecretRefs.AzureKeyVaults, 1)
	assert.Len(t, rds.Items[0].Spec.Jobs[0].SecretRefs.AzureKeyVaults[0].Items, 2)
	assert.Equal(t, "TestKeyVault", rds.Items[0].Spec.Jobs[0].SecretRefs.AzureKeyVaults[0].Name)
	assert.Equal(t, "Secret1", rds.Items[0].Spec.Jobs[0].SecretRefs.AzureKeyVaults[0].Items[0].Name)
	assert.Equal(t, "SECRET_1", rds.Items[0].Spec.Jobs[0].SecretRefs.AzureKeyVaults[0].Items[0].EnvVar)
	assert.Equal(t, "secret", string(*rds.Items[0].Spec.Jobs[0].SecretRefs.AzureKeyVaults[0].Items[0].Type))
	assert.Equal(t, "Key1", rds.Items[0].Spec.Jobs[0].SecretRefs.AzureKeyVaults[0].Items[1].Name)
	assert.Equal(t, "KEY_1", rds.Items[0].Spec.Jobs[0].SecretRefs.AzureKeyVaults[0].Items[1].EnvVar)
	assert.Equal(t, "key", string(*rds.Items[0].Spec.Jobs[0].SecretRefs.AzureKeyVaults[0].Items[1].Type))
}

func TestPromote_PromoteToOtherEnvironment_Resources_NoOverride(t *testing.T) {
	anyApp := "any-app"
	anyDeploymentName := "deployment-1"
	anyImageTag := "abcdef"
	anyBuildDeployJobName := "any-build-deploy-job"
	anyPromoteJobName := "any-promote-job"
	anyProdEnvironment := "prod"
	anyDevEnvironment := "dev"

	// Setup
	kubeclient, kubeUtil, radixclient, commonTestUtils, env := setupTest(t)

	commonTestUtils.ApplyDeployment(
		utils.ARadixDeployment().
			WithRadixApplication(
				utils.NewRadixApplicationBuilder().
					WithRadixRegistration(
						utils.ARadixRegistration().
							WithName(anyApp)).
					WithAppName(anyApp).
					WithEnvironment(anyDevEnvironment, "master").
					WithEnvironment(anyProdEnvironment, "").
					WithComponents(
						utils.AnApplicationComponent().
							WithName("app").
							WithCommonResource(map[string]string{
								"memory": "64Mi",
								"cpu":    "250m",
							}, map[string]string{
								"memory": "128Mi",
								"cpu":    "500m",
							})).
					WithJobComponents(
						utils.AnApplicationJobComponent().
							WithName("job").
							WithSchedulerPort(numbers.Int32Ptr(8888)).
							WithCommonResource(map[string]string{
								"memory": "11Mi",
								"cpu":    "22m",
							}, map[string]string{
								"memory": "33Mi",
								"cpu":    "44m",
							}),
					)).
			WithAppName(anyApp).
			WithDeploymentName(anyDeploymentName).
			WithEnvironment(anyDevEnvironment).
			WithImageTag(anyImageTag).
			WithLabel(kube.RadixJobNameLabel, anyBuildDeployJobName))

	// Create prod environment without any deployments
	test.CreateEnvNamespace(kubeclient, anyApp, anyProdEnvironment)

	rr, _ := radixclient.RadixV1().RadixRegistrations().Get(context.TODO(), anyApp, metav1.GetOptions{})
	ra, _ := radixclient.RadixV1().RadixApplications(utils.GetAppNamespace(anyApp)).Get(context.TODO(), anyApp, metav1.GetOptions{})

	cli := NewPromoteStep()
	cli.Init(kubeclient, radixclient, kubeUtil, &monitoring.Clientset{}, rr, env)

	pipelineInfo := &model.PipelineInfo{
		PipelineArguments: model.PipelineArguments{
			FromEnvironment: anyDevEnvironment,
			ToEnvironment:   anyProdEnvironment,
			DeploymentName:  anyDeploymentName,
			JobName:         anyPromoteJobName,
			ImageTag:        anyImageTag,
			CommitID:        anyCommitID,
		},
	}

	applicationConfig, _ := application.NewApplicationConfig(kubeclient, kubeUtil, radixclient, rr, ra)
	gitCommitHash := pipelineInfo.GitCommitHash
	gitTags := pipelineInfo.GitTags
	pipelineInfo.SetApplicationConfig(applicationConfig)
	pipelineInfo.SetGitAttributes(gitCommitHash, gitTags)
	err := cli.Run(pipelineInfo)
	assert.NoError(t, err)

	rds, _ := radixclient.RadixV1().RadixDeployments(utils.GetEnvironmentNamespace(anyApp, anyProdEnvironment)).List(context.TODO(), metav1.ListOptions{})
	assert.Equal(t, 1, len(rds.Items))
	assert.True(t, strings.HasPrefix(rds.Items[0].Name, fmt.Sprintf("%s-%s-", anyProdEnvironment, anyImageTag)))
	assert.Equal(t, anyProdEnvironment, rds.Items[0].Labels[kube.RadixEnvLabel])
	assert.Equal(t, anyImageTag, rds.Items[0].Labels[kube.RadixImageTagLabel])
	assert.Equal(t, anyPromoteJobName, rds.Items[0].Labels[kube.RadixJobNameLabel])
	assert.Equal(t, "250m", rds.Items[0].Spec.Components[0].Resources.Requests["cpu"])
	assert.Equal(t, "64Mi", rds.Items[0].Spec.Components[0].Resources.Requests["memory"])
	assert.Equal(t, "500m", rds.Items[0].Spec.Components[0].Resources.Limits["cpu"])
	assert.Equal(t, "128Mi", rds.Items[0].Spec.Components[0].Resources.Limits["memory"])
	assert.Equal(t, "22m", rds.Items[0].Spec.Jobs[0].Resources.Requests["cpu"])
	assert.Equal(t, "11Mi", rds.Items[0].Spec.Jobs[0].Resources.Requests["memory"])
	assert.Equal(t, "44m", rds.Items[0].Spec.Jobs[0].Resources.Limits["cpu"])
	assert.Equal(t, "33Mi", rds.Items[0].Spec.Jobs[0].Resources.Limits["memory"])
}

func TestPromote_PromoteToOtherEnvironment_Authentication(t *testing.T) {
	anyApp := "any-app"
	anyDeploymentName := "deployment-1"
	anyImageTag := "abcdef"
	anyBuildDeployJobName := "any-build-deploy-job"
	anyPromoteJobName := "any-promote-job"
	anyProdEnvironment := "prod"
	anyDevEnvironment := "dev"

	// Setup
	kubeclient, kubeUtil, radixclient, commonTestUtils, dev := setupTest(t)

	verification := v1.VerificationTypeOptional
	commonTestUtils.ApplyDeployment(
		utils.NewDeploymentBuilder().
			WithAppName(anyApp).
			WithDeploymentName(anyDeploymentName).
			WithEnvironment(anyDevEnvironment).
			WithComponents(
				utils.NewDeployComponentBuilder().WithName("app").WithAuthentication(nil),
			).
			WithLabel(kube.RadixJobNameLabel, anyBuildDeployJobName).
			WithRadixApplication(
				utils.NewRadixApplicationBuilder().
					WithRadixRegistration(utils.ARadixRegistration().WithName(anyApp)).
					WithAppName(anyApp).
					WithEnvironment(anyProdEnvironment, "").
					WithComponents(
						utils.AnApplicationComponent().
							WithName("app").
							WithAuthentication(
								&v1.Authentication{
									ClientCertificate: &v1.ClientCertificate{
										PassCertificateToUpstream: utils.BoolPtr(true),
									},
								},
							).
							WithEnvironmentConfigs(
								utils.NewComponentEnvironmentBuilder().WithEnvironment(anyProdEnvironment).WithAuthentication(
									&v1.Authentication{
										ClientCertificate: &v1.ClientCertificate{
											Verification: &verification,
										},
									},
								),
							),
					)))

	// Create prod environment without any deployments
	test.CreateEnvNamespace(kubeclient, anyApp, anyProdEnvironment)

	rr, _ := radixclient.RadixV1().RadixRegistrations().Get(context.TODO(), anyApp, metav1.GetOptions{})
	ra, _ := radixclient.RadixV1().RadixApplications(utils.GetAppNamespace(anyApp)).Get(context.TODO(), anyApp, metav1.GetOptions{})

	cli := NewPromoteStep()
	cli.Init(kubeclient, radixclient, kubeUtil, &monitoring.Clientset{}, rr, dev)

	pipelineInfo := &model.PipelineInfo{
		PipelineArguments: model.PipelineArguments{
			FromEnvironment: anyDevEnvironment,
			ToEnvironment:   anyProdEnvironment,
			DeploymentName:  anyDeploymentName,
			JobName:         anyPromoteJobName,
			ImageTag:        anyImageTag,
			CommitID:        anyCommitID,
		},
	}

	applicationConfig, _ := application.NewApplicationConfig(kubeclient, kubeUtil, radixclient, rr, ra)
	gitCommitHash := pipelineInfo.GitCommitHash
	gitTags := pipelineInfo.GitTags
	pipelineInfo.SetApplicationConfig(applicationConfig)
	pipelineInfo.SetGitAttributes(gitCommitHash, gitTags)
	err := cli.Run(pipelineInfo)
	assert.NoError(t, err)

	rds, _ := radixclient.RadixV1().RadixDeployments(utils.GetEnvironmentNamespace(anyApp, anyProdEnvironment)).List(context.TODO(), metav1.ListOptions{})
	assert.Equal(t, 1, len(rds.Items))

	x0 := &v1.Authentication{
		ClientCertificate: &v1.ClientCertificate{
			Verification:              &verification,
			PassCertificateToUpstream: utils.BoolPtr(true),
		},
	}
	assert.NotNil(t, rds.Items[0].Spec.Components[0].Authentication)
	assert.NotNil(t, rds.Items[0].Spec.Components[0].Authentication.ClientCertificate)
	assert.Equal(t, x0, rds.Items[0].Spec.Components[0].Authentication)
}

func TestPromote_PromoteToOtherEnvironment_Resources_WithOverride(t *testing.T) {
	anyApp := "any-app"
	anyDeploymentName := "deployment-1"
	anyImageTag := "abcdef"
	anyBuildDeployJobName := "any-build-deploy-job"
	anyPromoteJobName := "any-promote-job"
	anyProdEnvironment := "prod"
	anyDevEnvironment := "dev"

	// Setup
	kubeclient, kubeUtil, radixclient, commonTestUtils, dev := setupTest(t)

	commonTestUtils.ApplyDeployment(
		utils.ARadixDeployment().
			WithRadixApplication(
				utils.NewRadixApplicationBuilder().
					WithRadixRegistration(
						utils.ARadixRegistration().
							WithName(anyApp)).
					WithAppName(anyApp).
					WithEnvironment(anyDevEnvironment, "master").
					WithEnvironment(anyProdEnvironment, "").
					WithComponents(
						utils.AnApplicationComponent().
							WithName("app").
							WithCommonResource(map[string]string{
								"memory": "64Mi",
								"cpu":    "250m",
							}, map[string]string{
								"memory": "128Mi",
								"cpu":    "500m",
							}).
							WithEnvironmentConfigs(
								utils.AnEnvironmentConfig().
									WithEnvironment(anyProdEnvironment).
									WithResource(
										map[string]string{
											"memory": "128Mi",
											"cpu":    "500m",
										}, map[string]string{
											"memory": "256Mi",
											"cpu":    "750m",
										}))).
					WithJobComponents(
						utils.AnApplicationJobComponent().
							WithName("job").
							WithSchedulerPort(numbers.Int32Ptr(8888)).
							WithCommonResource(
								map[string]string{
									"memory": "11Mi",
									"cpu":    "22m",
								}, map[string]string{
									"memory": "33Mi",
									"cpu":    "44m",
								}).
							WithEnvironmentConfigs(
								utils.AJobComponentEnvironmentConfig().
									WithEnvironment(anyProdEnvironment).
									WithResource(
										map[string]string{
											"memory": "111Mi",
											"cpu":    "222m",
										}, map[string]string{
											"memory": "333Mi",
											"cpu":    "444m",
										})),
					)).
			WithAppName(anyApp).
			WithDeploymentName(anyDeploymentName).
			WithEnvironment(anyDevEnvironment).
			WithImageTag(anyImageTag).
			WithLabel(kube.RadixJobNameLabel, anyBuildDeployJobName))

	// Create prod environment without any deployments
	test.CreateEnvNamespace(kubeclient, anyApp, anyProdEnvironment)

	rr, _ := radixclient.RadixV1().RadixRegistrations().Get(context.TODO(), anyApp, metav1.GetOptions{})
	ra, _ := radixclient.RadixV1().RadixApplications(utils.GetAppNamespace(anyApp)).Get(context.TODO(), anyApp, metav1.GetOptions{})

	cli := NewPromoteStep()
	cli.Init(kubeclient, radixclient, kubeUtil, &monitoring.Clientset{}, rr, dev)

	pipelineInfo := &model.PipelineInfo{
		PipelineArguments: model.PipelineArguments{
			FromEnvironment: anyDevEnvironment,
			ToEnvironment:   anyProdEnvironment,
			DeploymentName:  anyDeploymentName,
			JobName:         anyPromoteJobName,
			ImageTag:        anyImageTag,
			CommitID:        anyCommitID,
		},
	}

	applicationConfig, _ := application.NewApplicationConfig(kubeclient, kubeUtil, radixclient, rr, ra)
	gitCommitHash := pipelineInfo.GitCommitHash
	gitTags := pipelineInfo.GitTags
	pipelineInfo.SetApplicationConfig(applicationConfig)
	pipelineInfo.SetGitAttributes(gitCommitHash, gitTags)
	err := cli.Run(pipelineInfo)
	assert.NoError(t, err)

	rds, _ := radixclient.RadixV1().RadixDeployments(utils.GetEnvironmentNamespace(anyApp, anyProdEnvironment)).List(context.TODO(), metav1.ListOptions{})
	assert.Equal(t, 1, len(rds.Items))
	assert.True(t, strings.HasPrefix(rds.Items[0].Name, fmt.Sprintf("%s-%s-", anyProdEnvironment, anyImageTag)))
	assert.Equal(t, anyProdEnvironment, rds.Items[0].Labels[kube.RadixEnvLabel])
	assert.Equal(t, anyImageTag, rds.Items[0].Labels[kube.RadixImageTagLabel])
	assert.Equal(t, anyPromoteJobName, rds.Items[0].Labels[kube.RadixJobNameLabel])
	assert.Equal(t, "500m", rds.Items[0].Spec.Components[0].Resources.Requests["cpu"])
	assert.Equal(t, "128Mi", rds.Items[0].Spec.Components[0].Resources.Requests["memory"])
	assert.Equal(t, "750m", rds.Items[0].Spec.Components[0].Resources.Limits["cpu"])
	assert.Equal(t, "256Mi", rds.Items[0].Spec.Components[0].Resources.Limits["memory"])
	assert.Equal(t, "222m", rds.Items[0].Spec.Jobs[0].Resources.Requests["cpu"])
	assert.Equal(t, "111Mi", rds.Items[0].Spec.Jobs[0].Resources.Requests["memory"])
	assert.Equal(t, "444m", rds.Items[0].Spec.Jobs[0].Resources.Limits["cpu"])
	assert.Equal(t, "333Mi", rds.Items[0].Spec.Jobs[0].Resources.Limits["memory"])
}

func TestPromote_PromoteToSameEnvironment_NewStateIsExpected(t *testing.T) {
	anyApp := "any-app"
	anyDeploymentName := "deployment-1"
	anyImageTag := "abcdef"
	anyBuildDeployJobName := "any-build-deploy-job"
	anyPromoteJobName := "any-promote-job"
	anyDevEnvironment := "dev"

	// Setup
	kubeclient, kubeUtil, radixclient, commonTestUtils, dev := setupTest(t)

	commonTestUtils.ApplyDeployment(
		utils.ARadixDeployment().
			WithAppName(anyApp).
			WithDeploymentName(anyDeploymentName).
			WithEnvironment(anyDevEnvironment).
			WithImageTag(anyImageTag).
			WithLabel(kube.RadixJobNameLabel, anyBuildDeployJobName))

	rr, _ := radixclient.RadixV1().RadixRegistrations().Get(context.TODO(), anyApp, metav1.GetOptions{})
	ra, _ := radixclient.RadixV1().RadixApplications(utils.GetAppNamespace(anyApp)).Get(context.TODO(), anyApp, metav1.GetOptions{})

	cli := NewPromoteStep()
	cli.Init(kubeclient, radixclient, kubeUtil, &monitoring.Clientset{}, rr, dev)

	pipelineInfo := &model.PipelineInfo{
		PipelineArguments: model.PipelineArguments{
			FromEnvironment: anyDevEnvironment,
			ToEnvironment:   anyDevEnvironment,
			DeploymentName:  anyDeploymentName,
			JobName:         anyPromoteJobName,
			ImageTag:        anyImageTag,
			CommitID:        anyCommitID,
		},
	}

	applicationConfig, _ := application.NewApplicationConfig(kubeclient, kubeUtil, radixclient, rr, ra)
	gitCommitHash := pipelineInfo.GitCommitHash
	gitTags := pipelineInfo.GitTags
	pipelineInfo.SetApplicationConfig(applicationConfig)
	pipelineInfo.SetGitAttributes(gitCommitHash, gitTags)
	err := cli.Run(pipelineInfo)
	assert.NoError(t, err)

	rds, _ := radixclient.RadixV1().RadixDeployments(utils.GetEnvironmentNamespace(anyApp, anyDevEnvironment)).List(context.TODO(), metav1.ListOptions{})
	assert.Equal(t, 2, len(rds.Items))
}

func TestPromote_PromoteToOtherEnvironment_Identity(t *testing.T) {
	anyApp := "any-app"
	anyDeploymentName := "deployment-1"
	anyImageTag := "abcdef"
	anyBuildDeployJobName := "any-build-deploy-job"
	anyPromoteJobName := "any-promote-job"
	anyProdEnvironment := "prod"
	anyDevEnvironment := "dev"
	currentRdIdentity := &v1.Identity{Azure: &v1.AzureIdentity{ClientId: "any-current-identity-123"}}

	type scenarioSpec struct {
		name                 string
		commonConfig         *v1.Identity
		configureEnvironment bool
		environmentConfig    *v1.Identity
		expected             *v1.Identity
	}

	scenarios := []scenarioSpec{
		{name: "nil when commonConfig and environmentConfig is empty", commonConfig: &v1.Identity{}, configureEnvironment: true, environmentConfig: &v1.Identity{}, expected: nil},
		{name: "nil when commonConfig is nil and environmentConfig is empty", commonConfig: nil, configureEnvironment: true, environmentConfig: &v1.Identity{}, expected: nil},
		{name: "nil when commonConfig is empty and environmentConfig is nil", commonConfig: &v1.Identity{}, configureEnvironment: true, environmentConfig: nil, expected: nil},
		{name: "nil when commonConfig is nil and environmentConfig is not set", commonConfig: nil, configureEnvironment: false, environmentConfig: nil, expected: nil},
		{name: "nil when commonConfig is empty and environmentConfig is not set", commonConfig: &v1.Identity{}, configureEnvironment: false, environmentConfig: nil, expected: nil},
		{name: "use commonConfig when environmentConfig is empty", commonConfig: &v1.Identity{Azure: &v1.AzureIdentity{ClientId: "11111111-2222-3333-4444-555555555555"}}, configureEnvironment: true, environmentConfig: &v1.Identity{}, expected: &v1.Identity{Azure: &v1.AzureIdentity{ClientId: "11111111-2222-3333-4444-555555555555"}}},
		{name: "use commonConfig when environmentConfig.Azure is empty", commonConfig: &v1.Identity{Azure: &v1.AzureIdentity{ClientId: "11111111-2222-3333-4444-555555555555"}}, configureEnvironment: true, environmentConfig: &v1.Identity{Azure: &v1.AzureIdentity{}}, expected: &v1.Identity{Azure: &v1.AzureIdentity{ClientId: "11111111-2222-3333-4444-555555555555"}}},
		{name: "override non-empty commonConfig with environmentConfig.Azure", commonConfig: &v1.Identity{Azure: &v1.AzureIdentity{ClientId: "11111111-2222-3333-4444-555555555555"}}, configureEnvironment: true, environmentConfig: &v1.Identity{Azure: &v1.AzureIdentity{ClientId: "66666666-7777-8888-9999-aaaaaaaaaaaa"}}, expected: &v1.Identity{Azure: &v1.AzureIdentity{ClientId: "66666666-7777-8888-9999-aaaaaaaaaaaa"}}},
		{name: "override empty commonConfig with environmentConfig", commonConfig: &v1.Identity{}, configureEnvironment: true, environmentConfig: &v1.Identity{Azure: &v1.AzureIdentity{ClientId: "66666666-7777-8888-9999-aaaaaaaaaaaa"}}, expected: &v1.Identity{Azure: &v1.AzureIdentity{ClientId: "66666666-7777-8888-9999-aaaaaaaaaaaa"}}},
		{name: "override empty commonConfig.Azure with environmentConfig", commonConfig: &v1.Identity{Azure: &v1.AzureIdentity{}}, configureEnvironment: true, environmentConfig: &v1.Identity{Azure: &v1.AzureIdentity{ClientId: "66666666-7777-8888-9999-aaaaaaaaaaaa"}}, expected: &v1.Identity{Azure: &v1.AzureIdentity{ClientId: "66666666-7777-8888-9999-aaaaaaaaaaaa"}}},
		{name: "transform clientId with curly to standard format", commonConfig: &v1.Identity{Azure: &v1.AzureIdentity{ClientId: "{11111111-2222-3333-4444-555555555555}"}}, configureEnvironment: false, environmentConfig: nil, expected: &v1.Identity{Azure: &v1.AzureIdentity{ClientId: "11111111-2222-3333-4444-555555555555"}}},
		{name: "transform clientId with urn:uuid to standard format", commonConfig: &v1.Identity{Azure: &v1.AzureIdentity{ClientId: "urn:uuid:11111111-2222-3333-4444-555555555555"}}, configureEnvironment: false, environmentConfig: nil, expected: &v1.Identity{Azure: &v1.AzureIdentity{ClientId: "11111111-2222-3333-4444-555555555555"}}},
		{name: "transform clientId without dashes to standard format", commonConfig: &v1.Identity{Azure: &v1.AzureIdentity{ClientId: "11111111222233334444555555555555"}}, configureEnvironment: false, environmentConfig: nil, expected: &v1.Identity{Azure: &v1.AzureIdentity{ClientId: "11111111-2222-3333-4444-555555555555"}}},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			kubeclient, kubeUtil, radixclient, commonTestUtils, env := setupTest(t)
			var componentEnvironmentConfigs []utils.RadixEnvironmentConfigBuilder
			var jobEnvironmentConfigs []utils.RadixJobComponentEnvironmentConfigBuilder

			if scenario.configureEnvironment {
				componentEnvironmentConfigs = append(componentEnvironmentConfigs, utils.AnEnvironmentConfig().WithEnvironment(anyProdEnvironment).WithIdentity(scenario.environmentConfig))
				jobEnvironmentConfigs = append(jobEnvironmentConfigs, utils.AJobComponentEnvironmentConfig().WithEnvironment(anyProdEnvironment).WithIdentity(scenario.environmentConfig))
			}

			commonTestUtils.ApplyDeployment(
				utils.NewDeploymentBuilder().
					WithComponents(
						utils.NewDeployComponentBuilder().
							WithName("comp1").
							WithIdentity(currentRdIdentity),
					).
					WithJobComponents(
						utils.NewDeployJobComponentBuilder().
							WithName("job1").
							WithIdentity(currentRdIdentity),
					).
					WithAppName(anyApp).
					WithDeploymentName(anyDeploymentName).
					WithEnvironment(anyDevEnvironment).
					WithImageTag(anyImageTag).
					WithLabel(kube.RadixJobNameLabel, anyBuildDeployJobName).
					WithRadixApplication(
						utils.NewRadixApplicationBuilder().
							WithRadixRegistration(
								utils.ARadixRegistration().
									WithName(anyApp)).
							WithAppName(anyApp).
							WithEnvironment(anyDevEnvironment, "").
							WithEnvironment(anyProdEnvironment, "").
							WithComponents(
								utils.AnApplicationComponent().
									WithName("comp1").
									WithIdentity(scenario.commonConfig).
									WithEnvironmentConfigs(componentEnvironmentConfigs...)).
							WithJobComponents(
								utils.AnApplicationJobComponent().
									WithName("job1").
									WithIdentity(scenario.commonConfig).
									WithSchedulerPort(numbers.Int32Ptr(8888)).
									WithPayloadPath(utils.StringPtr("/path")).
									WithEnvironmentConfigs(jobEnvironmentConfigs...),
							)),
			)

			// Create prod environment without any deployments
			test.CreateEnvNamespace(kubeclient, anyApp, anyProdEnvironment)

			rr, _ := radixclient.RadixV1().RadixRegistrations().Get(context.TODO(), anyApp, metav1.GetOptions{})
			ra, _ := radixclient.RadixV1().RadixApplications(utils.GetAppNamespace(anyApp)).Get(context.TODO(), anyApp, metav1.GetOptions{})

			cli := NewPromoteStep()
			cli.Init(kubeclient, radixclient, kubeUtil, &monitoring.Clientset{}, rr, env)

			pipelineInfo := &model.PipelineInfo{
				PipelineArguments: model.PipelineArguments{
					FromEnvironment: anyDevEnvironment,
					ToEnvironment:   anyProdEnvironment,
					DeploymentName:  anyDeploymentName,
					JobName:         anyPromoteJobName,
					ImageTag:        anyImageTag,
					CommitID:        anyCommitID,
				},
			}

			applicationConfig, _ := application.NewApplicationConfig(kubeclient, kubeUtil, radixclient, rr, ra)
			pipelineInfo.SetApplicationConfig(applicationConfig)
			err := cli.Run(pipelineInfo)
			require.NoError(t, err)

			rds, _ := radixclient.RadixV1().RadixDeployments(utils.GetEnvironmentNamespace(anyApp, anyProdEnvironment)).List(context.TODO(), metav1.ListOptions{})
			require.Equal(t, 1, len(rds.Items))
			assert.Equal(t, scenario.expected, rds.Items[0].Spec.Components[0].Identity)
			assert.Equal(t, scenario.expected, rds.Items[0].Spec.Jobs[0].Identity)
		})

	}
}
