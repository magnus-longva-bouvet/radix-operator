package steps

import (
	"fmt"
	"testing"

	"github.com/coreos/prometheus-operator/pkg/client/monitoring"
	"github.com/equinor/radix-operator/pipeline-runner/model"
	application "github.com/equinor/radix-operator/pkg/apis/applicationconfig"
	"github.com/equinor/radix-operator/pkg/apis/kube"
	"github.com/equinor/radix-operator/pkg/apis/test"
	"github.com/equinor/radix-operator/pkg/apis/utils"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	anyClusterName       = "AnyClusterName"
	anyContainerRegistry = "any.container.registry"
	anyAppName           = "any-app"
	anyJobName           = "any-job-name"
	anyImageTag          = "anytag"
	anyCommitID          = "4faca8595c5283a9d0f17a623b9255a0d9866a2e"
)

func TestDeploy_BranchIsNotMapped_ShouldSkip(t *testing.T) {
	kubeclient, kubeUtil, radixclient, _ := setupTest()

	anyBranch := "master"
	anyEnvironment := "dev"
	anyComponentName := "app"
	anyNoMappedBranch := "feature"

	rr := utils.ARadixRegistration().
		WithName(anyAppName).
		BuildRR()

	ra := utils.NewRadixApplicationBuilder().
		WithAppName(anyAppName).
		WithEnvironment(anyEnvironment, anyBranch).
		WithComponents(
			utils.AnApplicationComponent().
				WithName(anyComponentName)).
		BuildRA()

	cli := NewDeployStep()
	cli.Init(kubeclient, radixclient, kubeUtil, &monitoring.Clientset{}, rr, ra)

	applicationConfig, _ := application.NewApplicationConfig(kubeclient, radixclient, rr, ra)
	branchIsMapped, targetEnvs := applicationConfig.IsBranchMappedToEnvironment(anyNoMappedBranch)

	pipelineInfo := &model.PipelineInfo{
		PipelineArguments: model.PipelineArguments{
			JobName:  anyJobName,
			ImageTag: anyImageTag,
			Branch:   anyNoMappedBranch,
			CommitID: anyCommitID,
		},
		TargetEnvironments: targetEnvs,
		BranchIsMapped:     branchIsMapped,
	}

	err := cli.Run(pipelineInfo)
	assert.Error(t, err)

}

func TestDeploy_PromotionSetup_ShouldCreateNamespacesForAllBranchesIfNotExtists(t *testing.T) {
	kubeclient, kubeUtil, radixclient, _ := setupTest()

	rr := utils.ARadixRegistration().
		WithName(anyAppName).
		BuildRR()

	ra := utils.NewRadixApplicationBuilder().
		WithAppName(anyAppName).
		WithEnvironment("dev", "master").
		WithEnvironment("prod", "").
		WithDNSAppAlias("dev", "app").
		WithComponents(
			utils.AnApplicationComponent().
				WithName("app").
				WithPublicPort("http").
				WithPort("http", 8080).
				WithEnvironmentConfigs(
					utils.AnEnvironmentConfig().
						WithEnvironment("prod").
						WithReplicas(test.IntPtr(4)),
					utils.AnEnvironmentConfig().
						WithEnvironment("dev").
						WithReplicas(test.IntPtr(4))),
			utils.AnApplicationComponent().
				WithName("redis").
				WithPublicPort("").
				WithPort("http", 6379).
				WithEnvironmentConfigs(
					utils.AnEnvironmentConfig().
						WithEnvironment("dev").
						WithEnvironmentVariable("DB_HOST", "db-dev").
						WithEnvironmentVariable("DB_PORT", "1234").
						WithResource(map[string]string{
							"memory": "64Mi",
							"cpu":    "250m",
						}, map[string]string{
							"memory": "128Mi",
							"cpu":    "500m",
						}),
					utils.AnEnvironmentConfig().
						WithEnvironment("prod").
						WithEnvironmentVariable("DB_HOST", "db-prod").
						WithEnvironmentVariable("DB_PORT", "9876").
						WithResource(map[string]string{
							"memory": "64Mi",
							"cpu":    "250m",
						}, map[string]string{
							"memory": "128Mi",
							"cpu":    "500m",
						}),
					utils.AnEnvironmentConfig().
						WithEnvironment("no-existing-env").
						WithEnvironmentVariable("DB_HOST", "db-prod").
						WithEnvironmentVariable("DB_PORT", "9876"))).
		BuildRA()

	// Prometheus doesn´t contain any fake
	cli := NewDeployStep()
	cli.Init(kubeclient, radixclient, kubeUtil, &monitoring.Clientset{}, rr, ra)

	applicationConfig, _ := application.NewApplicationConfig(kubeclient, radixclient, rr, ra)
	branchIsMapped, targetEnvs := applicationConfig.IsBranchMappedToEnvironment("master")

	pipelineInfo := &model.PipelineInfo{
		PipelineArguments: model.PipelineArguments{
			JobName:  anyJobName,
			ImageTag: anyImageTag,
			Branch:   "master",
			CommitID: anyCommitID,
		},
		BranchIsMapped:     branchIsMapped,
		TargetEnvironments: targetEnvs,
	}

	err := cli.Run(pipelineInfo)
	rds, _ := radixclient.RadixV1().RadixDeployments("any-app-dev").List(metav1.ListOptions{})

	t.Run("validate deploy", func(t *testing.T) {
		assert.NoError(t, err)
		assert.True(t, len(rds.Items) > 0)
	})

	rdNameDev := rds.Items[0].Name

	t.Run("validate deployment exist in only the namespace of the modified branch", func(t *testing.T) {
		rdDev, _ := radixclient.RadixV1().RadixDeployments("any-app-dev").Get(rdNameDev, metav1.GetOptions{})
		assert.NotNil(t, rdDev)

		rdProd, _ := radixclient.RadixV1().RadixDeployments("any-app-prod").Get(rdNameDev, metav1.GetOptions{})
		assert.Nil(t, rdProd)
	})

	t.Run("validate deployment environment variables", func(t *testing.T) {
		rdDev, _ := radixclient.RadixV1().RadixDeployments("any-app-dev").Get(rdNameDev, metav1.GetOptions{})
		assert.Equal(t, 2, len(rdDev.Spec.Components))
		assert.Equal(t, 2, len(rdDev.Spec.Components[1].EnvironmentVariables))
		assert.Equal(t, "db-dev", rdDev.Spec.Components[1].EnvironmentVariables["DB_HOST"])
		assert.Equal(t, "1234", rdDev.Spec.Components[1].EnvironmentVariables["DB_PORT"])
		assert.NotEmpty(t, rdDev.Annotations[kube.RadixBranchAnnotation])
		assert.NotEmpty(t, rdDev.Labels[kube.RadixCommitLabel])
		assert.NotEmpty(t, rdDev.Labels["radix-job-name"])
		assert.Equal(t, "master", rdDev.Annotations[kube.RadixBranchAnnotation])
		assert.Equal(t, anyCommitID, rdDev.Labels[kube.RadixCommitLabel])
		assert.Equal(t, anyJobName, rdDev.Labels["radix-job-name"])
	})

	t.Run("validate dns app alias", func(t *testing.T) {
		rdDev, _ := radixclient.RadixV1().RadixDeployments("any-app-dev").Get(rdNameDev, metav1.GetOptions{})
		assert.True(t, rdDev.Spec.Components[0].DNSAppAlias)
		assert.False(t, rdDev.Spec.Components[1].DNSAppAlias)
	})

	t.Run("validate resources", func(t *testing.T) {
		rdDev, _ := radixclient.RadixV1().RadixDeployments("any-app-dev").Get(rdNameDev, metav1.GetOptions{})

		fmt.Print(rdDev.Spec.Components[0].Resources)
		fmt.Print(rdDev.Spec.Components[1].Resources)
		assert.NotNil(t, rdDev.Spec.Components[1].Resources)
		assert.Equal(t, "128Mi", rdDev.Spec.Components[1].Resources.Limits["memory"])
		assert.Equal(t, "500m", rdDev.Spec.Components[1].Resources.Limits["cpu"])
	})

}

func TestDeploy_WrongResourceVersion_ShouldFailDeployment(t *testing.T) {
	anyApp := "any-app"
	anyEnv := "dev"
	anyComponentName := "frontend"

	targetEnvironments := make(map[string]bool)
	targetEnvironments[anyEnv] = true

	// Setup
	kubeclient, kubeUtil, radixclient, testUtils := setupTest()
	rd1, _ := testUtils.ApplyDeployment(
		utils.ARadixDeployment().
			WithAppName(anyApp).
			WithEnvironment(anyEnv).
			WithEmptyStatus().
			WithComponents(
				utils.NewDeployComponentBuilder().
					WithName(anyComponentName).
					WithPort("http", 8080).
					WithPublicPort("http")))

	// Get corresponding RR and RA
	rr, _ := radixclient.RadixV1().RadixRegistrations().Get(anyApp, metav1.GetOptions{})
	ra, _ := radixclient.RadixV1().RadixApplications(utils.GetAppNamespace(anyApp)).Get(anyApp, metav1.GetOptions{})

	// Pretend that pipepline start, knowing only about this RD
	latestResourceVersion := make(map[string]string)
	latestResourceVersion[anyEnv] = rd1.ResourceVersion

	// Then in the meantime another RD appears
	testUtils.ApplyDeployment(
		utils.ARadixDeployment().
			WithAppName(anyApp).
			WithEnvironment(anyEnv).
			WithEmptyStatus().
			WithComponents(
				utils.NewDeployComponentBuilder().
					WithName(anyComponentName).
					WithPort("http", 8080).
					WithPublicPort("http")))

	// Test
	cli := NewDeployStep()
	cli.Init(kubeclient, radixclient, kubeUtil, &monitoring.Clientset{}, rr, ra)

	pipelineInfo := &model.PipelineInfo{
		PipelineArguments: model.PipelineArguments{
			JobName:  anyJobName,
			ImageTag: anyImageTag,
			Branch:   "master",
			CommitID: anyCommitID,
		},
		BranchIsMapped:        true,
		TargetEnvironments:    targetEnvironments,
		LatestResourceVersion: latestResourceVersion,
	}

	err := cli.Run(pipelineInfo)
	assert.Error(t, err)
}
