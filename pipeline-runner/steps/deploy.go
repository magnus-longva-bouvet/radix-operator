package steps

import (
	"fmt"
	"strings"

	"github.com/equinor/radix-operator/pipeline-runner/model"
	"github.com/equinor/radix-operator/pkg/apis/deployment"
	"github.com/equinor/radix-operator/pkg/apis/pipeline"
	v1 "github.com/equinor/radix-operator/pkg/apis/radix/v1"
	log "github.com/sirupsen/logrus"
)

// DeploymentHasBeenModifiedError There is a new version of an RD in the environment
func DeploymentHasBeenModifiedError(appName, envName string) error {
	return fmt.Errorf("Newer version of deployment exists for app %s in environment %s", appName, envName)
}

// DeployStepImplementation Step to deploy RD into environment
type DeployStepImplementation struct {
	stepType pipeline.StepType
	model.DefaultStepImplementation
}

// NewDeployStep Constructor
func NewDeployStep() model.Step {
	return &DeployStepImplementation{
		stepType: pipeline.DeployStep,
	}
}

// ImplementationForType Override of default step method
func (cli *DeployStepImplementation) ImplementationForType() pipeline.StepType {
	return cli.stepType
}

// SucceededMsg Override of default step method
func (cli *DeployStepImplementation) SucceededMsg() string {
	return fmt.Sprintf("Succeded: deploy application %s", cli.GetAppName())
}

// ErrorMsg Override of default step method
func (cli *DeployStepImplementation) ErrorMsg(err error) string {
	return fmt.Sprintf("Failed to deploy application %s. Error: %v", cli.GetAppName(), err)
}

// Run Override of default step method
func (cli *DeployStepImplementation) Run(pipelineInfo *model.PipelineInfo) error {
	if !pipelineInfo.BranchIsMapped {
		// Do nothing
		return fmt.Errorf("Skip deploy step as branch %s is not mapped to any environment", pipelineInfo.PipelineArguments.Branch)
	}

	_, err := cli.deploy(pipelineInfo)
	return err
}

// Deploy Handles deploy step of the pipeline
func (cli *DeployStepImplementation) deploy(pipelineInfo *model.PipelineInfo) ([]v1.RadixDeployment, error) {
	appName := cli.GetAppName()
	containerRegistry, err := cli.GetKubeutil().GetContainerRegistry()
	if err != nil {
		return nil, err
	}

	log.Infof("Deploying app %s", appName)
	radixDeployments := []v1.RadixDeployment{}

	for _, env := range cli.GetApplicationConfig().Spec.Environments {
		if !deployment.DeployToEnvironment(env, pipelineInfo.TargetEnvironments) {
			continue
		}

		radixDeployment, err := deployment.ConstructForTargetEnvironment(
			cli.GetApplicationConfig(),
			containerRegistry,
			pipelineInfo.PipelineArguments.JobName,
			pipelineInfo.PipelineArguments.ImageTag,
			pipelineInfo.PipelineArguments.Branch,
			pipelineInfo.PipelineArguments.CommitID,
			env.Name)

		if err != nil {
			return nil, fmt.Errorf("Failed to create radix deployments objects for app %s. %v", appName, err)
		}

		deployment, err := deployment.NewDeployment(
			cli.GetKubeclient(),
			cli.GetRadixclient(),
			cli.GetPrometheusOperatorClient(),
			cli.GetRegistration(),
			&radixDeployment)
		if err != nil {
			return nil, err
		}

		deploymentHasBeenModified, err := cli.deploymentHasBeenModified(env.Name, pipelineInfo.LatestResourceVersion[env.Name])
		if err != nil {
			return nil, err
		}

		if deploymentHasBeenModified {
			return nil, DeploymentHasBeenModifiedError(appName, env.Name)
		}

		err = deployment.Apply()
		if err != nil {
			return nil, fmt.Errorf("Failed to apply radix deployments for app %s. %v", appName, err)
		}

		radixDeployments = append(radixDeployments, radixDeployment)
	}

	return radixDeployments, nil
}

func (cli *DeployStepImplementation) deploymentHasBeenModified(env, resourceVersionAtStartOfPipeline string) (bool, error) {
	latestResourceVersion, err := deployment.GetLatestResourceVersionOfTargetEnvironment(cli.GetRadixclient(), cli.GetAppName(), env)
	if err != nil {
		return true, err
	}

	if !strings.EqualFold(latestResourceVersion, resourceVersionAtStartOfPipeline) && resourceVersionAtStartOfPipeline != "" {
		return true, nil
	}

	return false, nil
}
