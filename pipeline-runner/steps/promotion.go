package steps

import (
	"fmt"
	"strings"

	"github.com/equinor/radix-operator/pipeline-runner/model"
	"github.com/equinor/radix-operator/pkg/apis/deployment"
	"github.com/equinor/radix-operator/pkg/apis/kube"
	"github.com/equinor/radix-operator/pkg/apis/pipeline"
	v1 "github.com/equinor/radix-operator/pkg/apis/radix/v1"
	"github.com/equinor/radix-operator/pkg/apis/radixvalidators"
	"github.com/equinor/radix-operator/pkg/apis/utils"
	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EmptyArgument Argument by name cannot be empty
func EmptyArgument(argumentName string) error {
	return fmt.Errorf("%s cannot be empty", argumentName)
}

// NonExistingFromEnvironment From environment does not exist
func NonExistingFromEnvironment(environment string) error {
	return fmt.Errorf("Non existing from environment %s", environment)
}

// NonExistingToEnvironment From environment does not exist
func NonExistingToEnvironment(environment string) error {
	return fmt.Errorf("Non existing to environment %s", environment)
}

// NonExistingDeployment Deployment wasn't found
func NonExistingDeployment(deploymentName string) error {
	return fmt.Errorf("Non existing deployment %s", deploymentName)
}

// NonExistingComponentName Component by name was not found
func NonExistingComponentName(appName, componentName string) error {
	return fmt.Errorf("Unable to get application component %s for app %s", componentName, appName)
}

// PromoteStepImplementation Step to promote deployment to another environment,
// or inside environment
type PromoteStepImplementation struct {
	stepType pipeline.StepType
	model.DefaultStepImplementation
}

// NewPromoteStep Constructor
func NewPromoteStep() model.Step {
	return &PromoteStepImplementation{
		stepType: pipeline.PromoteStep,
	}
}

// ImplementationForType Override of default step method
func (cli *PromoteStepImplementation) ImplementationForType() pipeline.StepType {
	return cli.stepType
}

// SucceededMsg Override of default step method
func (cli *PromoteStepImplementation) SucceededMsg() string {
	return fmt.Sprintf("Succeded: promoted application %s", cli.GetAppName())
}

// ErrorMsg Override of default step method
func (cli *PromoteStepImplementation) ErrorMsg(err error) string {
	return fmt.Sprintf("Failed to promote application %s. Error: %v", cli.GetAppName(), err)
}

// Run Override of default step method
func (cli *PromoteStepImplementation) Run(pipelineInfo *model.PipelineInfo) error {
	var radixDeployment *v1.RadixDeployment

	err := areArgumentsValid(pipelineInfo.PipelineArguments)
	if err != nil {
		return err
	}

	fromNs := utils.GetEnvironmentNamespace(cli.GetAppName(), pipelineInfo.PipelineArguments.FromEnvironment)
	toNs := utils.GetEnvironmentNamespace(cli.GetAppName(), pipelineInfo.PipelineArguments.ToEnvironment)

	_, err = cli.GetKubeclient().CoreV1().Namespaces().Get(fromNs, metav1.GetOptions{})
	if err != nil {
		return NonExistingFromEnvironment(pipelineInfo.PipelineArguments.FromEnvironment)
	}

	_, err = cli.GetKubeclient().CoreV1().Namespaces().Get(toNs, metav1.GetOptions{})
	if err != nil {
		return NonExistingToEnvironment(pipelineInfo.PipelineArguments.ToEnvironment)
	}

	log.Infof("Promoting %s from %s to %s", cli.GetAppName(), pipelineInfo.PipelineArguments.FromEnvironment, pipelineInfo.PipelineArguments.ToEnvironment)
	rd, err := cli.GetRadixclient().RadixV1().RadixDeployments(fromNs).Get(pipelineInfo.PipelineArguments.DeploymentName, metav1.GetOptions{})
	radixDeployment = rd.DeepCopy()
	if err != nil {
		return NonExistingDeployment(pipelineInfo.PipelineArguments.DeploymentName)
	}

	radixDeployment.Name = utils.GetDeploymentName(cli.GetAppName(), pipelineInfo.PipelineArguments.ToEnvironment, pipelineInfo.PipelineArguments.ImageTag)
	radixDeployment.ResourceVersion = ""
	radixDeployment.Namespace = toNs
	radixDeployment.Labels[kube.RadixEnvLabel] = pipelineInfo.PipelineArguments.ToEnvironment
	radixDeployment.Labels[kube.RadixJobNameLabel] = pipelineInfo.PipelineArguments.JobName
	radixDeployment.Spec.Environment = pipelineInfo.PipelineArguments.ToEnvironment

	err = mergeWithRadixApplication(cli.GetApplicationConfig(), radixDeployment, pipelineInfo.PipelineArguments.ToEnvironment)
	if err != nil {
		return err
	}

	isValid, err := radixvalidators.CanRadixDeploymentBeInserted(cli.GetRadixclient(), radixDeployment)
	if !isValid {
		return err
	}

	radixDeployment, err = cli.GetRadixclient().RadixV1().RadixDeployments(toNs).Create(radixDeployment)
	if err != nil {
		return err
	}

	return nil
}

func areArgumentsValid(arguments model.PipelineArguments) error {
	if arguments.FromEnvironment == "" {
		return EmptyArgument("From environment")
	}

	if arguments.ToEnvironment == "" {
		return EmptyArgument("To environment")
	}

	if arguments.DeploymentName == "" {
		return EmptyArgument("Deployment name")
	}

	if arguments.JobName == "" {
		return EmptyArgument("Job name")
	}

	if arguments.ImageTag == "" {
		return EmptyArgument("Image tag")
	}

	return nil
}

func mergeWithRadixApplication(radixConfig *v1.RadixApplication, radixDeployment *v1.RadixDeployment, environment string) error {
	for index, comp := range radixDeployment.Spec.Components {
		raComp := getComponentConfig(radixConfig, comp.Name)
		if raComp == nil {
			return NonExistingComponentName(radixConfig.GetName(), comp.Name)
		}

		radixDeployment.Spec.Components[index].DNSAppAlias =
			deployment.IsDNSAppAlias(environment, comp.Name, radixConfig.Spec.DNSAppAlias)
		radixDeployment.Spec.Components[index].DNSExternalAlias =
			deployment.GetExternalDNSAliasForComponentEnvironment(radixConfig, comp.Name, environment)

		environmentConfig := getEnvironmentConfig(raComp, environment)
		if environmentConfig != nil {
			radixDeployment.Spec.Components[index].Resources = environmentConfig.Resources
			radixDeployment.Spec.Components[index].Monitoring = environmentConfig.Monitoring
			radixDeployment.Spec.Components[index].Replicas = environmentConfig.Replicas
			radixDeployment.Spec.Components[index].EnvironmentVariables = environmentConfig.Variables
		}
	}

	return nil
}

func getComponentConfig(radixConfig *v1.RadixApplication, componentName string) *v1.RadixComponent {
	for _, comp := range radixConfig.Spec.Components {
		if strings.EqualFold(comp.Name, componentName) {
			return &comp
		}
	}

	return nil
}

func getEnvironmentConfig(componentConfig *v1.RadixComponent, environment string) *v1.RadixEnvironmentConfig {
	for _, environmentConfig := range componentConfig.EnvironmentConfig {
		if strings.EqualFold(environmentConfig.Environment, environment) {
			return &environmentConfig
		}
	}

	return nil
}
