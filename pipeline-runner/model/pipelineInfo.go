package model

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	application "github.com/equinor/radix-operator/pkg/apis/applicationconfig"
	"github.com/equinor/radix-operator/pkg/apis/defaults"
	"github.com/equinor/radix-operator/pkg/apis/pipeline"
	v1 "github.com/equinor/radix-operator/pkg/apis/radix/v1"
	"github.com/equinor/radix-operator/pkg/apis/utils"
	"github.com/equinor/radix-operator/pkg/apis/utils/git"
	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
)

const multiComponentImageName = "multi-component"

type componentType struct {
	name           string
	context        string
	dockerFileName string
}

// PipelineInfo Holds info about the pipeline to run
type PipelineInfo struct {
	Definition        *pipeline.Definition
	RadixApplication  *v1.RadixApplication
	PipelineArguments PipelineArguments
	Steps             []Step

	// Container registry to build with
	ContainerRegistry string
	//Subscription ID to build with
	SubscriptionId string

	// Temporary data
	RadixConfigMapName string
	GitConfigMapName   string
	TargetEnvironments map[string]bool
	BranchIsMapped     bool
	GitCommitHash      string
	GitTags            string

	// Holds information on the images referred to by their respective components
	ComponentImages map[string]pipeline.ComponentImage
}

// PipelineArguments Holds arguments for the pipeline
type PipelineArguments struct {
	PipelineType    string
	JobName         string
	Branch          string
	CommitID        string
	ImageTag        string
	UseCache        string
	PushImage       bool
	DeploymentName  string
	FromEnvironment string
	ToEnvironment   string

	RadixConfigFile string
	// Security context
	PodSecurityContext corev1.PodSecurityContext

	ContainerSecurityContext corev1.SecurityContext
	// Images used for copying radix config/building/scanning
	TektonPipeline string

	ImageBuilder string
	ImageScanner string

	// Used for tagging meta-information
	Clustertype string
	Clustername string
	// Used to indicate debugging session
	Debug bool
}

// GetPipelineArgsFromArguments Gets pipeline arguments from arg string
func GetPipelineArgsFromArguments(args map[string]string) PipelineArguments {
	radixConfigFile := args[defaults.RadixConfigFileEnvironmentVariable]
	branch := args[defaults.RadixBranchEnvironmentVariable]
	commitID := args[defaults.RadixCommitIdEnvironmentVariable]
	imageTag := args[defaults.RadixImageTagEnvironmentVariable]
	jobName := args[defaults.RadixPipelineJobEnvironmentVariable]
	useCache := args[defaults.RadixUseCacheEnvironmentVariable]
	pipelineType := args[defaults.RadixPipelineTypeEnvironmentVariable] // string(model.Build)
	pushImage := args[defaults.RadixPushImageEnvironmentVariable]       // "0"

	// promote pipeline
	deploymentName := args[defaults.RadixPromoteDeploymentEnvironmentVariable]       // For promotion pipeline
	fromEnvironment := args[defaults.RadixPromoteFromEnvironmentEnvironmentVariable] // For promotion
	toEnvironment := args[defaults.RadixPromoteToEnvironmentEnvironmentVariable]     // For promotion and deploy

	tektonPipeline := args[defaults.RadixTektonPipelineImageEnvironmentVariable]
	imageBuilder := args[defaults.RadixImageBuilderEnvironmentVariable]
	imageScanner := args[defaults.RadixImageScannerEnvironmentVariable]
	clusterType := args[defaults.RadixClusterTypeEnvironmentVariable]
	clusterName := args[defaults.ClusternameEnvironmentVariable]

	// Indicates that we are debugging the application
	debug, _ := strconv.ParseBool(args["DEBUG"])

	if imageTag == "" {
		imageTag = "latest"
	}
	if useCache == "" {
		useCache = "true"
	}

	pushImageBool := pipelineType == string(v1.BuildDeploy) || !(pushImage == "false" || pushImage == "0") // build and deploy require push

	return PipelineArguments{
		PipelineType:    pipelineType,
		JobName:         jobName,
		Branch:          branch,
		CommitID:        commitID,
		ImageTag:        imageTag,
		UseCache:        useCache,
		PushImage:       pushImageBool,
		DeploymentName:  deploymentName,
		FromEnvironment: fromEnvironment,
		ToEnvironment:   toEnvironment,
		TektonPipeline:  tektonPipeline,
		ImageBuilder:    imageBuilder,
		ImageScanner:    imageScanner,
		Clustertype:     clusterType,
		Clustername:     clusterName,
		RadixConfigFile: radixConfigFile,
		Debug:           debug,
	}
}

// InitPipeline Initialize pipeline with step implementations
func InitPipeline(pipelineType *pipeline.Definition,
	pipelineArguments PipelineArguments,
	stepImplementations ...Step) (*PipelineInfo, error) {

	timestamp := time.Now().Format("20060102150405")
	hash := strings.ToLower(utils.RandStringStrSeed(5, pipelineArguments.JobName))
	radixConfigMapName := fmt.Sprintf("radix-config-2-map-%s-%s-%s", timestamp, pipelineArguments.ImageTag, hash)
	gitConfigFileName := fmt.Sprintf("radix-git-information-%s-%s-%s", timestamp, pipelineArguments.ImageTag, hash)

	podSecContext := GetPodSecurityContext(RUN_AS_NON_ROOT, FS_GROUP)
	containerSecContext := GetContainerSecurityContext(PRIVILEGED_CONTAINER, ALLOW_PRIVILEGE_ESCALATION, RUN_AS_GROUP, RUN_AS_USER)

	pipelineArguments.ContainerSecurityContext = *containerSecContext
	pipelineArguments.PodSecurityContext = *podSecContext

	stepImplementationsForType, err := getStepStepImplementationsFromType(pipelineType, stepImplementations...)
	if err != nil {
		return nil, err
	}

	return &PipelineInfo{
		Definition:         pipelineType,
		PipelineArguments:  pipelineArguments,
		Steps:              stepImplementationsForType,
		RadixConfigMapName: radixConfigMapName,
		GitConfigMapName:   gitConfigFileName,
	}, nil
}

func getStepStepImplementationsFromType(pipelineType *pipeline.Definition, allStepImplementations ...Step) ([]Step, error) {
	stepImplementations := make([]Step, 0)

	for _, step := range pipelineType.Steps {
		stepImplementation := getStepImplementationForStepType(step, allStepImplementations)
		if stepImplementation == nil {
			return nil, fmt.Errorf("no step implementation found by type %s", stepImplementation)
		}

		stepImplementations = append(stepImplementations, stepImplementation)
	}

	return stepImplementations, nil
}

func getStepImplementationForStepType(stepType pipeline.StepType, allStepImplementations []Step) Step {
	for _, stepImplementation := range allStepImplementations {
		implementsType := stepImplementation.ImplementationForType()

		if stepType == implementsType {
			return stepImplementation
		}
	}

	return nil
}

// SetApplicationConfig Set radixconfig to be used later by other steps, as well
// as deriving info from the config
func (info *PipelineInfo) SetApplicationConfig(applicationConfig *application.ApplicationConfig, gitCommitHash string, gitTags string) {
	ra := applicationConfig.GetRadixApplicationConfig()
	info.RadixApplication = applicationConfig.GetRadixApplicationConfig()

	// Obtain metadata for rest of pipeline
	branchIsMapped, targetEnvironments := applicationConfig.IsThereAnythingToDeploy(info.PipelineArguments.Branch)

	// For deploy-only pipeline
	if info.IsDeployOnlyPipeline() {
		targetEnvironments[info.PipelineArguments.ToEnvironment] = true
		branchIsMapped = true
	}

	info.BranchIsMapped = branchIsMapped
	info.TargetEnvironments = targetEnvironments

	componentImages := getComponentImages(
		ra.GetName(),
		info.ContainerRegistry,
		info.PipelineArguments.ImageTag,
		ra.Spec.Components,
		ra.Spec.Jobs,
	)
	info.ComponentImages = componentImages
	info.GitCommitHash = gitCommitHash
	info.GitTags = gitTags
}

// IsDeployOnlyPipeline Determines if the pipeline is deploy-only
func (info *PipelineInfo) IsDeployOnlyPipeline() bool {
	return info.PipelineArguments.ToEnvironment != "" && info.PipelineArguments.FromEnvironment == ""
}

func getRadixComponentImageSources(components []v1.RadixComponent) []pipeline.ComponentImageSource {
	imageSources := make([]pipeline.ComponentImageSource, 0)

	for _, c := range components {
		s := pipeline.NewComponentImageSourceBuilder().
			WithSourceFunc(pipeline.RadixComponentSource(c)).
			Build()
		imageSources = append(imageSources, s)
	}

	return imageSources
}

func getRadixJobComponentImageSources(components []v1.RadixJobComponent) []pipeline.ComponentImageSource {
	imageSources := make([]pipeline.ComponentImageSource, 0)

	for _, c := range components {
		s := pipeline.NewComponentImageSourceBuilder().
			WithSourceFunc(pipeline.RadixJobComponentSource(c)).
			Build()
		imageSources = append(imageSources, s)
	}

	return imageSources
}

func getComponentImages(appName, containerRegistry, imageTag string, components []v1.RadixComponent, jobComponents []v1.RadixJobComponent) map[string]pipeline.ComponentImage {
	// Combine components and jobComponents

	componentSource := make([]pipeline.ComponentImageSource, 0)
	componentSource = append(componentSource, getRadixComponentImageSources(components)...)
	componentSource = append(componentSource, getRadixJobComponentImageSources(jobComponents)...)

	// First check if there are multiple components pointing to the same build context
	buildContextComponents := make(map[string][]componentType)

	// To ensure we can iterate over the map in the order
	// they were added
	buildContextKeys := make([]string, 0)

	for _, c := range componentSource {
		if c.Image != "" {
			// Using public image. Nothing to build
			continue
		}

		componentSource := getDockerfile(c.SourceFolder, c.DockerfileName)
		components := buildContextComponents[componentSource]
		if components == nil {
			components = make([]componentType, 0)
			buildContextKeys = append(buildContextKeys, componentSource)
		}

		components = append(components, componentType{c.Name, getContext(c.SourceFolder), getDockerfileName(c.DockerfileName)})
		buildContextComponents[componentSource] = components
	}

	componentImages := make(map[string]pipeline.ComponentImage)

	// Gather pre-built or public images
	for _, c := range componentSource {
		if c.Image != "" {
			componentImages[c.Name] = pipeline.ComponentImage{Build: false, Scan: false, ImageName: c.Image, ImagePath: c.Image}
		}
	}

	// Gather build containers
	numMultiComponentContainers := 0
	for _, key := range buildContextKeys {
		components := buildContextComponents[key]

		var imageName string

		if len(components) > 1 {
			log.Infof("Multiple components points to the same build context")
			imageName = multiComponentImageName

			if numMultiComponentContainers > 0 {
				// Start indexing them
				imageName = fmt.Sprintf("%s-%d", imageName, numMultiComponentContainers)
			}

			numMultiComponentContainers++
		} else {
			imageName = components[0].name
		}

		buildContainerName := fmt.Sprintf("build-%s", imageName)

		// A multi-component share context and dockerfile
		context := components[0].context
		dockerFile := components[0].dockerFileName

		// Set image back to component(s)
		for _, c := range components {
			componentImages[c.name] = pipeline.ComponentImage{
				ContainerName: buildContainerName,
				Context:       context,
				Dockerfile:    dockerFile,
				ImageName:     imageName,
				ImagePath:     utils.GetImagePath(containerRegistry, appName, imageName, imageTag),
				Build:         true,
				Scan:          true,
			}
		}
	}

	return componentImages
}

func getDockerfile(sourceFolder, dockerfileName string) string {
	context := getContext(sourceFolder)
	dockerfileName = getDockerfileName(dockerfileName)

	return fmt.Sprintf("%s%s", context, dockerfileName)
}

func getDockerfileName(name string) string {
	if name == "" {
		name = "Dockerfile"
	}

	return name
}

func getContext(sourceFolder string) string {
	sourceFolder = strings.Trim(sourceFolder, ".")
	sourceFolder = strings.Trim(sourceFolder, "/")
	if sourceFolder == "" {
		return fmt.Sprintf("%s/", git.Workspace)
	}
	return fmt.Sprintf("%s/%s/", git.Workspace, sourceFolder)
}
