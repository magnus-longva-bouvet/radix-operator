package steps

import (
	"fmt"
	"strings"
	"time"

	"github.com/equinor/radix-operator/pipeline-runner/model"
	"github.com/equinor/radix-operator/pkg/apis/utils"
	"github.com/equinor/radix-operator/pkg/apis/utils/git"

	"github.com/equinor/radix-operator/pkg/apis/kube"
	v1 "github.com/equinor/radix-operator/pkg/apis/radix/v1"
	log "github.com/sirupsen/logrus"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	azureServicePrincipleSecretName = "radix-sp-acr-azure"
)

func createACRBuildJob(rr *v1.RadixRegistration, ra *v1.RadixApplication, containerRegistry string, pipelineInfo *model.PipelineInfo, buildSecrets []corev1.EnvVar) (*batchv1.Job, error) {
	appName := rr.Name
	branch := pipelineInfo.PipelineArguments.Branch
	imageTag := pipelineInfo.PipelineArguments.ImageTag
	jobName := pipelineInfo.PipelineArguments.JobName

	initContainers := git.CloneInitContainers(rr.Spec.CloneURL, branch)
	buildContainers := createACRBuildContainers(containerRegistry, appName, pipelineInfo, ra.Spec.Components, buildSecrets)
	timestamp := time.Now().Format("20060102150405")
	defaultMode, backOffLimit := int32(256), int32(0)

	job := batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name: fmt.Sprintf("radix-builder-%s-%s", timestamp, imageTag),
			Labels: map[string]string{
				kube.RadixJobNameLabel:  jobName,
				kube.RadixBuildLabel:    fmt.Sprintf("%s-%s", appName, imageTag),
				"radix-app-name":        appName, // For backwards compatibility. Remove when cluster is migrated
				kube.RadixAppLabel:      appName,
				kube.RadixImageTagLabel: imageTag,
				kube.RadixJobTypeLabel:  kube.RadixJobTypeBuild,
			},
			Annotations: map[string]string{
				kube.RadixBranchAnnotation: branch,
			},
		},
		Spec: batchv1.JobSpec{
			BackoffLimit: &backOffLimit,
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						kube.RadixJobNameLabel: jobName,
					},
				},
				Spec: corev1.PodSpec{
					RestartPolicy:  "Never",
					InitContainers: initContainers,
					Containers:     buildContainers,
					Volumes: []corev1.Volume{
						{
							Name: git.BuildContextVolumeName,
						},
						corev1.Volume{
							Name: git.GitSSHKeyVolumeName,
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName:  git.GitSSHKeyVolumeName,
									DefaultMode: &defaultMode,
								},
							},
						},
						{
							Name: azureServicePrincipleSecretName,
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName: azureServicePrincipleSecretName,
								},
							},
						},
					},
				},
			},
		},
	}
	return &job, nil
}

func createACRBuildContainers(containerRegistry, appName string, pipelineInfo *model.PipelineInfo, components []v1.RadixComponent, buildSecrets []corev1.EnvVar) []corev1.Container {
	imageTag := pipelineInfo.PipelineArguments.ImageTag
	pushImage := pipelineInfo.PipelineArguments.PushImage
	clustertype := pipelineInfo.PipelineArguments.Clustertype
	clustername := pipelineInfo.PipelineArguments.Clustername

	containers := []corev1.Container{}
	azureServicePrincipleContext := "/radix-image-builder/.azure"
	firstPartContainerRegistry := strings.Split(containerRegistry, ".")[0]
	noPushFlag := "--no-push"
	if pushImage {
		noPushFlag = ""
	}

	for _, c := range components {
		if c.Image != "" {
			// Using public image. Nothing to build
			continue
		}

		imagePath := utils.GetImagePath(containerRegistry, appName, c.Name, imageTag)

		// For extra meta inforamtion about an image
		clustertypeImage := utils.GetImagePath(containerRegistry, appName, c.Name, fmt.Sprintf("%s-%s", clustertype, imageTag))
		clusternameImage := utils.GetImagePath(containerRegistry, appName, c.Name, fmt.Sprintf("%s-%s", clustername, imageTag))

		dockerFile := c.DockerfileName
		if dockerFile == "" {
			dockerFile = "Dockerfile"
		}
		context := getContext(c.SourceFolder)
		log.Debugf("using dockerfile %s in context %s", dockerFile, context)

		envVars := []corev1.EnvVar{
			{
				Name:  "DOCKER_FILE_NAME",
				Value: dockerFile,
			},
			{
				Name:  "DOCKER_REGISTRY",
				Value: firstPartContainerRegistry,
			},
			{
				Name:  "IMAGE",
				Value: imagePath,
			},
			{
				Name:  "CONTEXT",
				Value: context,
			},
			{
				Name:  "NO_PUSH",
				Value: noPushFlag,
			},
			{
				Name:  "AZURE_CREDENTIALS",
				Value: fmt.Sprintf("%s/sp_credentials.json", azureServicePrincipleContext),
			},

			// Extra meta information
			{
				Name:  "CLUSTERTYPE_IMAGE",
				Value: clustertypeImage,
			},
			{
				Name:  "CLUSTERNAME_IMAGE",
				Value: clusternameImage,
			},
		}

		envVars = append(envVars, buildSecrets...)

		container := corev1.Container{
			Name:            fmt.Sprintf("build-%s", c.Name),
			Image:           fmt.Sprintf("%s/radix-image-builder:master-latest", containerRegistry), // todo - version?
			ImagePullPolicy: corev1.PullAlways,
			Env:             envVars,
			VolumeMounts: []corev1.VolumeMount{
				{
					Name:      git.BuildContextVolumeName,
					MountPath: git.Workspace,
				},
				{
					Name:      azureServicePrincipleSecretName,
					MountPath: azureServicePrincipleContext,
					ReadOnly:  true,
				},
			},
		}
		containers = append(containers, container)
	}
	return containers
}
