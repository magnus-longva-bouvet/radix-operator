package handler

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/google/go-github/github"
	"github.com/pkg/errors"
	"github.com/statoil/radix-operator/pkg/apis/radix/v1"
	radixUtils "github.com/statoil/radix-operator/pkg/apis/utils"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type Config struct {
	DockerRegistryPath string
	WorkerImage        string
	RadixConfigBranch  string
}

type PipelineTrigger struct {
	kubeclient kubernetes.Interface
	config     *Config
}

func (p *PipelineTrigger) ProcessPullRequestEvent(rr *v1.RadixRegistration, prEvent *github.PullRequestEvent, req *http.Request) error {
	return errors.New("Pull request is not supported at this moment")
}

func (p *PipelineTrigger) ProcessPushEvent(rr *v1.RadixRegistration, pushEvent *github.PushEvent, req *http.Request) error {
	jobName, randomNr := getUniqueJobName(p.config.WorkerImage)
	logrus.Infof("Triggered by ref: %s", *pushEvent.Ref)
	pushBranch := strings.TrimPrefix(*pushEvent.Ref, "refs/heads/")
	job := p.createPipelineJob(jobName, randomNr, *pushEvent.Repo.SSHURL, pushBranch)

	logrus.Infof("Starting pipeline: %s, %s", jobName, p.config.WorkerImage)
	appNamespace := fmt.Sprintf("%s-app", rr.Name)
	job, err := p.kubeclient.BatchV1().Jobs(appNamespace).Create(job)
	if err != nil {
		return err
	}
	logrus.Infof("Started pipeline: %s, %s", jobName, p.config.WorkerImage)

	return nil
}

func NewPipelineTrigger(kubeclient kubernetes.Interface, config *Config) *PipelineTrigger {
	return &PipelineTrigger{
		kubeclient,
		config,
	}
}

func (p *PipelineTrigger) createPipelineJob(jobName, randomStr, sshUrl, pushBranch string) *batchv1.Job {
	gitCloneCommand := fmt.Sprintf("git clone %s -b %s .", sshUrl, "master")
	imageTag := fmt.Sprintf("%s/%s:%s", p.config.DockerRegistryPath, p.config.WorkerImage, "latest")
	logrus.Infof("Using image: %s", imageTag)

	backOffLimit := int32(0)
	defaultMode := int32(256)

	job := batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name: jobName,
			Labels: map[string]string{
				"job_label": jobName,
			},
		},
		Spec: batchv1.JobSpec{
			BackoffLimit: &backOffLimit,
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					ServiceAccountName: "radix-pipeline",
					InitContainers: []corev1.Container{
						{
							Name:    "clone",
							Image:   "alpine:3.7",
							Command: []string{"/bin/sh", "-c"},
							Args:    []string{fmt.Sprintf("apk add --no-cache bash openssh-client git && ls /root/.ssh && cd /workspace && %s", gitCloneCommand)},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "build-context",
									MountPath: "/workspace",
								},
								{
									Name:      "git-ssh-keys",
									MountPath: "/root/.ssh",
									ReadOnly:  true,
								},
							},
						},
					},
					Containers: []corev1.Container{
						{
							Name:  p.config.WorkerImage,
							Image: imageTag,
							Args: []string{
								fmt.Sprintf("BRANCH=%s", pushBranch),
								fmt.Sprintf("RADIX_FILE_NAME=%s", "/workspace/radixconfig.yaml"),
								fmt.Sprintf("IMAGE_TAG=%s", randomStr),
							},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "build-context",
									MountPath: "/workspace",
								},
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "build-context",
						},
						{
							Name: "git-ssh-keys",
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName:  "git-ssh-keys",
									DefaultMode: &defaultMode,
								},
							},
						},
					},
					// https://kubernetes.io/docs/tasks/configure-pod-container/pull-image-private-registry/
					ImagePullSecrets: []corev1.LocalObjectReference{
						{
							Name: "regcred",
						},
					},
					RestartPolicy: "Never",
				},
			},
		},
	}

	return &job
}

func getUniqueJobName(image string) (string, string) {
	var jobName []string
	randomStr := strings.ToLower(radixUtils.RandString(5))
	jobName = append(jobName, image)
	jobName = append(jobName, "-")
	jobName = append(jobName, getCurrentTimestamp())
	jobName = append(jobName, "-")
	jobName = append(jobName, randomStr)
	return strings.Join(jobName, ""), randomStr
}

func getCurrentTimestamp() string {
	t := time.Now()
	return t.Format("20060102150405") // YYYYMMDDHHMISS in Go
}
