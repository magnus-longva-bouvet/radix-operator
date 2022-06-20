package job

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"k8s.io/client-go/util/retry"

	"github.com/equinor/radix-operator/pkg/apis/defaults"
	"github.com/equinor/radix-operator/pkg/apis/kube"
	"github.com/equinor/radix-operator/pkg/apis/metrics"
	"github.com/equinor/radix-operator/pkg/apis/pipeline"
	v1 "github.com/equinor/radix-operator/pkg/apis/radix/v1"
	"github.com/equinor/radix-operator/pkg/apis/utils/git"
	radixclient "github.com/equinor/radix-operator/pkg/client/clientset/versioned"
	log "github.com/sirupsen/logrus"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// Job Instance variables
type Job struct {
	kubeclient                kubernetes.Interface
	radixclient               radixclient.Interface
	kubeutil                  *kube.Kube
	radixJob                  *v1.RadixJob
	originalRadixJobCondition v1.RadixJobCondition
}

// NewJob Constructor
func NewJob(
	kubeclient kubernetes.Interface,
	kubeutil *kube.Kube,
	radixclient radixclient.Interface,
	radixJob *v1.RadixJob) Job {
	originalRadixJobStatus := radixJob.Status.Condition

	return Job{
		kubeclient,
		radixclient,
		kubeutil, radixJob, originalRadixJobStatus}
}

// OnSync compares the actual state with the desired, and attempts to
// converge the two
func (job *Job) OnSync() error {
	job.restoreStatus()
	job.SyncTargetEnvironments()

	if IsRadixJobDone(job.radixJob) {
		log.Debugf("Ignoring RadixJob %s/%s as it's no longer active.", job.radixJob.Namespace, job.radixJob.Name)
		return nil
	}

	stopReconciliation, err := job.syncStatuses()
	if err != nil {
		return err
	}
	if stopReconciliation {
		log.Infof("stop reconciliation, status updated triggering new sync")
		return nil
	}

	_, err = job.kubeclient.BatchV1().Jobs(job.radixJob.Namespace).Get(context.TODO(), job.radixJob.Name, metav1.GetOptions{})

	if k8serrors.IsNotFound(err) {
		err = job.createPipelineJob()
	}

	job.maintainHistoryLimit()

	return err
}

// See https://github.com/equinor/radix-velero-plugin/blob/master/velero-plugins/deployment/restore.go
func (job *Job) restoreStatus() {
	if restoredStatus, ok := job.radixJob.Annotations[kube.RestoredStatusAnnotation]; ok {
		if job.radixJob.Status.Condition == "" {
			var status v1.RadixJobStatus
			err := json.Unmarshal([]byte(restoredStatus), &status)
			if err != nil {
				log.Error("Unable to get status from annotation", err)
				return
			}
			err = job.updateRadixJobStatusWithMetrics(job.radixJob, job.originalRadixJobCondition, func(currStatus *v1.RadixJobStatus) {
				currStatus.Condition = status.Condition
				currStatus.Created = status.Created
				currStatus.Started = status.Started
				currStatus.Ended = status.Ended
				currStatus.TargetEnvs = status.TargetEnvs
				currStatus.Steps = status.Steps
			})
			if err != nil {
				log.Error("Unable to restore status", err)
				return
			}
			// OwnerReference for pipeline step output configmaps are not restored by velero, and must be re-applied
			if err := job.setJobStepOutputOwnerReference(); err != nil {
				log.Error("Unable to set ownerReference on step output", err)
				return
			}
		}
	}
}

func (job *Job) syncStatuses() (stopReconciliation bool, err error) {
	stopReconciliation = false

	if job.radixJob.Spec.Stop {
		err = job.stopJob()
		if err != nil {
			return false, err
		}

		return true, nil
	}

	allJobs, err := job.radixclient.RadixV1().RadixJobs(job.radixJob.Namespace).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		err = fmt.Errorf("failed to get all RadixJobs: %v", err)
		return false, err
	}

	if job.isOtherJobRunningOnBranch(allJobs.Items) {
		err = job.queueJob()
		if err != nil {
			return false, err
		}

		return true, nil
	}

	err = job.setStatusOfJob()
	if err != nil {
		return false, err
	}

	return
}

func (job *Job) isOtherJobRunningOnBranch(allJobs []v1.RadixJob) bool {
	for _, rj := range allJobs {
		if rj.GetName() != job.radixJob.GetName() &&
			job.radixJob.Spec.Build.Branch != "" &&
			job.radixJob.Spec.Build.Branch == rj.Spec.Build.Branch &&
			rj.Status.Condition == v1.JobRunning {
			return true
		}
	}

	return false
}

// SyncTargetEnvironments sync the environments in the RadixJob with environments in the RA
func (job *Job) SyncTargetEnvironments() {
	rj := job.radixJob

	// TargetEnv has already been set
	if len(rj.Status.TargetEnvs) > 0 {
		return
	}
	targetEnvs := job.getTargetEnv(rj)

	// Update RJ with accurate env data
	err := job.updateRadixJobStatus(rj, func(currStatus *v1.RadixJobStatus) {
		if rj.Spec.PipeLineType == v1.Deploy {
			currStatus.TargetEnvs = append(currStatus.TargetEnvs, rj.Spec.Deploy.ToEnvironment)
		} else if rj.Spec.PipeLineType == v1.Promote {
			currStatus.TargetEnvs = append(currStatus.TargetEnvs, rj.Spec.Promote.ToEnvironment)
		} else if rj.Spec.PipeLineType == v1.BuildDeploy && targetEnvs != nil {
			currStatus.TargetEnvs = *targetEnvs
		}
	})
	if err != nil {
		log.Errorf("failed to sync target environments: %v", err)
	}
}

func (job *Job) getTargetEnv(rj *v1.RadixJob) *[]string {
	if rj.Spec.PipeLineType != v1.BuildDeploy {
		return nil
	}
	ra, err := job.radixclient.RadixV1().RadixApplications(rj.Namespace).Get(context.TODO(), rj.Spec.AppName, metav1.GetOptions{})
	if err != nil {
		log.Debugf("for BuildDeploy failed to find RadixApplication by name %s", rj.Spec.AppName)
		return &[]string{"N/A"}
	}
	targetEnvs := make([]string, 0)
	for _, env := range ra.Spec.Environments {
		if env.Build.From == rj.Spec.Build.Branch {
			targetEnvs = append(targetEnvs, env.Name)
		}
	}
	return &targetEnvs
}

// IsRadixJobDone Checks if job is done
func IsRadixJobDone(rj *v1.RadixJob) bool {
	return rj == nil || rj.Status.Condition == v1.JobFailed || rj.Status.Condition == v1.JobSucceeded || rj.Status.Condition == v1.JobStopped
}

func (job *Job) setStatusOfJob() error {
	pipelineJob, err := job.kubeclient.BatchV1().Jobs(job.radixJob.Namespace).Get(context.TODO(), job.radixJob.Name, metav1.GetOptions{})
	if k8serrors.IsNotFound(err) {
		// No kubernetes job created yet, so nothing to sync
		return nil
	}
	if err != nil {
		return err
	}

	steps, err := job.getJobSteps(pipelineJob)
	if err != nil {
		return err
	}
	environments, err := job.getJobEnvironments()
	if err != nil {
		return err
	}
	jobStatusCondition := getJobConditionFromJobStatus(pipelineJob.Status)

	err = job.updateRadixJobStatusWithMetrics(job.radixJob, job.originalRadixJobCondition, func(currStatus *v1.RadixJobStatus) {
		currStatus.Steps = steps
		currStatus.Condition = jobStatusCondition
		currStatus.Created = &job.radixJob.CreationTimestamp
		currStatus.Started = pipelineJob.Status.StartTime
		if len(pipelineJob.Status.Conditions) > 0 {
			currStatus.Ended = &pipelineJob.Status.Conditions[0].LastTransitionTime
		}
		if len(environments) > 0 {
			currStatus.TargetEnvs = environments
		}
	})
	if err != nil {
		return err
	}

	if jobStatusCondition == v1.JobSucceeded || jobStatusCondition == v1.JobFailed {
		err = job.setNextJobToRunning()
	}
	return err
}

func (job *Job) stopJob() error {
	isRunning := job.radixJob.Status.Condition == v1.JobRunning
	stoppedSteps, err := job.getStoppedSteps(isRunning)
	if err != nil {
		return err
	}

	err = job.updateRadixJobStatusWithMetrics(job.radixJob, job.originalRadixJobCondition, func(currStatus *v1.RadixJobStatus) {
		if isRunning && stoppedSteps != nil {
			currStatus.Steps = *stoppedSteps
		}
		currStatus.Created = &job.radixJob.CreationTimestamp
		currStatus.Condition = v1.JobStopped
		currStatus.Ended = &metav1.Time{Time: time.Now()}
	})
	if err != nil {
		return err
	}

	return job.setNextJobToRunning()
}

func (job *Job) getStoppedSteps(isRunning bool) (*[]v1.RadixJobStep, error) {
	if !isRunning {
		return nil, nil
	}
	// Delete pipeline job
	err := job.kubeclient.BatchV1().Jobs(job.radixJob.Namespace).Delete(context.TODO(), job.radixJob.Name, metav1.DeleteOptions{})
	if err != nil && !k8serrors.IsNotFound(err) {
		return nil, err
	}

	err = job.deleteStepJobs()
	if err != nil {
		return nil, err
	}

	stoppedSteps := make([]v1.RadixJobStep, 0)
	for _, step := range job.radixJob.Status.Steps {
		if step.Condition != v1.JobSucceeded && step.Condition != v1.JobFailed {
			step.Condition = v1.JobStopped
		}
		stoppedSteps = append(stoppedSteps, step)
	}
	return &stoppedSteps, nil
}

func (job *Job) deleteStepJobs() error {
	jobs, err := job.kubeclient.BatchV1().Jobs(job.radixJob.Namespace).List(context.TODO(), metav1.ListOptions{
		LabelSelector: fmt.Sprintf("%s=%s, %s!=%s", kube.RadixJobNameLabel, job.radixJob.Name, kube.RadixJobTypeLabel, kube.RadixJobTypeJob),
	})

	if err != nil {
		return err
	}

	if len(jobs.Items) > 0 {
		for _, kubernetesJob := range jobs.Items {
			// Delete jobs
			err := job.kubeclient.BatchV1().Jobs(job.radixJob.Namespace).Delete(context.TODO(), kubernetesJob.Name, metav1.DeleteOptions{})

			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (job *Job) setNextJobToRunning() error {
	rjList, err := job.radixclient.RadixV1().RadixJobs(job.radixJob.GetNamespace()).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return err
	}

	rjs := sortJobsByActiveFromTimestampAsc(rjList.Items)
	for _, otherRj := range rjs {
		if otherRj.Name != job.radixJob.Name && otherRj.Status.Condition == v1.JobQueued { // previous status for this otherRj was Queued
			return job.updateRadixJobStatusWithMetrics(&otherRj, v1.JobQueued, func(currStatus *v1.RadixJobStatus) {
				currStatus.Condition = v1.JobRunning
			})
		}
	}
	return nil
}

func sortJobsByActiveFromTimestampAsc(rjs []v1.RadixJob) []v1.RadixJob {
	sort.Slice(rjs, func(i, j int) bool {
		return isRJ1ActiveAfterRJ2(&rjs[j], &rjs[i])
	})
	return rjs
}

func isRJ1ActiveAfterRJ2(rj1 *v1.RadixJob, rj2 *v1.RadixJob) bool {
	rj1ActiveFrom := rj1.CreationTimestamp
	rj2ActiveFrom := rj2.CreationTimestamp

	return rj2ActiveFrom.Before(&rj1ActiveFrom)
}

func (job *Job) queueJob() error {
	return job.updateRadixJobStatusWithMetrics(job.radixJob, job.originalRadixJobCondition, func(currStatus *v1.RadixJobStatus) {
		currStatus.Created = &job.radixJob.CreationTimestamp
		currStatus.Condition = v1.JobQueued
	})
}

func (job *Job) getJobSteps(pipelineJob *batchv1.Job) ([]v1.RadixJobStep, error) {
	var steps []v1.RadixJobStep

	pipelinePod, err := job.getPipelinePod()
	if err != nil {
		return nil, err
	} else if pipelinePod == nil {
		return steps, nil
	}

	if len(pipelinePod.Status.ContainerStatuses) == 0 {
		return steps, nil
	}

	return job.getJobStepsBuildPipeline(pipelinePod, pipelineJob)
}

func (job *Job) getJobStepsBuildPipeline(pipelinePod *corev1.Pod, pipelineJob *batchv1.Job) ([]v1.RadixJobStep, error) {
	var steps []v1.RadixJobStep
	foundPrepareStepNames := make(map[string]bool)

	// Clone of radix config should be represented
	cloneConfigStep, applyConfigAndPreparePipelineStep := job.getCloneConfigApplyConfigAndPreparePipelineStep()
	if cloneConfigStep != nil {
		steps = append(steps, *cloneConfigStep)
		foundPrepareStepNames[cloneConfigStep.Name] = true
	}
	if applyConfigAndPreparePipelineStep != nil {
		steps = append(steps, *applyConfigAndPreparePipelineStep)
		foundPrepareStepNames[applyConfigAndPreparePipelineStep.Name] = true
	}

	// pipeline coordinator
	pipelineJobStep := getPipelineJobStep(pipelinePod)
	steps = append(steps, pipelineJobStep)

	jobStepsLabelSelector := fmt.Sprintf("%s=%s, %s!=%s", kube.RadixJobNameLabel, pipelineJob.GetName(), kube.RadixJobTypeLabel, kube.RadixJobTypeJob)
	jobStepList, err := job.kubeclient.BatchV1().Jobs(job.radixJob.Namespace).List(context.TODO(), metav1.ListOptions{
		LabelSelector: jobStepsLabelSelector,
	})

	if err != nil {
		return nil, err
	}

	for _, jobStep := range jobStepList.Items {
		jobType := jobStep.GetLabels()[kube.RadixJobTypeLabel]
		if strings.EqualFold(jobType, kube.RadixJobTypePreparePipelines) {
			// Prepare pipeline of radix config represented as an initial step
			continue
		}

		jobStepPod, err := job.kubeclient.CoreV1().Pods(job.radixJob.Namespace).List(context.TODO(), metav1.ListOptions{
			LabelSelector: fmt.Sprintf("%s=%s", "job-name", jobStep.Name),
		})
		if err != nil {
			return nil, err
		}
		if len(jobStepPod.Items) == 0 {
			continue
		}

		pod := jobStepPod.Items[0]
		for _, containerStatus := range pod.Status.InitContainerStatuses {
			if strings.HasPrefix(containerStatus.Name, git.InternalContainerPrefix) {
				continue
			}
			if _, ok := foundPrepareStepNames[containerStatus.Name]; ok {
				continue
			}
			steps = append(steps, getJobStepWithNoComponents(pod.GetName(), &containerStatus))
		}

		componentImages := make(map[string]pipeline.ComponentImage)
		if err := getObjectFromJobAnnotation(&jobStep, kube.RadixComponentImagesAnnotation, &componentImages); err != nil {
			return nil, err
		}

		containerOutputNames := make(pipeline.ContainerOutputName)
		if err := getObjectFromJobAnnotation(&jobStep, kube.RadixContainerOutputAnnotation, &containerOutputNames); err != nil {
			return nil, err
		}

		for _, containerStatus := range pod.Status.ContainerStatuses {
			components := getComponentsForContainer(containerStatus.Name, componentImages)
			containerOutputName := containerOutputNames[containerStatus.Name]
			jobStepOutput := getJobStepOutput(job.kubeclient, jobType, containerOutputName, job.radixJob.Namespace, containerStatus)
			step := getJobStep(pod.GetName(), &containerStatus, components, jobStepOutput)
			if _, ok := foundPrepareStepNames[step.Name]; ok {
				continue
			}
			steps = append(steps, step)
		}
	}

	return steps, nil
}

func getObjectFromJobAnnotation(job *batchv1.Job, annotationName string, obj interface{}) error {
	annotation := job.GetObjectMeta().GetAnnotations()[annotationName]
	if !strings.EqualFold(annotation, "") {
		err := json.Unmarshal([]byte(annotation), obj)
		if err != nil {
			return err
		}
	}
	return nil
}

func getComponentsForContainer(name string, componentImages map[string]pipeline.ComponentImage) []string {
	components := make([]string, 0)

	for component, componentImage := range componentImages {
		if strings.EqualFold(componentImage.ContainerName, name) {
			components = append(components, component)
		}
	}
	sort.Strings(components)
	return components
}

func (job *Job) getPipelinePod() (*corev1.Pod, error) {
	pods, err := job.kubeclient.CoreV1().Pods(job.radixJob.Namespace).List(context.TODO(), metav1.ListOptions{
		LabelSelector: fmt.Sprintf("%s=%s", "job-name", job.radixJob.Name),
	})

	if err != nil {
		return nil, err
	}
	if len(pods.Items) == 0 {
		// pipeline pod not found
		return nil, nil
	}

	return &pods.Items[0], nil
}

func getPipelineJobStep(pipelinePod *corev1.Pod) v1.RadixJobStep {
	var components []string
	return getJobStep(pipelinePod.GetName(), &pipelinePod.Status.ContainerStatuses[0], components, nil)
}

func (job *Job) getCloneConfigApplyConfigAndPreparePipelineStep() (*v1.RadixJobStep, *v1.RadixJobStep) {
	labelSelector := fmt.Sprintf("%s=%s, %s=%s", kube.RadixJobNameLabel, job.radixJob.GetName(), kube.RadixJobTypeLabel, kube.RadixJobTypePreparePipelines)

	preparePipelineStep, err := job.kubeclient.BatchV1().Jobs(job.radixJob.Namespace).List(context.TODO(), metav1.ListOptions{
		LabelSelector: labelSelector,
	})

	if err != nil || len(preparePipelineStep.Items) != 1 {
		return nil, nil
	}

	jobPods, err := job.kubeclient.CoreV1().Pods(job.radixJob.Namespace).List(context.TODO(), metav1.ListOptions{
		LabelSelector: fmt.Sprintf("%s=%s", "job-name", preparePipelineStep.Items[0].Name),
	})

	if err != nil || len(jobPods.Items) != 1 {
		return nil, nil
	}
	jobPod := jobPods.Items[0]

	cloneContainerStatus := getContainerStatusByName(git.CloneConfigContainerName, jobPod.Status.InitContainerStatuses)
	if cloneContainerStatus == nil {
		return nil, nil
	}
	cloneConfigContainerStep := getJobStepWithNoComponents(jobPods.Items[0].GetName(), cloneContainerStatus)
	applyConfigAndPreparePipelineContainerJobStep := getJobStepWithNoComponents(jobPod.GetName(), &jobPod.Status.ContainerStatuses[0])

	return &cloneConfigContainerStep, &applyConfigAndPreparePipelineContainerJobStep
}

func getContainerStatusByName(name string, containerStatuses []corev1.ContainerStatus) *corev1.ContainerStatus {
	for _, containerStatus := range containerStatuses {
		if containerStatus.Name == name {
			return &containerStatus
		}
	}

	return nil
}

func getJobStepWithNoComponents(podName string, containerStatus *corev1.ContainerStatus) v1.RadixJobStep {
	return getJobStepWithContainerName(podName, containerStatus.Name, containerStatus, nil, nil)
}

func getJobStep(podName string, containerStatus *corev1.ContainerStatus, components []string, jobStepOutput *v1.RadixJobStepOutput) v1.RadixJobStep {
	return getJobStepWithContainerName(podName, containerStatus.Name, containerStatus, components, jobStepOutput)
}

func getJobStepWithContainerName(podName, containerName string, containerStatus *corev1.ContainerStatus, components []string, jobStepOutput *v1.RadixJobStepOutput) v1.RadixJobStep {
	var startedAt *metav1.Time
	var finishedAt *metav1.Time

	status := v1.JobSucceeded

	if containerStatus == nil {
		status = v1.JobWaiting

	} else if containerStatus.State.Terminated != nil {
		startedAt = &containerStatus.State.Terminated.StartedAt
		finishedAt = &containerStatus.State.Terminated.FinishedAt

		if containerStatus.State.Terminated.ExitCode > 0 {
			status = v1.JobFailed
		}

	} else if containerStatus.State.Running != nil {
		startedAt = &containerStatus.State.Running.StartedAt
		status = v1.JobRunning

	} else if containerStatus.State.Waiting != nil {
		status = v1.JobWaiting

	}

	return v1.RadixJobStep{
		Name:       containerName,
		Started:    startedAt,
		Ended:      finishedAt,
		Condition:  status,
		PodName:    podName,
		Components: components,
		Output:     jobStepOutput,
	}
}

func (job *Job) getJobEnvironments() ([]string, error) {
	deploymentsLinkedToJob, err := job.radixclient.RadixV1().RadixDeployments(corev1.NamespaceAll).List(
		context.TODO(),
		metav1.ListOptions{
			LabelSelector: fmt.Sprintf("%s=%s", "radix-job-name", job.radixJob.Name),
		})
	if err != nil {
		return nil, err
	}

	var environments []string
	for _, deployment := range deploymentsLinkedToJob.Items {
		environments = append(environments, deployment.Spec.Environment)
	}

	return environments, nil
}

func (job *Job) updateRadixJobStatusWithMetrics(savingRadixJob *v1.RadixJob, originalRadixJobCondition v1.RadixJobCondition, changeStatusFunc func(currStatus *v1.RadixJobStatus)) error {
	if err := job.updateRadixJobStatus(savingRadixJob, changeStatusFunc); err != nil {
		return err
	}

	if originalRadixJobCondition != job.radixJob.Status.Condition {
		metrics.RadixJobStatusChanged(job.radixJob)

		if job.radixJob.Status.Condition == v1.JobSucceeded {
			metrics.RadixJobVulnerabilityScan(job.radixJob)
		}
	}

	return nil
}

func (job *Job) updateRadixJobStatus(rj *v1.RadixJob, changeStatusFunc func(currStatus *v1.RadixJobStatus)) error {
	rjInterface := job.radixclient.RadixV1().RadixJobs(rj.GetNamespace())
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		currentJob, err := rjInterface.Get(context.TODO(), rj.Name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		changeStatusFunc(&currentJob.Status)
		_, err = rjInterface.UpdateStatus(context.TODO(), currentJob, metav1.UpdateOptions{})

		if err == nil && rj.GetName() == job.radixJob.GetName() {
			currentJob, err = rjInterface.Get(context.TODO(), rj.GetName(), metav1.GetOptions{})
			if err == nil {
				job.radixJob = currentJob
			}
		}
		return err
	})
	return err
}

func (job *Job) maintainHistoryLimit() {
	historyLimit := os.Getenv(defaults.JobsHistoryLimitEnvironmentVariable)
	if historyLimit != "" {
		limit, err := strconv.Atoi(historyLimit)
		if err != nil {
			log.Warnf("%s is not set to a proper number, %s, and cannot be parsed.", defaults.JobsHistoryLimitEnvironmentVariable, historyLimit)
			return
		}

		allRJs, err := job.radixclient.RadixV1().RadixJobs(job.radixJob.Namespace).List(context.TODO(), metav1.ListOptions{})
		if err != nil {
			log.Errorf("Failed to get all RadixDeployments. Error was %v", err)
			return
		}

		if len(allRJs.Items) > limit {
			jobs := allRJs.Items
			numToDelete := len(jobs) - limit
			if numToDelete <= 0 {
				return
			}

			jobs = sortJobsByActiveFromTimestampAsc(jobs)
			for i := 0; i < numToDelete; i++ {
				log.Infof("Removing job %s from %s", jobs[i].Name, jobs[i].Namespace)
				//goland:noinspection GoUnhandledErrorResult - do not fail on error
				job.radixclient.RadixV1().RadixJobs(job.radixJob.Namespace).Delete(context.TODO(), jobs[i].Name, metav1.DeleteOptions{})
			}
		}
	}
}

func (job *Job) setJobStepOutputOwnerReference() error {
	for _, step := range job.radixJob.Status.Steps {
		if output := step.Output; output != nil {
			switch {
			case output.Scan != nil:
				if err := job.setScanStepOutputOwnerReference(output.Scan); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

func (job *Job) setScanStepOutputOwnerReference(scanOutput *v1.RadixJobStepScanOutput) error {
	if scanOutput == nil {
		return nil
	}

	configMapName := strings.TrimSpace(scanOutput.VulnerabilityListConfigMap)
	if configMapName == "" {
		return nil
	}

	namespace := job.radixJob.Namespace
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		cm, err := job.kubeutil.GetConfigMap(namespace, configMapName)
		if err != nil && k8serrors.IsNotFound(err) {
			log.Debugf("ConfigMap %s not found", configMapName)
			return nil
		}

		// Skip ownerReference update if already set
		if len(cm.OwnerReferences) > 0 {
			return nil
		}

		cm.OwnerReferences = GetOwnerReference(job.radixJob)
		_, err = job.kubeclient.CoreV1().ConfigMaps(namespace).Update(context.TODO(), cm, metav1.UpdateOptions{})
		return err
	})
}
