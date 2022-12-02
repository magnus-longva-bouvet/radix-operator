package job

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/equinor/radix-operator/pkg/apis/defaults"
	kubeUtils "github.com/equinor/radix-operator/pkg/apis/kube"
	v1 "github.com/equinor/radix-operator/pkg/apis/radix/v1"
	"github.com/equinor/radix-operator/pkg/apis/test"
	"github.com/equinor/radix-operator/pkg/apis/utils"
	radixclient "github.com/equinor/radix-operator/pkg/client/clientset/versioned"
	radix "github.com/equinor/radix-operator/pkg/client/clientset/versioned/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kube "k8s.io/client-go/kubernetes"
	kubernetes "k8s.io/client-go/kubernetes/fake"
	secretproviderfake "sigs.k8s.io/secrets-store-csi-driver/pkg/client/clientset/versioned/fake"
)

const clusterName = "AnyClusterName"
const anyContainerRegistry = "any.container.registry"
const egressIps = "0.0.0.0"

type RadixJobTestSuiteBase struct {
	suite.Suite
	testUtils   *test.Utils
	kubeClient  kube.Interface
	kubeUtils   *kubeUtils.Kube
	radixClient radixclient.Interface
}

func (s *RadixJobTestSuiteBase) SetupTest() {
	s.setupTest()
}

func (s *RadixJobTestSuiteBase) TearDownTest() {
	s.teardownTest()
}

func (s *RadixJobTestSuiteBase) setupTest() {
	// Setup
	kubeClient := kubernetes.NewSimpleClientset()
	radixClient := radix.NewSimpleClientset()
	secretproviderclient := secretproviderfake.NewSimpleClientset()
	kubeUtil, _ := kubeUtils.New(kubeClient, radixClient, secretproviderclient)
	handlerTestUtils := test.NewTestUtils(kubeClient, radixClient, secretproviderclient)
	handlerTestUtils.CreateClusterPrerequisites(clusterName, anyContainerRegistry, egressIps)
	s.testUtils, s.kubeClient, s.kubeUtils, s.radixClient = &handlerTestUtils, kubeClient, kubeUtil, radixClient
}

func (s *RadixJobTestSuiteBase) teardownTest() {
	// Cleanup setup
	os.Unsetenv(defaults.OperatorRollingUpdateMaxUnavailable)
	os.Unsetenv(defaults.OperatorRollingUpdateMaxSurge)
	os.Unsetenv(defaults.OperatorReadinessProbeInitialDelaySeconds)
	os.Unsetenv(defaults.OperatorReadinessProbePeriodSeconds)
	os.Unsetenv(defaults.ActiveClusternameEnvironmentVariable)
	os.Unsetenv(defaults.OperatorTenantIdEnvironmentVariable)
}

func (s *RadixJobTestSuiteBase) applyJobWithSync(jobBuilder utils.JobBuilder, config *Config) (*v1.RadixJob, error) {
	rj, err := s.testUtils.ApplyJob(jobBuilder)
	if err != nil {
		return nil, err
	}

	err = s.runSync(rj, config)
	if err != nil {
		return nil, err
	}

	updatedJob, err := s.radixClient.RadixV1().RadixJobs(rj.GetNamespace()).Get(context.TODO(), rj.Name, metav1.GetOptions{})
	return updatedJob, err
}

func (s *RadixJobTestSuiteBase) runSync(rj *v1.RadixJob, config *Config) error {
	job := NewJob(s.kubeClient, s.kubeUtils, s.radixClient, rj, config)
	err := job.OnSync()
	if err != nil {
		return err
	}

	return nil
}

func TestRadixJobTestSuite(t *testing.T) {
	suite.Run(t, new(RadixJobTestSuite))
}

type RadixJobTestSuite struct {
	RadixJobTestSuiteBase
}

func (s *RadixJobTestSuite) TestObjectSynced_StatusMissing_StatusFromAnnotation() {
	config := &Config{
		PipelineJobsHistoryLimit: 3,
	}

	appName := "anyApp"
	completedJobStatus := utils.ACompletedJobStatus()

	// Test
	job, err := s.applyJobWithSync(utils.NewJobBuilder().
		WithStatusOnAnnotation(completedJobStatus).
		WithAppName(appName).
		WithJobName("anyJob"), config)

	assert.NoError(s.T(), err)

	expectedStatus := completedJobStatus.Build()
	actualStatus := job.Status
	assertStatusEqual(s.T(), expectedStatus, actualStatus)
}

func (s *RadixJobTestSuite) TestObjectSynced_MultipleJobs_SecondJobQueued() {
	config := &Config{
		PipelineJobsHistoryLimit: 3,
	}
	// Setup
	firstJob, _ := s.applyJobWithSync(utils.AStartedBuildDeployJob().WithJobName("FirstJob").WithBranch("master"), config)

	// Test
	secondJob, _ := s.applyJobWithSync(utils.ARadixBuildDeployJob().WithJobName("SecondJob").WithBranch("master"), config)

	assert.True(s.T(), secondJob.Status.Condition == v1.JobQueued)

	// Stopping first job should set second job to running
	firstJob.Spec.Stop = true
	s.radixClient.RadixV1().RadixJobs(firstJob.ObjectMeta.Namespace).Update(context.TODO(), firstJob, metav1.UpdateOptions{})
	s.runSync(firstJob, config)

	secondJob, _ = s.radixClient.RadixV1().RadixJobs(secondJob.ObjectMeta.Namespace).Get(context.TODO(), secondJob.Name, metav1.GetOptions{})
	assert.True(s.T(), secondJob.Status.Condition == v1.JobRunning)
}

func (s *RadixJobTestSuite) TestObjectSynced_MultipleJobsDifferentBranch_SecondJobRunning() {
	config := &Config{
		PipelineJobsHistoryLimit: 3,
	}
	// Setup
	s.applyJobWithSync(utils.AStartedBuildDeployJob().WithJobName("FirstJob").WithBranch("master"), config)

	// Test
	secondJob, _ := s.applyJobWithSync(utils.ARadixBuildDeployJob().WithJobName("SecondJob").WithBranch("release"), config)

	assert.True(s.T(), secondJob.Status.Condition != v1.JobQueued)
}

type jobScenario struct {
	// name Scenario name
	name string
	// existingRadixDeploymentJobs List of RadixDeployments and its RadixJobs, setup before test
	existingRadixDeploymentJobs []radixDeploymentJob
	// testingRadixDeploymentJob RadixDeployments and its RadixJobs under test
	testingRadixDeploymentJob radixDeploymentJob
	// jobsHistoryLimitPerBranchAndStatus Limit, defined in the env-var   RADIX_PIPELINE_JOBS_HISTORY_LIMIT
	jobsHistoryLimit int
	// expectedJobNames Name of jobs, expected to exist on finishing test
	expectedJobNames []string
}

type radixDeploymentJob struct {
	// jobName Radix pipeline job
	jobName string
	// rdName RadixDeployment name
	rdName string
	// env of environments, where RadixDeployments are deployed
	env       string
	jobStatus v1.RadixJobCondition
}

func (s *RadixJobTestSuite) TestHistoryLimit_EachEnvHasOwnHistory() {
	appName := "anyApp"
	appNamespace := utils.GetAppNamespace(appName)
	const envDev = "dev"
	const envQa = "qa"
	const envProd = "prod"
	const branchDevQa = "main"
	const branchProd = "release"
	raBuilder := utils.ARadixApplication().WithAppName(appName).
		WithEnvironment(envDev, branchDevQa).
		WithEnvironment(envQa, branchDevQa).
		WithEnvironment(envProd, branchProd)

	scenarios := []jobScenario{
		{
			name:             "All jobs are successful and running - no deleted job",
			jobsHistoryLimit: 2,
			existingRadixDeploymentJobs: []radixDeploymentJob{
				{jobName: "j1", rdName: "rd1", env: envDev, jobStatus: v1.JobSucceeded},
				{jobName: "j2", rdName: "rd2", env: envDev, jobStatus: v1.JobSucceeded},
			},
			testingRadixDeploymentJob: radixDeploymentJob{
				jobName: "j3", rdName: "rd3", env: envDev, jobStatus: v1.JobRunning,
			},
			expectedJobNames: []string{"j1", "j2", "j3"},
		},
		{
			name:             "All jobs are successful and queued - no deleted job",
			jobsHistoryLimit: 2,
			existingRadixDeploymentJobs: []radixDeploymentJob{
				{jobName: "j1", rdName: "rd1", env: envDev, jobStatus: v1.JobSucceeded},
				{jobName: "j2", rdName: "rd2", env: envDev, jobStatus: v1.JobSucceeded},
			},
			testingRadixDeploymentJob: radixDeploymentJob{
				jobName: "j3", rdName: "rd3", env: envDev, jobStatus: v1.JobQueued,
			},
			expectedJobNames: []string{"j1", "j2", "j3"},
		},
		{
			name:             "All jobs are successful and waiting - no deleted job",
			jobsHistoryLimit: 2,
			existingRadixDeploymentJobs: []radixDeploymentJob{
				{jobName: "j1", rdName: "rd1", env: envDev, jobStatus: v1.JobSucceeded},
				{jobName: "j2", rdName: "rd2", env: envDev, jobStatus: v1.JobSucceeded},
			},
			testingRadixDeploymentJob: radixDeploymentJob{
				jobName: "j3", rdName: "rd3", env: envDev, jobStatus: v1.JobWaiting,
			},
			expectedJobNames: []string{"j1", "j2", "j3"},
		},
		{
			name:             "Stopped job within the limit - not deleted",
			jobsHistoryLimit: 2,
			existingRadixDeploymentJobs: []radixDeploymentJob{
				{jobName: "j1", rdName: "rd1", env: envDev, jobStatus: v1.JobSucceeded},
			},
			testingRadixDeploymentJob: radixDeploymentJob{
				jobName: "j2", rdName: "rd2", env: envDev, jobStatus: v1.JobStopped,
			},
			expectedJobNames: []string{"j1", "j2"},
		},
		{
			name:             "Stopped job out of the limit - old deleted",
			jobsHistoryLimit: 2,
			existingRadixDeploymentJobs: []radixDeploymentJob{
				{jobName: "j1", rdName: "rd1", env: envDev, jobStatus: v1.JobSucceeded},
				{jobName: "j2", rdName: "rd2", env: envDev, jobStatus: v1.JobStopped},
				{jobName: "j3", rdName: "rd3", env: envDev, jobStatus: v1.JobStopped},
			},
			testingRadixDeploymentJob: radixDeploymentJob{
				jobName: "j4", rdName: "rd4", env: envDev, jobStatus: v1.JobStopped,
			},
			expectedJobNames: []string{"j1", "j3", "j4"},
		},
		{
			name:             "Failed job within the limit - not deleted",
			jobsHistoryLimit: 2,
			existingRadixDeploymentJobs: []radixDeploymentJob{
				{jobName: "j1", rdName: "rd1", env: envDev, jobStatus: v1.JobSucceeded},
			},
			testingRadixDeploymentJob: radixDeploymentJob{
				jobName: "j2", rdName: "rd2", env: envDev, jobStatus: v1.JobFailed,
			},
			expectedJobNames: []string{"j1", "j2"},
		},
		{
			name:             "Failed job out of the limit - old deleted",
			jobsHistoryLimit: 2,
			existingRadixDeploymentJobs: []radixDeploymentJob{
				{jobName: "j1", rdName: "rd1", env: envDev, jobStatus: v1.JobSucceeded},
				{jobName: "j2", rdName: "rd2", env: envDev, jobStatus: v1.JobFailed},
				{jobName: "j3", rdName: "rd3", env: envDev, jobStatus: v1.JobFailed},
			},
			testingRadixDeploymentJob: radixDeploymentJob{
				jobName: "j4", rdName: "rd4", env: envDev, jobStatus: v1.JobFailed,
			},
			expectedJobNames: []string{"j1", "j3", "j4"},
		},
		{
			name:             "StoppedNoChanges job within the limit - not deleted",
			jobsHistoryLimit: 2,
			existingRadixDeploymentJobs: []radixDeploymentJob{
				{jobName: "j1", rdName: "rd1", env: envDev, jobStatus: v1.JobSucceeded},
			},
			testingRadixDeploymentJob: radixDeploymentJob{
				jobName: "j2", rdName: "rd2", env: envDev, jobStatus: v1.JobStoppedNoChanges,
			},
			expectedJobNames: []string{"j1", "j2"},
		},
		{
			name:             "StoppedNoChanges job out of the limit - old deleted",
			jobsHistoryLimit: 2,
			existingRadixDeploymentJobs: []radixDeploymentJob{
				{jobName: "j1", rdName: "rd1", env: envDev, jobStatus: v1.JobSucceeded},
				{jobName: "j2", rdName: "rd2", env: envDev, jobStatus: v1.JobStoppedNoChanges},
				{jobName: "j3", rdName: "rd3", env: envDev, jobStatus: v1.JobStoppedNoChanges},
			},
			testingRadixDeploymentJob: radixDeploymentJob{
				jobName: "j4", rdName: "rd4", env: envDev, jobStatus: v1.JobStoppedNoChanges,
			},
			expectedJobNames: []string{"j1", "j3", "j4"},
		},
		{
			name:             "Stopped and failed jobs within the limit - not deleted",
			jobsHistoryLimit: 2,
			existingRadixDeploymentJobs: []radixDeploymentJob{
				{jobName: "j1", rdName: "rd1", env: envDev, jobStatus: v1.JobSucceeded},
				{jobName: "j2", rdName: "rd2", env: envDev, jobStatus: v1.JobStopped},
				{jobName: "j3", rdName: "rd3", env: envDev, jobStatus: v1.JobFailed},
				{jobName: "j4", rdName: "rd4", env: envDev, jobStatus: v1.JobStoppedNoChanges},
			},
			testingRadixDeploymentJob: radixDeploymentJob{
				jobName: "j5", rdName: "rd5", env: envDev, jobStatus: v1.JobStopped,
			},
			expectedJobNames: []string{"j1", "j2", "j3", "j4", "j5"},
		},
		{
			name:             "Stopped job out of the limit - old stopped deleted",
			jobsHistoryLimit: 2,
			existingRadixDeploymentJobs: []radixDeploymentJob{
				{jobName: "j1", rdName: "rd1", env: envDev, jobStatus: v1.JobSucceeded},
				{jobName: "j2", rdName: "rd2", env: envDev, jobStatus: v1.JobStopped},
				{jobName: "j3", rdName: "rd3", env: envDev, jobStatus: v1.JobFailed},
				{jobName: "j4", rdName: "rd4", env: envDev, jobStatus: v1.JobStoppedNoChanges},
				{jobName: "j5", rdName: "rd5", env: envDev, jobStatus: v1.JobStopped},
			},
			testingRadixDeploymentJob: radixDeploymentJob{
				jobName: "j6", rdName: "rd6", env: envDev, jobStatus: v1.JobStopped,
			},
			expectedJobNames: []string{"j1", "j3", "j4", "j5", "j6"},
		},
		{
			name:             "Failed job out of the limit - old falsed deleted",
			jobsHistoryLimit: 2,
			existingRadixDeploymentJobs: []radixDeploymentJob{
				{jobName: "j1", rdName: "rd1", env: envDev, jobStatus: v1.JobSucceeded},
				{jobName: "j2", rdName: "rd2", env: envDev, jobStatus: v1.JobStopped},
				{jobName: "j3", rdName: "rd3", env: envDev, jobStatus: v1.JobFailed},
				{jobName: "j4", rdName: "rd4", env: envDev, jobStatus: v1.JobStoppedNoChanges},
				{jobName: "j5", rdName: "rd5", env: envDev, jobStatus: v1.JobFailed},
			},
			testingRadixDeploymentJob: radixDeploymentJob{
				jobName: "j6", rdName: "rd6", env: envDev, jobStatus: v1.JobFailed,
			},
			expectedJobNames: []string{"j1", "j2", "j4", "j5", "j6"},
		},
		{
			name:             "StoppedNoChanges job out of the limit - old stopped-no-changes deleted",
			jobsHistoryLimit: 2,
			existingRadixDeploymentJobs: []radixDeploymentJob{
				{jobName: "j1", rdName: "rd1", env: envDev, jobStatus: v1.JobSucceeded},
				{jobName: "j2", rdName: "rd2", env: envDev, jobStatus: v1.JobStopped},
				{jobName: "j3", rdName: "rd3", env: envDev, jobStatus: v1.JobFailed},
				{jobName: "j4", rdName: "rd4", env: envDev, jobStatus: v1.JobStoppedNoChanges},
				{jobName: "j5", rdName: "rd5", env: envDev, jobStatus: v1.JobStoppedNoChanges},
			},
			testingRadixDeploymentJob: radixDeploymentJob{
				jobName: "j6", rdName: "rd6", env: envDev, jobStatus: v1.JobStoppedNoChanges,
			},
			expectedJobNames: []string{"j1", "j2", "j3", "j5", "j6"},
		},
		{
			name:             "Failed job is within the limit on branch - not deleted",
			jobsHistoryLimit: 2,
			existingRadixDeploymentJobs: []radixDeploymentJob{
				{jobName: "j1", rdName: "rd1", env: envDev, jobStatus: v1.JobSucceeded},
				{jobName: "j2", rdName: "rd2", env: envDev, jobStatus: v1.JobFailed},
				{jobName: "j3", rdName: "rd3", env: envQa, jobStatus: v1.JobFailed},
				{jobName: "j4", rdName: "rd4", env: envQa, jobStatus: v1.JobFailed},
				{jobName: "j5", rdName: "rd5", env: envProd, jobStatus: v1.JobFailed},
				{jobName: "j6", rdName: "rd6", env: envProd, jobStatus: v1.JobFailed},
			},
			testingRadixDeploymentJob: radixDeploymentJob{
				jobName: "j7", rdName: "rd7", env: envDev, jobStatus: v1.JobFailed,
			},
			expectedJobNames: []string{"j1", "j2", "j3", "j4", "j5", "j6", "j7"},
		},
		{
			name:             "Failed job out of the limit on branch - old failed deleted",
			jobsHistoryLimit: 2,
			existingRadixDeploymentJobs: []radixDeploymentJob{
				{jobName: "j1", rdName: "rd1", env: envDev, jobStatus: v1.JobSucceeded},
				{jobName: "j2", rdName: "rd2", env: envDev, jobStatus: v1.JobFailed},
				{jobName: "j3", rdName: "rd3", env: envQa, jobStatus: v1.JobFailed},
				{jobName: "j4", rdName: "rd4", env: envQa, jobStatus: v1.JobFailed},
				{jobName: "j5", rdName: "rd5", env: envProd, jobStatus: v1.JobFailed},
				{jobName: "j6", rdName: "rd6", env: envDev, jobStatus: v1.JobFailed},
				{jobName: "j7", rdName: "rd7", env: envProd, jobStatus: v1.JobFailed},
			},
			testingRadixDeploymentJob: radixDeploymentJob{
				jobName: "j8", rdName: "rd8", env: envDev, jobStatus: v1.JobFailed,
			},
			expectedJobNames: []string{"j1", "j3", "j4", "j5", "j6", "j7", "j8"},
		},
		{
			name:             "Stopped job is within the limit on branch - not deleted",
			jobsHistoryLimit: 2,
			existingRadixDeploymentJobs: []radixDeploymentJob{
				{jobName: "j1", rdName: "rd1", env: envDev, jobStatus: v1.JobSucceeded},
				{jobName: "j2", rdName: "rd2", env: envDev, jobStatus: v1.JobStopped},
				{jobName: "j3", rdName: "rd3", env: envQa, jobStatus: v1.JobStopped},
				{jobName: "j4", rdName: "rd4", env: envQa, jobStatus: v1.JobStopped},
				{jobName: "j5", rdName: "rd5", env: envProd, jobStatus: v1.JobStopped},
				{jobName: "j6", rdName: "rd6", env: envProd, jobStatus: v1.JobStopped},
			},
			testingRadixDeploymentJob: radixDeploymentJob{
				jobName: "j7", rdName: "rd7", env: envDev, jobStatus: v1.JobStopped,
			},
			expectedJobNames: []string{"j1", "j2", "j3", "j4", "j5", "j6", "j7"},
		},
		{
			name:             "Stopped job out of the limit on branch - old stopped deleted",
			jobsHistoryLimit: 2,
			existingRadixDeploymentJobs: []radixDeploymentJob{
				{jobName: "j1", rdName: "rd1", env: envDev, jobStatus: v1.JobSucceeded},
				{jobName: "j2", rdName: "rd2", env: envDev, jobStatus: v1.JobStopped},
				{jobName: "j3", rdName: "rd3", env: envQa, jobStatus: v1.JobStopped},
				{jobName: "j4", rdName: "rd4", env: envQa, jobStatus: v1.JobStopped},
				{jobName: "j5", rdName: "rd5", env: envProd, jobStatus: v1.JobStopped},
				{jobName: "j6", rdName: "rd6", env: envDev, jobStatus: v1.JobStopped},
				{jobName: "j7", rdName: "rd7", env: envProd, jobStatus: v1.JobStopped},
			},
			testingRadixDeploymentJob: radixDeploymentJob{
				jobName: "j8", rdName: "rd8", env: envDev, jobStatus: v1.JobStopped,
			},
			expectedJobNames: []string{"j1", "j3", "j4", "j5", "j6", "j7", "j8"},
		},
		{
			name:             "StoppedNoChanges job is within the limit on branch - not deleted",
			jobsHistoryLimit: 2,
			existingRadixDeploymentJobs: []radixDeploymentJob{
				{jobName: "j1", rdName: "rd1", env: envDev, jobStatus: v1.JobSucceeded},
				{jobName: "j2", rdName: "rd2", env: envDev, jobStatus: v1.JobStoppedNoChanges},
				{jobName: "j3", rdName: "rd3", env: envQa, jobStatus: v1.JobStoppedNoChanges},
				{jobName: "j4", rdName: "rd4", env: envQa, jobStatus: v1.JobStoppedNoChanges},
				{jobName: "j5", rdName: "rd5", env: envProd, jobStatus: v1.JobStoppedNoChanges},
				{jobName: "j6", rdName: "rd6", env: envProd, jobStatus: v1.JobStoppedNoChanges},
			},
			testingRadixDeploymentJob: radixDeploymentJob{
				jobName: "j7", rdName: "rd7", env: envDev, jobStatus: v1.JobStoppedNoChanges,
			},
			expectedJobNames: []string{"j1", "j2", "j3", "j4", "j5", "j6", "j7"},
		},
		{
			name:             "StoppedNoChanges job out of the limit on branch - old StoppedNoChanges deleted",
			jobsHistoryLimit: 2,
			existingRadixDeploymentJobs: []radixDeploymentJob{
				{jobName: "j1", rdName: "rd1", env: envDev, jobStatus: v1.JobSucceeded},
				{jobName: "j2", rdName: "rd2", env: envDev, jobStatus: v1.JobStoppedNoChanges},
				{jobName: "j3", rdName: "rd3", env: envQa, jobStatus: v1.JobStoppedNoChanges},
				{jobName: "j4", rdName: "rd4", env: envQa, jobStatus: v1.JobStoppedNoChanges},
				{jobName: "j5", rdName: "rd5", env: envProd, jobStatus: v1.JobStoppedNoChanges},
				{jobName: "j6", rdName: "rd6", env: envDev, jobStatus: v1.JobStoppedNoChanges},
				{jobName: "j7", rdName: "rd7", env: envProd, jobStatus: v1.JobStoppedNoChanges},
			},
			testingRadixDeploymentJob: radixDeploymentJob{
				jobName: "j8", rdName: "rd8", env: envDev, jobStatus: v1.JobStoppedNoChanges,
			},
			expectedJobNames: []string{"j1", "j3", "j4", "j5", "j6", "j7", "j8"},
		},
	}

	for _, scenario := range scenarios {
		s.T().Run(scenario.name, func(t *testing.T) {
			defer s.teardownTest()
			s.setupTest()
			config := &Config{
				PipelineJobsHistoryLimit: scenario.jobsHistoryLimit,
			}
			testTime := time.Now().Add(time.Hour * -100)
			for _, rdJob := range scenario.existingRadixDeploymentJobs {
				_, err := s.testUtils.ApplyDeployment(utils.ARadixDeployment().
					WithAppName(appName).WithDeploymentName(rdJob.rdName).WithEnvironment(rdJob.env).WithJobName(rdJob.jobName).
					WithActiveFrom(testTime))
				s.NoError(err)
				s.applyJobWithSyncFor(raBuilder, appName, rdJob, config)
				testTime = testTime.Add(time.Hour)
			}

			_, err := s.testUtils.ApplyDeployment(utils.ARadixDeployment().
				WithAppName(appName).WithDeploymentName(scenario.testingRadixDeploymentJob.rdName).
				WithEnvironment(scenario.testingRadixDeploymentJob.env).
				WithActiveFrom(testTime))
			s.NoError(err)
			s.applyJobWithSyncFor(raBuilder, appName, scenario.testingRadixDeploymentJob, config)

			radixJobList, err := s.radixClient.RadixV1().RadixJobs(appNamespace).List(context.TODO(), metav1.ListOptions{})
			s.NoError(err)
			s.assertExistRadixJobsWithNames(radixJobList, scenario)
		})
	}
}

func (s *RadixJobTestSuite) assertExistRadixJobsWithNames(radixJobList *v1.RadixJobList, scenario jobScenario) {
	resultJobNames := make(map[string]bool)
	for _, rj := range radixJobList.Items {
		resultJobNames[rj.GetName()] = true
	}
	for _, jobName := range scenario.expectedJobNames {
		_, ok := resultJobNames[jobName]
		s.True(ok, "missing job %s", jobName)
	}
}

func (s *RadixJobTestSuite) applyJobWithSyncFor(raBuilder utils.ApplicationBuilder, appName string, rdJob radixDeploymentJob, config *Config) {
	_, err := s.applyJobWithSync(utils.ARadixBuildDeployJob().
		WithRadixApplication(raBuilder).
		WithAppName(appName).
		WithJobName(rdJob.jobName).
		WithDeploymentName(rdJob.rdName).
		WithBranch(rdJob.env).
		WithStatus(utils.NewJobStatusBuilder().
			WithCondition(rdJob.jobStatus)), config)
	s.NoError(err)
}

func (s *RadixJobTestSuite) TestTargetEnvironmentIsSet() {
	config := &Config{
		PipelineJobsHistoryLimit: 3,
	}

	job, err := s.applyJobWithSync(utils.ARadixBuildDeployJob().WithJobName("test").WithBranch("master"), config)

	expectedEnvs := []string{"test"}

	assert.NoError(s.T(), err)

	// Master maps to Test env
	assert.Equal(s.T(), job.Spec.Build.Branch, "master")
	assert.Equal(s.T(), expectedEnvs, job.Status.TargetEnvs)
}

func assertStatusEqual(t *testing.T, expectedStatus, actualStatus v1.RadixJobStatus) {
	getTimestamp := func(t time.Time) string {
		return t.Format(time.RFC3339)
	}

	assert.Equal(t, getTimestamp(expectedStatus.Started.Time), getTimestamp(actualStatus.Started.Time))
	assert.Equal(t, getTimestamp(expectedStatus.Ended.Time), getTimestamp(actualStatus.Ended.Time))
	assert.Equal(t, expectedStatus.Condition, actualStatus.Condition)
	assert.Equal(t, expectedStatus.TargetEnvs, actualStatus.TargetEnvs)

	for index, expectedStep := range expectedStatus.Steps {
		assert.Equal(t, expectedStep.Name, actualStatus.Steps[index].Name)
		assert.Equal(t, expectedStep.Condition, actualStatus.Steps[index].Condition)
		assert.Equal(t, getTimestamp(expectedStep.Started.Time), getTimestamp(actualStatus.Steps[index].Started.Time))
		assert.Equal(t, getTimestamp(expectedStep.Ended.Time), getTimestamp(actualStatus.Steps[index].Ended.Time))
		assert.Equal(t, expectedStep.Components, actualStatus.Steps[index].Components)
		assert.Equal(t, expectedStep.PodName, actualStatus.Steps[index].PodName)
	}
}
