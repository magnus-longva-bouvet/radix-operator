package main

import (
	"os"
	"path/filepath"
	"strings"

	_ "k8s.io/client-go/plugin/pkg/client/auth"

	pipe "github.com/equinor/radix-operator/pipeline-runner/pipelines"
	"github.com/equinor/radix-operator/pkg/apis/utils"
	log "github.com/sirupsen/logrus"
)

var (
	pipelineDate     string
	pipelineCommitid string
	pipelineBranch   string
)

func init() {
	if pipelineCommitid == "" {
		pipelineCommitid = "no commitid"
	}

	if pipelineBranch == "" {
		pipelineBranch = "no branch"
	}

	if pipelineDate == "" {
		pipelineDate = "(Mon YYYY)"
	}
}

// Requirements to run, pipeline must have:
// - access to read RR of the app mention in "RADIX_FILE_NAME"
// - access to create Jobs in "app" namespace it runs under
// - access to create RD in all namespaces
// - access to create new namespaces
// - a secret git-ssh-keys containing deployment key to git repo provided in RR
// - a secret radix-docker with credentials to access our private ACR
func main() {
	args := getArgs()
	branch := args["BRANCH"]
	commitID := args["COMMIT_ID"]
	fileName := args["RADIX_FILE_NAME"]
	imageTag := args["IMAGE_TAG"]
	jobName := args["JOB_NAME"]
	useCache := args["USE_CACHE"]

	log.Infof("Starting Radix Pipeline from commit %s on branch %s built %s", pipelineCommitid, pipelineBranch, pipelineDate)

	if branch == "" {
		branch = "dev"
	}
	if fileName == "" {
		fileName, _ = filepath.Abs("./pipelines/testdata/radixconfig.yaml")
	}
	if imageTag == "" {
		imageTag = "latest"
	}
	if useCache == "" {
		useCache = "true"
	}

	client, radixClient, prometheusOperatorClient := utils.GetKubernetesClient()
	pushHandler, err := pipe.Init(client, radixClient, prometheusOperatorClient)
	if err != nil {
		os.Exit(1)
	}

	radixApplication, err := pipe.LoadConfigFromFile(fileName)
	if err != nil {
		os.Exit(1)
	}

	radixRegistration, targetEnvironments, err := pushHandler.Prepare(radixApplication, branch)
	if err != nil {
		os.Exit(1)
	}

	err = pushHandler.Run(radixRegistration, radixApplication, targetEnvironments, jobName, branch, commitID, imageTag, useCache)
	if err != nil {
		os.Exit(2)
	}
	os.Exit(0)
}

func getArgs() map[string]string {
	argsWithoutProg := os.Args[1:]
	args := map[string]string{}
	for _, arg := range argsWithoutProg {
		keyValue := strings.Split(arg, "=")
		key := keyValue[0]
		value := keyValue[1]
		args[key] = value
	}
	return args
}
