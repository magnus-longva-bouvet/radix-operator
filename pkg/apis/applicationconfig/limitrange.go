package applicationconfig

import (
	"os"

	log "github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/api/resource"
)

const (
	OperatorEnvLimitDefaultMemoryEnvironmentVariable        = "RADIXOPERATOR_APP_ENV_LIMITS_DEFAULT_MEMORY"
	OperatorEnvLimitDefaultCPUEnvironmentVariable           = "RADIXOPERATOR_APP_ENV_LIMITS_DEFAULT_CPU"
	OperatorEnvLimitDefaultRequestMemoryEnvironmentVariable = "RADIXOPERATOR_APP_ENV_LIMITS_DEFAULT_REQUEST_MEMORY"
	OperatorEnvLimitDefaultReqestCPUEnvironmentVariable     = "RADIXOPERATOR_APP_ENV_LIMITS_DEFAULT_REQUEST_CPU"

	limitRangeName = "mem-cpu-limit-range-env"
)

func (app *ApplicationConfig) createLimitRangeOnEnvironmentNamespace(namespace string) error {
	defaultCPU := getDefaultCPU()
	defaultMemory := getDefaultMemory()
	defaultCPURequest := getDefaultCPURequest()
	defaultMemoryRequest := getDefaultMemoryRequest()

	// If not all limits are defined, then don't put any limits on namespace
	if defaultCPU == nil ||
		defaultMemory == nil ||
		defaultCPURequest == nil ||
		defaultMemoryRequest == nil {
		log.Warningf("Not all limits are defined for the Operator, so no limitrange will be put on namespace %s", namespace)
		return nil
	}

	limitRange := app.kubeutil.BuildLimitRange(namespace,
		limitRangeName, app.config.Name,
		*defaultCPU,
		*defaultMemory,
		*defaultCPURequest,
		*defaultMemoryRequest)

	return app.kubeutil.ApplyLimitRange(namespace, limitRange)
}

func getDefaultCPU() *resource.Quantity {
	defaultCPUSetting := os.Getenv(OperatorEnvLimitDefaultCPUEnvironmentVariable)
	if defaultCPUSetting == "" {
		return nil
	}

	defaultCPU := resource.MustParse(defaultCPUSetting)
	return &defaultCPU
}

func getDefaultMemory() *resource.Quantity {
	defaultMemorySetting := os.Getenv(OperatorEnvLimitDefaultMemoryEnvironmentVariable)
	if defaultMemorySetting == "" {
		return nil
	}

	defaultMemory := resource.MustParse(defaultMemorySetting)
	return &defaultMemory
}

func getDefaultCPURequest() *resource.Quantity {
	defaultCPURequestSetting := os.Getenv(OperatorEnvLimitDefaultReqestCPUEnvironmentVariable)
	if defaultCPURequestSetting == "" {
		return nil
	}

	defaultCPURequest := resource.MustParse(defaultCPURequestSetting)
	return &defaultCPURequest
}

func getDefaultMemoryRequest() *resource.Quantity {
	defaultMemoryRequestSetting := os.Getenv(OperatorEnvLimitDefaultRequestMemoryEnvironmentVariable)
	if defaultMemoryRequestSetting == "" {
		return nil
	}

	defaultMemoryRequest := resource.MustParse(defaultMemoryRequestSetting)
	return &defaultMemoryRequest
}
