package model_test

import (
	"testing"

	"github.com/equinor/radix-operator/pipeline-runner/model"
	"github.com/equinor/radix-operator/pkg/apis/pipeline"
	v1 "github.com/equinor/radix-operator/pkg/apis/radix/v1"
	"github.com/stretchr/testify/assert"
)

var (
	applyConfigStep = &model.DefaultStepImplementation{StepType: pipeline.ApplyConfigStep, SuccessMessage: "config applied"}
	buildStep       = &model.DefaultStepImplementation{StepType: pipeline.BuildStep, SuccessMessage: "built"}
	deployStep      = &model.DefaultStepImplementation{StepType: pipeline.DeployStep, SuccessMessage: "deployed"}
)

func Test_DefaultPipeType(t *testing.T) {
	pipelineType, _ := pipeline.GetPipelineFromName("")
	p, _ := model.InitPipeline(pipelineType, nil, true, model.PipelineArguments{}, applyConfigStep, buildStep, deployStep)

	assert.Equal(t, v1.BuildDeploy, p.Definition.Type)
	assert.Equal(t, 3, len(p.Steps))
	assert.Equal(t, "config applied", p.Steps[0].SucceededMsg())
	assert.Equal(t, "built", p.Steps[1].SucceededMsg())
	assert.Equal(t, "deployed", p.Steps[2].SucceededMsg())
}

func Test_BuildDeployPipeType(t *testing.T) {
	pipelineType, _ := pipeline.GetPipelineFromName(string(v1.BuildDeploy))
	p, _ := model.InitPipeline(pipelineType, nil, true, model.PipelineArguments{}, applyConfigStep, buildStep, deployStep)

	assert.Equal(t, v1.BuildDeploy, p.Definition.Type)
	assert.Equal(t, 3, len(p.Steps))
	assert.Equal(t, "config applied", p.Steps[0].SucceededMsg())
	assert.Equal(t, "built", p.Steps[1].SucceededMsg())
	assert.Equal(t, "deployed", p.Steps[2].SucceededMsg())
}

func Test_BuildAndDefaultPushOnlyPipeline(t *testing.T) {
	pipelineType, _ := pipeline.GetPipelineFromName(string(v1.Build))

	pipelineArgs := model.GetPipelineArgsFromArguments(make(map[string]string))
	p, _ := model.InitPipeline(pipelineType, nil, true, pipelineArgs, applyConfigStep, buildStep, deployStep)
	assert.Equal(t, v1.Build, p.Definition.Type)
	assert.True(t, p.PipelineArguments.PushImage)
	assert.Equal(t, 2, len(p.Steps))
	assert.Equal(t, "config applied", p.Steps[0].SucceededMsg())
	assert.Equal(t, "built", p.Steps[1].SucceededMsg())
}

func Test_BuildOnlyPipeline(t *testing.T) {
	pipelineType, _ := pipeline.GetPipelineFromName(string(v1.Build))

	pipelineArgs := model.PipelineArguments{
		PushImage: false,
	}

	p, _ := model.InitPipeline(pipelineType, nil, true, pipelineArgs, applyConfigStep, buildStep, deployStep)
	assert.Equal(t, v1.Build, p.Definition.Type)
	assert.False(t, p.PipelineArguments.PushImage)
	assert.Equal(t, 2, len(p.Steps))
	assert.Equal(t, "config applied", p.Steps[0].SucceededMsg())
	assert.Equal(t, "built", p.Steps[1].SucceededMsg())
}

func Test_BuildAndPushOnlyPipeline(t *testing.T) {
	pipelineType, _ := pipeline.GetPipelineFromName(string(v1.Build))

	pipelineArgs := model.PipelineArguments{
		PushImage: true,
	}

	p, _ := model.InitPipeline(pipelineType, nil, true, pipelineArgs, applyConfigStep, buildStep, deployStep)
	assert.Equal(t, v1.Build, p.Definition.Type)
	assert.True(t, p.PipelineArguments.PushImage)
	assert.Equal(t, 2, len(p.Steps))
	assert.Equal(t, "config applied", p.Steps[0].SucceededMsg())
	assert.Equal(t, "built", p.Steps[1].SucceededMsg())
}

func Test_NonExistingPipelineType(t *testing.T) {
	_, err := pipeline.GetPipelineFromName("non existing pipeline")
	assert.NotNil(t, err)
}
