package git

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
)

const (
	// InternalContainerPrefix To indicate that this is not for user interest
	InternalContainerPrefix = "internal-"

	// CloneConfigContainerName Name of container for clone in the outer pipeline
	CloneConfigContainerName = "clone-config"

	// CloneContainerName Name of container
	CloneContainerName = "clone"

	// GitSSHKeyVolumeName Deploy key + known_hosts
	GitSSHKeyVolumeName = "git-ssh-keys"

	// BuildContextVolumeName Name of volume to hold build context
	BuildContextVolumeName = "build-context"

	// Workspace Folder to hold the code to build
	Workspace = "/workspace"

	// The script to ensure that github reponds before cloning. It breaks after max attempts
	waitForGithubToRespond = "n=1;max=10;delay=2;while true; do if [ \"$n\" -lt \"$max\" ]; then nslookup github.com && break; n=$((n+1)); sleep $(($delay*$n)); else echo \"The command has failed after $n attempts.\"; break; fi done"
)

// CloneInitContainers The sidecars for cloning repo
func CloneInitContainers(sshURL, branch string) []corev1.Container {
	return CloneInitContainersWithContainerName(sshURL, branch, CloneContainerName)
}

// CloneInitContainersWithContainerName The sidecars for cloning repo
func CloneInitContainersWithContainerName(sshURL, branch, cloneContainerName string) []corev1.Container {
	containers := []corev1.Container{
		{
			Name:            fmt.Sprintf("%snslookup", InternalContainerPrefix),
			Image:           "alpine",
			Args:            []string{waitForGithubToRespond},
			Command:         []string{"/bin/sh", "-c"},
			ImagePullPolicy: "Always",
		},
		{
			Name:            cloneContainerName,
			Image:           "alpine/git",
			ImagePullPolicy: "IfNotPresent",
			Args: []string{
				"clone",
				"--recurse-submodules",
				sshURL,
				"--single-branch",
				"-b",
				branch,
				"--verbose",
				"--progress",
				"/workspace"},
			VolumeMounts: []corev1.VolumeMount{
				{
					Name:      BuildContextVolumeName,
					MountPath: Workspace,
				},
				{
					Name:      GitSSHKeyVolumeName,
					MountPath: "/root/.ssh",
					ReadOnly:  true,
				},
			},
		},
	}

	return containers
}
