package defaults

const (
	// OperatorDNSZoneEnvironmentVariable The DNS zone used fro creating ingress of the cluster
	OperatorDNSZoneEnvironmentVariable = "DNS_ZONE"

	// OperatorAppAliasBaseURLEnvironmentVariable The base url for any app alias of the cluster
	OperatorAppAliasBaseURLEnvironmentVariable = "APP_ALIAS_BASE_URL"

	// OperatorClusterTypeEnvironmentVariable The type of cluster dev|playground|prod
	OperatorClusterTypeEnvironmentVariable = "RADIXOPERATOR_CLUSTER_TYPE"

	// ClusternameEnvironmentVariable The name of the cluster
	ClusternameEnvironmentVariable = "RADIX_CLUSTERNAME"

	// ContainerRegistryEnvironmentVariable The name of the container registry
	ContainerRegistryEnvironmentVariable = "RADIX_CONTAINER_REGISTRY"

	// EnvironmentnameEnvironmentVariable The name of the environment for the application
	EnvironmentnameEnvironmentVariable = "RADIX_ENVIRONMENT"

	// PublicEndpointEnvironmentVariable The environment variable holding the public endpoint of the component
	PublicEndpointEnvironmentVariable = "RADIX_PUBLIC_DOMAIN_NAME"

	// CanonicalEndpointEnvironmentVariable Variable to hold the cluster spcific ingress
	CanonicalEndpointEnvironmentVariable = "RADIX_CANONICAL_DOMAIN_NAME"

	// RadixAppEnvironmentVariable The environment variable holding the name of the app
	RadixAppEnvironmentVariable = "RADIX_APP"

	// RadixComponentEnvironmentVariable The environment variable holding the name of the component
	RadixComponentEnvironmentVariable = "RADIX_COMPONENT"

	// RadixPortsEnvironmentVariable The environment variable holding the available ports of the component
	RadixPortsEnvironmentVariable = "RADIX_PORTS"

	// RadixPortNamesEnvironmentVariable The environment variable holding the available port names of the component
	RadixPortNamesEnvironmentVariable = "RADIX_PORT_NAMES"

	// RadixDNSZoneEnvironmentVariable The environment variable on a radix app giving the dns zone. Will be equal to OperatorDNSZoneEnvironmentVariable
	RadixDNSZoneEnvironmentVariable = "RADIX_DNS_ZONE"

	// RadixClusterTypeEnvironmentVariable The type of cluster dev|playground|prod. Will be equal to OperatorClusterTypeEnvironmentVariable
	RadixClusterTypeEnvironmentVariable = "RADIX_CLUSTER_TYPE"

	// ActiveClusternameEnvironmentVariable The name of the active cluster. If ActiveClusternameEnvironmentVariable == ClusternameEnvironmentVariable, this is the active cluster
	ActiveClusternameEnvironmentVariable = "RADIX_ACTIVE_CLUSTERNAME"
)
