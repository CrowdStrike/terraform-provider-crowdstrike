package cloudsecurity

import (
	"context"
	"reflect"

	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/objectdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
)

const (
	privilegedContainerCode                      = "201000"
	sensitiveDataInEnvironmentCode               = "201001"
	sensitiveDataInSecretKeyRefCode              = "201002"
	containerRunAsRootCode                       = "201004"
	containerWithoutRunAsNonRootCode             = "201005"
	privilegeEscalationAllowedCode               = "201006"
	containerWithNetworkCapabilitiesCode         = "201007"
	containerWithUnsafeProcMountCode             = "201008"
	containerUsingUnsafeSysctlsCode              = "201009"
	containerWithoutResourceLimitsCode           = "201010"
	sensitiveHostDirectoriesCode                 = "201011"
	containerWithSysadminCapabilityCode          = "201012"
	serviceAttachedToLoadBalancerCode            = "201013"
	serviceAttachedToNodePortCode                = "201014"
	hostPortAttachedToContainerCode              = "201015"
	hostNetworkAttachedToContainerCode           = "201016"
	containerInHostPidNamespaceCode              = "201017"
	containerInHostIpcNamespaceCode              = "201018"
	workloadInDefaultNamespaceCode               = "201019"
	workloadWithUnconfinedSeccompProfileCode     = "201020"
	workloadWithoutSelinuxOrApparmorCode         = "201021"
	containerWithManyCapabilitiesCode            = "201022"
	workloadWithoutRecommendedSeccompProfileCode = "201023"
	workloadWithoutSecurityContextCode           = "201024"
	runtimeSocketInContainerCode                 = "201025"
	entrypointContainsNetworkScanningCommandCode = "201026"
	entrypointContainsChrootCommandCode          = "201027"
	malformedSysctlValueCode                     = "201028"
	serviceAccountTokenAutomountedCode           = "201029"
)

var fieldNameToRuleCodeMap = map[string]string{
	"PrivilegedContainer":                      privilegedContainerCode,
	"SensitiveDataInEnvironment":               sensitiveDataInEnvironmentCode,
	"SensitiveDataInSecretKeyRef":              sensitiveDataInSecretKeyRefCode,
	"ContainerRunAsRoot":                       containerRunAsRootCode,
	"ContainerWithoutRunAsNonRoot":             containerWithoutRunAsNonRootCode,
	"PrivilegeEscalationAllowed":               privilegeEscalationAllowedCode,
	"ContainerWithNetworkCapabilities":         containerWithNetworkCapabilitiesCode,
	"ContainerWithUnsafeProcMount":             containerWithUnsafeProcMountCode,
	"ContainerUsingUnsafeSysctls":              containerUsingUnsafeSysctlsCode,
	"ContainerWithoutResourceLimits":           containerWithoutResourceLimitsCode,
	"SensitiveHostDirectories":                 sensitiveHostDirectoriesCode,
	"ContainerWithSysadminCapability":          containerWithSysadminCapabilityCode,
	"ServiceAttachedToLoadBalancer":            serviceAttachedToLoadBalancerCode,
	"ServiceAttachedToNodePort":                serviceAttachedToNodePortCode,
	"HostPortAttachedToContainer":              hostPortAttachedToContainerCode,
	"HostNetworkAttachedToContainer":           hostNetworkAttachedToContainerCode,
	"ContainerInHostPidNamespace":              containerInHostPidNamespaceCode,
	"ContainerInHostIpcNamespace":              containerInHostIpcNamespaceCode,
	"WorkloadInDefaultNamespace":               workloadInDefaultNamespaceCode,
	"WorkloadWithUnconfinedSeccompProfile":     workloadWithUnconfinedSeccompProfileCode,
	"WorkloadWithoutSelinuxOrApparmor":         workloadWithoutSelinuxOrApparmorCode,
	"ContainerWithManyCapabilities":            containerWithManyCapabilitiesCode,
	"WorkloadWithoutRecommendedSeccompProfile": workloadWithoutRecommendedSeccompProfileCode,
	"WorkloadWithoutSecurityContext":           workloadWithoutSecurityContextCode,
	"RuntimeSocketInContainer":                 runtimeSocketInContainerCode,
	"EntrypointContainsNetworkScanningCommand": entrypointContainsNetworkScanningCommandCode,
	"EntrypointContainsChrootCommand":          entrypointContainsChrootCommandCode,
	"MalformedSysctlValue":                     malformedSysctlValueCode,
	"ServiceAccountTokenAutomounted":           serviceAccountTokenAutomountedCode,
}

var ruleCodeToFieldNameMap = map[string]string{
	privilegedContainerCode:                      "PrivilegedContainer",
	sensitiveDataInEnvironmentCode:               "SensitiveDataInEnvironment",
	sensitiveDataInSecretKeyRefCode:              "SensitiveDataInSecretKeyRef",
	containerRunAsRootCode:                       "ContainerRunAsRoot",
	containerWithoutRunAsNonRootCode:             "ContainerWithoutRunAsNonRoot",
	privilegeEscalationAllowedCode:               "PrivilegeEscalationAllowed",
	containerWithNetworkCapabilitiesCode:         "ContainerWithNetworkCapabilities",
	containerWithUnsafeProcMountCode:             "ContainerWithUnsafeProcMount",
	containerUsingUnsafeSysctlsCode:              "ContainerUsingUnsafeSysctls",
	containerWithoutResourceLimitsCode:           "ContainerWithoutResourceLimits",
	sensitiveHostDirectoriesCode:                 "SensitiveHostDirectories",
	containerWithSysadminCapabilityCode:          "ContainerWithSysadminCapability",
	serviceAttachedToLoadBalancerCode:            "ServiceAttachedToLoadBalancer",
	serviceAttachedToNodePortCode:                "ServiceAttachedToNodePort",
	hostPortAttachedToContainerCode:              "HostPortAttachedToContainer",
	hostNetworkAttachedToContainerCode:           "HostNetworkAttachedToContainer",
	containerInHostPidNamespaceCode:              "ContainerInHostPidNamespace",
	containerInHostIpcNamespaceCode:              "ContainerInHostIpcNamespace",
	workloadInDefaultNamespaceCode:               "WorkloadInDefaultNamespace",
	workloadWithUnconfinedSeccompProfileCode:     "WorkloadWithUnconfinedSeccompProfile",
	workloadWithoutSelinuxOrApparmorCode:         "WorkloadWithoutSelinuxOrApparmor",
	containerWithManyCapabilitiesCode:            "ContainerWithManyCapabilities",
	workloadWithoutRecommendedSeccompProfileCode: "WorkloadWithoutRecommendedSeccompProfile",
	workloadWithoutSecurityContextCode:           "WorkloadWithoutSecurityContext",
	runtimeSocketInContainerCode:                 "RuntimeSocketInContainer",
	entrypointContainsNetworkScanningCommandCode: "EntrypointContainsNetworkScanningCommand",
	entrypointContainsChrootCommandCode:          "EntrypointContainsChrootCommand",
	malformedSysctlValueCode:                     "MalformedSysctlValue",
	serviceAccountTokenAutomountedCode:           "ServiceAccountTokenAutomounted",
}

var defaultRulesAttributeMap = map[string]attr.Type{
	"privileged_container":                         types.StringType,
	"sensitive_data_in_environment":                types.StringType,
	"sensitive_data_in_secret_key_ref":             types.StringType,
	"container_run_as_root":                        types.StringType,
	"container_without_run_as_non_root":            types.StringType,
	"privilege_escalation_allowed":                 types.StringType,
	"container_with_network_capabilities":          types.StringType,
	"container_with_unsafe_proc_mount":             types.StringType,
	"container_using_unsafe_sysctls":               types.StringType,
	"container_without_resource_limits":            types.StringType,
	"sensitive_host_directories":                   types.StringType,
	"container_with_sysadmin_capability":           types.StringType,
	"service_attached_to_load_balancer":            types.StringType,
	"service_attached_to_node_port":                types.StringType,
	"host_port_attached_to_container":              types.StringType,
	"host_network_attached_to_container":           types.StringType,
	"container_in_host_pid_namespace":              types.StringType,
	"container_in_host_ipc_namespace":              types.StringType,
	"workload_in_default_namespace":                types.StringType,
	"workload_with_unconfined_seccomp_profile":     types.StringType,
	"workload_without_selinux_or_apparmor":         types.StringType,
	"container_with_many_capabilities":             types.StringType,
	"workload_without_recommended_seccomp_profile": types.StringType,
	"workload_without_security_context":            types.StringType,
	"runtime_socket_in_container":                  types.StringType,
	"entrypoint_contains_network_scanning_command": types.StringType,
	"entrypoint_contains_chroot_command":           types.StringType,
	"malformed_sysctl_value":                       types.StringType,
	"service_account_token_automounted":            types.StringType,
}

var defaultRulesDefaultValue = types.ObjectValueMust(
	defaultRulesAttributeMap,
	map[string]attr.Value{
		"privileged_container":                         types.StringValue("Alert"),
		"sensitive_data_in_environment":                types.StringValue("Alert"),
		"sensitive_data_in_secret_key_ref":             types.StringValue("Alert"),
		"container_run_as_root":                        types.StringValue("Alert"),
		"container_without_run_as_non_root":            types.StringValue("Alert"),
		"privilege_escalation_allowed":                 types.StringValue("Alert"),
		"container_with_network_capabilities":          types.StringValue("Alert"),
		"container_with_unsafe_proc_mount":             types.StringValue("Alert"),
		"container_using_unsafe_sysctls":               types.StringValue("Alert"),
		"container_without_resource_limits":            types.StringValue("Alert"),
		"sensitive_host_directories":                   types.StringValue("Alert"),
		"container_with_sysadmin_capability":           types.StringValue("Alert"),
		"service_attached_to_load_balancer":            types.StringValue("Alert"),
		"service_attached_to_node_port":                types.StringValue("Alert"),
		"host_port_attached_to_container":              types.StringValue("Alert"),
		"host_network_attached_to_container":           types.StringValue("Alert"),
		"container_in_host_pid_namespace":              types.StringValue("Alert"),
		"container_in_host_ipc_namespace":              types.StringValue("Alert"),
		"workload_in_default_namespace":                types.StringValue("Alert"),
		"workload_with_unconfined_seccomp_profile":     types.StringValue("Alert"),
		"workload_without_selinux_or_apparmor":         types.StringValue("Alert"),
		"container_with_many_capabilities":             types.StringValue("Alert"),
		"workload_without_recommended_seccomp_profile": types.StringValue("Alert"),
		"workload_without_security_context":            types.StringValue("Alert"),
		"runtime_socket_in_container":                  types.StringValue("Alert"),
		"entrypoint_contains_network_scanning_command": types.StringValue("Alert"),
		"entrypoint_contains_chroot_command":           types.StringValue("Alert"),
		"malformed_sysctl_value":                       types.StringValue("Alert"),
		"service_account_token_automounted":            types.StringValue("Alert"),
	},
)

var defaultRulesSchema = schema.SingleNestedAttribute{
	Optional:    true,
	Computed:    true,
	Description: "Set the action Falcon KAC should take when assessing default rules. All default rules are set to \"Alert\" by default. Action must be one of:\n - \"Disabled\": Do nothing\n - \"Alert\": Send an alert\n - \"Prevent\": Prevent the object from running",
	Default:     objectdefault.StaticValue(defaultRulesDefaultValue),
	Attributes: map[string]schema.Attribute{
		"privileged_container":                         defaultRuleSchema("Privileged workload running in kubernetes. A privileged workload allows access to host resources and kernel capabilities which increases the attack surface significantly."),
		"sensitive_data_in_environment":                defaultRuleSchema("Environment variables expose sensitive data. Secrets found in environment variables."),
		"sensitive_data_in_secret_key_ref":             defaultRuleSchema("Environment variables expose sensitive data. Secrets found in SecretKeyRef of spec."),
		"container_run_as_root":                        defaultRuleSchema("The container is configured to run as root. Containers running as root allow applications to modify the container filesystem, memory and system packages at runtime. Additionally, root users can create raw sockets and bind on ports under 1024. These workloads should be avoided as it increases the attack surface."),
		"container_without_run_as_non_root":            defaultRuleSchema("The container is allowed to run as root. Containers running as root allow applications to modify the container filesystem, memory and system packages at runtime. Additionally, root users can create raw sockets and bind on ports under 1024. These workloads should be avoided as it increases the attack surface."),
		"privilege_escalation_allowed":                 defaultRuleSchema("AllowPrivilegeEscalation controls whether a process can gain more privileges than its parent process. It can be a security risk as it may help child process gain more privileges."),
		"container_with_network_capabilities":          defaultRuleSchema("CAP_NET_RAW is a powerful Linux capability. Processes with this capability can forge any kind of packet or bind to any address. This allows a container to open raw sockets and inject malicious packets into the Kubernetes container network."),
		"container_with_unsafe_proc_mount":             defaultRuleSchema("Container has access to the host's /proc filesystem. By default, container runtime masks certain parts of the /proc filesystem from within a container in order to prevent potential security issues. There are only two valid options for this entry: Default, which maintains the standard container runtime behavior, or Unmasked, which removes all masking for the /proc filesystem."),
		"container_using_unsafe_sysctls":               defaultRuleSchema("Sysctl allows users to modify the kernel settings at run time. Some sysctl configs can exhaust resources for other containers."),
		"container_without_resource_limits":            defaultRuleSchema("The container needs to have enough resources allocated on host to run. Without any resource constraints on container, a large application can drain all host resources, causing DoS attack (Denial of Service)."),
		"sensitive_host_directories":                   defaultRuleSchema("Containers can mount sensitive folders from the hosts, giving them potentially dangerous access to critical host configurations and binaries. Sharing sensitive folders and files, such as / (root), /var/run/, docker.sock, etc. can allow a container to reconfigure the Kubernetes clusters, run new container images, etc."),
		"container_with_sysadmin_capability":           defaultRuleSchema("One of the containers found with CAP_SYS_ADMIN capability. CAP_SYS_ADMIN capability is equivalent to root user. It can help an attacker to escape the container."),
		"service_attached_to_load_balancer":            defaultRuleSchema("The service is accessible from local network or the internet. A load balancer is exposing the workload, making it accessible from local network or the Internet."),
		"service_attached_to_node_port":                defaultRuleSchema("Workload is exposed through a node port. A node port can expose the workload on host network making it accessible from local network or the internet."),
		"host_port_attached_to_container":              defaultRuleSchema("This container setting binds the container listening port to the IP address of the host. This exposes the pod to adjacent networks and/or to the Internet. Binding a pod to a hostPort, limits the number of places the pod can be scheduled, because each [hostIP, hostPort, protocol] combination must be unique."),
		"host_network_attached_to_container":           defaultRuleSchema("Workload is exposed through a shared host network. Sharing host network allows container to sniff traffic on the host, access localhost services on node and potentially bypass network policy to attack the host network."),
		"container_in_host_pid_namespace":              defaultRuleSchema("Workload is exposed through a shared host pid. Sharing host PID allows visibility of process on host, potentially leaking host and container processes, environment variables, configurations etc."),
		"container_in_host_ipc_namespace":              defaultRuleSchema("Workload is exposed through a shared host ipc. Sharing host IPC allows container to communicate with host processes through IPC mechanism and access shared memory. It can potentially leak information or DoS the host process."),
		"workload_in_default_namespace":                defaultRuleSchema("Workload running in default namespace. Each workload or micro-service should run in a dedicated namespace with namespace specific security policies. A default namespace can be used by an attacker to bypass these specific security policies."),
		"workload_with_unconfined_seccomp_profile":     defaultRuleSchema("Workload should not have Unconfined seccomp profile attached. A seccomp policy specifies which system calls are allowed by the container. It is a sandboxing technique to limit system calls. An unconfined profile removes any system call limitations which allows an attacker to use any dangerous system call to break out of the container."),
		"workload_without_selinux_or_apparmor":         defaultRuleSchema("Workload should have SELinux or AppArmor profile attached. SELinux (RedHat-based distributions) and AppArmor (Debian-based distributions) provides Mandatory Access Control (MAC). It is a kernel level security module which restricts the access to a resource, based on a policy rather than a user role. A process initiated by the root user inside a container can not access host resources even if they are available, which limits an attacker escaping a container."),
		"container_with_many_capabilities":             defaultRuleSchema("This means that container has got more than expected number of capabilities. Limiting the admission of containers with capabilities ensures that only a small number of containers have extended capabilities outside the default range. This helps ensure that if a container is compromised, it is unable to provide a productive path for an attacker to move laterally to other containers in the pod."),
		"workload_without_recommended_seccomp_profile": defaultRuleSchema("Workload should have seccomp profile attached. A seccomp policy specifies which system calls can be called by an application. It is a sandboxing technique that reduces the chance that a kernel vulnerability will be successfully exploited."),
		"workload_without_security_context":            defaultRuleSchema("Workload should have appropriate security context present."),
		"runtime_socket_in_container":                  defaultRuleSchema("The container runtime socket such as /var/run/docker.sock is the UNIX socket that the Container Runtime is listening to. This is the primary entry point for the Container Runtime API. Providing access to runtime's socket is equivalent to giving unrestricted root access to your host. It leads to container escape and privilege escalation to host."),
		"entrypoint_contains_network_scanning_command": defaultRuleSchema("Presence of network scanning tool in the Pod command. The pod command configures how the container will run when initiated. Adversaries may attempt to get a listing of services running on remote hosts, including those that may be vulnerable to remote exploitation. Methods to acquire this information include port scans and vulnerability scans using tools that are brought onto a system."),
		"entrypoint_contains_chroot_command":           defaultRuleSchema("Adversaries may attempt to gain root access to host by running chroot on the /mnt directory in the pod command. The pod command configures how the container will run when initiated."),
		"malformed_sysctl_value":                       defaultRuleSchema("Sysctl allows users to modify the kernel settings at run time. A sysctl value was detected that attempts to set multiple kernel settings. This is an indication of malicious attempt to tamper with worker nodes in Kubernetes cluster. This is related to the vulnerability (CVE-2022-0811) that allows the attacker to pass malicious kernel settings via sysctl value and gain root access."),
		"service_account_token_automounted":            defaultRuleSchema("Service account secret token is mounted within the pod. Kubernetes mounts the service account token within a pod by default. If an application within the pod is compromised, an attacker can further compromise the cluster with the service account token."),
	},
}

type defaultRulesTFModel struct {
	PrivilegedContainer                      types.String `tfsdk:"privileged_container"`
	SensitiveDataInEnvironment               types.String `tfsdk:"sensitive_data_in_environment"`
	SensitiveDataInSecretKeyRef              types.String `tfsdk:"sensitive_data_in_secret_key_ref"`
	ContainerRunAsRoot                       types.String `tfsdk:"container_run_as_root"`
	ContainerWithoutRunAsNonRoot             types.String `tfsdk:"container_without_run_as_non_root"`
	PrivilegeEscalationAllowed               types.String `tfsdk:"privilege_escalation_allowed"`
	ContainerWithNetworkCapabilities         types.String `tfsdk:"container_with_network_capabilities"`
	ContainerWithUnsafeProcMount             types.String `tfsdk:"container_with_unsafe_proc_mount"`
	ContainerUsingUnsafeSysctls              types.String `tfsdk:"container_using_unsafe_sysctls"`
	ContainerWithoutResourceLimits           types.String `tfsdk:"container_without_resource_limits"`
	SensitiveHostDirectories                 types.String `tfsdk:"sensitive_host_directories"`
	ContainerWithSysadminCapability          types.String `tfsdk:"container_with_sysadmin_capability"`
	ServiceAttachedToLoadBalancer            types.String `tfsdk:"service_attached_to_load_balancer"`
	ServiceAttachedToNodePort                types.String `tfsdk:"service_attached_to_node_port"`
	HostPortAttachedToContainer              types.String `tfsdk:"host_port_attached_to_container"`
	HostNetworkAttachedToContainer           types.String `tfsdk:"host_network_attached_to_container"`
	ContainerInHostPidNamespace              types.String `tfsdk:"container_in_host_pid_namespace"`
	ContainerInHostIpcNamespace              types.String `tfsdk:"container_in_host_ipc_namespace"`
	WorkloadInDefaultNamespace               types.String `tfsdk:"workload_in_default_namespace"`
	WorkloadWithUnconfinedSeccompProfile     types.String `tfsdk:"workload_with_unconfined_seccomp_profile"`
	WorkloadWithoutSelinuxOrApparmor         types.String `tfsdk:"workload_without_selinux_or_apparmor"`
	ContainerWithManyCapabilities            types.String `tfsdk:"container_with_many_capabilities"`
	WorkloadWithoutRecommendedSeccompProfile types.String `tfsdk:"workload_without_recommended_seccomp_profile"`
	WorkloadWithoutSecurityContext           types.String `tfsdk:"workload_without_security_context"`
	RuntimeSocketInContainer                 types.String `tfsdk:"runtime_socket_in_container"`
	EntrypointContainsNetworkScanningCommand types.String `tfsdk:"entrypoint_contains_network_scanning_command"`
	EntrypointContainsChrootCommand          types.String `tfsdk:"entrypoint_contains_chroot_command"`
	MalformedSysctlValue                     types.String `tfsdk:"malformed_sysctl_value"`
	ServiceAccountTokenAutomounted           types.String `tfsdk:"service_account_token_automounted"`
}

func defaultRuleSchema(ruleDescription string) schema.StringAttribute {
	return schema.StringAttribute{
		Optional:            true,
		Computed:            true,
		Default:             stringdefault.StaticString("Alert"),
		MarkdownDescription: ruleDescription,
		Description:         "Determines what action Falcon KAC takes when assessing the default rule.",
		Validators: []validator.String{
			stringvalidator.OneOf("Alert", "Prevent", "Disabled"),
		},
	}
}

func (m *defaultRulesTFModel) wrapDefaultRule(apiRule *models.PolicyhandlerKACDefaultPolicyRule) {
	action := types.StringValue(*apiRule.Action)

	// Get the field name from the rule code
	fieldName, exists := ruleCodeToFieldNameMap[*apiRule.Code]
	if !exists {
		return
	}

	// Use reflection to set the field
	v := reflect.ValueOf(m).Elem()
	field := v.FieldByName(fieldName)
	if field.IsValid() && field.CanSet() {
		field.Set(reflect.ValueOf(action))
	}
}

func (m *defaultRulesTFModel) toApiDefaultRuleActions(
	ctx context.Context,
	tfRuleGroup ruleGroupTFModel,
) ([]*models.APIUpdateDefaultRuleAction, diag.Diagnostics) {
	var diags diag.Diagnostics

	diags.Append(tfRuleGroup.DefaultRules.As(ctx, m, basetypes.ObjectAsOptions{})...)
	if diags.HasError() {
		return nil, diags
	}

	var apiDefaultRuleActions []*models.APIUpdateDefaultRuleAction

	// Use reflection to iterate through all fields in the struct
	v := reflect.ValueOf(m).Elem()
	t := reflect.TypeOf(m).Elem()

	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		fieldType := t.Field(i)
		fieldName := fieldType.Name

		tfString, ok := field.Interface().(types.String)
		if !ok {
			continue
		}

		if tfString.IsUnknown() {
			continue
		}

		ruleCode, exists := fieldNameToRuleCodeMap[fieldName]
		if !exists {
			continue
		}

		action := tfString.ValueString()
		apiDefaultRuleAction := &models.APIUpdateDefaultRuleAction{
			Code:   stringPtr(ruleCode),
			Action: &action,
		}
		apiDefaultRuleActions = append(apiDefaultRuleActions, apiDefaultRuleAction)
	}

	return apiDefaultRuleActions, diags
}

func stringPtr(s string) *string {
	return &s
}
