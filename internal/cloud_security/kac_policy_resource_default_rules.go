package cloudsecurity

import (
	"context"

	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/objectplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
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

var defaultRuleObjectType = types.ObjectType{
	AttrTypes: map[string]attr.Type{
		"code":   types.StringType,
		"action": types.StringType,
	},
}

var defaultRulesAttributeMap = map[string]attr.Type{
	"privileged_container":                         defaultRuleObjectType,
	"sensitive_data_in_environment":                defaultRuleObjectType,
	"sensitive_data_in_secret_key_ref":             defaultRuleObjectType,
	"container_run_as_root":                        defaultRuleObjectType,
	"container_without_run_as_non_root":            defaultRuleObjectType,
	"privilege_escalation_allowed":                 defaultRuleObjectType,
	"container_with_network_capabilities":          defaultRuleObjectType,
	"container_with_unsafe_proc_mount":             defaultRuleObjectType,
	"container_using_unsafe_sysctls":               defaultRuleObjectType,
	"container_without_resource_limits":            defaultRuleObjectType,
	"sensitive_host_directories":                   defaultRuleObjectType,
	"container_with_sysadmin_capability":           defaultRuleObjectType,
	"service_attached_to_load_balancer":            defaultRuleObjectType,
	"service_attached_to_node_port":                defaultRuleObjectType,
	"host_port_attached_to_container":              defaultRuleObjectType,
	"host_network_attached_to_container":           defaultRuleObjectType,
	"container_in_host_pid_namespace":              defaultRuleObjectType,
	"container_in_host_ipc_namespace":              defaultRuleObjectType,
	"workload_in_default_namespace":                defaultRuleObjectType,
	"workload_with_unconfined_seccomp_profile":     defaultRuleObjectType,
	"workload_without_selinux_or_apparmor":         defaultRuleObjectType,
	"container_with_many_capabilities":             defaultRuleObjectType,
	"workload_without_recommended_seccomp_profile": defaultRuleObjectType,
	"workload_without_security_context":            defaultRuleObjectType,
	"runtime_socket_in_container":                  defaultRuleObjectType,
	"entrypoint_contains_network_scanning_command": defaultRuleObjectType,
	"entrypoint_contains_chroot_command":           defaultRuleObjectType,
	"malformed_sysctl_value":                       defaultRuleObjectType,
	"service_account_token_automounted":            defaultRuleObjectType,
}

var defaultRulesSchema = map[string]schema.Attribute{
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
}

type defaultRulesTFModel struct {
	PrivilegedContainer                      types.Object `tfsdk:"privileged_container"`
	SensitiveDataInEnvironment               types.Object `tfsdk:"sensitive_data_in_environment"`
	SensitiveDataInSecretKeyRef              types.Object `tfsdk:"sensitive_data_in_secret_key_ref"`
	ContainerRunAsRoot                       types.Object `tfsdk:"container_run_as_root"`
	ContainerWithoutRunAsNonRoot             types.Object `tfsdk:"container_without_run_as_non_root"`
	PrivilegeEscalationAllowed               types.Object `tfsdk:"privilege_escalation_allowed"`
	ContainerWithNetworkCapabilities         types.Object `tfsdk:"container_with_network_capabilities"`
	ContainerWithUnsafeProcMount             types.Object `tfsdk:"container_with_unsafe_proc_mount"`
	ContainerUsingUnsafeSysctls              types.Object `tfsdk:"container_using_unsafe_sysctls"`
	ContainerWithoutResourceLimits           types.Object `tfsdk:"container_without_resource_limits"`
	SensitiveHostDirectories                 types.Object `tfsdk:"sensitive_host_directories"`
	ContainerWithSysadminCapability          types.Object `tfsdk:"container_with_sysadmin_capability"`
	ServiceAttachedToLoadBalancer            types.Object `tfsdk:"service_attached_to_load_balancer"`
	ServiceAttachedToNodePort                types.Object `tfsdk:"service_attached_to_node_port"`
	HostPortAttachedToContainer              types.Object `tfsdk:"host_port_attached_to_container"`
	HostNetworkAttachedToContainer           types.Object `tfsdk:"host_network_attached_to_container"`
	ContainerInHostPidNamespace              types.Object `tfsdk:"container_in_host_pid_namespace"`
	ContainerInHostIpcNamespace              types.Object `tfsdk:"container_in_host_ipc_namespace"`
	WorkloadInDefaultNamespace               types.Object `tfsdk:"workload_in_default_namespace"`
	WorkloadWithUnconfinedSeccompProfile     types.Object `tfsdk:"workload_with_unconfined_seccomp_profile"`
	WorkloadWithoutSelinuxOrApparmor         types.Object `tfsdk:"workload_without_selinux_or_apparmor"`
	ContainerWithManyCapabilities            types.Object `tfsdk:"container_with_many_capabilities"`
	WorkloadWithoutRecommendedSeccompProfile types.Object `tfsdk:"workload_without_recommended_seccomp_profile"`
	WorkloadWithoutSecurityContext           types.Object `tfsdk:"workload_without_security_context"`
	RuntimeSocketInContainer                 types.Object `tfsdk:"runtime_socket_in_container"`
	EntrypointContainsNetworkScanningCommand types.Object `tfsdk:"entrypoint_contains_network_scanning_command"`
	EntrypointContainsChrootCommand          types.Object `tfsdk:"entrypoint_contains_chroot_command"`
	MalformedSysctlValue                     types.Object `tfsdk:"malformed_sysctl_value"`
	ServiceAccountTokenAutomounted           types.Object `tfsdk:"service_account_token_automounted"`
}

type defaultRuleTFModel struct {
	Code   types.String `tfsdk:"code"`
	Action types.String `tfsdk:"action"`
}

func defaultRuleSchema(ruleDescription string) schema.SingleNestedAttribute {
	return schema.SingleNestedAttribute{
		Optional: true,
		Computed: true,
		PlanModifiers: []planmodifier.Object{
			objectplanmodifier.UseStateForUnknown(),
		},
		MarkdownDescription: ruleDescription,
		Attributes: map[string]schema.Attribute{
			"code": schema.StringAttribute{
				Computed:    true,
				Description: "Identifier, as a 6 digit code, for the KAC policy default rule.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"action": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Default:     stringdefault.StaticString("Alert"),
				Description: "Determines what action Falcon KAC takes when assessing the default rule.",
				Validators: []validator.String{
					stringvalidator.OneOf("Alert", "Prevent", "Disabled"),
				},
			},
		},
	}
}

func (m *defaultRulesTFModel) wrapDefaultRule(
	ctx context.Context,
	apiRule *models.PolicyhandlerKACDefaultPolicyRule,
) diag.Diagnostics {
	var diags diag.Diagnostics
	ruleObj, objDiags := types.ObjectValueFrom(ctx, map[string]attr.Type{
		"code":   types.StringType,
		"action": types.StringType,
	}, defaultRuleTFModel{
		Code:   types.StringValue(*apiRule.Code),
		Action: types.StringValue(*apiRule.Action),
	})
	diags.Append(objDiags...)

	switch *apiRule.Code {
	case privilegedContainerCode:
		m.PrivilegedContainer = ruleObj
	case sensitiveDataInEnvironmentCode:
		m.SensitiveDataInEnvironment = ruleObj
	case sensitiveDataInSecretKeyRefCode:
		m.SensitiveDataInSecretKeyRef = ruleObj
	case containerRunAsRootCode:
		m.ContainerRunAsRoot = ruleObj
	case containerWithoutRunAsNonRootCode:
		m.ContainerWithoutRunAsNonRoot = ruleObj
	case privilegeEscalationAllowedCode:
		m.PrivilegeEscalationAllowed = ruleObj
	case containerWithNetworkCapabilitiesCode:
		m.ContainerWithNetworkCapabilities = ruleObj
	case containerWithUnsafeProcMountCode:
		m.ContainerWithUnsafeProcMount = ruleObj
	case containerUsingUnsafeSysctlsCode:
		m.ContainerUsingUnsafeSysctls = ruleObj
	case containerWithoutResourceLimitsCode:
		m.ContainerWithoutResourceLimits = ruleObj
	case sensitiveHostDirectoriesCode:
		m.SensitiveHostDirectories = ruleObj
	case containerWithSysadminCapabilityCode:
		m.ContainerWithSysadminCapability = ruleObj
	case serviceAttachedToLoadBalancerCode:
		m.ServiceAttachedToLoadBalancer = ruleObj
	case serviceAttachedToNodePortCode:
		m.ServiceAttachedToNodePort = ruleObj
	case hostPortAttachedToContainerCode:
		m.HostPortAttachedToContainer = ruleObj
	case hostNetworkAttachedToContainerCode:
		m.HostNetworkAttachedToContainer = ruleObj
	case containerInHostPidNamespaceCode:
		m.ContainerInHostPidNamespace = ruleObj
	case containerInHostIpcNamespaceCode:
		m.ContainerInHostIpcNamespace = ruleObj
	case workloadInDefaultNamespaceCode:
		m.WorkloadInDefaultNamespace = ruleObj
	case workloadWithUnconfinedSeccompProfileCode:
		m.WorkloadWithUnconfinedSeccompProfile = ruleObj
	case workloadWithoutSelinuxOrApparmorCode:
		m.WorkloadWithoutSelinuxOrApparmor = ruleObj
	case containerWithManyCapabilitiesCode:
		m.ContainerWithManyCapabilities = ruleObj
	case workloadWithoutRecommendedSeccompProfileCode:
		m.WorkloadWithoutRecommendedSeccompProfile = ruleObj
	case workloadWithoutSecurityContextCode:
		m.WorkloadWithoutSecurityContext = ruleObj
	case runtimeSocketInContainerCode:
		m.RuntimeSocketInContainer = ruleObj
	case entrypointContainsNetworkScanningCommandCode:
		m.EntrypointContainsNetworkScanningCommand = ruleObj
	case entrypointContainsChrootCommandCode:
		m.EntrypointContainsChrootCommand = ruleObj
	case malformedSysctlValueCode:
		m.MalformedSysctlValue = ruleObj
	case serviceAccountTokenAutomountedCode:
		m.ServiceAccountTokenAutomounted = ruleObj
	default:
		// TODO: add error/warning for code does not match any default rule
		return diags
	}

	return diags
}

//nolint:gocyclo
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

	if !m.PrivilegedContainer.IsNull() && !m.PrivilegedContainer.IsUnknown() {
		var rule defaultRuleTFModel
		diags.Append(m.PrivilegedContainer.As(ctx, &rule, basetypes.ObjectAsOptions{})...)
		if !diags.HasError() {
			ruleCode := rule.Code.ValueString()
			if rule.Code.IsNull() || rule.Code.IsUnknown() {
				ruleCode = privilegedContainerCode
			}
			apiDefaultRuleAction := &models.APIUpdateDefaultRuleAction{
				Code:   &ruleCode,
				Action: rule.Action.ValueStringPointer(),
			}
			apiDefaultRuleActions = append(apiDefaultRuleActions, apiDefaultRuleAction)
		}
	}

	if !m.SensitiveDataInEnvironment.IsNull() && !m.SensitiveDataInEnvironment.IsUnknown() {
		var rule defaultRuleTFModel
		diags.Append(m.SensitiveDataInEnvironment.As(ctx, &rule, basetypes.ObjectAsOptions{})...)
		if !diags.HasError() {
			ruleCode := rule.Code.ValueString()
			if rule.Code.IsNull() || rule.Code.IsUnknown() {
				ruleCode = sensitiveDataInEnvironmentCode
			}
			apiDefaultRuleAction := &models.APIUpdateDefaultRuleAction{
				Code:   &ruleCode,
				Action: rule.Action.ValueStringPointer(),
			}
			apiDefaultRuleActions = append(apiDefaultRuleActions, apiDefaultRuleAction)
		}
	}

	if !m.SensitiveDataInSecretKeyRef.IsNull() && !m.SensitiveDataInSecretKeyRef.IsUnknown() {
		var rule defaultRuleTFModel
		diags.Append(m.SensitiveDataInSecretKeyRef.As(ctx, &rule, basetypes.ObjectAsOptions{})...)
		if !diags.HasError() {
			ruleCode := rule.Code.ValueString()
			if rule.Code.IsNull() || rule.Code.IsUnknown() {
				ruleCode = sensitiveDataInSecretKeyRefCode
			}
			apiDefaultRuleAction := &models.APIUpdateDefaultRuleAction{
				Code:   &ruleCode,
				Action: rule.Action.ValueStringPointer(),
			}
			apiDefaultRuleActions = append(apiDefaultRuleActions, apiDefaultRuleAction)
		}
	}

	if !m.ContainerRunAsRoot.IsNull() && !m.ContainerRunAsRoot.IsUnknown() {
		var rule defaultRuleTFModel
		diags.Append(m.ContainerRunAsRoot.As(ctx, &rule, basetypes.ObjectAsOptions{})...)
		if !diags.HasError() {
			ruleCode := rule.Code.ValueString()
			if rule.Code.IsNull() || rule.Code.IsUnknown() {
				ruleCode = containerRunAsRootCode
			}
			apiDefaultRuleAction := &models.APIUpdateDefaultRuleAction{
				Code:   &ruleCode,
				Action: rule.Action.ValueStringPointer(),
			}
			apiDefaultRuleActions = append(apiDefaultRuleActions, apiDefaultRuleAction)
		}
	}

	if !m.ContainerWithoutRunAsNonRoot.IsNull() && !m.ContainerWithoutRunAsNonRoot.IsUnknown() {
		var rule defaultRuleTFModel
		diags.Append(m.ContainerWithoutRunAsNonRoot.As(ctx, &rule, basetypes.ObjectAsOptions{})...)
		if !diags.HasError() {
			ruleCode := rule.Code.ValueString()
			if rule.Code.IsNull() || rule.Code.IsUnknown() {
				ruleCode = containerWithoutRunAsNonRootCode
			}
			apiDefaultRuleAction := &models.APIUpdateDefaultRuleAction{
				Code:   &ruleCode,
				Action: rule.Action.ValueStringPointer(),
			}
			apiDefaultRuleActions = append(apiDefaultRuleActions, apiDefaultRuleAction)
		}
	}

	if !m.PrivilegeEscalationAllowed.IsNull() && !m.PrivilegeEscalationAllowed.IsUnknown() {
		var rule defaultRuleTFModel
		diags.Append(m.PrivilegeEscalationAllowed.As(ctx, &rule, basetypes.ObjectAsOptions{})...)
		if !diags.HasError() {
			ruleCode := rule.Code.ValueString()
			if rule.Code.IsNull() || rule.Code.IsUnknown() {
				ruleCode = privilegeEscalationAllowedCode
			}
			apiDefaultRuleAction := &models.APIUpdateDefaultRuleAction{
				Code:   &ruleCode,
				Action: rule.Action.ValueStringPointer(),
			}
			apiDefaultRuleActions = append(apiDefaultRuleActions, apiDefaultRuleAction)
		}
	}

	if !m.ContainerWithNetworkCapabilities.IsNull() && !m.ContainerWithNetworkCapabilities.IsUnknown() {
		var rule defaultRuleTFModel
		diags.Append(m.ContainerWithNetworkCapabilities.As(ctx, &rule, basetypes.ObjectAsOptions{})...)
		if !diags.HasError() {
			ruleCode := rule.Code.ValueString()
			if rule.Code.IsNull() || rule.Code.IsUnknown() {
				ruleCode = containerWithNetworkCapabilitiesCode
			}
			apiDefaultRuleAction := &models.APIUpdateDefaultRuleAction{
				Code:   &ruleCode,
				Action: rule.Action.ValueStringPointer(),
			}
			apiDefaultRuleActions = append(apiDefaultRuleActions, apiDefaultRuleAction)
		}
	}

	if !m.ContainerWithUnsafeProcMount.IsNull() && !m.ContainerWithUnsafeProcMount.IsUnknown() {
		var rule defaultRuleTFModel
		diags.Append(m.ContainerWithUnsafeProcMount.As(ctx, &rule, basetypes.ObjectAsOptions{})...)
		if !diags.HasError() {
			ruleCode := rule.Code.ValueString()
			if rule.Code.IsNull() || rule.Code.IsUnknown() {
				ruleCode = containerWithUnsafeProcMountCode
			}
			apiDefaultRuleAction := &models.APIUpdateDefaultRuleAction{
				Code:   &ruleCode,
				Action: rule.Action.ValueStringPointer(),
			}
			apiDefaultRuleActions = append(apiDefaultRuleActions, apiDefaultRuleAction)
		}
	}

	if !m.ContainerUsingUnsafeSysctls.IsNull() && !m.ContainerUsingUnsafeSysctls.IsUnknown() {
		var rule defaultRuleTFModel
		diags.Append(m.ContainerUsingUnsafeSysctls.As(ctx, &rule, basetypes.ObjectAsOptions{})...)
		if !diags.HasError() {
			ruleCode := rule.Code.ValueString()
			if rule.Code.IsNull() || rule.Code.IsUnknown() {
				ruleCode = containerUsingUnsafeSysctlsCode
			}
			apiDefaultRuleAction := &models.APIUpdateDefaultRuleAction{
				Code:   &ruleCode,
				Action: rule.Action.ValueStringPointer(),
			}
			apiDefaultRuleActions = append(apiDefaultRuleActions, apiDefaultRuleAction)
		}
	}

	if !m.ContainerWithoutResourceLimits.IsNull() && !m.ContainerWithoutResourceLimits.IsUnknown() {
		var rule defaultRuleTFModel
		diags.Append(m.ContainerWithoutResourceLimits.As(ctx, &rule, basetypes.ObjectAsOptions{})...)
		if !diags.HasError() {
			ruleCode := rule.Code.ValueString()
			if rule.Code.IsNull() || rule.Code.IsUnknown() {
				ruleCode = containerWithoutResourceLimitsCode
			}
			apiDefaultRuleAction := &models.APIUpdateDefaultRuleAction{
				Code:   &ruleCode,
				Action: rule.Action.ValueStringPointer(),
			}
			apiDefaultRuleActions = append(apiDefaultRuleActions, apiDefaultRuleAction)
		}
	}

	if !m.SensitiveHostDirectories.IsNull() && !m.SensitiveHostDirectories.IsUnknown() {
		var rule defaultRuleTFModel
		diags.Append(m.SensitiveHostDirectories.As(ctx, &rule, basetypes.ObjectAsOptions{})...)
		if !diags.HasError() {
			ruleCode := rule.Code.ValueString()
			if rule.Code.IsNull() || rule.Code.IsUnknown() {
				ruleCode = sensitiveHostDirectoriesCode
			}
			apiDefaultRuleAction := &models.APIUpdateDefaultRuleAction{
				Code:   &ruleCode,
				Action: rule.Action.ValueStringPointer(),
			}
			apiDefaultRuleActions = append(apiDefaultRuleActions, apiDefaultRuleAction)
		}
	}

	if !m.ContainerWithSysadminCapability.IsNull() && !m.ContainerWithSysadminCapability.IsUnknown() {
		var rule defaultRuleTFModel
		diags.Append(m.ContainerWithSysadminCapability.As(ctx, &rule, basetypes.ObjectAsOptions{})...)
		if !diags.HasError() {
			ruleCode := rule.Code.ValueString()
			if rule.Code.IsNull() || rule.Code.IsUnknown() {
				ruleCode = containerWithSysadminCapabilityCode
			}
			apiDefaultRuleAction := &models.APIUpdateDefaultRuleAction{
				Code:   &ruleCode,
				Action: rule.Action.ValueStringPointer(),
			}
			apiDefaultRuleActions = append(apiDefaultRuleActions, apiDefaultRuleAction)
		}
	}

	if !m.ServiceAttachedToLoadBalancer.IsNull() && !m.ServiceAttachedToLoadBalancer.IsUnknown() {
		var rule defaultRuleTFModel
		diags.Append(m.ServiceAttachedToLoadBalancer.As(ctx, &rule, basetypes.ObjectAsOptions{})...)
		if !diags.HasError() {
			ruleCode := rule.Code.ValueString()
			if rule.Code.IsNull() || rule.Code.IsUnknown() {
				ruleCode = serviceAttachedToLoadBalancerCode
			}
			apiDefaultRuleAction := &models.APIUpdateDefaultRuleAction{
				Code:   &ruleCode,
				Action: rule.Action.ValueStringPointer(),
			}
			apiDefaultRuleActions = append(apiDefaultRuleActions, apiDefaultRuleAction)
		}
	}

	if !m.ServiceAttachedToNodePort.IsNull() && !m.ServiceAttachedToNodePort.IsUnknown() {
		var rule defaultRuleTFModel
		diags.Append(m.ServiceAttachedToNodePort.As(ctx, &rule, basetypes.ObjectAsOptions{})...)
		if !diags.HasError() {
			ruleCode := rule.Code.ValueString()
			if rule.Code.IsNull() || rule.Code.IsUnknown() {
				ruleCode = serviceAttachedToNodePortCode
			}
			apiDefaultRuleAction := &models.APIUpdateDefaultRuleAction{
				Code:   &ruleCode,
				Action: rule.Action.ValueStringPointer(),
			}
			apiDefaultRuleActions = append(apiDefaultRuleActions, apiDefaultRuleAction)
		}
	}

	if !m.HostPortAttachedToContainer.IsNull() && !m.HostPortAttachedToContainer.IsUnknown() {
		var rule defaultRuleTFModel
		diags.Append(m.HostPortAttachedToContainer.As(ctx, &rule, basetypes.ObjectAsOptions{})...)
		if !diags.HasError() {
			ruleCode := rule.Code.ValueString()
			if rule.Code.IsNull() || rule.Code.IsUnknown() {
				ruleCode = hostPortAttachedToContainerCode
			}
			apiDefaultRuleAction := &models.APIUpdateDefaultRuleAction{
				Code:   &ruleCode,
				Action: rule.Action.ValueStringPointer(),
			}
			apiDefaultRuleActions = append(apiDefaultRuleActions, apiDefaultRuleAction)
		}
	}

	if !m.HostNetworkAttachedToContainer.IsNull() && !m.HostNetworkAttachedToContainer.IsUnknown() {
		var rule defaultRuleTFModel
		diags.Append(m.HostNetworkAttachedToContainer.As(ctx, &rule, basetypes.ObjectAsOptions{})...)
		if !diags.HasError() {
			ruleCode := rule.Code.ValueString()
			if rule.Code.IsNull() || rule.Code.IsUnknown() {
				ruleCode = hostNetworkAttachedToContainerCode
			}
			apiDefaultRuleAction := &models.APIUpdateDefaultRuleAction{
				Code:   &ruleCode,
				Action: rule.Action.ValueStringPointer(),
			}
			apiDefaultRuleActions = append(apiDefaultRuleActions, apiDefaultRuleAction)
		}
	}

	if !m.ContainerInHostPidNamespace.IsNull() && !m.ContainerInHostPidNamespace.IsUnknown() {
		var rule defaultRuleTFModel
		diags.Append(m.ContainerInHostPidNamespace.As(ctx, &rule, basetypes.ObjectAsOptions{})...)
		if !diags.HasError() {
			ruleCode := rule.Code.ValueString()
			if rule.Code.IsNull() || rule.Code.IsUnknown() {
				ruleCode = containerInHostPidNamespaceCode
			}
			apiDefaultRuleAction := &models.APIUpdateDefaultRuleAction{
				Code:   &ruleCode,
				Action: rule.Action.ValueStringPointer(),
			}
			apiDefaultRuleActions = append(apiDefaultRuleActions, apiDefaultRuleAction)
		}
	}

	if !m.ContainerInHostIpcNamespace.IsNull() && !m.ContainerInHostIpcNamespace.IsUnknown() {
		var rule defaultRuleTFModel
		diags.Append(m.ContainerInHostIpcNamespace.As(ctx, &rule, basetypes.ObjectAsOptions{})...)
		if !diags.HasError() {
			ruleCode := rule.Code.ValueString()
			if rule.Code.IsNull() || rule.Code.IsUnknown() {
				ruleCode = containerInHostIpcNamespaceCode
			}
			apiDefaultRuleAction := &models.APIUpdateDefaultRuleAction{
				Code:   &ruleCode,
				Action: rule.Action.ValueStringPointer(),
			}
			apiDefaultRuleActions = append(apiDefaultRuleActions, apiDefaultRuleAction)
		}
	}

	if !m.WorkloadInDefaultNamespace.IsNull() && !m.WorkloadInDefaultNamespace.IsUnknown() {
		var rule defaultRuleTFModel
		diags.Append(m.WorkloadInDefaultNamespace.As(ctx, &rule, basetypes.ObjectAsOptions{})...)
		if !diags.HasError() {
			ruleCode := rule.Code.ValueString()
			if rule.Code.IsNull() || rule.Code.IsUnknown() {
				ruleCode = workloadInDefaultNamespaceCode
			}
			apiDefaultRuleAction := &models.APIUpdateDefaultRuleAction{
				Code:   &ruleCode,
				Action: rule.Action.ValueStringPointer(),
			}
			apiDefaultRuleActions = append(apiDefaultRuleActions, apiDefaultRuleAction)
		}
	}

	if !m.WorkloadWithUnconfinedSeccompProfile.IsNull() && !m.WorkloadWithUnconfinedSeccompProfile.IsUnknown() {
		var rule defaultRuleTFModel
		diags.Append(m.WorkloadWithUnconfinedSeccompProfile.As(ctx, &rule, basetypes.ObjectAsOptions{})...)
		if !diags.HasError() {
			ruleCode := rule.Code.ValueString()
			if rule.Code.IsNull() || rule.Code.IsUnknown() {
				ruleCode = workloadWithUnconfinedSeccompProfileCode
			}
			apiDefaultRuleAction := &models.APIUpdateDefaultRuleAction{
				Code:   &ruleCode,
				Action: rule.Action.ValueStringPointer(),
			}
			apiDefaultRuleActions = append(apiDefaultRuleActions, apiDefaultRuleAction)
		}
	}

	if !m.WorkloadWithoutSelinuxOrApparmor.IsNull() && !m.WorkloadWithoutSelinuxOrApparmor.IsUnknown() {
		var rule defaultRuleTFModel
		diags.Append(m.WorkloadWithoutSelinuxOrApparmor.As(ctx, &rule, basetypes.ObjectAsOptions{})...)
		if !diags.HasError() {
			ruleCode := rule.Code.ValueString()
			if rule.Code.IsNull() || rule.Code.IsUnknown() {
				ruleCode = workloadWithoutSelinuxOrApparmorCode
			}
			apiDefaultRuleAction := &models.APIUpdateDefaultRuleAction{
				Code:   &ruleCode,
				Action: rule.Action.ValueStringPointer(),
			}
			apiDefaultRuleActions = append(apiDefaultRuleActions, apiDefaultRuleAction)
		}
	}

	if !m.ContainerWithManyCapabilities.IsNull() && !m.ContainerWithManyCapabilities.IsUnknown() {
		var rule defaultRuleTFModel
		diags.Append(m.ContainerWithManyCapabilities.As(ctx, &rule, basetypes.ObjectAsOptions{})...)
		if !diags.HasError() {
			ruleCode := rule.Code.ValueString()
			if rule.Code.IsNull() || rule.Code.IsUnknown() {
				ruleCode = containerWithManyCapabilitiesCode
			}
			apiDefaultRuleAction := &models.APIUpdateDefaultRuleAction{
				Code:   &ruleCode,
				Action: rule.Action.ValueStringPointer(),
			}
			apiDefaultRuleActions = append(apiDefaultRuleActions, apiDefaultRuleAction)
		}
	}

	if !m.WorkloadWithoutRecommendedSeccompProfile.IsNull() && !m.WorkloadWithoutRecommendedSeccompProfile.IsUnknown() {
		var rule defaultRuleTFModel
		diags.Append(m.WorkloadWithoutRecommendedSeccompProfile.As(ctx, &rule, basetypes.ObjectAsOptions{})...)
		if !diags.HasError() {
			ruleCode := rule.Code.ValueString()
			if rule.Code.IsNull() || rule.Code.IsUnknown() {
				ruleCode = workloadWithoutRecommendedSeccompProfileCode
			}
			apiDefaultRuleAction := &models.APIUpdateDefaultRuleAction{
				Code:   &ruleCode,
				Action: rule.Action.ValueStringPointer(),
			}
			apiDefaultRuleActions = append(apiDefaultRuleActions, apiDefaultRuleAction)
		}
	}

	if !m.WorkloadWithoutSecurityContext.IsNull() && !m.WorkloadWithoutSecurityContext.IsUnknown() {
		var rule defaultRuleTFModel
		diags.Append(m.WorkloadWithoutSecurityContext.As(ctx, &rule, basetypes.ObjectAsOptions{})...)
		if !diags.HasError() {
			ruleCode := rule.Code.ValueString()
			if rule.Code.IsNull() || rule.Code.IsUnknown() {
				ruleCode = workloadWithoutSecurityContextCode
			}
			apiDefaultRuleAction := &models.APIUpdateDefaultRuleAction{
				Code:   &ruleCode,
				Action: rule.Action.ValueStringPointer(),
			}
			apiDefaultRuleActions = append(apiDefaultRuleActions, apiDefaultRuleAction)
		}
	}

	if !m.RuntimeSocketInContainer.IsNull() && !m.RuntimeSocketInContainer.IsUnknown() {
		var rule defaultRuleTFModel
		diags.Append(m.RuntimeSocketInContainer.As(ctx, &rule, basetypes.ObjectAsOptions{})...)
		if !diags.HasError() {
			ruleCode := rule.Code.ValueString()
			if rule.Code.IsNull() || rule.Code.IsUnknown() {
				ruleCode = runtimeSocketInContainerCode
			}
			apiDefaultRuleAction := &models.APIUpdateDefaultRuleAction{
				Code:   &ruleCode,
				Action: rule.Action.ValueStringPointer(),
			}
			apiDefaultRuleActions = append(apiDefaultRuleActions, apiDefaultRuleAction)
		}
	}

	if !m.EntrypointContainsNetworkScanningCommand.IsNull() && !m.EntrypointContainsNetworkScanningCommand.IsUnknown() {
		var rule defaultRuleTFModel
		diags.Append(m.EntrypointContainsNetworkScanningCommand.As(ctx, &rule, basetypes.ObjectAsOptions{})...)
		if !diags.HasError() {
			ruleCode := rule.Code.ValueString()
			if rule.Code.IsNull() || rule.Code.IsUnknown() {
				ruleCode = entrypointContainsNetworkScanningCommandCode
			}
			apiDefaultRuleAction := &models.APIUpdateDefaultRuleAction{
				Code:   &ruleCode,
				Action: rule.Action.ValueStringPointer(),
			}
			apiDefaultRuleActions = append(apiDefaultRuleActions, apiDefaultRuleAction)
		}
	}

	if !m.EntrypointContainsChrootCommand.IsNull() && !m.EntrypointContainsChrootCommand.IsUnknown() {
		var rule defaultRuleTFModel
		diags.Append(m.EntrypointContainsChrootCommand.As(ctx, &rule, basetypes.ObjectAsOptions{})...)
		if !diags.HasError() {
			ruleCode := rule.Code.ValueString()
			if rule.Code.IsNull() || rule.Code.IsUnknown() {
				ruleCode = entrypointContainsChrootCommandCode
			}
			apiDefaultRuleAction := &models.APIUpdateDefaultRuleAction{
				Code:   &ruleCode,
				Action: rule.Action.ValueStringPointer(),
			}
			apiDefaultRuleActions = append(apiDefaultRuleActions, apiDefaultRuleAction)
		}
	}

	if !m.MalformedSysctlValue.IsNull() && !m.MalformedSysctlValue.IsUnknown() {
		var rule defaultRuleTFModel
		diags.Append(m.MalformedSysctlValue.As(ctx, &rule, basetypes.ObjectAsOptions{})...)
		if !diags.HasError() {
			ruleCode := rule.Code.ValueString()
			if rule.Code.IsNull() || rule.Code.IsUnknown() {
				ruleCode = malformedSysctlValueCode
			}
			apiDefaultRuleAction := &models.APIUpdateDefaultRuleAction{
				Code:   &ruleCode,
				Action: rule.Action.ValueStringPointer(),
			}
			apiDefaultRuleActions = append(apiDefaultRuleActions, apiDefaultRuleAction)
		}
	}

	if !m.ServiceAccountTokenAutomounted.IsNull() && !m.ServiceAccountTokenAutomounted.IsUnknown() {
		var rule defaultRuleTFModel
		diags.Append(m.ServiceAccountTokenAutomounted.As(ctx, &rule, basetypes.ObjectAsOptions{})...)
		if !diags.HasError() {
			ruleCode := rule.Code.ValueString()
			if rule.Code.IsNull() || rule.Code.IsUnknown() {
				ruleCode = serviceAccountTokenAutomountedCode
			}
			apiDefaultRuleAction := &models.APIUpdateDefaultRuleAction{
				Code:   &ruleCode,
				Action: rule.Action.ValueStringPointer(),
			}
			apiDefaultRuleActions = append(apiDefaultRuleActions, apiDefaultRuleAction)
		}
	}

	return apiDefaultRuleActions, diags
}
