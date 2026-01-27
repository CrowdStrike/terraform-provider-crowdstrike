package cloudsecurity_test

type dataRuleConfig struct {
	cloudProvider string
	ruleName      string
	resourceType  string
	benchmark     string
	framework     string
	service       string
}

var awsConfig = dataRuleConfig{
	cloudProvider: "AWS",
	ruleName:      "Auto Scaling group launch configuration not configured with a customer created IAM role",
	resourceType:  "AWS::AutoScaling::LaunchConfiguration",
	benchmark:     "CIS*",
	framework:     "CIS",
	service:       "ELB",
}

var azureConfig = dataRuleConfig{
	cloudProvider: "Azure",
	ruleName:      "Virtual Machine allows public internet access to Docker (port 2375/2376)",
	resourceType:  "Microsoft.Compute/virtualMachines",
	benchmark:     "CIS*",
	framework:     "CIS",
	service:       "Virtual Machines",
}

var gcpConfig = dataRuleConfig{
	cloudProvider: "GCP",
	ruleName:      "GKE Cluster insecure kubelet read only port is enabled",
	resourceType:  "container.googleapis.com/Cluster",
	benchmark:     "CIS*",
	framework:     "CIS",
	service:       "Google Kubernetes Engine",
}
