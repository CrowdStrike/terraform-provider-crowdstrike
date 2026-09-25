# A Fusion SOAR workflow can be imported by specifying the workflow ID.
# Import reads the definition from the API's YAML export, which is formatted
# differently from most configurations, so the first apply after import
# updates the workflow once to store the configured definition.
terraform import crowdstrike_fusion_soar_workflow.example 7fb858a949034a0cbca175f660f1e769
