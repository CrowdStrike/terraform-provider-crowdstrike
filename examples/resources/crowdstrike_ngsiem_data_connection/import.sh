# Next-Gen SIEM data connections import with a composite ID of the form `connector_id:connection_id`.
# The connector_id is required because the connection read API does not return it.
#
# Note: CrowdStrike returns the ingest token only when the connection is first created, so an imported
# connection has no ingest_token in state. That's fine if its collector is already configured. If you
# need a fresh token, regenerate one for the connection in CrowdStrike, or recreate the resource
# (terraform apply -replace=...) to have Terraform manage a new one.
terraform import crowdstrike_ngsiem_data_connection.example "a1bfd0c4380f436790cb41afc2b95f38:7fb858a949034a0cbca175f660f1e769"
