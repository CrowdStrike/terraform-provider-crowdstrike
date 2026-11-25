terraform {
  required_providers {
    crowdstrike = {
      source = "registry.terraform.io/crowdstrike/crowdstrike"
    }
  }
}

provider "crowdstrike" {
  cloud = "us-2"
}

# Require a valid installation token for every sensor installation in the CID.
# Create an installation token before turning this on so existing deployments
# have a token to use.
resource "crowdstrike_install_token" "deployment" {
  name = "Production Deployment Token"
}

resource "crowdstrike_install_token_settings" "example" {
  tokens_required   = true
  max_active_tokens = 50

  depends_on = [crowdstrike_install_token.deployment]
}
