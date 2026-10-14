terraform {
  required_version = ">= 1.5.0"

  backend "local" {}

  # No azurerm: dry run never creates Azure resources.
  required_providers {
    null = {
      source  = "hashicorp/null"
      version = "~> 3.2"
    }
    external = {
      source  = "hashicorp/external"
      version = "~> 2.3"
    }
  }
}
