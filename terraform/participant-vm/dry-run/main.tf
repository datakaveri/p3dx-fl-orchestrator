# DRY_RUN_VMS overlay: copied over ../main.tf in the per-run copy (see
# provisioning.copyTerraformSource) so the full flow runs against an EXISTING
# VM with no azurerm resources. Keep in sync with ../main.tf.

variable "existing_vm_ip" {
  description = "Host (IP or hostname) of the existing VM for this run's role, from DRY_RUN_VMS."
  type        = string
}

# The VM already exists, so there is no admin_ssh_key to bake this run's
# key in: append its public key to the VM user's authorized_keys using this
# machine's own default SSH identity, so the SSH steps below work unchanged.
resource "null_resource" "authorize_key" {
  triggers = {
    always = timestamp()
  }

  provisioner "local-exec" {
    interpreter = ["bash", "-c"]
    command     = <<-EOT
      echo "STAGE: Authorizing this run's SSH key on ${var.existing_vm_ip}"
      ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new ${var.admin_username}@${var.existing_vm_ip} 'umask 077; mkdir -p ~/.ssh; cat >> ~/.ssh/authorized_keys' < "${pathexpand(var.ssh_public_key_path)}"
    EOT
  }
}

data "external" "output_owner" {
  count = var.role == "data-provider" ? 1 : 0

  program = ["bash", "${path.module}/templates/lookup-output-owner.sh", var.gov_layer_url, var.gov_layer_token]
}

locals {
  output_owner_ip = var.role == "data-provider" ? try(data.external.output_owner[0].result.ip_address, "") : ""
}

resource "null_resource" "wait_for_combine_fl" {
  depends_on = [data.external.output_owner, null_resource.authorize_key]

  triggers = {
    always = timestamp()
  }

  connection {
    type        = "ssh"
    host        = var.existing_vm_ip
    user        = var.admin_username
    private_key = file(pathexpand(var.ssh_private_key_path))
    timeout     = "5m"
  }

  provisioner "file" {
    content = templatefile("${path.module}/templates/cloud-init.sh.tftpl", {
      role                    = var.role
      participant_name        = var.participant_name
      admin_username          = var.admin_username
      ghcr_namespace          = var.ghcr_namespace
      ghcr_token              = var.ghcr_token
      generate_dataset_b64    = filebase64("${path.module}/../../../Flotilla_Deployment/generate_dataset.py")
      discovery_type          = var.discovery_type
      image_tag               = var.image_tag
      server_host             = local.output_owner_ip
      client_advertise_host   = var.existing_vm_ip
      self_ip                 = var.existing_vm_ip
      gateway_image           = var.gateway_image != "" ? var.gateway_image : "ghcr.io/${var.ghcr_namespace}/flotilla-gateway:${var.image_tag}"
      gateway_dir             = var.gateway_dir
      sidecar_dir             = var.sidecar_dir
      flotilla_dir            = var.flotilla_dir
      val_data_dir            = var.val_data_dir
      client_data_dir         = var.client_data_dir
      keycloak_issuer         = var.keycloak_issuer
      keycloak_jwks_url       = var.keycloak_jwks_url
      gateway_internal_subnet = var.gateway_internal_subnet
      gateway_internal_ip     = cidrhost(var.gateway_internal_subnet, 10)
    })
    destination = "/tmp/cloud-init.sh"
  }

  provisioner "remote-exec" {
    inline = [
      "chmod +x /tmp/cloud-init.sh",
      "/tmp/cloud-init.sh",
    ]
  }
}

resource "null_resource" "configure_broker" {
  depends_on = [null_resource.wait_for_combine_fl]

  triggers = {
    always = timestamp()
  }

  provisioner "local-exec" {
    interpreter = ["bash", "-c"]
    command = templatefile("${path.module}/templates/configure-broker.sh.tftpl", {
      self_ip          = var.existing_vm_ip
      role             = var.role
      participant_name = var.participant_name
      gov_layer_url    = var.gov_layer_url
      gov_layer_token  = var.gov_layer_token
    })
  }
}
