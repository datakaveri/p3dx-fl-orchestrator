locals {
  name_prefix = "flo-${var.role}-${var.participant_name}"

  fl_inbound_rules = {
    "user" = [
      { name = "AllowFLGatewayJoin", priority = 1002, port = "50051" },
      { name = "AllowFLGatewayRest", priority = 1004, port = "12345" },
    ]
    "data-provider" = [
      { name = "AllowFLSidecarRelay", priority = 1003, port = "50054" },
    ]
  }

  tags = {
    project     = "p3dx-flo"
    role        = var.role
    participant = var.participant_name
    created_by  = coalesce(var.created_by, "unknown")
    managed_by  = "terraform"
  }
}

resource "azurerm_resource_group" "this" {
  name     = "rg-${local.name_prefix}"
  location = var.location
  tags     = local.tags
}

resource "azurerm_virtual_network" "this" {
  name                = "${local.name_prefix}-vnet"
  address_space       = [var.vnet_address_space]
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  tags                = local.tags
}

resource "azurerm_subnet" "this" {
  name                 = "default"
  resource_group_name  = azurerm_resource_group.this.name
  virtual_network_name = azurerm_virtual_network.this.name
  address_prefixes     = [var.subnet_prefix]
}

resource "azurerm_network_security_group" "this" {
  name                = "${local.name_prefix}-nsg"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  tags                = local.tags

  security_rule {
    name                       = "AllowSSH"
    priority                   = 1001
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = var.allowed_ssh_cidr
    destination_address_prefix = "*"
  }

  # Flotilla join gateway: only the gateway is reachable from outside.
  #   server VM ("user"): 50051 = client joins (TLS + provider token),
  #                       12345 = orchestrator REST (TLS + service token);
  #                       flotilla-server itself publishes nothing.
  #   client VM ("data-provider"): 50054 = the sidecar's inbound relay that
  #                       the session's gateway dials for training traffic
  #                       (the orchestrator narrows it to the server VM's IP
  #                       after provisioning when it can).
  dynamic "security_rule" {
    for_each = local.fl_inbound_rules[var.role == "user" ? "user" : "data-provider"]
    content {
      name                       = security_rule.value.name
      priority                   = security_rule.value.priority
      direction                  = "Inbound"
      access                     = "Allow"
      protocol                   = "Tcp"
      source_port_range          = "*"
      destination_port_range     = security_rule.value.port
      source_address_prefix      = var.allowed_fl_cidr
      destination_address_prefix = "*"
    }
  }
}

resource "azurerm_subnet_network_security_group_association" "this" {
  subnet_id                 = azurerm_subnet.this.id
  network_security_group_id = azurerm_network_security_group.this.id
}

resource "azurerm_public_ip" "this" {
  count               = var.enable_public_ip ? 1 : 0
  name                = "${local.name_prefix}-pip"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  allocation_method   = "Static"
  sku                 = "Standard"
  tags                = local.tags
}

resource "azurerm_network_interface" "this" {
  name                = "${local.name_prefix}-nic"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  tags                = local.tags

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.this.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = var.enable_public_ip ? azurerm_public_ip.this[0].id : null
  }
}

resource "azurerm_linux_virtual_machine" "this" {
  name                            = local.name_prefix
  computer_name                   = substr(local.name_prefix, 0, 63)
  resource_group_name             = azurerm_resource_group.this.name
  location                        = azurerm_resource_group.this.location
  size                            = var.vm_size
  admin_username                  = var.admin_username
  network_interface_ids           = [azurerm_network_interface.this.id]
  disable_password_authentication = true
  tags                            = local.tags

  admin_ssh_key {
    username   = var.admin_username
    public_key = file(pathexpand(var.ssh_public_key_path))
  }

  os_disk {
    name                 = "${local.name_prefix}-osdisk"
    caching              = "ReadWrite"
    storage_account_type = var.os_disk_type
    disk_size_gb         = var.os_disk_size_gb
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "ubuntu-24_04-lts"
    sku       = "server"
    version   = "latest"
  }
}

# For a data-provider VM, looks up the current output-owner's IP from
# gov_layer LOCALLY (not from the VM — see the README's "broker_host
# wiring" section for why), so wait_for_combine_fl below can hand it to the
# client as SERVER_GRPC_HOST. Best-effort: never fails `terraform apply`
# (see templates/lookup-output-owner.sh) — an empty result just means the
# client image gets built but not started, with a WARNING explaining why.
data "external" "output_owner" {
  count = var.role == "data-provider" ? 1 : 0

  program = ["bash", "${path.module}/templates/lookup-output-owner.sh", var.gov_layer_url, var.gov_layer_token]
}

locals {
  output_owner_ip = var.role == "data-provider" ? try(data.external.output_owner[0].result.ip_address, "") : ""
}

# Installs Docker on the VM and builds+starts the right Flotilla image for
# `role` (server+session for "user", client for "data-provider") — see
# templates/cloud-init.sh.tftpl. Runs over SSH from wherever `terraform
# apply` executes, using ssh_private_key_path (vmAutoProvision.service.js
# generates a fresh keypair per run for exactly this; deploy.sh's manual
# flow falls back to your own default key). STAGE:/WARNING: lines in the
# script's output are what vmAutoProvision.service.js's `remoteStageLineRe`
# surfaces as individual "VM setup" events in the provisioning UI.
resource "null_resource" "wait_for_combine_fl" {
  count = var.enable_public_ip ? 1 : 0

  depends_on = [data.external.output_owner]

  triggers = {
    vm_id = azurerm_linux_virtual_machine.this.id
  }

  connection {
    type        = "ssh"
    host        = azurerm_public_ip.this[0].ip_address
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
      client_advertise_host   = azurerm_public_ip.this[0].ip_address
      self_ip                 = azurerm_public_ip.this[0].ip_address
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

# Registers this VM's {role, participant_name, ip_address} with the
# governance layer's vm-registry, so other participants/tooling can look up
# its IP later. See templates/configure-broker.sh.tftpl — this runs LOCALLY
# (not on the VM), since gov_layer is normally only reachable from the
# machine running terraform apply, not from the VM itself. Runs after
# wait_for_combine_fl so a "user" VM isn't advertised as the output-owner
# until its server is actually up.
resource "null_resource" "configure_broker" {
  count = var.enable_public_ip ? 1 : 0

  depends_on = [null_resource.wait_for_combine_fl]

  triggers = {
    vm_id = azurerm_linux_virtual_machine.this.id
  }

  provisioner "local-exec" {
    interpreter = ["bash", "-c"]
    command = templatefile("${path.module}/templates/configure-broker.sh.tftpl", {
      self_ip          = azurerm_public_ip.this[0].ip_address
      role             = var.role
      participant_name = var.participant_name
      gov_layer_url    = var.gov_layer_url
      gov_layer_token  = var.gov_layer_token
    })
  }
}
