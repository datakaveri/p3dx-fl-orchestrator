output "resource_group_name" {
  value = "dry-run"
}

output "vm_name" {
  value = "existing-${var.role}-${var.participant_name}"
}

output "public_ip_address" {
  value = var.existing_vm_ip
}

output "private_ip_address" {
  value = var.existing_vm_ip
}

output "ssh_command" {
  value = "ssh ${var.admin_username}@${var.existing_vm_ip}"
}
