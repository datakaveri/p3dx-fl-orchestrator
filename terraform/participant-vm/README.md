# participant-vm

Self-service Terraform config so a **data provider** or **the user** can spin up a
cheap VM in *their own* Azure subscription for p3dx-flo. It does not touch the
`Federated_learning` subscription/resource group that `auto_vm_creation.sh`
uses — each participant runs this against their own account, since a data
provider may be an outside org with no access to that subscription.

This module only creates the bare VM (plus its networking) — it does not
install or start any FL software on it. Provisioning combine_fl is a
separate, manual step once the VM exists.

VM is intentionally minimal/cheap right now:

| Setting     | Value                                    |
|-------------|-------------------------------------------|
| Size        | Standard_B1s (1 vCPU / 1 GiB, burstable)   |
| OS disk     | 30 GiB Standard_LRS (HDD tier)             |
| Image       | Ubuntu 24.04 LTS                           |
| Public IP   | Standard SKU, static                       |
| Auth        | SSH key only (password auth disabled)      |

Roughly the lowest-cost VM Azure offers; scale `vm_size`/`os_disk_type` up later
once real workloads land on it.

**Ports**: alongside SSH, the NSG (`azurerm_network_security_group.this`)
opens `50051` and `50052-50060` — the ports combine_fl's gRPC discovery and
client runtime would use once you set it up on the VM yourself. Both default
open via `allowed_fl_cidr` (`0.0.0.0/0`, same posture as `allowed_ssh_cidr`)
— tighten it once you know the other participants' IPs.

## VM registration

After the VM is up, `terraform apply` registers its
`{role, participant_name, ip_address}` with the governance layer's
vm-registry (`p3dx_gov_layer`'s `POST /vm-registry`) via
`null_resource.configure_broker` / `templates/configure-broker.sh.tftpl` —
so other participants/tooling can look up this VM's IP later (e.g. a
data-provider looking up the output-owner's IP). No separate step, no
separate terraform run.

**This runs locally, not on the VM.** `p3dx_gov_layer` is normally only
reachable at `localhost:8083` on whichever machine runs it (see the
workspace's `CLAUDE.md` / `start-all.sh`) — an Azure VM can't reach that
directly. So this step runs on the machine executing `terraform apply`,
which needs network access to `gov_layer_url` (default
`http://localhost:8083/api/v1`).

**Consequences worth knowing:**

- **Cross-machine/cross-org setups** (e.g. a data-provider who is an outside
  org running `deploy.sh` from their own laptop, per the intro above) only
  work if `gov_layer_url` in their `terraform.tfvars` points to a
  `p3dx_gov_layer` instance reachable from *their* machine — the default
  `localhost:8083` only works when the same machine (or network) is running
  gov_layer and provisioning the VM. If everyone's provisioning from the same
  machine/network as gov_layer (e.g. testing this end-to-end yourself), the
  default just works.
- If `p3dx_gov_layer` has `VM_REGISTRY_TOKEN` set, put the same value in
  `gov_layer_token` (sensitive, not printed in plan/apply output).
- This step is best-effort — a failure (gov_layer unreachable) logs a
  `WARNING:` but doesn't fail `terraform apply`. Re-run `terraform apply` to
  retry (it's idempotent — reruns just re-register with the same values).

## Prerequisites

- [Terraform](https://developer.hashicorp.com/terraform/install) >= 1.5
- [Azure CLI](https://learn.microsoft.com/cli/azure/install-azure-cli)
- An SSH key pair (`ssh-keygen -t ed25519` if you don't have one)

## Usage (each participant runs this themselves)

```bash
# 1. Log into YOUR OWN Azure account
az login                       # add --use-device-code if on a headless/remote box
az account set --subscription "<your subscription ID>"

# 2. Configure this participant
cd terraform/participant-vm
cp terraform.tfvars.example terraform.tfvars
# edit terraform.tfvars: subscription_id, role ("data-provider" or "user"),
# participant_name (short unique id, e.g. "dp1", "acme-corp")

# 3. Deploy
./deploy.sh
```

`deploy.sh` wraps init/plan/apply: it checks prerequisites and your Azure
login, echoes every command it runs, shows the plan, asks you to confirm,
then prints "Creating VM..." while `apply` runs and streams its output live.
Pass `--yes` to skip the confirmation prompt, or `--destroy` to tear the VM
down the same way. (Plain `terraform init && terraform apply` still works if
you'd rather drive it yourself — but then you must set `participant_name`
yourself in `terraform.tfvars`.)

**VM naming:** the VM itself (Azure name and hostname) is exactly
`participant_name`; every other resource is named
`flo-<role>-<participant_name>[-<instance_key>]` (resource group `rg-...`,
`-vnet`, `-nsg`, `-nic`, `-pip`, `-osdisk`). If you leave `participant_name`
unset in `terraform.tfvars`, `deploy.sh` derives it from your signed-in Azure
identity (`az account show`) — e.g. `jdoe@company.com` → VM `jdoe` in
`rg-flo-data-provider-jdoe`. The full identity is also stored on the VM as the
`created_by` tag. Set `participant_name` explicitly if you'd rather choose the
name yourself.

When the orchestrator provisions a VM for an FL submission, `participant_name`
is `p3dx-fl-<first 10 chars of the submission id without "gov-" and dashes>`
(e.g. `gov-1a2b3c4d-5e6f-...` → `p3dx-fl-1a2b3c4d5e`) for the server VM and
every provider VM alike. On a provider VM it sets `instance_key` to the
provider's username slug (≤ 16 chars), so two providers deploying into one
subscription get separate resource groups; its state lives at
`terraform.tfstate.d/<participant_name>/<role>[-<instance_key>]/terraform.tfstate`
(dry runs under `terraform.tfstate.d/dry-run/...`).

It prints `ssh_command` in its output when it's done — use that to connect.

### Showing progress on the FL dashboard

On the Federated Learning page (`p3dx-auth-ui`), both the data-provider and
output-owner views have a **"Provision your VM"** card with a **"Get
provisioning command"** button. Clicking it mints a short-lived token and
shows a command like:

```
PROVISION_TOKEN=<token> PROVISION_BACKEND_URL=http://localhost:3002/p3dx ./deploy.sh
```

Run that (instead of plain `./deploy.sh`) and the same steps you see in your
terminal — checking prerequisites, Azure login, init, plan, apply — also
appear live on that card, via a small SSE relay in p3dx-aaa
(`vmProvisioning.service.js`). The backend never sees your Azure credentials;
it only relays these step pings, and `deploy.sh` still creates the VM
entirely on its own even if the backend is unreachable.

To run this for **multiple data providers**, each one clones/copies this
directory (or you keep one copy and re-run it with a different
`participant_name` + separate `-state=...` / workspace per provider — see
below), since each deploys into their own subscription with their own
Terraform state.

### Running it for more than one participant from one checkout

Terraform state is per-directory by default, so running `terraform apply`
twice with different `terraform.tfvars` in the same directory would make the
second apply think it should destroy the first VM. Use a
[workspace](https://developer.hashicorp.com/terraform/language/state/workspaces)
per participant instead:

```bash
terraform workspace new dp1
terraform apply -var-file=dp1.tfvars

terraform workspace new dp2
terraform apply -var-file=dp2.tfvars
```

(This only makes sense when the same person/CI is deploying on behalf of
multiple providers into subscriptions they all have credentials for. When
each data provider is a separate outside org running this themselves, they
each just use their own checkout/state as in the basic usage above.)

## Tearing down

```bash
terraform destroy
```

## Notes

- `allowed_ssh_cidr` defaults to `0.0.0.0/0` (open) to keep first-run friction
  low. Set it to your own IP (`x.x.x.x/32`) once you know it, especially for
  anything left running longer than a quick test.
- `subscription_id` can be left unset in `terraform.tfvars` (`null`) to just
  use whatever subscription `az account set` already selected.
