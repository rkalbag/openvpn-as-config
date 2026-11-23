# openvpn-as-config

Community tool, not an official OpenVPN Inc. product.

Configure an OpenVPN Access Server once in the Admin Web UI, capture the result as a small file, and apply it to any new Access Server after it boots: on a VM, in a container, from CI or from a cloud run-command service.

`as_config.py` is a single Python 3 file. It uses only the standard library and `sacli`, and runs as root on the Access Server itself. The server can be built any way you like (Marketplace image, ARM, CloudFormation, Terraform, a container); the tool only handles its configuration.

## What it copies

| Copied | Not copied |
|---|---|
| Configuration settings changed from the defaults (`sacli ConfigQuery` keys) | Server-specific keys: hostname, license, cluster role and the others under [Protected keys](#protected-keys) |
| Groups and their properties, including access rules and auto-login | Passwords (new users get random temporary ones) |
| Individual users and their properties | MFA (TOTP) enrolment |
| Domain Routing rulesets and their assignments | Web and user certificates (each server has its own CA) |
| Policies | |

## Requirements

- Access Server with `sacli`. Tested with Access Server 3.2.4 (`openvpn/openvpn-as:3.2.4-f3c295a7-Ubuntu26`). The source and target must run the same version unless you pass `--force-version`.
- `python3` on the server, which the tool uses as it finds it (the Access Server 3.2.4 container image ships Python 3.14). No packages to install.
- Root on the server: `sudo` on a VM, or `docker exec`, which runs as root by default.

## Quick start

The examples run the tool from `~/as-config`, a private directory on the server; [Copy and run](#copy-and-run) shows how to copy it there.

**1. Take a baseline of a fresh server, before configuring it.** On the source server:

```sh
sudo python3 -I ~/as-config/as_config.py baseline -o ~/as-config/baseline.json
```

**2. Configure the server in the Admin Web UI** as you want every server to be.

**3. Export the differences.** On the same server:

```sh
sudo python3 -I ~/as-config/as_config.py export --baseline ~/as-config/baseline.json -o ~/as-config/as-config.json
```

`export` prints notes for values that look environment-specific, such as subnets and IP addresses, and lists the secret names it created. Copy `as-config.json` off the server, then edit it:

- Replace environment-specific values with `${NAME}`, and list each name under `variables`.
- Secret values (LDAP bind passwords, RADIUS shared secrets and so on) are already written as `${AS_SECRET_…}` and listed under `secrets`.

Keep `as-config.json` in version control. Keep `baseline.json` private and out of version control (see [Commands](#commands)).

**4. Write a values file for each environment**, for example `staging.env`:

```sh
# NAME=VALUE, one per line; quotes are optional
APP_SUBNET=10.20.0.0/16
```

Secrets do not go in this file. They are read from environment variables when you run `apply`.

**5. Check the file**, on any machine with Python 3:

```sh
python3 as_config.py validate as-config.json --values staging.env --offline
```

**6. Apply it to each new server**: see [Copy and run](#copy-and-run). Run with `--dry-run` first to see the planned changes.

### Starting from a server that is already configured

If you have no baseline from before the server was configured, take one from a fresh server of the same Access Server version, such as a temporary container of the same image tag, and run `export` against it on the configured server. Two fresh servers of the same version differ only in [protected keys](#protected-keys), which `export` skips, so the result should be the same. This route has not been tested yet: read the exported file before using it.

## Copy and run

The tool must run as root on the Access Server host or inside its container.

Over SSH, on a VM:

```sh
ssh admin@vpn.example.com 'install -d -m 700 ~/as-config'
scp as_config.py as-config.json staging.env admin@vpn.example.com:as-config/
ssh admin@vpn.example.com 'sudo python3 -I ~/as-config/as_config.py apply ~/as-config/as-config.json --values ~/as-config/staging.env --dry-run'
ssh admin@vpn.example.com 'sudo python3 -I ~/as-config/as_config.py apply ~/as-config/as-config.json --values ~/as-config/staging.env'
```

Use a private directory, never `/tmp`: Python loads modules from the script's own directory, so as root a file planted next to the tool would run as root. The tool refuses to run as root from a directory other users can write to; `python3 -I` adds a second layer of protection.

If the file lists `secrets`, pass them as environment variables. `sudo` clears the environment by default, so name each variable with `--preserve-env`. Typing each value at a prompt keeps it out of shell history and process lists:

```sh
ssh -t admin@vpn.example.com
read -rs AS_SECRET_AUTH_LDAP_0_BIND_PW && export AS_SECRET_AUTH_LDAP_0_BIND_PW
sudo --preserve-env=AS_SECRET_AUTH_LDAP_0_BIND_PW \
  python3 -I ~/as-config/as_config.py apply ~/as-config/as-config.json --values ~/as-config/staging.env
```

In Docker (the container is called `openvpn-as` here):

```sh
docker cp as_config.py      openvpn-as:/root/
docker cp as-config.json    openvpn-as:/root/
docker cp staging.env       openvpn-as:/root/
docker exec openvpn-as python3 -I /root/as_config.py apply /root/as-config.json --values /root/staging.env --dry-run
docker exec openvpn-as python3 -I /root/as_config.py apply /root/as-config.json --values /root/staging.env
```

For secrets, set them in your shell and pass each name with `-e NAME`. With no `=value`, Docker copies the value from your environment, so it is not on the command line:

```sh
docker exec -e AS_SECRET_AUTH_LDAP_0_BIND_PW openvpn-as python3 -I /root/as_config.py apply /root/as-config.json --values /root/staging.env
```

`apply` stops before changing anything if a secret is missing (`secrets missing from the environment: …`).

Terraform users run the same commands from a provisioner or the cloud's run-command service; there is no separate module.

## Commands

| Command | What it does |
|---|---|
| `baseline -o baseline.json` | Saves the server's state (config, user and group properties, rulesets, policies, version). Password hashes are dropped and secret values are stored only as unsalted SHA-256 hashes, which a weak password does not survive if the file leaks: treat the baseline as a secret (it is written with mode 600; do not commit it). |
| `export --baseline baseline.json -o as-config.json` | Writes the differences from the baseline. Skips protected keys. Refuses if the baseline is from another Access Server version. Prints notes for values that look environment-specific (IP addresses, subnets). |
| `validate as-config.json [--values staging.env] [--offline]` | Checks the file against the schema, checks that every `${NAME}` is declared (and has a value, with `--values`), rejects unassigned rulesets and other mistakes, and flags protected keys. On an Access Server it also warns about config keys the server does not know (Access Server stores misspelt keys silently). |
| `apply as-config.json --values staging.env [--dry-run] [--force-version] [--prune-groups] [--prune-rulesets] [--prune-policies] [--prune-users] [--keep-backups N] [--state-dir DIR]` | Applies the file (steps below). Nothing on the server is deleted unless the file asks for it or a prune flag is given. |
| `rollback /var/lib/as-config/backup-<timestamp>` | Restores a backup taken by `apply`. |
| `schema` | Prints the JSON Schema; `schema/as-config.schema.json` is generated from it. |

What `apply` does:

1. Checks it runs as root and that the file's `access_server_version` matches `sacli version` (override with `--force-version`).
2. Waits until `sacli status` reports the API on (`--wait`, default 300 s).
3. Reads the live server and plans the changes: merges `config.set` and `config.unset` into the **live** configuration, skipping protected keys, and compares groups, users, rulesets and policies.
4. Prints the changes. With `--dry-run`, or when there is nothing to change, it stops here: nothing is written, no backup is taken and `sacli start` does not run.
5. Backs up everything it may change to `/var/lib/as-config/backup-<timestamp>/` (mode 700; `--state-dir` changes the location).
6. Runs `ConfigReplace` once with the merged configuration, then `sacli Validate`; new validation errors trigger a rollback.
7. Merges policies by name, creates and updates groups and users, gives each new local user a random temporary password, and creates and updates rulesets and their assignments. Groups, users, rulesets and policies that exist on the server but are not in the file are deleted only with the matching prune flag.
8. Runs `sacli start` once.
9. Reads the server again and compares it with the plan. On any mismatch or error after step 5 it restores the backup and exits 3.

Exit codes: `0` success or no changes, `1` refused or invalid input (nothing changed), `3` apply failed and the server was restored, `4` apply failed and the restore failed too (the message gives the `rollback` command to run).

## Deletions and prune flags

`apply` adds and updates. It deletes only what you ask for:

| On the server, not in the file | Default | Deleted with |
|---|---|---|
| group | kept, with a warning | `--prune-groups` |
| user | kept, with a warning | `--prune-users` (superusers are never deleted) |
| Domain Routing ruleset | kept and left assigned, with a warning | `--prune-rulesets` |
| policy | kept, with a warning | `--prune-policies` |
| `__DEFAULT__` (user defaults) | never deleted | never deleted |

A prune flag only acts on a section the file contains: `--prune-groups` with a file that has no `groups` key deletes nothing. Config keys are removed only when listed in `config.unset`, and a property is removed from a group or user only when that group or user is in the file without it.

Always run `--dry-run` with the same flags first. The output looks like this:

```
1 item(s) on this server are not in the file and will be kept:
  warning: KEPT (superuser, never pruned) user openvpn
4 change(s), 3 deletion(s):
  DELETE policy local-pol
  DELETE ruleset local-rs
  group eng: rulesets ['corp-domains', 'local-rs'] -> ['corp-domains']
  DELETE group local-only
dry run: nothing written
```

- Each deletion is on its own line starting with `DELETE`, and the summary line counts them.
- `KEPT (use --prune-…)` lines name items the file does not mention that a prune flag would delete.
- `config + key = value`, `config ~ key: old -> new`, `group + name`, `group name: prop = value`, `ruleset ~ name: rules`, `policy + name` and `policy ~ name` are additions and changes.
- Secret values are shown as `<secret>`.

## File format

`as-config.json`, format 1 (full schema: [schema/as-config.schema.json](schema/as-config.schema.json)):

```json
{
  "format": 1,
  "access_server_version": "3.2.4",
  "config": {
    "set": { "vpn.client.routing.reroute_dns": "false",
             "vpn.server.routing.private_network.1": "${APP_SUBNET}",
             "auth.ldap.0.bind_pw": "${AS_SECRET_AUTH_LDAP_0_BIND_PW}" },
    "unset": ["admin_ui.https.ip_address"]
  },
  "groups": {
    "eng": { "group_declare": "true", "prop_autologin": "true",
             "access_to": ["+ROUTE:${APP_SUBNET}"], "rulesets": ["corp-domains"] },
    "__DEFAULT__": { "prop_autogenerate": "true" }
  },
  "users": {
    "alice": { "conn_group": "eng" }
  },
  "rulesets": {
    "corp-domains": { "comment": "internal domains", "rules": [
      { "type": "domain_routing", "match_type": "domain_or_subdomain",
        "match_data": "corp.example", "action": "route", "comment": "" } ] }
  },
  "policies": [ { "name": "p-web", "allow": ["tcp/443"] } ],
  "variables": ["APP_SUBNET"],
  "secrets": ["AS_SECRET_AUTH_LDAP_0_BIND_PW"]
}
```

- **config**: keys to set and keys to remove. All values are strings, as `sacli ConfigQuery` reports them.
- **groups**: groups to create or update; groups not listed are kept unless `--prune-groups`. Properties are `sacli UserPropPut` keys, except that `access_to.0..N` is written as the list `access_to`, and `rulesets` lists Domain Routing rulesets by name in priority order. `__DEFAULT__` is the user-defaults record: it is updated when present, never deleted.
- **users**: users to create or update, in the same shape. A new local user gets a random temporary password, written to `temporary-passwords.json` in the backup directory (root only) and never printed in the tool's output (see the limits below for the command line); existing users keep their passwords. Users not listed are kept unless you pass `--prune-users`. Password hashes and TOTP secrets are never exported.
- **rulesets**: Domain Routing rulesets to create or update, by name; rulesets not listed are kept, and stay assigned to their owners, unless `--prune-rulesets`. Each must be assigned to at least one group or user, because Access Server cannot list unassigned rulesets. Rule order is priority order.
- **policies**: policies to create or replace, matched by name; other policies on the server are kept unless `--prune-policies`. Omit the key to leave policies alone. Sections `groups`, `users` and `rulesets` are likewise left alone when the key is absent.
- **variables**: names that `${NAME}` may refer to; values come from the `--values` file (`NAME=VALUE` lines, `#` comments, optional quotes). Write `$${` for a literal `${`.
- **secrets**: names whose values come from environment variables at apply time. `export` turns secret-looking config keys and group or user properties (passwords, bind passwords, shared secrets, private keys) into `${AS_SECRET_<NAME>}` automatically. Secret values never appear on a `sacli` command line: they reach the server through `--value_file` files in the root-only backup directory, deleted straight after use, and are shown as `<secret>` in all output.

## Protected keys

Never exported, never written by `apply`, and flagged by `validate`; the target keeps its own values.

| Key or pattern | Reason |
|---|---|
| `host.name` | the server's own address |
| `auth.sessiontoken.secretkey` | per-server secret |
| `subscription.*` | license state; changes on every restart |
| `upgrade.*` | install history |
| `vpn.server.daemon.tcp.n_daemons`, `vpn.server.daemon.udp.n_daemons` | set from the CPU count at install |
| `acme.internal.*`, `acme.node`, `acme.sni` | ACME account, certificate and hostname |
| `extip.polling_service.internal.*` | external IP poller state |
| `cluster.*`, `node_type`, `dbpush.*` | cluster role and topology |
| `cs.cert`, `cs.priv_key`, `cs.ca_bundle` | web certificate (from Access Server documentation; not observed in tests) |

## Limits found in testing

- **Restarts can drop clients.** `sacli start` restarts only the OpenVPN daemons whose settings changed. Changing ports, protocols, VPN subnets or daemon counts disconnects clients on those daemons. Observed through daemon process IDs and logs only; a live client test was not possible with the Docker image's zero-connection license.
- **No forced password change.** Access Server 3.2.4 has no "must change at next login" flag. Hand out the temporary passwords; users can change them if the server allows it (`prop_pwd_change`, `cs.cws.pwd_change`).
- **Temporary passwords pass through the command line.** `sacli SetLocalPassword` only accepts `--new_pass` (it has no file option, and reading from stdin fails), so the password is on the `sacli` command line: briefly visible in the server's process list, and recorded by anything that logs `sacli` arguments, such as a wrapper passed with `--sacli`. Every other secret goes through `--value_file`.
- **MFA enrolment is not copied.** Users with TOTP enrol again on the new server.
- **Web certificates and individual user certificates are not copied.** Each server has its own CA and certificates; use ACME or upload certificates separately.
- **Deleting a group leaves members pointing at it** (`conn_group`). Access Server does not complain; the tool does not fix it either.
- **Same version only by default.** Files carry the Access Server version; applying to another version needs `--force-version`, and keys may have changed between versions.
- **Unknown keys are stored silently** by Access Server. `validate` on a server warns about them; treat those warnings as likely typos.

## Security notes

- **Treat `as-config.json` and the values file like code.** They can do anything an administrator can: create superusers, change authentication, open routes. Review changes to them (for example in pull requests), and copy them to the server only over a trusted channel.
- **Run from a private directory** (see [Copy and run](#copy-and-run)). The tool refuses to run as root from a directory other users can write to.
- **Secret values never appear in the tool's output.** Values from `secrets`, and secret values the server already holds, are replaced with `<secret>` in everything the tool prints, including error messages from `sacli` that repeat a rejected value.
- **Backups hold secrets.** Each `backup-*` directory contains password hashes, secret config values and, after creating users, `temporary-passwords.json`. They are root-only (directory 700, files 600). After a successful apply the oldest are deleted so that 10 remain (`--keep-backups N`; `0` keeps all). Hand out temporary passwords and then delete `temporary-passwords.json`.
- **The state directory must be private.** `--state-dir` (default `/var/lib/as-config`) and any directory given to `rollback` must be root-owned, mode 700, not a symlink, and not inside a directory anyone can write to; otherwise the tool refuses. Files there are written without following symlinks, and `-o` output files are replaced atomically, so a planted link cannot redirect a write.
- **`sacli`** is taken from `/usr/local/openvpn_as/scripts/sacli` when it exists, and from `PATH` only otherwise.

## Development

The files besides `as_config.py` are for working on the tool; you do not need them to use it.

### Testing

`tests/run.sh` resets two local Access Server containers (`docker-compose.yml`, `scripts/reset.sh`) and runs the end-to-end tests: export, apply, re-apply without changes, removals, automatic rollback on an injected failure, version mismatch, dry run, the rollback command, input refusals, keep-by-default and prune flags, policy merging, secrets kept off the command line, package contents, and the security checks (planted modules, symlinked outputs, unsafe state directories, secrets in error messages, backup retention, symlinks in packages). It takes about a minute and a half after the image is pulled.

```sh
docker compose pull
./tests/run.sh
```

The test containers in `docker-compose.yml` publish their ports on `127.0.0.1` only, so their admin UIs are not reachable from the network.

### Packaging

```sh
./scripts/package.sh        # -> dist/openvpn-as-config-<version>.zip
```

The archive holds only files tracked by git. Working directories that can contain server secrets (`out/`, `tests/tmp/`, `data/`, `backups/`, `dist/`) are skipped even if they were force-added. The script refuses to run outside a git repository, and refuses tracked symlinks (which could pull any file on the machine into the archive).
