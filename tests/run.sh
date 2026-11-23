#!/usr/bin/env bash
# End-to-end tests for as_config.py against the two local Access Server containers.
# Usage: tests/run.sh            (resets both containers first; takes a few minutes)
set -uo pipefail
cd "$(dirname "$0")/.."
command -v docker >/dev/null || export PATH="/Applications/Docker.app/Contents/Resources/bin:$PATH"

W=tests/tmp
rm -rf "$W"; mkdir -p "$W"
PASS=0; FAIL=0; FAILED=()

ok()   { PASS=$((PASS+1)); echo "  PASS  $*"; }
bad()  { FAIL=$((FAIL+1)); FAILED+=("$*"); echo "  FAIL  $*"; }
check() { local name=$1; shift; if "$@"; then ok "$name"; else bad "$name"; fi; }
src()  { docker exec -i as-src "$@"; }
tgt()  { docker exec -i as-tgt "$@"; }
tool_tgt() { docker exec -i -e AS_CONFIG_TEST_FAIL_VERIFY="${FAIL_VERIFY:-0}" as-tgt python3 /root/as_config.py "$@"; }
# py FILE... -- assertion code; files are loaded as a, b, c...
pyassert() { python3 - "$@"; }
snap() {  # snap CONTAINER PREFIX: save config, userprops, rulesets, policies, status
  docker exec "$1" sacli ConfigQuery > "$W/$2.config.json"
  docker exec "$1" sacli UserPropGet > "$W/$2.users.json"
  docker exec "$1" sacli AccessControlRulesetsList > "$W/$2.rulesets.json"
  docker exec "$1" sacli ShowAllPolicies > "$W/$2.policies.json"
  docker exec "$1" sacli Status > "$W/$2.status.json"
}
same_state() {  # same_state PREFIX1 PREFIX2 : config, users (minus pvt_epoch), rulesets by name, policies
  python3 - "$W/$1" "$W/$2" <<'EOF'
import json, sys
a, b = sys.argv[1], sys.argv[2]
sys.path.insert(0, ".")
import as_config as t
def load(p, part): return json.load(open(f"{p}.{part}.json"))
def users(p): return {k: v for k, v in load(p, "users").items()}
def config(p): return t.unprotected(load(p, "config"))   # protected keys drift on their own (Q6)
def rs(p): return sorted((r["name"], r["comment"], r["owner"], r["position"]) for r in (load(p, "rulesets") or []))
diff = []
if config(a) != config(b): diff.append("config")
if users(a) != users(b): diff.append("users")
if rs(a) != rs(b): diff.append("rulesets")
if load(a, "policies") != load(b, "policies"): diff.append("policies")
if diff: print("    differs:", diff)
sys.exit(1 if diff else 0)
EOF
}

echo "== setup: reset containers, copy the tool"
./scripts/reset.sh >/dev/null 2>&1 || { echo "reset failed"; exit 1; }
for c in as-src as-tgt; do docker cp as_config.py $c:/root/as_config.py; done
check "schema file matches the schema built into the tool" \
  bash -c "python3 as_config.py schema | diff -q - schema/as-config.schema.json >/dev/null"
snap as-tgt tgt0

# ---------------------------------------------------------------------------
echo "== 1. baseline on as-src, then simulate Admin UI changes with sacli"
src python3 /root/as_config.py baseline -o /root/baseline.json 2>/dev/null
check "baseline written, root-only" bash -c "docker exec as-src stat -c %a /root/baseline.json | grep -qx 600"
src sh -s <<'EOF'
set -e
q() { sacli "$@" >/dev/null; }
q --key=vpn.client.routing.reroute_dns --value=false ConfigPut          # changed settings
q --key=vpn.server.routing.private_access --value=route ConfigPut
q --key=cs.tls_version_min --value=1.2 ConfigPut
q --key=vpn.server.routing.private_network.1 --value=10.20.0.0/16 ConfigPut
q --key=admin_ui.https.ip_address ConfigDel                             # removed setting
q --user=eng --key=type --value=group UserPropPut                       # group 1
q --user=eng --key=group_declare --value=true UserPropPut
q --user=eng --key=access_to.0 --value=+ROUTE:10.20.0.0/16 UserPropPut
q --user=eng --key=prop_autologin --value=true UserPropPut
q --user=ops --key=type --value=group UserPropPut                       # group 2
q --user=ops --key=group_declare --value=true UserPropPut
q --user=ops --key=access_to.0 --value=+ROUTE:10.20.5.0/24 UserPropPut
q --user=ops --key=access_to.1 --value=+NAT:10.30.0.0/16 UserPropPut
q --user=ops --key=policy --value=p-web UserPropPut
q --user=alice --key=type --value=user_connect UserPropPut              # user
q --user=alice --key=conn_group --value=eng UserPropPut
sacli --user=alice --new_pass=Src-Only-Pw1 SetLocalPassword >/dev/null
RS=$(sacli --name=corp-domains --comment=internal AccessControlRulesetsAdd)   # ruleset
q --ruleset_id=$RS --rule_type=domain_routing --match_type=domain_or_subdomain --match_data=corp.example --action=route --position=1 AccessControlRulesAdd
q --ruleset_id=$RS --rule_type=filter --match_type=domain --match_data=ads.example --action=deny --position=2 AccessControlRulesAdd
q --user=eng --ruleset_id=$RS --position=1 AccessControlUserRulesetsAdd
echo '[{"name":"p-web","allow":["tcp/443"]}]' > /tmp/p.json                 # policy
q --value_file=/tmp/p.json SetAllPoliciesFromFile
q start
EOF
check "UI changes simulated" test $? -eq 0

# ---------------------------------------------------------------------------
echo "== 2. export contains only those changes"
src python3 /root/as_config.py export --baseline /root/baseline.json -o /root/as-config.json 2>"$W/export.log"
check "export exit 0" test $? -eq 0
docker cp as-src:/root/as-config.json "$W/exported.json"
check "exported file passes validate" python3 as_config.py validate "$W/exported.json" --offline
check "export has exactly the intended content and no protected keys" pyassert "$W/exported.json" <<'EOF'
import json, sys
sys.path.insert(0, ".")
import as_config as t
d = json.load(open(sys.argv[1]))
want_set = {"vpn.client.routing.reroute_dns": "false", "vpn.server.routing.private_access": "route",
            "cs.tls_version_min": "1.2", "vpn.server.routing.private_network.1": "10.20.0.0/16"}
problems = []
if d["config"]["set"] != want_set: problems.append(("set", d["config"]["set"]))
if d["config"]["unset"] != ["admin_ui.https.ip_address"]: problems.append(("unset", d["config"]["unset"]))
if sorted(d["groups"]) != ["eng", "ops"]: problems.append(("groups", list(d["groups"])))
if d["groups"]["eng"] != {"group_declare": "true", "prop_autologin": "true", "access_to": ["+ROUTE:10.20.0.0/16"], "rulesets": ["corp-domains"]}:
    problems.append(("eng", d["groups"]["eng"]))
if d["groups"]["ops"] != {"group_declare": "true", "policy": "p-web", "access_to": ["+ROUTE:10.20.5.0/24", "+NAT:10.30.0.0/16"]}:
    problems.append(("ops", d["groups"]["ops"]))
if d.get("users") != {"alice": {"conn_group": "eng"}}: problems.append(("users", d.get("users")))
if list(d.get("rulesets", {})) != ["corp-domains"] or len(d["rulesets"]["corp-domains"]["rules"]) != 2: problems.append(("rulesets", d.get("rulesets")))
if d.get("policies") != [{"name": "p-web", "allow": ["tcp/443"]}]: problems.append(("policies", d.get("policies")))
keys = list(d["config"]["set"]) + d["config"]["unset"]
if any(t.is_protected(k) for k in keys): problems.append("protected key exported")
text = open(sys.argv[1]).read()
if "pvt_" in text or "secretkey" in text or "Src-Only-Pw1" in text: problems.append("private data in file")
for p in problems: print("    ", p)
sys.exit(1 if problems else 0)
EOF

# Template the environment-specific subnets, as a user would before committing the file.
python3 - "$W/exported.json" "$W/as-config.json" <<'EOF'
import json, sys
d = json.load(open(sys.argv[1]))
d["config"]["set"]["vpn.server.routing.private_network.1"] = "${APP_SUBNET}"
d["groups"]["eng"]["access_to"] = ["+ROUTE:${APP_SUBNET}"]
d["groups"]["ops"]["access_to"] = ["+ROUTE:${OPS_SUBNET}", "+NAT:10.30.0.0/16"]
d["variables"] = ["APP_SUBNET", "OPS_SUBNET"]
json.dump(d, open(sys.argv[2], "w"), indent=2)
EOF
printf 'APP_SUBNET=10.120.0.0/16\nOPS_SUBNET=10.120.5.0/24\n' > "$W/staging.env"
check "templated file validates with values" python3 as_config.py validate "$W/as-config.json" --values "$W/staging.env" --offline
check "validate fails when a variable has no value" \
  bash -c "! python3 as_config.py validate $W/as-config.json --values /dev/null --offline >/dev/null"
docker cp "$W/as-config.json" as-tgt:/root/as-config.json
docker cp "$W/staging.env" as-tgt:/root/staging.env

# ---------------------------------------------------------------------------
echo "== 3. apply on as-tgt"
tool_tgt apply /root/as-config.json --values /root/staging.env > "$W/apply3.out" 2>&1
check "apply exit 0" test $? -eq 0
snap as-tgt tgt3
check "settings, groups, user, ruleset and policy as intended; protected keys unchanged" \
  pyassert "$W/tgt0" "$W/tgt3" <<'EOF'
import json, sys
sys.path.insert(0, ".")
import as_config as t
L = lambda p, part: json.load(open(f"{p}.{part}.json"))
b, a = L(sys.argv[1], "config"), L(sys.argv[2], "config")
problems = []
want = {"vpn.client.routing.reroute_dns": "false", "vpn.server.routing.private_access": "route",
        "cs.tls_version_min": "1.2", "vpn.server.routing.private_network.1": "10.120.0.0/16"}
for k, v in want.items():
    if a.get(k) != v: problems.append((k, a.get(k)))
if "admin_ui.https.ip_address" in a: problems.append("unset key still present")
for k in b:   # subscription.* changes on its own (Q6), so it cannot be compared
    if t.is_protected(k) and not k.startswith("subscription.") and a.get(k) != b[k]: problems.append(("protected changed", k))
others = {k for k in set(a) | set(b) if k not in want and k != "admin_ui.https.ip_address" and not t.is_protected(k) and a.get(k) != b.get(k)}
if others: problems.append(("unexpected config changes", others))
u = L(sys.argv[2], "users")
strip = lambda d: {k: v for k, v in d.items() if not k.startswith("pvt_")}
if strip(u.get("eng", {})) != {"type": "group", "group_declare": "true", "prop_autologin": "true", "access_to.0": "+ROUTE:10.120.0.0/16"}: problems.append(("eng", u.get("eng")))
if strip(u.get("ops", {})) != {"type": "group", "group_declare": "true", "policy": "p-web", "access_to.0": "+ROUTE:10.120.5.0/24", "access_to.1": "+NAT:10.30.0.0/16"}: problems.append(("ops", u.get("ops")))
if strip(u.get("alice", {})) != {"type": "user_connect", "conn_group": "eng"}: problems.append(("alice", u.get("alice")))
rs = [(r["name"], r["owner"], r["position"]) for r in L(sys.argv[2], "rulesets")]
if rs != [("corp-domains", "eng", 1)]: problems.append(("rulesets", rs))
if L(sys.argv[2], "policies") != [{"name": "p-web", "allow": ["tcp/443"]}]: problems.append("policies")
for p in problems: print("    ", p)
sys.exit(1 if problems else 0)
EOF
docker exec as-tgt sh -c 'sacli --ruleset_id=$(sacli AccessControlRulesetsList | python3 -c "import json,sys;print(json.load(sys.stdin)[0][\"id\"])") AccessControlRulesList' > "$W/tgt3.rules.json"
check "ruleset rules copied in order" pyassert "$W/tgt3.rules.json" <<'EOF'
import json, sys
r = [(x["position"], x["type"], x["match_type"], x["match_data"], x["action"]) for x in json.load(open(sys.argv[1]))]
sys.exit(0 if r == [(1, "domain_routing", "domain_or_subdomain", "corp.example", "route"), (2, "filter", "domain", "ads.example", "deny")] else 1)
EOF
BACKUP3=$(grep -o '/var/lib/as-config/backup-[0-9TZ]*' "$W/apply3.out" | head -1)
PERMS=$(docker exec as-tgt sh -c "stat -c %a $BACKUP3 $BACKUP3/*" | sort -u | tr '\n' ' ')
check "backup directory and files are root-only" test "$PERMS" = "600 700 "
PW=$(docker exec as-tgt cat "$BACKUP3/temporary-passwords.json" | python3 -c 'import json,sys;print(json.load(sys.stdin)["alice"])')
login() { docker exec as-tgt curl -sk -o /dev/null -w '%{http_code}' -u "alice:$1" https://127.0.0.1:943/rest/GetUserlogin; }
check "new user logs in with the temporary password" test "$(login "$PW")" = 200
check "source password does not work on the target" test "$(login Src-Only-Pw1)" = 401
check "temporary password is not printed" bash -c "! grep -qF -- '$PW' $W/apply3.out"

# ---------------------------------------------------------------------------
echo "== 4. re-apply: no changes, no sacli start"
snap as-tgt tgt4a
tool_tgt apply /root/as-config.json --values /root/staging.env > "$W/apply4.out" 2>&1
check "re-apply exit 0" test $? -eq 0
check "re-apply reports no changes" grep -qx "no changes" "$W/apply4.out"
snap as-tgt tgt4b
check "sacli start did not run (last_restarted unchanged)" pyassert "$W/tgt4a.status.json" "$W/tgt4b.status.json" <<'EOF'
import json, sys
a, b = (json.load(open(p))["last_restarted"] for p in sys.argv[1:])
sys.exit(0 if a == b else 1)
EOF
check "state unchanged by re-apply" same_state tgt4a tgt4b
check "no new backup directory" bash -c "[ \$(docker exec as-tgt sh -c 'ls -d /var/lib/as-config/backup-* | wc -l') -eq 1 ]"

# ---------------------------------------------------------------------------
echo "== 5. remove a group and unset a key in the file, re-apply with --prune-groups"
python3 - "$W/as-config.json" "$W/as-config-5.json" <<'EOF'
import json, sys
d = json.load(open(sys.argv[1]))
del d["groups"]["ops"]
d["variables"] = ["APP_SUBNET"]
del d["config"]["set"]["cs.tls_version_min"]
d["config"]["unset"].append("cs.tls_version_min")
json.dump(d, open(sys.argv[2], "w"), indent=2)
EOF
docker cp "$W/as-config-5.json" as-tgt:/root/as-config-5.json
tool_tgt apply /root/as-config-5.json --values /root/staging.env --prune-groups > "$W/apply5.out" 2>&1
check "apply exit 0" test $? -eq 0
snap as-tgt tgt5
check "deletions listed on DELETE lines" bash -c "grep -q '^  DELETE group ops$' $W/apply5.out && grep -q '^  DELETE config cs.tls_version_min' $W/apply5.out"
check "group ops and key cs.tls_version_min removed; the rest kept" pyassert "$W/tgt5" <<'EOF'
import json, sys
p = sys.argv[1]
c, u = json.load(open(p + ".config.json")), json.load(open(p + ".users.json"))
ok = "ops" not in u and "eng" in u and "alice" in u and "cs.tls_version_min" not in c and c.get("vpn.client.routing.reroute_dns") == "false"
sys.exit(0 if ok else 1)
EOF

# ---------------------------------------------------------------------------
echo "== 6. injected failure: automatic rollback"
python3 - "$W/as-config-5.json" "$W/as-config-6.json" <<'EOF'
import json, sys
d = json.load(open(sys.argv[1]))
d["config"]["set"]["vpn.client.routing.allow_private_nets_to_clients"] = "true"
d["groups"]["qa"] = {"group_declare": "true", "access_to": ["+ROUTE:${APP_SUBNET}"], "rulesets": ["corp-domains"]}
d["rulesets"]["corp-domains"]["comment"] = "changed"
d["policies"] = []
json.dump(d, open(sys.argv[2], "w"), indent=2)
EOF
docker cp "$W/as-config-6.json" as-tgt:/root/as-config-6.json
snap as-tgt tgt6a
FAIL_VERIFY=1 tool_tgt apply /root/as-config-6.json --values /root/staging.env > "$W/apply6.out" 2>&1
RC6=$?
check "apply exits 3 (failed, rolled back)" test $RC6 -eq 3
check "output reports the rollback" grep -q "restore complete: server matches the backup" "$W/apply6.out"
snap as-tgt tgt6b
check "target state equals the backup" same_state tgt6a tgt6b
BACKUP6=$(grep -o '/var/lib/as-config/backup-[0-9TZ]*' "$W/apply6.out" | head -1)
docker exec as-tgt cat "$BACKUP6/snapshot.json" > "$W/backup6.json"
check "live config equals the backup snapshot (protected keys aside)" pyassert "$W/backup6.json" "$W/tgt6b.config.json" <<'EOF'
import json, sys
sys.path.insert(0, ".")
import as_config as t
sys.exit(0 if t.unprotected(json.load(open(sys.argv[1]))["config"]) == t.unprotected(json.load(open(sys.argv[2]))) else 1)
EOF
check "services all on after rollback" pyassert "$W/tgt6b.status.json" <<'EOF'
import json, sys
s = json.load(open(sys.argv[1]))["service_status"]
sys.exit(0 if all(v == "on" for v in s.values()) else 1)
EOF

# ---------------------------------------------------------------------------
echo "== 7. version mismatch"
python3 - "$W/as-config-5.json" "$W/as-config-7.json" <<'EOF'
import json, sys
d = json.load(open(sys.argv[1])); d["access_server_version"] = "3.2.3"
json.dump(d, open(sys.argv[2], "w"), indent=2)
EOF
docker cp "$W/as-config-7.json" as-tgt:/root/as-config-7.json
tool_tgt apply /root/as-config-7.json --values /root/staging.env > "$W/apply7a.out" 2>&1
RC7=$?
check "refused without --force-version (exit 1)" test $RC7 -eq 1
check "refusal message names both versions" grep -q "file is for Access Server 3.2.3, this server runs 3.2.4" "$W/apply7a.out"
tool_tgt apply /root/as-config-7.json --values /root/staging.env --force-version > "$W/apply7b.out" 2>&1
check "accepted with --force-version" test $? -eq 0
check "warning printed with --force-version" grep -q "continuing because of --force-version" "$W/apply7b.out"
src sh -c 'cp /root/baseline.json /tmp/b.json; sed -i "s/\"access_server_version\": \"3.2.4\"/\"access_server_version\": \"3.2.3\"/" /tmp/b.json'
src python3 /root/as_config.py export --baseline /tmp/b.json -o /tmp/x.json > "$W/export7.out" 2>&1
check "export refuses a baseline from another version" bash -c "[ $? -eq 1 ] && grep -q 'take a new baseline' $W/export7.out"

# ---------------------------------------------------------------------------
echo "== 8. dry run"
snap as-tgt tgt8a
tool_tgt apply /root/as-config-6.json --values /root/staging.env --dry-run > "$W/apply8.out" 2>&1
check "dry run exit 0" test $? -eq 0
check "dry run prints the differences" bash -c "grep -q 'config + vpn.client.routing.allow_private_nets_to_clients = \"true\"' $W/apply8.out && grep -q 'group + qa' $W/apply8.out && grep -q 'ruleset ~ corp-domains: comment' $W/apply8.out && grep -q 'dry run: nothing written' $W/apply8.out"
snap as-tgt tgt8b
check "nothing written" same_state tgt8a tgt8b
check "sacli start did not run" pyassert "$W/tgt8a.status.json" "$W/tgt8b.status.json" <<'EOF'
import json, sys
a, b = (json.load(open(p))["last_restarted"] for p in sys.argv[1:])
sys.exit(0 if a == b else 1)
EOF
check "no backup directory created (3 so far: scenarios 3, 5, 6)" bash -c "[ \$(docker exec as-tgt sh -c 'ls -d /var/lib/as-config/backup-* | wc -l') -eq 3 ]"

# ---------------------------------------------------------------------------
echo "== 9. rollback command back to the fresh target"
tool_tgt rollback "$BACKUP3" > "$W/rollback9.out" 2>&1
check "rollback exit 0" test $? -eq 0
snap as-tgt tgt9
check "target equals its fresh state" same_state tgt0 tgt9

# ---------------------------------------------------------------------------
echo "== 10. refusals"
docker exec as-tgt sh -c 'cp /root/as_config.py /root/as-config.json /tmp/ && chmod 644 /tmp/as_config.py /tmp/as-config.json'
docker exec -u nobody as-tgt python3 /tmp/as_config.py apply /tmp/as-config.json --values /root/staging.env > "$W/r10a.out" 2>&1
check "non-root refused" bash -c "[ $? -eq 1 ] && grep -q 'must run as root' $W/r10a.out"
echo '{"format": 1, "access_server_version": "3.2.4", "config": {"set": {"a": 1}, "unset": []}}' > "$W/bad.json"
check "wrong value type rejected by validate" bash -c "! python3 as_config.py validate $W/bad.json --offline >/dev/null"
echo '{"format": 1, "access_server_version": "3.2.4", "config": {"set": {"x": "${NOPE}"}, "unset": []}}' > "$W/bad2.json"
check "undeclared variable rejected by validate" bash -c "! python3 as_config.py validate $W/bad2.json --offline >/dev/null"
echo '{"format": 1, "access_server_version": "3.2.4", "config": {"set": {}, "unset": []}, "rulesets": {"lonely": {"rules": []}}}' > "$W/bad3.json"
check "unassigned ruleset rejected by validate" bash -c "! python3 as_config.py validate $W/bad3.json --offline >/dev/null"

# ---------------------------------------------------------------------------
# Phase 4. The target is fresh again after scenario 9.
echo "== 11. items the file does not mention are kept without a prune flag"
tool_tgt apply /root/as-config.json --values /root/staging.env > "$W/apply11a.out" 2>&1
check "base file applied" test $? -eq 0
tgt sh -s <<'EOF'
q() { sacli "$@" >/dev/null; }
q --user=local-only --key=type --value=group UserPropPut
q --user=local-only --key=group_declare --value=true UserPropPut
RS=$(sacli --name=local-rs AccessControlRulesetsAdd)
q --ruleset_id=$RS --rule_type=domain_routing --match_type=domain --match_data=local.example --action=route --position=1 AccessControlRulesAdd
q --user=local-only --ruleset_id=$RS --position=1 AccessControlUserRulesetsAdd
q --user=eng --ruleset_id=$RS --position=2 AccessControlUserRulesetsAdd
sacli ShowAllPolicies | python3 -c "import json,sys;p=json.load(sys.stdin);p.append({'name':'local-pol','x':1});json.dump(p,open('/tmp/pp.json','w'))"
q --value_file=/tmp/pp.json SetAllPoliciesFromFile
EOF
snap as-tgt tgt11a
tool_tgt apply /root/as-config.json --values /root/staging.env > "$W/apply11b.out" 2>&1
check "plain apply exit 0" test $? -eq 0
check "warns about each kept item" bash -c "grep -q 'warning: KEPT (use --prune-groups) group local-only' $W/apply11b.out && grep -q 'warning: KEPT (use --prune-rulesets) ruleset local-rs' $W/apply11b.out && grep -q 'warning: KEPT (use --prune-policies) policy local-pol' $W/apply11b.out"
check "no deletions planned" bash -c "! grep -q DELETE $W/apply11b.out"
snap as-tgt tgt11b
check "extra group, ruleset (still assigned to eng) and policy all kept" same_state tgt11a tgt11b
check "superuser is never offered for pruning" grep -q "KEPT (superuser, never pruned) user openvpn" "$W/apply11b.out"

echo "== 12. dry run with prune flags lists each deletion"
tool_tgt apply /root/as-config.json --values /root/staging.env --dry-run --prune-groups --prune-rulesets --prune-policies > "$W/apply12.out" 2>&1
check "dry run exit 0" test $? -eq 0
check "one DELETE line per item" bash -c "[ \$(grep -c '^  DELETE ' $W/apply12.out) -eq 3 ] && grep -qx '  DELETE group local-only' $W/apply12.out && grep -qx '  DELETE ruleset local-rs' $W/apply12.out && grep -qx '  DELETE policy local-pol' $W/apply12.out"
check "summary counts the deletions" grep -q "3 deletion(s)" "$W/apply12.out"
snap as-tgt tgt12
check "dry run wrote nothing" same_state tgt11b tgt12

echo "== 13. prune flags delete them"
tool_tgt apply /root/as-config.json --values /root/staging.env --prune-groups --prune-rulesets --prune-policies > "$W/apply13.out" 2>&1
check "apply with prune flags exit 0" test $? -eq 0
snap as-tgt tgt13
check "extra group, ruleset and policy deleted; file's own items intact" pyassert "$W/tgt13" <<'EOF'
import json, sys
p = sys.argv[1]
u = json.load(open(p + ".users.json")); rs = json.load(open(p + ".rulesets.json")); pol = json.load(open(p + ".policies.json"))
ok = ("local-only" not in u and {"eng", "ops", "alice", "openvpn"} <= set(u)
      and sorted((r["name"], r["owner"]) for r in rs) == [("corp-domains", "eng")]
      and [x["name"] for x in pol] == ["p-web"])
if not ok: print("    ", sorted(u), rs, pol)
sys.exit(0 if ok else 1)
EOF

echo "== 14. policies merge by name"
docker exec as-tgt sh -c 'echo "[{\"name\":\"keep-me\",\"k\":1},{\"name\":\"p-web\",\"allow\":[\"tcp/443\"]}]" > /tmp/pp.json && sacli --value_file=/tmp/pp.json SetAllPoliciesFromFile >/dev/null'
python3 - "$W/as-config.json" "$W/as-config-14.json" <<'EOF'
import json, sys
d = json.load(open(sys.argv[1]))
d["policies"] = [{"name": "p-web", "allow": ["tcp/443", "tcp/8443"]}, {"name": "p-new", "allow": ["udp/53"]}]
json.dump(d, open(sys.argv[2], "w"), indent=2)
EOF
docker cp "$W/as-config-14.json" as-tgt:/root/as-config-14.json
tool_tgt apply /root/as-config-14.json --values /root/staging.env > "$W/apply14.out" 2>&1
check "apply exit 0" test $? -eq 0
docker exec as-tgt sacli ShowAllPolicies > "$W/tgt14.policies.json"
check "changed policy replaced, new policy added, other policy untouched" pyassert "$W/tgt14.policies.json" <<'EOF'
import json, sys
p = {x["name"]: x for x in json.load(open(sys.argv[1]))}
ok = (p.get("keep-me") == {"name": "keep-me", "k": 1} and p.get("p-web", {}).get("allow") == ["tcp/443", "tcp/8443"]
      and p.get("p-new", {}).get("allow") == ["udp/53"] and len(p) == 3)
sys.exit(0 if ok else 1)
EOF

echo "== 15. secret values never reach a command line"
SECRET="radius-$(python3 -c 'import secrets;print(secrets.token_hex(12))')"
cat > "$W/sacli-log.sh" <<'EOF'
#!/bin/sh
# Test wrapper: record every argument list, then run the real sacli.
printf '%s\n' "$*" >> /root/sacli-args.log
exec sacli "$@"
EOF
docker cp "$W/sacli-log.sh" as-tgt:/root/sacli-log.sh
docker exec as-tgt sh -c 'chmod 700 /root/sacli-log.sh && rm -f /root/sacli-args.log'
python3 - "$W/as-config.json" "$W/as-config-15.json" <<'EOF'
import json, sys
d = json.load(open(sys.argv[1]))
d["groups"]["radius-users"] = {"group_declare": "true", "prop_radius_shared_secret": "${RADIUS_SECRET}", "note": "key ${RADIUS_SECRET}"}
d["config"]["set"]["auth.radius.0.server.0.secret"] = "${RADIUS_SECRET}"
d["secrets"] = ["RADIUS_SECRET"]
json.dump(d, open(sys.argv[2], "w"), indent=2)
EOF
docker cp "$W/as-config-15.json" as-tgt:/root/as-config-15.json
docker exec -e RADIUS_SECRET="$SECRET" as-tgt python3 /root/as_config.py apply /root/as-config-15.json --values /root/staging.env --sacli /root/sacli-log.sh > "$W/apply15.out" 2>&1
check "apply through the logging wrapper exit 0" test $? -eq 0
docker exec as-tgt cat /root/sacli-args.log > "$W/sacli-args.log"
check "wrapper logged the sacli calls" grep -q "UserPropPut" "$W/sacli-args.log"
check "secret group properties went through --value_file" bash -c "grep -q 'key=prop_radius_shared_secret --value_file=' $W/sacli-args.log && grep -q 'key=note --value_file=' $W/sacli-args.log"
check "secret value never in sacli arguments" bash -c "! grep -qF -- '$SECRET' $W/sacli-args.log"
check "secret value never in apply output" bash -c "! grep -qF -- '$SECRET' $W/apply15.out"
check "secret values stored on the server" bash -c "docker exec as-tgt sacli --pfilt=radius-users UserPropGet | grep -qF -- '\"prop_radius_shared_secret\": \"$SECRET\"' && docker exec as-tgt sacli ConfigQuery | grep -qF -- '$SECRET'"
check "no temporary value files left behind" bash -c "! docker exec as-tgt sh -c 'ls /var/lib/as-config/backup-*/prop-* 2>/dev/null' | grep -q ."
src sh -c "sacli --user=eng --key=prop_radius_shared_secret --value='$SECRET' UserPropPut >/dev/null"
src python3 /root/as_config.py export --baseline /root/baseline.json -o /tmp/x15.json > "$W/export15.out" 2>&1
docker cp as-src:/tmp/x15.json "$W/export15.json"
check "export turns a secret group property into a \${AS_SECRET_...} reference" pyassert "$W/export15.json" "$SECRET" <<'EOF'
import json, sys
d = json.load(open(sys.argv[1]))
ok = (d["groups"]["eng"].get("prop_radius_shared_secret") == "${AS_SECRET_ENG_PROP_RADIUS_SHARED_SECRET}"
      and "AS_SECRET_ENG_PROP_RADIUS_SHARED_SECRET" in d["secrets"] and sys.argv[2] not in open(sys.argv[1]).read())
sys.exit(0 if ok else 1)
EOF

echo "== 16. package contains only tracked deliverables"
P="$W/pkgrepo"; mkdir -p "$P"
cp -R as_config.py README.md FINDINGS.md CLAUDE.md docker-compose.yml .gitignore schema scripts "$P/"
mkdir -p "$P/tests" && cp tests/run.sh "$P/tests/"
(cd "$P" && git init -q && git add -A \
  && mkdir -p out tests/tmp data backups && for d in out tests/tmp data backups; do echo secret > "$d/leak.txt"; done \
  && git add -f out/leak.txt tests/tmp/leak.txt data/leak.txt backups/leak.txt)
(cd "$P" && ./scripts/package.sh) > "$W/package.out" 2>&1
check "package.sh exit 0" test $? -eq 0
ZIP=$(ls "$P"/dist/openvpn-as-config-*.zip 2>/dev/null | head -1)
check "package is named dist/openvpn-as-config-<version>.zip" bash -c "[ -n \"$ZIP\" ] && [ \"\$(basename \"$ZIP\")\" = openvpn-as-config-\$(python3 as_config.py --version | awk '{print \$2}').zip ]"
check "zip contains the deliverables and nothing under out/, tests/tmp/, data/ or backups/" pyassert "$ZIP" <<'EOF'
import sys, zipfile
names = zipfile.ZipFile(sys.argv[1]).namelist()
rel = [n.split("/", 1)[1] for n in names]
if not all(n.startswith("openvpn-as-config-") for n in names): print("    wrong top folder"); sys.exit(1)
bad = [n for n in rel if n.startswith(("out/", "tests/tmp/", "data/", "backups/", "dist/"))]
need = {"as_config.py", "README.md", "FINDINGS.md", "schema/as-config.schema.json", "docker-compose.yml",
        "scripts/reset.sh", "scripts/package.sh", "tests/run.sh"}
if bad or not need <= set(rel): print("    bad:", bad, "missing:", need - set(rel))
sys.exit(0 if not bad and need <= set(rel) else 1)
EOF
check "force-added working files were reported and skipped" bash -c "[ \$(grep -c 'skipping working file' $W/package.out) -eq 4 ]"
check "package.sh refuses outside a git repository" bash -c "mkdir -p $W/nogit/scripts && cp scripts/package.sh as_config.py $W/nogit/ 2>/dev/null; cp scripts/package.sh $W/nogit/scripts/ && ! (cd $W/nogit && GIT_CEILING_DIRECTORIES=\$(cd .. && pwd) ./scripts/package.sh) >/dev/null 2>&1"

# ---------------------------------------------------------------------------
echo "== 17. code-review fixes"
check "secret-name rule: real secrets caught, settings like api_key_algorithm and bypass not" pyassert <<'EOF'
import sys
sys.path.insert(0, ".")
import as_config as t
secret = ["auth.ldap.0.bind_pw", "auth.radius.0.server.0.secret", "prop_radius_shared_secret", "acme.eab_hmac_key", "auth.ldap.0.bind_dn_credentials", "x.password"]
plain = ["acme.api_key_algorithm", "vpn.client.routing.bypass", "x.bypass_subnets", "auth.sessiontoken.lifetime", "cs.cws.pwd_change", "vpn.client.routing.reroute_dns"]
bad = [k for k in secret if not t.is_secret_key(k)] + [k for k in plain if t.is_secret_key(k)]
if bad: print("    misclassified:", bad)
sys.exit(1 if bad else 0)
EOF
check "export escaping round-trips any text containing \${" pyassert <<'EOF'
import sys
sys.path.insert(0, ".")
import as_config as t
cases = ["${1}", "a ${ b", "${APP}", "$${X}", "x${A}y${2}", "${", "}${_z}{", "plain"]
bad = [c for c in cases if t.substitute(t.substitute_literal(c), {}) != c]
if bad: print("    broken:", bad)
sys.exit(1 if bad else 0)
EOF
check "verify masks a config value that came from secrets" pyassert <<'EOF'
import sys
sys.path.insert(0, ".")
import as_config as t
t.snapshot = lambda sacli: {"config": {"auth.ldap.0.bind_dn": "normalised"}, "userprops": {}, "rulesets": {}, "links": {}, "policies": []}
plan = t.Plan(); plan.config = {"auth.ldap.0.bind_dn": "TopSecret-123"}
problems = t.verify({"config": {"set": {}, "unset": []}}, plan, {"config": {}}, None, None, frozenset(), {"auth.ldap.0.bind_dn"})
leak = [p for p in problems if "TopSecret-123" in p]
if not problems or leak: print("    problems:", problems)
sys.exit(0 if problems and not leak else 1)
EOF
check "validate copes with sacli printing nothing for ConfigDefaults" pyassert "$W/as-config.json" <<'EOF'
import argparse, io, contextlib, sys
sys.path.insert(0, ".")
import as_config as t
class Empty:
    def __init__(self, path=None): pass
    def json(self, command, **opts): return None
    def version(self): return "3.2.4"
t.Sacli = Empty
t.os.geteuid = lambda: 0
out = io.StringIO()
with contextlib.redirect_stdout(out):
    t.cmd_validate(argparse.Namespace(file=sys.argv[1], values=None, offline=False, sacli=None))
sys.exit(0 if "valid" in out.getvalue() else 1)
EOF

# A rollback must keep the server's current protected keys (they change on their own).
python3 - "$W/as-config.json" "$W/as-config-17.json" <<'EOF'
import json, sys
d = json.load(open(sys.argv[1]))
d["config"]["set"]["vpn.client.routing.reroute_dns"] = "true"
json.dump(d, open(sys.argv[2], "w"), indent=2)
EOF
docker cp "$W/as-config-17.json" as-tgt:/root/as-config-17.json
tool_tgt apply /root/as-config-17.json --values /root/staging.env > "$W/apply17a.out" 2>&1
check "apply for the rollback test exit 0" test $? -eq 0
BACKUP17=$(grep -o '/var/lib/as-config/backup-[0-9TZ]*' "$W/apply17a.out" | head -1)
docker exec as-tgt sacli --key=extip.polling_service.internal.last_poll_timestamp --value=1795200000 ConfigPut >/dev/null
tool_tgt rollback "$BACKUP17" > "$W/rollback17.out" 2>&1
check "rollback exit 0 although a protected key changed after the backup" test $? -eq 0
docker exec as-tgt sacli ConfigQuery > "$W/tgt17.config.json"
check "rollback restored the setting and kept the newer protected value" pyassert "$W/tgt17.config.json" <<'EOF'
import json, sys
c = json.load(open(sys.argv[1]))
ok = c.get("vpn.client.routing.reroute_dns") == "false" and c.get("extip.polling_service.internal.last_poll_timestamp") == "1795200000"
if not ok: print("    reroute_dns:", c.get("vpn.client.routing.reroute_dns"), "timestamp:", c.get("extip.polling_service.internal.last_poll_timestamp"))
sys.exit(0 if ok else 1)
EOF
docker exec as-tgt sacli --key=extip.polling_service.internal.last_poll_timestamp ConfigDel >/dev/null

# A failure after creating a ruleset, before assigning it, must not leave an invisible ruleset behind.
python3 - "$W/as-config.json" "$W/as-config-17b.json" <<'EOF'
import json, sys
d = json.load(open(sys.argv[1]))
d["rulesets"]["orphan-check"] = {"comment": "", "rules": [{"type": "domain_routing", "match_type": "domain", "match_data": "orphan.example", "action": "route"}]}
d["groups"]["eng"]["rulesets"] = ["corp-domains", "orphan-check"]
json.dump(d, open(sys.argv[2], "w"), indent=2)
EOF
docker cp "$W/as-config-17b.json" as-tgt:/root/as-config-17b.json
docker exec -i -e AS_CONFIG_TEST_FAIL_AFTER_RULESET_CREATE=1 as-tgt python3 /root/as_config.py apply /root/as-config-17b.json --values /root/staging.env > "$W/apply17b.out" 2>&1
check "failure after ruleset creation exits 3" test $? -eq 3
docker exec -i as-tgt python3 - > "$W/tgt17b.rulesets.txt" <<'EOF'
import sqlite3
c = sqlite3.connect("file:/openvpn/etc/db/userprop.db?mode=ro", uri=True)
print(sorted(r[0] for r in c.execute("select name from access_control_rulesets")))
EOF
check "no unassigned ruleset left in the database" grep -qx "\['corp-domains'\]" "$W/tgt17b.rulesets.txt"

# ---------------------------------------------------------------------------
echo "== 18. security-review fixes"
docker exec as-tgt sh -c 'rm -rf /tmp/demo; mkdir -p /tmp/demo && chmod 1777 /tmp/demo && cp /root/as_config.py /tmp/demo/ && echo "print(\"PLANTED MODULE RAN\")" > /tmp/demo/json.py'
docker exec as-tgt python3 /tmp/demo/as_config.py --version > "$W/sec-planted.out" 2>&1
RC=$?
check "refuses to run as root from a world-writable directory" bash -c "[ $RC -eq 1 ] && grep -q 'refusing to run as root from /tmp/demo' $W/sec-planted.out"
check "planted module did not run" bash -c "! grep -q 'PLANTED MODULE RAN' $W/sec-planted.out"
check "python3 -I from the same directory works" bash -c "docker exec as-tgt python3 -I /tmp/demo/as_config.py --version | grep -q 'as_config.py 1.2'"
docker exec as-tgt rm -rf /tmp/demo

docker exec as-tgt sh -c 'echo original > /root/decoy.txt; ln -sf /root/decoy.txt /tmp/sec.json.tmp; ln -sf /root/decoy.txt /tmp/sec2.json
  python3 /root/as_config.py baseline -o /tmp/sec.json >/dev/null 2>&1; python3 /root/as_config.py baseline -o /tmp/sec2.json >/dev/null 2>&1'
check "a planted <output>.tmp symlink does not redirect the write" bash -c "[ \"\$(docker exec as-tgt cat /root/decoy.txt)\" = original ]"
check "a symlink at the output path is replaced, not followed" bash -c "docker exec as-tgt sh -c '[ -f /tmp/sec2.json ] && [ ! -L /tmp/sec2.json ]'"
docker exec as-tgt rm -f /root/decoy.txt /tmp/sec.json /tmp/sec.json.tmp /tmp/sec2.json

docker exec as-tgt sh -c 'rm -rf /tmp/open-state /tmp/link-state; mkdir -m 777 /tmp/open-state; ln -s /var/lib/as-config /tmp/link-state'
tool_tgt apply /root/as-config-17.json --values /root/staging.env --state-dir /tmp/open-state > "$W/sec-state1.out" 2>&1
RC1=$?
tool_tgt apply /root/as-config-17.json --values /root/staging.env --state-dir /tmp/link-state > "$W/sec-state2.out" 2>&1
RC2=$?
check "refuses a world-writable state directory" bash -c "[ $RC1 -eq 1 ] && grep -q 'must be owned by root with mode 700' $W/sec-state1.out"
check "refuses a symlinked state directory" bash -c "[ $RC2 -eq 1 ] && grep -q 'not a symlink' $W/sec-state2.out"
check "nothing applied after the refusals" bash -c "docker exec as-tgt sacli ConfigQuery | grep -q '\"vpn.client.routing.reroute_dns\": \"false\"'"
docker exec as-tgt sh -c 'B=$(ls -d /var/lib/as-config/backup-* | tail -1); rm -rf /tmp/fake-bk; cp -a "$B" /tmp/fake-bk && chmod 777 /tmp/fake-bk'
tool_tgt rollback /tmp/fake-bk > "$W/sec-rollback.out" 2>&1
RC=$?
check "rollback refuses a backup directory others can write to" bash -c "[ $RC -eq 1 ] && grep -q 'backup directory /tmp/fake-bk must be owned by root with mode 700' $W/sec-rollback.out"
docker exec as-tgt rm -rf /tmp/open-state /tmp/link-state /tmp/fake-bk

PORT_SECRET="notaport-$(python3 -c 'import secrets;print(secrets.token_hex(8))')"
python3 - "$W/as-config.json" "$W/as-config-18.json" <<'EOF'
import json, sys
d = json.load(open(sys.argv[1]))
d["config"]["set"]["cs.https.port"] = "${PORT_SECRET}"     # an ordinary key name, an invalid secret value
d["secrets"] = ["PORT_SECRET"]
json.dump(d, open(sys.argv[2], "w"), indent=2)
EOF
docker cp "$W/as-config-18.json" as-tgt:/root/as-config-18.json
docker exec -e PORT_SECRET="$PORT_SECRET" as-tgt python3 /root/as_config.py apply /root/as-config-18.json --values /root/staging.env > "$W/sec-redact.out" 2>&1
RC=$?
check "invalid secret value is rejected by sacli Validate and rolled back (exit 3)" bash -c "[ $RC -eq 3 ] && grep -q 'sacli Validate rejected' $W/sec-redact.out"
check "the rejected secret value is not in the output" bash -c "! grep -qF -- '$PORT_SECRET' $W/sec-redact.out && grep -q '<secret>' $W/sec-redact.out"

docker exec as-tgt sh -c 'ls -d /var/lib/as-config/backup-* | wc -l' > "$W/sec-count-before.txt"
tool_tgt apply /root/as-config-17.json --values /root/staging.env --keep-backups 2 > "$W/sec-keep1.out" 2>&1
K1=$?
tool_tgt apply /root/as-config.json --values /root/staging.env --keep-backups 2 > "$W/sec-keep2.out" 2>&1
K2=$?
check "two applies with --keep-backups 2 succeed" bash -c "[ $K1 -eq 0 ] && [ $K2 -eq 0 ]"
check "only the 2 newest backups remain" bash -c "[ \$(docker exec as-tgt sh -c 'ls -d /var/lib/as-config/backup-* | wc -l') -eq 2 ] && [ \$(cat $W/sec-count-before.txt) -gt 2 ]"
check "the backup of the last apply is kept" bash -c "B=\$(grep -o '/var/lib/as-config/backup-[0-9TZ]*' $W/sec-keep2.out | head -1); docker exec as-tgt test -f \$B/snapshot.json"

P2="$W/pkgrepo-symlink"; mkdir -p "$P2"
cp -R as_config.py README.md .gitignore schema scripts "$P2/"
(cd "$P2" && ln -s README.md linked.md && git init -q && git add -A)
(cd "$P2" && ./scripts/package.sh) > "$W/package-symlink.out" 2>&1
RC=$?
check "package.sh refuses a tracked symlink" bash -c "[ $RC -eq 1 ] && grep -q 'linked.md is a symlink' $W/package-symlink.out"

check "test containers publish ports on 127.0.0.1 only" bash -c "docker port as-src | grep -v '^.*-> 127.0.0.1:' | grep -q . && exit 1; docker port as-tgt | grep -v '^.*-> 127.0.0.1:' | grep -q . && exit 1; exit 0"

# ---------------------------------------------------------------------------
echo "== 19. community disclaimer"
check "README.md title is openvpn-as-config" bash -c "[ \"\$(head -1 README.md)\" = '# openvpn-as-config' ]"
check "README.md has the community disclaimer under the title" bash -c "[ \"\$(sed -n 3p README.md)\" = 'Community tool, not an official OpenVPN Inc. product.' ]"

echo
echo "passed: $PASS  failed: $FAIL"
for f in "${FAILED[@]:-}"; do [ -n "$f" ] && echo "  failed: $f"; done
[ "$FAIL" -eq 0 ]
