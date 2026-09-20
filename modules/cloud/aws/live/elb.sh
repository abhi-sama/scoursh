#!/usr/bin/env bash
# modules/cloud/aws/live/elb.sh - the §8.1 ELB (Classic + ALB/NLB) read-only
# service pass (docs/DESIGN.md §8.1; docs/STEP6-CLOUD-PLAN.md CLOUD-14).
#
# THIS IS A SERVICE SCRIPT: sourced by modules/cloud/aws/engine.sh's
# `cloud_run_service`, so it inherits the whole run context and anything it
# emits lands in this process's shard.  Per that function's own contract it
# carries NO sourced-once guard - `elb.sh` is `regional`
# (`_CLOUD_SERVICES`), so one run legitimately reaches this file once per
# enabled region, and a guard would silently make every region after the
# first a no-op.  Its pure half is modules/cloud/aws/live/elb_engine.sh, which
# does have one.
#
# TWO AWS CLI NAMESPACES, ONE FILE.  `elb` (Classic Load Balancer) and `elbv2`
# (Application/Network Load Balancer) are one AWS product, "Elastic Load
# Balancing", across two API generations - docs/STEP6-CLOUD-PLAN.md's own
# counting note records this, and _CLOUD_SERVICES carries one row for both.
# Every `aws_ro` call below is spelled with its real CLI service name
# (`elb` or `elbv2`) so tests/lint-aws-readonly.sh can see it (s3.sh's own
# header explains why a wrapper would hide it from that lint).
#
# EVERY AWS CALL GOES THROUGH `aws_ro` (docs/FOUNDATION.md tension 23) and the
# response is redirected to a file rather than captured with `$(...)` - see
# s3.sh's own header for why a command substitution would silently discard
# the honesty-outcome globals `aws_ro` sets.
#
# THE HONESTY ACCOUNTING RULES ARE s3.sh's, UNCHANGED:
#   1. `checks_run` NAMES WHAT SUCCEEDED - a check id is recorded only once its
#      own call actually answered for at least one load balancer.
#   2. AN `AccessDenied` (OR ANY OTHER COVERAGE-LOSS OUTCOME) IS A
#      `coverage_reduction`, NEVER SILENCE.
#   3. There is no `not_found`-shaped "answer that is not a loss" here, unlike
#      s3's three absence checks - every one of ELB's three properties is read
#      off a call that, when it succeeds, always returns a real value
#      (`describe-listeners` and `describe-load-balancer-attributes` never
#      404 for a load balancer this run just listed), so every call failure
#      on this file is a genuine coverage loss.
#
# shellcheck shell=bash
# shellcheck source=modules/cloud/aws/live/elb_engine.sh
source "${BASH_SOURCE[0]%/*}/elb_engine.sh"

# ---------------------------------------------------------------------------
# 1. Per-pass state
# ---------------------------------------------------------------------------
declare -g _ELB_LB_TOTAL=0
declare -g _ELB_LB_EXAMINED=0
declare -g _ELB_CLASSIC_TRUNCATED=0
declare -g _ELB_V2_TRUNCATED=0
declare -g _ELB_CLASSIC_OK=0
declare -g _ELB_V2_OK=0
declare -gA _ELB_EVALUATED=()
declare -gA _ELB_LOST=()
declare -gA _ELB_LOST_REASON=()

# Every check id this pass can emit, in registry order - read by the
# selection gate, the `checks_run` roll-up and the not-evaluated accounting,
# exactly as s3.sh's own `_S3_CHECK_IDS` is.
declare -ga _ELB_CHECK_IDS=(
  CLOUD-ELB-HTTP_NO_REDIRECT-01
  CLOUD-ELB-WEAK_TLS_POLICY-01
  CLOUD-ELB-NO_ACCESS_LOGS-01
)

# `_elb_selected ID` - byte-for-byte s3.sh's `_s3_selected`; see that file's
# own header for why the `declare -F` guard is permissive rather than
# fail-closed.
_elb_selected() {
  declare -F cloud_check_selected >/dev/null 2>&1 || return 0
  cloud_check_selected "$1"
}

_elb_note_evaluated() {
  _ELB_EVALUATED[$1]=$(( ${_ELB_EVALUATED[$1]:-0} + 1 ))
}

_elb_note_lost() {
  _ELB_LOST[$1]=$(( ${_ELB_LOST[$1]:-0} + 1 ))
  # FIRST reason wins - s3.sh's own reasoning: the earliest failure is the
  # actionable one and the one that explains the rest.
  [[ -n ${_ELB_LOST_REASON[$1]:-} ]] || _ELB_LOST_REASON[$1]=$2
}

# ---------------------------------------------------------------------------
# 2. The pass
# ---------------------------------------------------------------------------
_elb_run_service() {
  local account=${SCOURSH_CLOUD_ACCOUNT_ID:-} region=${SCOURSH_CLOUD_REGION:-}
  # `mktemp -d`, never a fixed or pid-derived name - s3.sh's own note on why:
  # a predictable scratch path under $SCOURSH_SCRATCH's `${TMPDIR:-/tmp}`
  # fallback is one a local user could pre-create as a symlink this process
  # then writes through (CWE-377 via CWE-59).
  local work
  work=$(mktemp -d "${SCOURSH_SCRATCH:-${TMPDIR:-/tmp}}/cloud-elb.XXXXXX")
  chmod 700 "$work" 2>/dev/null || true

  local id selected=0
  for id in "${_ELB_CHECK_IDS[@]+"${_ELB_CHECK_IDS[@]}"}"; do
    _elb_selected "$id" && selected=$(( selected + 1 ))
  done
  if (( selected == 0 )); then
    run_record coverage_reduction "module=cloud reason=all_elb_checks_deselected service=elb account=$account region=$region - every CLOUD-ELB-* check id was removed by this run's check-selection filters (--profile-scan / --intensity / --allow-intrusive), so no ELB API call was made and no load balancer was examined."
    return 0
  fi

  local partition
  partition=$(elb_partition_of "${SCOURSH_AWS_CALLER_ARN:-}")

  # -------------------------------------------------------------------------
  # The two list calls.  Neither failing is fatal to the other: an account can
  # legitimately be denied `elb:Describe*` and still have `elbv2:Describe*`
  # (or vice versa) if its read-only role was assembled unevenly.
  # -------------------------------------------------------------------------
  local classicf=$work/elb-list.json rc=0 classic_ok=0
  aws_ro elb describe-load-balancers >"$classicf" || rc=$?
  if (( rc == 0 )); then
    classic_ok=1
    _ELB_CLASSIC_OK=1
    [[ ${SCOURSH_AWS_RO_OUTCOME:-} == truncated ]] && _ELB_CLASSIC_TRUNCATED=1
  else
    local reason=''
    aws_ro_reduction_reason_set reason
    local cid
    for cid in "${_ELB_CHECK_IDS[@]+"${_ELB_CHECK_IDS[@]}"}"; do
      _elb_note_lost "$cid" "$reason"
    done
    run_record coverage_reduction "module=cloud reason=$reason service=elb operation=describe-load-balancers account=$account region=$region cell=${SCOURSH_CLOUD_CELL:-} - the classic ELB list could not be read (${SCOURSH_AWS_RO_OUTCOME}${SCOURSH_AWS_RO_CODE:+, code ${SCOURSH_AWS_RO_CODE}}), so no Classic Load Balancer in this region was examined."
  fi

  rc=0
  local v2f=$work/elbv2-list.json v2_ok=0
  aws_ro elbv2 describe-load-balancers >"$v2f" || rc=$?
  if (( rc == 0 )); then
    v2_ok=1
    _ELB_V2_OK=1
    [[ ${SCOURSH_AWS_RO_OUTCOME:-} == truncated ]] && _ELB_V2_TRUNCATED=1
  else
    local reason2=''
    aws_ro_reduction_reason_set reason2
    local cid2
    for cid2 in "${_ELB_CHECK_IDS[@]+"${_ELB_CHECK_IDS[@]}"}"; do
      _elb_note_lost "$cid2" "$reason2"
    done
    run_record coverage_reduction "module=cloud reason=$reason2 service=elbv2 operation=describe-load-balancers account=$account region=$region cell=${SCOURSH_CLOUD_CELL:-} - the ALB/NLB list could not be read (${SCOURSH_AWS_RO_OUTCOME}${SCOURSH_AWS_RO_CODE:+, code ${SCOURSH_AWS_RO_CODE}}), so no ALB/NLB in this region was examined."
  fi

  if (( ! classic_ok && ! v2_ok )); then
    _elb_record_coverage "$account" "$region"
    return 0
  fi

  # -------------------------------------------------------------------------
  # Classic ELBs: collect (index, name), then examine each.
  # -------------------------------------------------------------------------
  if (( classic_ok )); then
    local -a classic_names=()
    local i=0 name=''
    elb_doc_load "$classicf" || true
    while :; do
      elb_doc_has "$(elb_path LoadBalancerDescriptions "$i" LoadBalancerName)" || break
      elb_doc_get name "$(elb_path LoadBalancerDescriptions "$i" LoadBalancerName)"
      [[ -n $name ]] && classic_names+=("$name")
      i=$(( i + 1 ))
    done
    _ELB_LB_TOTAL=$(( _ELB_LB_TOTAL + ${#classic_names[@]} ))

    local idx=0 cname
    for cname in "${classic_names[@]+"${classic_names[@]}"}"; do
      _elb_examine_classic "$cname" "$idx" "$classicf" "$partition" "$region" "$account" "$work"
      idx=$(( idx + 1 ))
    done
  fi

  # -------------------------------------------------------------------------
  # ALB/NLB: collect (arn, name), then examine each.
  # -------------------------------------------------------------------------
  if (( v2_ok )); then
    local -a v2_arns=()
    local j=0 arn=''
    elb_doc_load "$v2f" || true
    while :; do
      elb_doc_has "$(elb_path LoadBalancers "$j" LoadBalancerArn)" || break
      elb_doc_get arn "$(elb_path LoadBalancers "$j" LoadBalancerArn)"
      [[ -n $arn ]] && v2_arns+=("$arn")
      j=$(( j + 1 ))
    done
    _ELB_LB_TOTAL=$(( _ELB_LB_TOTAL + ${#v2_arns[@]} ))

    local varn
    for varn in "${v2_arns[@]+"${v2_arns[@]}"}"; do
      _elb_examine_v2 "$varn" "$region" "$account" "$work"
    done
  fi

  _elb_record_coverage "$account" "$region"
  return 0
}

# `_elb_examine_classic NAME INDEX LISTFILE PARTITION REGION ACCOUNT WORKDIR`
# - never returns non-zero: a load balancer that cannot be fully examined is
# an accounted-for reduction, not a reason to abandon the ones after it.
_elb_examine_classic() {
  local name=$1 idx=$2 listf=$3 partition=$4 region=$5 account=$6 work=$7
  local arn safe=${name//[^A-Za-z0-9._-]/_}
  arn=$(elb_classic_arn "$partition" "$region" "$account" "$name")
  _ELB_LB_EXAMINED=$(( _ELB_LB_EXAMINED + 1 ))

  # HTTP_NO_REDIRECT and the HTTPS-listener/policy-name inventory both come
  # straight out of the ALREADY-SUCCESSFUL list response - a Classic ELB
  # embeds every listener's protocol, port and policy names in
  # `describe-load-balancers` itself, so no extra call is needed to see them.
  local http_id=CLOUD-ELB-HTTP_NO_REDIRECT-01 tls_id=CLOUD-ELB-WEAK_TLS_POLICY-01 logs_id=CLOUD-ELB-NO_ACCESS_LOGS-01
  elb_doc_load "$listf" || true

  local k=0 proto='' port='' policy0=''
  local -a tls_ports=() tls_policies=()
  if _elb_selected "$http_id"; then
    _elb_note_evaluated "$http_id"
  fi
  while :; do
    # `entry` is the ListenerDescriptions[K] object; `Listener` and
    # `PolicyNames` are SIBLING keys under it (`{Listener: {...}, PolicyNames:
    # [...]}`, per the real `describe-load-balancers` shape), never one nested
    # under the other - a path built by appending `PolicyNames` onto the
    # `.../Listener` prefix names a leaf the document has no way to hold, so
    # `policy0` would silently read empty on every listener, which is exactly
    # the "TLS policy examined and found nothing wrong" false clean this
    # module's honesty rules forbid.
    local entry base
    entry=$(elb_path LoadBalancerDescriptions "$idx" ListenerDescriptions "$k")
    base=$(elb_path "$entry" Listener)
    elb_doc_has "$(elb_path "$base" Protocol)" || break
    elb_doc_get proto "$(elb_path "$base" Protocol)" || true
    elb_doc_get port "$(elb_path "$base" LoadBalancerPort)" || true
    case $proto in
      HTTP)
        if _elb_selected "$http_id"; then
          # A Classic Load Balancer has no redirect action at all - it is a
          # pass-through TCP/HTTP proxy, so every HTTP listener it exposes
          # reaches a backend in the clear with nothing this account can
          # configure to change that. The finding is therefore unconditional,
          # unlike ALB's DefaultActions check.
          elb_emit_finding "$http_id" "$arn" "$region" "$port" \
            "Classic Load Balancer $name ($region) has a listener on port $port using plain HTTP, with no ability to redirect to HTTPS: a Classic ELB is a pass-through proxy and has no redirect action of any kind. Traffic to this listener is unencrypted between client and load balancer."
        fi
        ;;
      HTTPS | SSL)
        elb_doc_get policy0 "$(elb_path "$entry" PolicyNames 0)" || true
        if [[ -n $policy0 ]]; then
          tls_ports+=("$port")
          tls_policies+=("$policy0")
        fi
        ;;
    esac
    k=$(( k + 1 ))
  done

  # The weak-TLS-policy call, only for listeners that actually carry a named
  # policy - `_elb_selected` gates it exactly like s3.sh gates its own
  # optional per-bucket calls.
  if _elb_selected "$tls_id" && (( ${#tls_ports[@]} > 0 )); then
    local pidx=0 pport pname polf rc=0
    for pidx in "${!tls_ports[@]}"; do
      pport=${tls_ports[$pidx]}
      pname=${tls_policies[$pidx]}
      polf=$work/${safe}.policy.$pport.json
      rc=0
      aws_ro elb describe-load-balancer-policies --load-balancer-name "$name" --policy-names "$pname" >"$polf" || rc=$?
      if (( rc != 0 )); then
        local reason=''
        aws_ro_reduction_reason_set reason
        _elb_note_lost "$tls_id" "$reason"
        run_record coverage_reduction "module=cloud reason=$reason service=elb operation=describe-load-balancer-policies load_balancer=$name policy=$pname - the policy attached to port $pport could not be read (${SCOURSH_AWS_RO_OUTCOME}${SCOURSH_AWS_RO_CODE:+, code ${SCOURSH_AWS_RO_CODE}}), so this listener's TLS policy was NOT tested."
        continue
      fi
      _elb_note_evaluated "$tls_id"
      # Classified from the POLICY'S OWN ATTRIBUTES, never from the listener's
      # `PolicyNames` entry - `elb_classic_policy_doc_is_weak`'s own header
      # explains why the name alone is unsafe to classify on for a Classic
      # ELB.  `elb_doc_load` here re-flattens THIS response, overwriting the
      # LoadBalancerDescriptions document already fully consumed above (the
      # listener/policy-name inventory loop completed before this loop
      # begins), so there is no cross-loop conflict.
      elb_doc_load "$polf" || true
      if elb_classic_policy_doc_is_weak; then
        elb_emit_finding "$tls_id" "$arn" "$region" "$pport" \
          "Classic Load Balancer $name ($region) listener on port $pport uses the TLS policy '$pname', which enables SSLv3, TLS 1.0 or TLS 1.1 (or references a predefined policy that does), rather than enforcing a TLS 1.2-or-later floor."
      fi
    done
  fi

  # Access logs, once per load balancer.
  if _elb_selected "$logs_id"; then
    local attf=$work/$safe.attrs.json rc=0
    aws_ro elb describe-load-balancer-attributes --load-balancer-name "$name" >"$attf" || rc=$?
    if (( rc != 0 )); then
      local reason=''
      aws_ro_reduction_reason_set reason
      _elb_note_lost "$logs_id" "$reason"
      run_record coverage_reduction "module=cloud reason=$reason service=elb operation=describe-load-balancer-attributes load_balancer=$name - the load balancer's attributes could not be read (${SCOURSH_AWS_RO_OUTCOME}${SCOURSH_AWS_RO_CODE:+, code ${SCOURSH_AWS_RO_CODE}}), so its access-log setting was NOT tested."
    else
      _elb_note_evaluated "$logs_id"
      elb_doc_load "$attf" || true
      local enabled=''
      elb_doc_get enabled "$(elb_path LoadBalancerAttributes AccessLog Enabled)" || true
      if [[ $enabled != true ]]; then
        elb_emit_finding "$logs_id" "$arn" "$region" '' \
          "Classic Load Balancer $name ($region) does not have access logging enabled, so there is no per-request record of who was served by it. A later investigation into a suspected abuse or outage has nothing to work from."
      fi
    fi
  fi
  return 0
}

# `_elb_examine_v2 ARN REGION ACCOUNT WORKDIR` - ALB/NLB.
_elb_examine_v2() {
  local arn=$1 region=$2 account=$3 work=$4
  local safe=${arn//[^A-Za-z0-9._-]/_}
  _ELB_LB_EXAMINED=$(( _ELB_LB_EXAMINED + 1 ))
  local http_id=CLOUD-ELB-HTTP_NO_REDIRECT-01 tls_id=CLOUD-ELB-WEAK_TLS_POLICY-01 logs_id=CLOUD-ELB-NO_ACCESS_LOGS-01

  if _elb_selected "$http_id" || _elb_selected "$tls_id"; then
    local lf=$work/$safe.listeners.json rc=0
    aws_ro elbv2 describe-listeners --load-balancer-arn "$arn" >"$lf" || rc=$?
    if (( rc != 0 )); then
      local reason=''
      aws_ro_reduction_reason_set reason
      _elb_selected "$http_id" && _elb_note_lost "$http_id" "$reason"
      _elb_selected "$tls_id" && _elb_note_lost "$tls_id" "$reason"
      run_record coverage_reduction "module=cloud reason=$reason service=elbv2 operation=describe-listeners load_balancer=$arn - the listener set could not be read (${SCOURSH_AWS_RO_OUTCOME}${SCOURSH_AWS_RO_CODE:+, code ${SCOURSH_AWS_RO_CODE}}), so this load balancer's HTTP-redirect and TLS-policy posture were NOT tested."
    else
      _elb_selected "$http_id" && _elb_note_evaluated "$http_id"
      _elb_selected "$tls_id" && _elb_note_evaluated "$tls_id"
      elb_doc_load "$lf" || true
      local n=0 proto='' port='' policy=''
      while :; do
        elb_doc_has "$(elb_path Listeners "$n" Protocol)" || break
        elb_doc_get proto "$(elb_path Listeners "$n" Protocol)" || true
        elb_doc_get port "$(elb_path Listeners "$n" Port)" || true
        case $proto in
          HTTP)
            if _elb_selected "$http_id" \
              && ! elb_default_actions_redirect_https "$(elb_path Listeners "$n")"; then
              elb_emit_finding "$http_id" "$arn" "$region" "$port" \
                "Load balancer listener on port $port speaks plain HTTP with no default action that redirects to HTTPS. Traffic reaching this listener is unencrypted between client and load balancer."
            fi
            ;;
          HTTPS | TLS)
            if _elb_selected "$tls_id"; then
              elb_doc_get policy "$(elb_path Listeners "$n" SslPolicy)" || true
              if [[ -n $policy ]] && elb_policy_is_weak "$policy"; then
                elb_emit_finding "$tls_id" "$arn" "$region" "$port" \
                  "Load balancer listener on port $port uses the TLS security policy '$policy', whose name does not itself prove a TLS 1.2-or-later floor. AWS's own naming convention embeds the guaranteed minimum protocol in every predefined policy that enforces one (containing TLS-1-2 or TLS13); this policy's name carries neither."
              fi
            fi
            ;;
        esac
        n=$(( n + 1 ))
      done
    fi
  fi

  if _elb_selected "$logs_id"; then
    local af=$work/$safe.attrs.json rc=0
    aws_ro elbv2 describe-load-balancer-attributes --load-balancer-arn "$arn" >"$af" || rc=$?
    if (( rc != 0 )); then
      local reason=''
      aws_ro_reduction_reason_set reason
      _elb_note_lost "$logs_id" "$reason"
      run_record coverage_reduction "module=cloud reason=$reason service=elbv2 operation=describe-load-balancer-attributes load_balancer=$arn - the load balancer's attributes could not be read (${SCOURSH_AWS_RO_OUTCOME}${SCOURSH_AWS_RO_CODE:+, code ${SCOURSH_AWS_RO_CODE}}), so its access-log setting was NOT tested."
    else
      _elb_note_evaluated "$logs_id"
      elb_doc_load "$af" || true
      # `Attributes` is a flat array of `{Key, Value}` pairs rather than a
      # fixed-shape object (elbv2's own API shape, unlike classic ELB's
      # nested LoadBalancerAttributes.AccessLog.Enabled), so the key an
      # operator wants is found by WALKING the array rather than by a fixed
      # path - the array's own order is not part of the contract.
      local m=0 key='' val='' enabled=''
      while :; do
        elb_doc_has "$(elb_path Attributes "$m" Key)" || break
        elb_doc_get key "$(elb_path Attributes "$m" Key)"
        if [[ $key == access_logs.s3.enabled ]]; then
          elb_doc_get val "$(elb_path Attributes "$m" Value)" || true
          enabled=$val
          break
        fi
        m=$(( m + 1 ))
      done
      if [[ $enabled != true ]]; then
        elb_emit_finding "$logs_id" "$arn" "$region" '' \
          "Load balancer $arn ($region) does not have access logging enabled (access_logs.s3.enabled is not true), so there is no per-request record of who it served. A later investigation into a suspected abuse or outage has nothing to work from."
      fi
    fi
  fi
  return 0
}

# ---------------------------------------------------------------------------
# 3. The roll-up
# ---------------------------------------------------------------------------
_elb_record_coverage() {
  local account=$1 region=$2 id
  local ran=0
  for id in "${_ELB_CHECK_IDS[@]+"${_ELB_CHECK_IDS[@]}"}"; do
    _elb_selected "$id" || continue
    if (( ${_ELB_EVALUATED[$id]:-0} > 0 )); then
      run_record checks_run "$id"
      ran=$(( ran + 1 ))
      if (( ${_ELB_LOST[$id]:-0} > 0 )); then
        run_record coverage_reduction "module=cloud reason=${_ELB_LOST_REASON[$id]} service=elb check=$id account=$account region=$region answered=${_ELB_EVALUATED[$id]} unanswered=${_ELB_LOST[$id]} - this check ran, but ${_ELB_LOST[$id]} call(s) it depends on did not answer, so it is covered for some of this region's load balancers and not for others."
      fi
    else
      run_record coverage_reduction "module=cloud reason=${_ELB_LOST_REASON[$id]:-no_load_balancer_examined} service=elb check=$id account=$account region=$region lb_total=${_ELB_LB_TOTAL} lb_examined=${_ELB_LB_EXAMINED} - this check answered for NO load balancer in this region and is therefore NOT recorded in checks_run. Its absence from the findings is not evidence that every load balancer is configured correctly."
    fi
  done

  # A GENUINELY EMPTY REGION IS DISTINCT FROM A DENIED ONE, and `_ELB_LB_TOTAL
  # == 0` alone cannot tell them apart - it is exactly as true when both list
  # calls failed as when both succeeded and found nothing.  Only the OUTCOME
  # of the two list calls (recorded above as `_ELB_CLASSIC_OK`/`_ELB_V2_OK`)
  # can distinguish "we looked and it is empty" from "we did not look", which
  # is why this reads those flags rather than the count.
  if (( _ELB_LB_TOTAL == 0 )); then
    if (( _ELB_CLASSIC_OK && _ELB_V2_OK )); then
      run_record notes "module=cloud service=elb account=$account region=$region lb_total=0 - both the classic ELB and ALB/NLB list(s) were read successfully and contain no load balancer in this region, so every CLOUD-ELB-* check is covered vacuously."
    elif (( _ELB_CLASSIC_OK || _ELB_V2_OK )); then
      run_record coverage_gap "cloud elb: account $account region $region - one of the two ELB API namespaces (classic elb / elbv2) could not be read while the other found no load balancer, so an empty result from the readable one is NOT proof this region has no load balancer of the OTHER kind. Its own coverage_reduction above names which call failed and why."
    fi
  fi

  if (( _ELB_CLASSIC_TRUNCATED )); then
    run_record coverage_reduction "module=cloud reason=aws_api_truncated service=elb operation=describe-load-balancers account=$account region=$region - the Classic ELB list came back INCOMPLETE, so an unknown number of this region's classic load balancers were never enumerated."
  fi
  if (( _ELB_V2_TRUNCATED )); then
    run_record coverage_reduction "module=cloud reason=aws_api_truncated service=elbv2 operation=describe-load-balancers account=$account region=$region - the ALB/NLB list came back INCOMPLETE, so an unknown number of this region's load balancers were never enumerated."
  fi

  if (( ran == 0 && _ELB_LB_TOTAL > 0 )); then
    run_record coverage_gap "cloud elb: account $account region $region has $_ELB_LB_TOTAL load balancer(s) and NOT ONE of the ${#_ELB_CHECK_IDS[@]} CLOUD-ELB-* checks answered for any of them, so no load balancer's HTTP-redirect, TLS-policy or access-logging posture was tested. This is a run that did not look, not a region with nothing wrong - each check's own coverage_reduction above names the failure class."
  fi
  return 0
}

_elb_run_service
