#!/usr/bin/env bash
# tests/suites/image-acquire.sh - modules/image/acquire.sh: offline image
# acquisition, and the untrusted-archive handling that is the whole reason
# IMG-02 is a ticket of its own.
#
# What this suite is FOR, in the order the risk runs:
#
#   A. The JSON reader is the FIFTH byte-identical copy and not a fifth
#      DIFFERENT parser - asserted leaf for leaf against lib/state.sh's, the
#      way tests/suites/cloud.sh already asserts it for the cloud copy.
#   B. `image_tar_members` tells an ABSENT member from a BROKEN archive, which
#      under `set -Eeuo pipefail` a bare `tar -xf` cannot.
#   C. The three classic archive escapes are refused IN BASH, with a canary
#      planted OUTSIDE the extraction root that must survive each one.
#   D. Deletion is guarded: nothing this module removes is ever a bare or
#      unvalidated path, and a hostile whiteout member cannot clobber the
#      extraction root.
#   E/F. Both offline shapes open, and a multi-image source with no
#      `reference` is REFUSED rather than resolved by picking one.
#   G. Layer order is later-wins and OCI whiteouts (`.wh.` and `.wh..wh..opq`)
#      are applied.
#   H. config/images.conf (rules/RULE-FORMAT.md §9.6.8) resolves an id, and a
#      malformed file is exit 4 rather than "behaves as if absent".
#
# EVERY CASE THAT PINS A DECISION NAMES THE READING IT FAILS UNDER, per
# AGENTS.md's testing rule.  Two shapes of that rule matter here more than
# usual, and both are used throughout:
#
#   A "was refused" assertion is only worth anything beside a "still fires"
#   assertion.  A validator that refused EVERYTHING would pass every hostile
#   case in section C while making the module unable to read any image at all,
#   so each refusal is paired with the benign name it must still admit.
#
#   The hostile fixtures are built HERE, at test time, by
#   tests/fixtures/image/mkustar.sh's hand-rolled ustar writer - because
#   `tar -cf` REFUSES to write the members these cases need (measured: bsdtar
#   will not archive a `../` name), so a suite that built them with `tar`
#   would be testing archives that are not hostile and would pin nothing.
#   That file's own header carries the full reasoning.
#
# No network, no Docker, no container runtime: every input is a committed
# fixture or a few hundred bytes this suite writes into scratch.
#
# shellcheck shell=bash
#
# SC2016: assertion prose quotes shell and tar syntax literally.
# shellcheck disable=SC2016

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
export SCOURSH_INSTALL_ROOT=$ROOT
# shellcheck source=modules/image/acquire.sh
source "$ROOT/modules/image/acquire.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"
# shellcheck source=tests/fixtures/image/mkustar.sh
source "$ROOT/tests/fixtures/image/mkustar.sh"

W=$SCOURSH_SCRATCH/image-acquire
rm -rf -- "${W:?}"
mkdir -p "$W"
W=$(cd -- "$W" && pwd -P)

FIX=$ROOT/tests/fixtures/image
ONE=$FIX/docker-archive/one-image.tar
TWO=$FIX/docker-archive/two-images.tar
OCI=$FIX/oci-layout
US=$(printf '\037')
TAB=$(printf '\011')

# A fresh, empty extraction root.  They live two levels under $VBASE (set in
# section C) so a `../../victim/...` member genuinely resolves onto the canary
# - a root somewhere else would make the traversal cases pass for the wrong
# reason, since the member would escape into a directory with nothing in it.
_fresh() {
  local d=${VBASE:-$W}/roots/$1
  rm -rf -- "${d:?}"
  mkdir -p "$d"
  printf '%s' "$d"
}

# =============================================================================
printf -- '\n-- A. the JSON reader is a COPY, not a fifth parser --\n'
# =============================================================================

# The failing reading is a well-meaning "improvement" to one of the five
# copies: they would then disagree about a document neither author looked at,
# and this module would be reading image manifests through a parser no other
# suite covers.  tests/suites/cloud.sh makes the identical assertion for the
# cloud copy; this is that assertion for the image one.
t_case 'image_json_flatten agrees leaf-for-leaf with lib/state.sh _state_json_flatten'
# shellcheck source=/dev/null
if ( source "$ROOT/lib/state.sh"
     _doc='{"a":{"b":[1,"x\ty",true,null]},"c":"d"}'
     _mine=$(printf '%s' "$_doc" | image_json_flatten)
     _theirs=$(printf '%s' "$_doc" | _state_json_flatten)
     [[ $_mine == "$_theirs" ]] ); then
  _t_ok 'image_json_flatten agrees leaf-for-leaf with lib/state.sh _state_json_flatten'
else
  _t_no 'image_json_flatten diverged from lib/state.sh _state_json_flatten' \
    'the five copies must be byte-identical; a bug in one is then the same bug in all'
fi

# A docker-save manifest.json is a top-level ARRAY, which is the shape a
# reader written for `{...}` documents alone silently produces nothing for -
# and "no layers" out of a valid manifest reads as a clean, empty image.
t_case 'the flattener reads a top-level ARRAY structurally, index component and all'
_flat=$(printf '%s' '[{"Config":"c.json","Layers":["a/layer.tar","b/layer.tar"]}]' | image_json_flatten)
assert_contains "$_flat" "0${US}Layers${US}1${TAB}s${TAB}b/layer.tar" \
  'a top-level array leaf carries its own index in the US-joined path - FAILS under a reader that only handles a top-level object, which would report a valid manifest as having no layers at all'

t_case 'a structural path cannot be forged by a JSON string containing the same bytes'
_flat=$(printf '%s' '{"note":"Layers0","Layers":["real/layer.tar"]}' | image_json_flatten)
assert_contains "$_flat" "Layers${US}0${TAB}s${TAB}real/layer.tar" \
  'the real layer leaf is found at its structural path - the discipline modules/dast/graphql_engine.sh records for __schema, applied to an image manifest'

# =============================================================================
printf -- '\n-- B. image_tar_members: an ABSENT member vs a BROKEN archive --\n'
# =============================================================================

t_case 'listing a whole archive is exit 0'
_rc=0
_listing=$(image_tar_members "$ONE") || _rc=$?
assert_eq 0 "$_rc" 'tar -tf over the whole archive is the one call whose status is unambiguous'
assert_contains "$_listing" 'manifest.json' 'and the listing names manifest.json'

t_case 'an ABSENT member is answered in bash and is NOT an error'
_rc=0
image_member_present "$_listing" 'var/lib/dpkg/status' || _rc=$?
assert_eq 1 "$_rc" \
  'an absent member is a plain 1 from a bash string test - FAILS under the reading that asks tar for the member, which exits 1 and so aborts the run under set -Eeuo pipefail on the NORMAL case (most layers carry no package DB at all)'
_rc=0
image_tar_members "$ONE" >/dev/null || _rc=$?
assert_eq 0 "$_rc" \
  'the archive-level status stayed 0 - the distinction a blanket `|| true` destroys, which is what would swallow a security refusal, since a hostile archive ALSO exits 1'

t_case 'a BROKEN archive is exit 5, distinct from an absent member'
printf 'this is not a tar archive at all, not even close\n' >"$W/broken.tar"
_rc=0
image_tar_members "$W/broken.tar" >/dev/null 2>&1 || _rc=$?
assert_eq 5 "$_rc" \
  'a corrupt archive is 5 (the tool could not do its job), never 1 - FAILS under the `|| true` reading, where corrupt and absent become the same silent nothing'
assert_ne 1 "$_rc" 'and it must not share a status with an absent member'

t_case 'an unreadable path is exit 5, not a crash'
_rc=0
image_tar_members "$W/no-such-file.tar" >/dev/null 2>&1 || _rc=$?
assert_eq 5 "$_rc" 'an unreadable archive is refused before tar is invoked at all'

t_case 'image_tar_listing_set is a SETTER'
_lst=sentinel
_rc=0
image_tar_listing_set _lst "$W/broken.tar" >/dev/null 2>&1 || _rc=$?
assert_eq 5 "$_rc" \
  'the setter propagates 5 - FAILS under `l=$(image_tar_members x)`, where the ASSIGNMENT status is what set -e sees and the distinction this wrapper exists for is lost at the call site'
assert_eq '' "$_lst" 'and a failed listing leaves no stale value behind'

# =============================================================================
printf -- '\n-- C. the three archive escapes, refused IN BASH --\n'
# =============================================================================
# Each case plants a canary OUTSIDE the extraction root and asserts it
# survives, which is the only form of this claim a test can falsify.

# The canary lives under a SHORT absolute path of its own, not under $W, for
# two measured reasons.  First, the traversal member has to actually REACH it:
# `../../victim/canary.txt` is only a meaningful escape if the extraction root
# really sits two levels below the victim, so the roots are created as
# $VBASE/roots/<name> and the canary as $VBASE/victim/canary.txt.  Second, a
# ustar header's `name` field is 100 bytes and this writer does not use the
# `prefix` field: an absolute member name built from $SCOURSH_SCRATCH (which
# on macOS starts /var/folders/...) overflows it and silently truncates the
# archive - measured, as a listing that stopped after two members and a
# section that then asserted refusals of members which were never there.
VBASE=$(mktemp -d "/tmp/scoursh-img02.XXXXXX")
_victim=$VBASE/victim
mkdir -p "$_victim"
printf 'CANARY-ORIGINAL\n' >"$_victim/canary.txt"
trap 'rm -rf -- "${VBASE:?}"' EXIT

HOSTILE=$W/hostile.tar
ustar_begin "$HOSTILE"
ustar_add "$HOSTILE" 'ok.txt' 0 '' 'benign
'
ustar_add "$HOSTILE" '../../victim/canary.txt' 0 '' 'PWNED
'
ustar_add "$HOSTILE" "$_victim/canary.txt" 0 '' 'PWNED
'
ustar_add "$HOSTILE" 'lib' 2 "$_victim" ''
ustar_add "$HOSTILE" 'lib/canary.txt' 0 '' 'PWNED
'
ustar_end "$HOSTILE"

t_case 'the hostile fixture really is hostile'
_hl=$(image_tar_members "$HOSTILE")
assert_contains "$_hl" '../../victim/canary.txt' \
  'the archive genuinely carries a parent-traversal member - without this, the whole section would be asserting refusals of members that were never there'
assert_contains "$_hl" 'lib/canary.txt' 'and a path through a symlink it also carries'

t_case 'the validator is not inert: a benign member name is ADMITTED'
_rc=0
image_member_admissible "$_hl" 'ok.txt' || _rc=$?
assert_eq 0 "$_rc" \
  'a well-formed member is admitted - FAILS under a validator broken into refusing everything, which would pass every hostile case below while making the module unable to read any image at all'

t_case 'escape 1: a `..` component is refused, from the NAME alone'
_rc=0
image_member_admissible "$_hl" '../../victim/canary.txt' || _rc=$?
assert_eq 1 "$_rc" 'a parent-traversal member is refused'
assert_eq parent_traversal_member_name "$_IMAGE_REFUSE_REASON" 'and the reason names the traversal specifically'
_rc=0
image_member_is_safe '../../victim/canary.txt' || _rc=$?
assert_eq 1 "$_rc" \
  'the refusal is reachable with NO archive and NO tar process at all - this is what makes "the bash validation is THE control" checkable rather than claimed, and it FAILS under an implementation that leans on tar refusing the member itself, which is one userland behaviour and not a guarantee'
_dest=$(_fresh dest1)
_rc=0
image_extract_member "$HOSTILE" "$_hl" '../../victim/canary.txt' "$_dest" >/dev/null 2>&1 || _rc=$?
assert_eq 1 "$_rc" 'extraction refuses it too, not only the predicate'
assert_eq 'CANARY-ORIGINAL' "$(cat "$_victim/canary.txt")" \
  'and the canary OUTSIDE the extraction root is untouched'

t_case 'a `..` INSIDE a component is not refused'
_rc=0
image_member_is_safe 'etc/my..config/os-release' || _rc=$?
assert_eq 0 "$_rc" \
  'a file legitimately named `my..config` is admitted - FAILS under a substring test for "..", which would silently drop real files from every scan and call it caution'

t_case 'escape 2: an absolute member name is refused'
_rc=0
image_member_admissible "$_hl" "$_victim/canary.txt" || _rc=$?
assert_eq 1 "$_rc" 'an absolute member name is refused'
assert_eq absolute_member_name "$_IMAGE_REFUSE_REASON" 'and the reason names it'
_dest=$(_fresh dest2)
_rc=0
image_extract_member "$HOSTILE" "$_hl" "$_victim/canary.txt" "$_dest" >/dev/null 2>&1 || _rc=$?
assert_eq 1 "$_rc" \
  'extraction refuses it - FAILS under the reading that leans on tar stripping the leading slash, which is bsdtar choosing to, not a property of tar'
assert_eq 'CANARY-ORIGINAL' "$(cat "$_victim/canary.txt")" 'and the canary is untouched'

t_case 'escape 3: a member whose parent the ARCHIVE declares as a symlink is refused'
_rc=0
image_member_admissible "$_hl" 'lib/canary.txt' || _rc=$?
assert_eq 1 "$_rc" \
  'a path through a non-directory parent is refused - the escape neither name-shape check can see, since `lib/canary.txt` has no `..`, no leading slash, and nothing individually to object to'
assert_eq member_parent_is_not_a_directory "$_IMAGE_REFUSE_REASON" 'and the reason names the parent'
_dest=$(_fresh dest3)
_rc=0
image_extract_member "$HOSTILE" "$_hl" 'lib/canary.txt' "$_dest" >/dev/null 2>&1 || _rc=$?
assert_eq 1 "$_rc" 'extraction refuses it'
assert_eq 'CANARY-ORIGINAL' "$(cat "$_victim/canary.txt")" 'the canary is untouched'
assert_file_absent "$_dest/lib" 'and nothing was created inside the extraction root either'

t_case 'a member under a DECLARED directory is still admitted and extracted'
_ll=$(image_tar_members "$ONE")
_dest=$(_fresh dest3b)
_rc=0
image_extract_member "$ONE" "$_ll" 'l0/layer.tar' "$_dest" || _rc=$?
assert_eq 0 "$_rc" \
  'a real nested path whose parent the archive declares with a trailing slash is extracted - FAILS under a parent check that refuses every nested member, which would make the module unable to open a docker-save archive at all'
assert_file_exists "$_dest/l0/layer.tar" 'and the member is really there'

t_case 'the parent check reads the trailing slash, never tar -tvf mode bits'
_probe=$W/probe.tar
ustar_begin "$_probe"
ustar_add "$_probe" 'a/' 5 '' ''
ustar_add "$_probe" 'a/f' 0 '' 'x'
ustar_add "$_probe" 'b' 0 '' 'a regular file where a directory would be needed'
ustar_add "$_probe" 'b/f' 0 '' 'y'
ustar_end "$_probe"
_pl=$(image_tar_members "$_probe")
assert_status 0 'a directory-declared parent admits its child' \
  image_member_parents_are_dirs "$_pl" 'a/f'
assert_status 1 'a REGULAR-FILE parent is refused too, not only a symlink one - the check is on the type the archive DECLARED, so it covers a hardlink and a device node without needing a case for each' \
  image_member_parents_are_dirs "$_pl" 'b/f'

# =============================================================================
printf -- '\n-- D. deletion is guarded --\n'
# =============================================================================
# The hazard this section exists for: every path this module removes is
# derived from attacker-controlled bytes, so an `rm` reached with an empty or
# unvalidated variable removes the extraction root - or worse.

t_case 'image_rm_under_root refuses an EMPTY relative name'
_dest=$(_fresh rm1)
printf 'keep\n' >"$_dest/keep.txt"
_rc=0
image_rm_under_root "$_dest" '' || _rc=$?
assert_eq 1 "$_rc" 'an empty target is refused'
assert_eq unsafe_delete_target "$_IMAGE_REFUSE_REASON" 'and says why'
assert_file_exists "$_dest/keep.txt" \
  'the extraction root still has its contents - FAILS under a bare `rm -rf "$root/$rel"`, which with an empty rel removes the root itself'

t_case 'image_rm_under_root refuses a traversal and an absolute target'
_rc=0
image_rm_under_root "$_dest" '../victim/canary.txt' || _rc=$?
assert_eq 1 "$_rc" 'a traversing delete target is refused'
_rc=0
image_rm_under_root "$_dest" "$_victim/canary.txt" || _rc=$?
assert_eq 1 "$_rc" 'an absolute delete target is refused'
assert_eq 'CANARY-ORIGINAL' "$(cat "$_victim/canary.txt")" \
  'and the canary outside the root survives every refused deletion'

t_case 'image_rm_under_root is not inert: it removes a real file INSIDE the root'
printf 'go\n' >"$_dest/gone.txt"
_rc=0
image_rm_under_root "$_dest" 'gone.txt' || _rc=$?
assert_eq 0 "$_rc" 'a valid target inside the root is removed'
assert_file_absent "$_dest/gone.txt" \
  'and it is really gone - FAILS under a guard so strict it refuses everything, which would pass every refusal case above while silently leaving whiteouts unapplied'
assert_file_exists "$_dest/keep.txt" 'its sibling is untouched'

t_case 'a malformed whiteout member names nothing and is REFUSED'
assert_status 1 'a bare `.wh.` is refused - FAILS under the naive reading that strips the prefix, gets the empty string, and hands it to a deleter, which then removes the DIRECTORY the marker sat in' \
  image_whiteout_target '.wh.'
assert_status 1 'a `.wh.` with an empty basename inside a directory is refused the same way' \
  image_whiteout_target 'var/lib/.wh.'
assert_status 1 'the opaque marker is not a per-file whiteout and is refused by this function' \
  image_whiteout_target '.wh..wh..opq'
assert_status 1 'and an ordinary member is not a whiteout at all' \
  image_whiteout_target 'etc/os-release'

t_case 'image_whiteout_target is not inert: a real whiteout resolves to its target'
assert_eq 'var/lib/dpkg/status' "$(image_whiteout_target 'var/lib/dpkg/.wh.status')" \
  'a well-formed whiteout names the path it deletes'
assert_eq 'installed' "$(image_whiteout_target '.wh.installed')" \
  'and one at the archive root resolves to a bare name'

t_case 'a hostile whiteout member cannot clobber the extraction root'
_wh=$W/hostile-wh-layer.tar
ustar_begin "$_wh"
ustar_add "$_wh" 'lib/' 5 '' ''
ustar_add "$_wh" 'lib/apk/' 5 '' ''
ustar_add "$_wh" 'lib/apk/db/' 5 '' ''
ustar_add "$_wh" 'lib/apk/db/installed' 0 '' 'REAL-DB
'
ustar_add "$_wh" '.wh.' 0 '' ''
ustar_add "$_wh" 'lib/.wh.' 0 '' ''
ustar_end "$_wh"
_whm=$W/hostile-wh.tar
ustar_begin "$_whm"
ustar_add "$_whm" 'cfg.json' 0 '' '{}'
ustar_add "$_whm" 'l0/' 5 '' ''
ustar_add_file "$_whm" 'l0/layer.tar' "$_wh"
ustar_add "$_whm" 'manifest.json' 0 '' '[{"Config":"cfg.json","RepoTags":["fixture/wh:v1"],"Layers":["l0/layer.tar"]}]'
ustar_end "$_whm"
_dest=$(_fresh whdest)
printf 'PRE-EXISTING\n' >"$_dest/canary-in-root.txt"
_rc=0
image_open docker-archive "$_whm" || _rc=$?
assert_eq 0 "$_rc" 'the archive carrying the malformed whiteouts still opens'
image_collect_metadata docker-archive "$_whm" "$_dest" >/dev/null
assert_file_exists "$_dest/canary-in-root.txt" \
  'the extraction root and its contents survive a layer carrying `.wh.` and `lib/.wh.` - FAILS under any implementation that turns a malformed whiteout into a deletion'
assert_eq 'REAL-DB' "$(cat "$_dest/lib/apk/db/installed" 2>/dev/null || printf '')" \
  'and the real package database in that same layer was still collected, so the refusal did not take the layer with it'

# =============================================================================
printf -- '\n-- E. shape A: a `docker save` tarball --\n'
# =============================================================================

t_case 'a one-image archive opens with its layers in MANIFEST order'
_rc=0
image_open docker-archive "$ONE" || _rc=$?
assert_eq 0 "$_rc" 'the archive opens'
assert_eq 'l0/layer.tar l1/layer.tar l2/layer.tar' "${_IMAGE_LAYERS[*]}" \
  'layers are in the manifest array index order, base first - FAILS under a reading that takes them in whatever order the flattener printed, which is document order and is not something a hostile manifest has to respect'
assert_eq 'cfg0.json' "$_IMAGE_CONFIG_MEMBER" 'and the config member is read from the same entry'

t_case 'a MULTI-image archive with no reference is REFUSED, never resolved by picking one'
_rc=0
image_open docker-archive "$TWO" || _rc=$?
assert_eq 1 "$_rc" \
  'two images and no reference is a refusal - FAILS under "take the first entry", which reports having scanned the image the operator meant while having scanned a different one'
assert_eq multi_image_archive_needs_a_reference "$_IMAGE_REFUSE_REASON" 'and the reason says what to do about it'

t_case 'a reference selects the entry whose RepoTags carries it'
_rc=0
image_open docker-archive "$TWO" 'fixture/second:v1' || _rc=$?
assert_eq 0 "$_rc" 'the referenced image opens'
assert_eq 'l9/layer.tar' "${_IMAGE_LAYERS[*]}" \
  'and it is the SECOND entry that was selected - a case built on the first entry would pass under the rejected "always take entry 0" reading'

t_case 'an unknown reference is refused rather than falling back'
_rc=0
image_open docker-archive "$TWO" 'fixture/nope:v9' || _rc=$?
assert_eq 1 "$_rc" 'an unmatched reference is a refusal'
assert_eq reference_not_found_in_archive "$_IMAGE_REFUSE_REASON" 'and it names the miss'

t_case 'an archive with no manifest.json is refused'
_nm=$W/no-manifest.tar
ustar_begin "$_nm"
ustar_add "$_nm" 'random.txt' 0 '' 'x'
ustar_end "$_nm"
_rc=0
image_open docker-archive "$_nm" || _rc=$?
assert_eq 1 "$_rc" 'no manifest is a refusal'
assert_eq no_manifest_json_in_archive "$_IMAGE_REFUSE_REASON" 'with its own reason'

t_case 'a manifest naming a layer the archive does not contain is refused'
_ml=$W/missing-layer.tar
ustar_begin "$_ml"
ustar_add "$_ml" 'cfg.json' 0 '' '{}'
ustar_add "$_ml" 'manifest.json' 0 '' '[{"Config":"cfg.json","RepoTags":["a/b:v1"],"Layers":["ghost/layer.tar"]}]'
ustar_end "$_ml"
_rc=0
image_open docker-archive "$_ml" || _rc=$?
assert_eq 1 "$_rc" 'a phantom layer is a refusal'
assert_eq manifest_names_a_layer_the_archive_does_not_contain "$_IMAGE_REFUSE_REASON" 'and says which way it failed'

t_case 'a manifest naming a TRAVERSING layer member is refused'
_tl=$W/traversing-layer.tar
ustar_begin "$_tl"
ustar_add "$_tl" 'cfg.json' 0 '' '{}'
ustar_add "$_tl" 'manifest.json' 0 '' '[{"Config":"cfg.json","RepoTags":["a/b:v1"],"Layers":["../../etc/passwd"]}]'
ustar_end "$_tl"
_rc=0
image_open docker-archive "$_tl" >/dev/null 2>&1 || _rc=$?
assert_eq 1 "$_rc" \
  'a layer name out of attacker-written JSON goes through the SAME validation as a name out of the listing - FAILS under the reading that trusts the manifest because "it is our own metadata", when it is the image author who wrote it'

# =============================================================================
printf -- '\n-- F. shape B: an OCI image layout --\n'
# =============================================================================

t_case 'an OCI layout opens, layers in manifest order'
_rc=0
image_open oci-layout "$OCI" || _rc=$?
assert_eq 0 "$_rc" 'the layout opens'
assert_eq 2 "${#_IMAGE_LAYERS[@]}" 'both layers are found'
assert_contains "${_IMAGE_LAYERS[0]}" '/blobs/sha256/3333' 'layer 0 is the base blob'
assert_contains "${_IMAGE_LAYERS[1]}" '/blobs/sha256/4444' 'and layer 1 follows it'

t_case 'the layout reference matches the org.opencontainers.image.ref.name annotation'
_rc=0
image_open oci-layout "$OCI" 'fixture/oci:v1' || _rc=$?
assert_eq 0 "$_rc" 'the annotated manifest is selected by reference'
_rc=0
image_open oci-layout "$OCI" 'fixture/nope:v1' || _rc=$?
assert_eq 1 "$_rc" 'and an unmatched reference is refused'
assert_eq reference_not_found_in_layout "$_IMAGE_REFUSE_REASON" 'with its own reason'

t_case 'a malformed digest can never become a path'
assert_status 1 'a digest with a traversal in it is refused by SHAPE, before any path is built' \
  _image_oci_blob_path "$OCI" 'sha256:../../../etc/passwd'
assert_status 1 'so is a digest with a slash in its hex half' \
  _image_oci_blob_path "$OCI" 'sha256:aa/bb'
assert_status 1 'and one with no algorithm at all' \
  _image_oci_blob_path "$OCI" '/etc/passwd'
assert_eq "$OCI/blobs/sha256/3333333333333333333333333333333333333333333333333333333333333333" \
  "$(_image_oci_blob_path "$OCI" 'sha256:3333333333333333333333333333333333333333333333333333333333333333')" \
  'a well-formed digest still resolves - FAILS under a shape check so strict nothing resolves, which would make every layout unreadable while passing every refusal above'

t_case 'a layout whose index names a blob that is not there is refused'
_bad=$W/oci-bad
rm -rf -- "${_bad:?}"
mkdir -p "$_bad/blobs/sha256"
printf '%s' '{"imageLayoutVersion":"1.0.0"}' >"$_bad/oci-layout"
printf '%s' '{"schemaVersion":2,"manifests":[{"digest":"sha256:9999999999999999999999999999999999999999999999999999999999999999"}]}' >"$_bad/index.json"
_rc=0
image_open oci-layout "$_bad" || _rc=$?
assert_eq 1 "$_rc" 'a missing manifest blob is a refusal'
assert_eq manifest_blob_missing_from_layout "$_IMAGE_REFUSE_REASON" 'and names the gap'

t_case 'a path that is not a layout directory at all is refused'
_rc=0
image_open oci-layout "$ONE" || _rc=$?
assert_eq 1 "$_rc" 'a tarball handed to the layout reader is refused rather than half-parsed'
assert_eq oci_layout_path_is_not_a_directory "$_IMAGE_REFUSE_REASON" 'with its own reason'

t_case 'an unknown source kind is refused rather than guessed'
_rc=0
image_open docker-daemon "$ONE" || _rc=$?
assert_eq 1 "$_rc" \
  'a docker-daemon source is not a second acquisition path - FAILS under an implementation that adds a third arm here instead of producing a tarball and re-entering the ordinary tarball path, which is the second door tension 19 refuses for the network'
assert_eq unknown_image_source_kind "$_IMAGE_REFUSE_REASON" 'and says so'

# =============================================================================
printf -- '\n-- G. layer order and whiteouts (report.md §1.6) --\n'
# =============================================================================

t_case 'later wins: a path written, whited out, then written again comes from the LAST layer'
image_open docker-archive "$ONE"
_w=$(image_layer_winner docker-archive "$ONE" 'lib/apk/db/installed')
assert_eq 2 "$_w" \
  'the winner is layer 2 - FAILS in BOTH directions: a BACKWARDS walk with an early exit reads layer 1 whiteout as deleting layer 2 copy and reports the file absent, and a forward walk that stops at the first layer carrying it reports layer 0 stale copy'

t_case 'and the CONTENT that lands is the winning layer own'
_dest=$(_fresh collect-a)
_got=$(image_collect_metadata docker-archive "$ONE" "$_dest")
assert_eq 'LAYER-2-APK-DB' "$(cat "$_dest/lib/apk/db/installed")" \
  'the bytes are layer 2 - a CONTENT assertion, because a winner-index assertion alone would pass an implementation that computed the right index and then extracted from the wrong layer'
assert_contains "$_got" "lib/apk/db/installed${TAB}2" 'and the reported layer index agrees with the bytes'

t_case 'a path no layer carries is MISSING, and missing is not the same fact as refused'
assert_contains "${IMAGE_COLLECT_MISSING[*]}" 'var/lib/dpkg/status' \
  'an Alpine-shaped image has no dpkg database and says so'
assert_eq 0 "${#IMAGE_COLLECT_REFUSED[@]}" \
  'and nothing was REFUSED - merging the two would render "this image has no dpkg" and "this image dpkg sat behind a member we would not extract" as the same clean result, which is the overstated coverage docs/DESIGN.md §15 forbids'

t_case 'an OPAQUE whiteout clears what the layers below contributed to a directory'
image_open oci-layout "$OCI"
_dest=$(_fresh collect-b)
image_collect_metadata oci-layout '' "$_dest" >/dev/null
assert_contains "${IMAGE_COLLECT_MISSING[*]}" 'var/lib/dpkg/status' \
  'layer 1 var/lib/.wh..wh..opq removed layer 0 dpkg database - FAILS under a reading that only looks for `var/lib/dpkg/.wh.status`, which reports a package database the final image does not have and would then enumerate packages that are not installed'
assert_file_absent "$_dest/var/lib/dpkg/status" 'and nothing was extracted for it'
assert_contains "$(cat "$_dest/etc/os-release")" 'ID=fixtureoci' \
  'while a path the opaque marker does not cover is still collected, so the whiteout narrowed the result rather than emptying it'

t_case 'image_whiteout_names names every ancestor, not only the file'
_names=$(image_whiteout_names 'var/lib/dpkg/status')
assert_contains "$_names" 'var/lib/dpkg/.wh.status' 'the per-file marker'
assert_contains "$_names" 'var/lib/.wh..wh..opq' 'an ancestor opaque marker'
assert_contains "$_names" 'var/.wh..wh..opq' 'and every ancestor above it'

t_case 'no layer is left unpacked in scratch after a collection'
assert_eq '' "$_IMAGE_LAYER_SCRATCH" \
  'the per-layer scratch directory is released - FAILS under a loop that forgets image_layer_release, which accumulates every layer of every image and IS the full-rootfs materialisation report.md §1.6 forbids'

t_case 'only the wanted metadata paths are ever extracted'
_dest=$(_fresh collect-c)
image_open docker-archive "$ONE"
image_collect_metadata docker-archive "$ONE" "$_dest" >/dev/null
_files=$(cd "$_dest" && find . -type f | LC_ALL=C sort | tr '\n' ' ')
assert_not_contains "$_files" 'fixture-marker' \
  'a file the image carries but this module never asked for is NOT extracted - FAILS under a whole-rootfs extraction, which report.md §1.6 rules out as a design invariant rather than an optimisation'

t_case 'a caller can ask for a narrower path set than the default'
_dest=$(_fresh collect-d)
image_collect_metadata docker-archive "$ONE" "$_dest" 'etc/os-release' >/dev/null
_files=$(cd "$_dest" && find . -type f | LC_ALL=C sort | tr '\n' ' ')
assert_contains "$_files" 'os-release' 'the requested path is there'
assert_not_contains "$_files" 'installed' 'and nothing outside the request is'

t_case 'the default wanted-path list names LOCATIONS only, and now names all three rpm database shapes too (IMG-12)'
assert_contains "${IMAGE_METADATA_PATHS[*]}" 'lib/apk/db/installed' 'the apk database location'
assert_contains "${IMAGE_METADATA_PATHS[*]}" 'var/lib/dpkg/status' 'the dpkg database location'
assert_contains "${IMAGE_METADATA_PATHS[*]}" 'var/lib/rpm/rpmdb.sqlite' \
  'the modern rpm database location - FAILS if IMG-12 forgot to extend this list, which would silently leave rpm_installed_enumerate with nothing to read on every rpm-based image'
assert_contains "${IMAGE_METADATA_PATHS[*]}" 'var/lib/rpm/Packages' 'the Berkeley-DB rpm database location'
assert_contains "${IMAGE_METADATA_PATHS[*]}" 'var/lib/rpm/Packages.db' 'the ndb rpm database location'

# =============================================================================
printf -- '\n-- H. config/images.conf (rules/RULE-FORMAT.md §9.6.8) --\n'
# =============================================================================

_conf=$W/images.conf
cat >"$_conf" <<CONF
id: one
source: docker-archive
path: $ONE
dockerfile: fixtures/one/Dockerfile
notes: The committed one-image fixture.

id: layout
source: oci-layout
path: $OCI
reference: fixture/oci:v1
CONF

t_case 'an id resolves to its (kind, path, reference) triple'
_rc=0
image_source_resolve one '' "$_conf" || _rc=$?
assert_eq 0 "$_rc" 'a configured id resolves'
assert_eq docker-archive "$_IMAGE_SRC_KIND" 'the kind comes from the record'
assert_eq "$ONE" "$_IMAGE_SRC_PATH" 'and so does the path'
assert_eq images_conf "$_IMAGE_SRC_ORIGIN" 'and the origin records where the answer came from'

t_case 'IMG-14: an optional dockerfile key resolves into _IMAGE_SRC_DOCKERFILE'
assert_eq 'fixtures/one/Dockerfile' "$_IMAGE_SRC_DOCKERFILE" \
  'the operator-declared correlation path (rules/RULE-FORMAT.md §9.6.8) is read off the record'

t_case 'a reference in the record is carried through'
image_source_resolve layout '' "$_conf"
assert_eq oci-layout "$_IMAGE_SRC_KIND" 'the layout kind'
assert_eq 'fixture/oci:v1' "$_IMAGE_SRC_REF" 'and the reference the record names'

t_case 'IMG-14: a record with no dockerfile key leaves _IMAGE_SRC_DOCKERFILE empty, never a guess'
assert_eq '' "$_IMAGE_SRC_DOCKERFILE" \
  'FAILS under a resolver that defaults to some inferred path - an image with no declared dockerfile must not correlate at all'

t_case 'an unknown id with no --source resolves to NOTHING rather than inventing a path'
_rc=0
image_source_resolve nosuch '' "$_conf" || _rc=$?
assert_eq 1 "$_rc" \
  'an unknown id is a miss - FAILS under a fallback that guesses a path, where a run silently examines nothing and renders as a clean image'
assert_eq '' "$_IMAGE_SRC_PATH" 'and it leaves no stale path behind'

t_case '--source alone works with no config file at all, and infers the shape from disk'
_rc=0
image_source_resolve adhoc "$ONE" "$W/no-such-images.conf" || _rc=$?
assert_eq 0 "$_rc" 'an override resolves with no config file present'
assert_eq docker-archive "$_IMAGE_SRC_KIND" 'a FILE is a docker-save tarball'
assert_eq source_flag_kind_inferred "$_IMAGE_SRC_ORIGIN" \
  'and the origin records that the shape was INFERRED rather than declared - FAILS under a resolver that reports an inferred kind as if the operator had configured it, which is the difference between "scoursh read the image your config names" and "scoursh guessed"'
image_source_resolve adhoc "$OCI" "$W/no-such-images.conf"
assert_eq oci-layout "$_IMAGE_SRC_KIND" 'and a DIRECTORY is an OCI layout'

t_case '--source overrides the PATH of a configured id and nothing else'
image_source_resolve layout "$W/elsewhere" "$_conf"
assert_eq "$W/elsewhere" "$_IMAGE_SRC_PATH" 'the path is the override'
assert_eq oci-layout "$_IMAGE_SRC_KIND" \
  'the kind still comes from the record - FAILS under an override that re-infers the kind, which would call a rebuilt OCI layout a tarball the moment the operator pointed at a path that does not exist yet'
assert_eq 'fixture/oci:v1' "$_IMAGE_SRC_REF" 'and so does the reference'

t_case 'IMG-14: --source overriding a configured id still carries its declared dockerfile through'
image_source_resolve one "$W/elsewhere" "$_conf"
assert_eq 'fixtures/one/Dockerfile' "$_IMAGE_SRC_DOCKERFILE" \
  '--source overrides only where the archive lives, never which Dockerfile the operator says built it'

t_case 'IMG-14: --source with NO record leaves the dockerfile correlation path empty'
image_source_resolve adhoc2 "$ONE" "$W/no-such-images.conf"
assert_eq '' "$_IMAGE_SRC_DOCKERFILE" \
  'an ad-hoc --source run has no config/images.conf record to read a dockerfile key from'

t_case 'an ABSENT images.conf is not an error'
_rc=0
image_sources_load "$W/definitely-absent.conf" || _rc=$?
assert_eq 1 "$_rc" 'the loader reports "no file" without dying'
assert_eq 0 "$IMAGE_SOURCES_LOADED" 'and records that nothing was loaded'

t_case 'a MALFORMED images.conf is exit 4, never "behaves as if absent"'
printf 'id: broken\nsource: not-a-real-shape\npath: /tmp/x\n' >"$W/bad.conf"
_rc=0
( set -Eeuo pipefail
  # shellcheck source=/dev/null
  source "$ROOT/modules/image/acquire.sh"
  image_sources_load "$W/bad.conf"
) >/dev/null 2>&1 || _rc=$?
assert_eq 4 "$_rc" \
  'an unknown `source` value fails schema validation and exits 4 (rules/RULE-FORMAT.md §11, E024) - FAILS under a loader that treats a malformed file as an absent one, where an operator typo silently disables the image they thought they were scanning'

t_case 'the shipped example validates against the schema it documents'
_rc=0
( set -Eeuo pipefail
  # shellcheck source=/dev/null
  source "$ROOT/modules/image/acquire.sh"
  image_sources_load "$ROOT/config/images.conf.example"
) >/dev/null 2>&1 || _rc=$?
assert_eq 0 "$_rc" \
  'config/images.conf.example parses and validates - the same reason lib/records.sh strips `.example` in its path table, so a shipped example cannot drift from its schema'

t_summary image-acquire
