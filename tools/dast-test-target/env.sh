# tools/dast-test-target/env.sh - constants shared between
# tools/dast-test-target.sh and tools/dast-test-identities.sh, so the
# container name, port, and node-http-client path can never drift out of
# sync between the two scripts. Sourced only, never executed directly;
# assumes the caller has already sourced lib/core.sh (for SCOURSH_INSTALL_ROOT).

# Exported (not just set) because each one's only reader is a SEPARATE file
# that sources this one - shellcheck follows a `source` forward, from the
# sourcing script into this file, never the reverse, so without `export` it
# reports every one of these SC2034 "appears unused". Same convention
# lib/checks.sh uses for CHECKS_PROFILE_DEFAULT and lib/core.sh for its own
# SCOURSH_EXIT_* constants.
DTT_PORT=${SCOURSH_DAST_TEST_TARGET_PORT:-3400}
DTT_IMAGE=${SCOURSH_DAST_TEST_TARGET_IMAGE:-bkimminich/juice-shop:v20.1.1}
DTT_CONTAINER=scoursh-dast-test-target
DTT_CLIENT_JS="$SCOURSH_INSTALL_ROOT/tools/dast-test-target/http-client.js"
DTT_URL="http://127.0.0.1:$DTT_PORT"

# Local, gitignored state: the two identities' generated passwords (as
# 600-permission secret-files, rules/RULE-FORMAT.md §9.6.2's own convention)
# and a companion config/auth.conf-format record referencing them by path.
# Never committed - see .gitignore's "scoursh's own local DAST test-target
# state" entry.
DTT_STATE_DIR="$SCOURSH_INSTALL_ROOT/.dast-test-target"
DTT_AUTH_CONF="$DTT_STATE_DIR/auth.conf"

export DTT_PORT DTT_IMAGE DTT_CONTAINER DTT_CLIENT_JS DTT_URL DTT_STATE_DIR DTT_AUTH_CONF
