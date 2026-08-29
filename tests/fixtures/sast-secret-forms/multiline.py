# FAKE test values only - see README.md in this directory.
# Documented ARCHITECTURAL gap, not a rule defect: rules/RULE-FORMAT.md §8.2
# freezes matching as line-oriented ("a pattern can never match across a
# newline"), so a value on a different line from its keyword is unreachable by
# any pattern rule.  Pinned here so the gap stays visible instead of being
# silently assumed covered.
PASSWORD = (
    "Tr0ub4dor3xK"      # [[G01]]
)
PASSWORD = """
Tr0ub4dor3xK  # [[G02]] value line carries no keyword at all
"""
CONNECTION = {
    "password":
        "Tr0ub4dor3xK"  # [[G03]]
}
