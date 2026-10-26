# Owns: static go.mod require/replace/exclude selection. No module downloads.
# Unknown local replacements/excluded pins have no provable registry coordinate;
# the caller retains its declared replacement/exclusion coverage reduction.
function trim(s) { sub(/^[ \t]+/, "", s); sub(/[ \t]+$/, "", s); return s }
function entry(kind, s,    n,a,k,r,l,rn,rv) {
    s = trim(s)
    if (kind == "require") {
        n = split(s, a, /[ \t]+/)
        if (n < 2) return
        order[++count] = a[1]; version[a[1]] = a[2]
        direct[a[1]] = (s ~ /\/\/ indirect/ ? "transitive" : "direct")
    } else if (kind == "exclude") {
        sub(/\/\/.*/, "", s); n = split(trim(s), a, /[ \t]+/)
        if (n == 2) excluded[a[1] SUBSEP a[2]] = 1
    } else if (kind == "replace") {
        sub(/\/\/.*/, "", s); n = split(s, a, /=>/)
        if (n != 2) return
        l = trim(a[1]); r = trim(a[2]); n = split(l, a, /[ \t]+/)
        k = a[1] SUBSEP (n > 1 ? a[2] : "*")
        n = split(r, a, /[ \t]+/)
        # Only an explicit module and version identify registry content.
        replacement[k] = (n == 2 && a[2] ~ /^v[0-9]/ ? a[1] "\037" a[2] : "")
    }
}
{
    s = trim($0)
    if (s == "" || s ~ /^\/\//) next
    if (s ~ /^\)/) { block = ""; next }
    if (block != "") { entry(block, s); next }
    if (s ~ /^(require|replace|exclude)[ \t]+/) {
        kind = s; sub(/[ \t].*$/, "", kind)
        sub(/^[^ \t]+[ \t]+/, "", s)
        if (s ~ /^\(/) block = kind
        else entry(kind, s)
    }
}
END {
    for (i = 1; i <= count; i++) {
        name = order[i]; ver = version[name]; k = name SUBSEP ver
        if (excluded[k]) continue
        if (!(k in replacement)) k = name SUBSEP "*"
        if (k in replacement) {
            if (replacement[k] == "") continue
            print replacement[k] "\037" direct[name]
        } else print name "\037" ver "\037" direct[name]
    }
}
