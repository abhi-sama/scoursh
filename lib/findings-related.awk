# Owns: related native TLS checks on exactly the same statement. Input is the
# already escaped findings.fields stream twice, so encoded paths remain opaque
# and no target-derived text is decoded, executed or re-escaped here.
function fields(    i,p,k) {
    for(k in v) delete v[k]
    for(i=1;i<=NF;i++) {p=index($i,"=");k=substr($i,1,p-1);v[k]=substr($i,p+1)}
    id=v["check_id"]
    eligible=(v["module"]=="sast" && (id=="SAST-CRY-TLS_VERIFY_DISABLED-01" || id=="SAST-GO-TLS_SKIP_VERIFY-01"))
    group=v["cell"] SUBSEP v["loc_path"] SUBSEP v["loc_line"] SUBSEP v["loc_match_digest"] SUBSEP v["loc_occurrence"]
}
BEGIN {FS=OFS="\t"}
FNR==NR {
    fields()
    if(eligible) peers[group SUBSEP id]=v["fingerprint"]
    next
}
{
    fields()
    if(!eligible) {print;next}
    other=(id=="SAST-CRY-TLS_VERIFY_DISABLED-01" ? "SAST-GO-TLS_SKIP_VERIFY-01":"SAST-CRY-TLS_VERIFY_DISABLED-01")
    peer=peers[group SUBSEP other]
    if(peer=="") {print;next}
    related=v["related"]
    if(index("\\n" related "\\n","\\n" peer "\\n")==0) related=(related!="" ? related "\\n":"") peer
    out="";inserted=0
    for(i=1;i<=NF;i++) {
        k=$i;sub(/=.*/,"",k)
        if(k=="related") {$i="related=" related;inserted=1}
        if(!inserted && k!~/^_/ && k>"related") {out=out (out!=""?OFS:"") "related=" related;inserted=1}
        out=out (out!=""?OFS:"") $i
    }
    if(!inserted) out=out OFS "related=" related
    print out
}
