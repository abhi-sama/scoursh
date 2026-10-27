# Owns: owning-object checks for the native IaC candidates (FOUNDATION 3).
# Static YAML/JSON mappings, HCL blocks and Docker stages only. No evaluation,
# provider calls, template rendering, dependency resolution or network access.
function trim(s) { sub(/^[ \t\r\n]+/,"",s); sub(/[ \t\r\n,]+$/,"",s); return s }
function unquote(s) { s=trim(s); if(s ~ /^["\047]/) s=substr(s,2,length(s)-2); return s }
function node(p,k,v,n,col,    id) {
    id=++nn; parent[id]=p; key[id]=k; value[id]=unquote(v); at[id]=n; column[id]=col
    child[p SUBSEP k]=id
    if(!(n in firstnode)) firstnode[n]=id
    lastnode[n]=id
    return id
}
function childval(p,k) { return value[child[p SUBSEP k]] }
function ancestor(id,k) { for(;id;id=parent[id]) if(key[id]==k) return id; return 0 }
function below(id,p) { for(;id;id=parent[id]) if(id==p) return 1; return 0 }
function field(n,col,    i,best) {
    best=firstnode[n]
    for(i=firstnode[n];i<=lastnode[n];i++) if(at[i]==n && column[i]<=col && column[i]>=column[best]) best=i
    return best
}
function strip(s,    i,c,p,q,e,out,mask) {
    q=""; e=0; out=mask=""
    for(i=1;i<=length(s);i++) {
        c=substr(s,i,1);p=substr(s,i,2)
        if(block) {
            if(p=="*/") {block=0;i++;out=out "  ";mask=mask "  "}
            else {out=out " ";mask=mask " "};continue
        }
        if(q!="") {
            out=out c;mask=mask " "
            if(e) e=0;else if(c=="\\") e=1;else if(c==q) q=""
        } else if(c=="#" || (hcl && p=="//")) break
        else if(hcl && p=="/*") {block=1;i++;out=out "  ";mask=mask "  "}
        else {out=out c;if(c=="\"" || c=="\047") {q=c;mask=mask " "} else mask=mask c}
    }
    stripped=out;masked=mask
}
function yaml(s,n,    ind,t,k,v,p,id,islist,c) {
    strip(s);s=stripped
    ind=match(s,/[^ \t]/)-1;if(ind<0) return
    if(scalar && ind>scalar_indent) return
    scalar=0
    t=trim(s)
    if(t ~ /^(---|[.][.][.])$/) {yd=0;doc=node(0,"document","",n,1);return}
    if(t ~ /^[{][{]/) {
        p=yd;while(p>0 && indent[ys[p]]>=ind) p--
        computed[(p?ys[p]:doc)]=1
        return
    }
    islist=(t ~ /^-([ \t]|$)/)
    while(yd>0 && (indent[ys[yd]]>ind || (indent[ys[yd]]==ind && !islist))) yd--
    p=(yd ? ys[yd] : doc)
    if(t ~ /^<<[ \t]*:/) {computed[p]=1;return} # unresolved YAML merge
    if(islist) {
        # Indentless YAML sequences are children of the mapping at the same
        # indentation, rather than siblings of that mapping.
        if(yd && key[p]=="#") {yd--;p=(yd?ys[yd]:doc)}
        id=node(p,"#","",n,ind+1);indent[id]=ind+0.5;ys[++yd]=id;p=id
        sub(/^-[ \t]*/,"",t);ind+=2
    }
    if(match(t,/^["\047]?[A-Za-z0-9_.\/:-]+["\047]?:[ \t]*/)) {
        c=RLENGTH;k=substr(t,1,c);sub(/:[ \t]*$/,"",k);k=unquote(k);v=substr(t,c+1)
        id=node(p,k,v,n,ind+1);indent[id]=ind;ys[++yd]=id
        if(v ~ /^[{][{]/) computed[id]=1
        if(v ~ /^[|>][-+0-9]*([ \t]*#.*)?$/) {scalar=1;scalar_indent=ind}
    } else if(islist) value[p]=unquote(t)
}
function json(s,n,    i,c,j,t,e,p,k,id) {
    for(i=1;i<=length(s);i++) {
        c=substr(s,i,1); if(c ~ /[ \t\r]/) continue
        if(c=="\"") {
            t="";e=0
            for(j=i+1;j<=length(s);j++) {
                c=substr(s,j,1)
                if(!e && c=="\"") break
                t=t c;if(e) e=0;else if(c=="\\") e=1
            }
            if(j>length(s)) {unsupported=1;return}
            if(jtype[jd]=="object" && expectkey[jd]) {jkey[jd]=t;jcol[jd]=i;expectkey[jd]=0}
            else {
                k=(jtype[jd]=="array"?"#":jkey[jd]);id=node(js[jd],k,t,n,(jcol[jd]?jcol[jd]:i));jkey[jd]=""
            }
            i=j;continue
        }
        if(c=="{" || c=="[") {
            if(!jd) id=doc
            else {k=(jtype[jd]=="array"?"#":jkey[jd]);id=node(js[jd],k,"",n,(jcol[jd]?jcol[jd]:i));jkey[jd]=""}
            jd++;js[jd]=id;jtype[jd]=(c=="{"?"object":"array");expectkey[jd]=(c=="{");jcol[jd]=0
        } else if(c=="}" || c=="]") {jd--;if(jd<0) {unsupported=1;jd=0}}
        else if(c==",") {expectkey[jd]=(jtype[jd]=="object");jcol[jd]=0}
        else if(c==":") continue
        else {
            t=substr(s,i);sub(/[,}\]].*$/,"",t)
            k=(jtype[jd]=="array"?"#":jkey[jd]);id=node(js[jd],k,trim(t),n,(jcol[jd]?jcol[jd]:i));jkey[jd]="";i+=length(t)-1
        }
    }
}
function terraform(s,n,    i,c,t,p,k,id,q) {
    if(heredoc!="") {
        clean[n]=bare[n]=""
        if(trim(s)==heredoc) heredoc=""
        return
    }
    strip(s);clean[n]=stripped;bare[n]=masked
    blockof[n]=(hd?hs[hd]:0)
    for(i=1;i<=length(masked);i++) {
        c=substr(masked,i,1)
        if(c=="{") {
            t=trim(substr(stripped,1,i-1));k=t;sub(/^.*[{};]/,"",k)
            id=node((hd?hs[hd]:0),trim(k),"",n,i);hs[++hd]=id;blockof[n]=id
        } else if(c=="}" && hd) {end[hs[hd]]=n;endcol[hs[hd]]=i;hd--}
    }
    if(match(masked,/<<-?[A-Za-z_][A-Za-z0-9_]*/)) {heredoc=substr(masked,RSTART,RLENGTH);sub(/^<<-?/,"",heredoc)}
}
function hcl_owner(n,col,    j,b,nearest) {
    b=0
    for(j=1;j<=nn;j++) {
        if(at[j]>n || (end[j] && end[j]<n)) continue
        if(at[j]==n && column[j]>col) continue
        if(end[j]==n && endcol[j]<col) continue
        b=j
    }
    return b
}
function hcl_text(b,    j,s,t,e) {
    t="";e=(end[b]?end[b]:lines)
    for(j=at[b];j<=e;j++) {
        s=clean[j]
        if(j==e && endcol[b]) s=substr(s,1,endcol[b])
        if(j==at[b]) s=substr(s,column[b]+1)
        t=t s "\n"
    }
    return t
}
function hcl_attribute(b,name,    s,i,c,q,e,d,t,k,v,j) {
    s=hcl_text(b);q="";e=d=0
    for(i=1;i<=length(s);i++) {
        c=substr(s,i,1)
        if(q!="") {if(e)e=0;else if(c=="\\")e=1;else if(c==q)q="";continue}
        if(c=="\"") {q=c;continue}
        if(c=="{" || c=="[") {d++;continue}
        if(c=="}" || c=="]") {d--;continue}
        if(d || c !~ /[A-Za-z_]/) continue
        t=substr(s,i);match(t,/^[A-Za-z_][A-Za-z0-9_]*/);k=substr(t,1,RLENGTH);i+=RLENGTH-1
        if(k!=name) continue
        t=substr(s,i+1)
        if(t !~ /^[ \t]*=/) continue
        sub(/^[ \t]*=[ \t]*/,"",t)
        if(substr(t,1,1)=="\"") {t=substr(t,2);sub(/".*$/,"",t);return t}
        sub(/[^A-Za-z0-9_].*$/,"",t);return t
    }
    return ""
}
function resource(id,    p,k) {
    for(p=id;p;p=parent[p]) {
        k=childval(p,"kind")
        if(k!="" && childval(p,"apiVersion")!="" &&
           (key[p]=="document" || (key[p]=="#" && key[parent[p]]=="items" && childval(parent[parent[p]],"kind")=="List"))) return p
    }
    return 0
}
function workload(r,    k,v) {
    k=childval(r,"kind");v=childval(r,"apiVersion")
    if(k=="Pod") return v ~ /^v[0-9]/
    if(k ~ /^(Job|CronJob)$/) return v ~ /^batch\//
    return k ~ /^(Deployment|StatefulSet|DaemonSet|ReplicaSet)$/ && v ~ /^(apps|extensions)\//
}
function podspec(r,    k,s) {
    k=childval(r,"kind");s=child[r SUBSEP "spec"]
    if(k=="CronJob") s=child[child[child[s SUBSEP "jobTemplate"] SUBSEP "spec"] SUBSEP "template"]
    else if(k!="Pod") s=child[s SUBSEP "template"]
    if(k!="Pod") s=child[s SUBSEP "spec"]
    return s
}
function container(id,s,    p) {
    for(p=id;p;p=parent[p]) if(key[p]=="#" && key[parent[p]] ~ /^(containers|initContainers|ephemeralContainers)$/ && parent[parent[p]]==s) return p
    return 0
}
function nonroot(p) { return childval(child[p SUBSEP "securityContext"],"runAsNonRoot")=="true" }
function secret_path(k,v) { return k ~ /(_PATH|_FILE|Path|File|path|file)$/ && v ~ /^\// }
# A secret-named setting says what it holds in its own suffix: TOKEN_ISSUER is
# a URL, JWT_SECRET_TTL a duration.  _FILE/_PATH stay with secret_path above.
function secret_setting(k) { return k ~ /(PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|CREDENTIAL)S?[A-Za-z0-9_]*_(DIR|NAME|URL|URI|ARN|ID|TTL|EXPIRY|EXPIRES|ENABLED|TYPE|ISSUER|AUDIENCE|ENDPOINT|LENGTH|MINUTES|SECONDS|DAYS|HOURS|REF)$/ }
function decide(n,col,    id,r,p,s,c,k,v,j,t,b,e,stage,a,u,rest,props,typ,script,uncertain,q,account,namespace,found) {
    if(check !~ /^IAC-(DOCKER|TF|COMPOSE|CFN|HELM|K8S)-/) return "keep"
    if(check ~ /^IAC-DOCKER-/) {
        t=clean[n];b=bare[n];stage=stageof[n]
        if(check ~ /SECRET_ENV/) {
            v=t;sub(/^[^=]*=[ \t]*/,"",v);v=unquote(v)
            if(v ~ /^\$[{][A-Za-z_][A-Za-z0-9_]*[}]$/ || v ~ /^\$[A-Za-z_][A-Za-z0-9_]*$/) return "drop"
        }
        if(check ~ /PIPE_TO_SHELL/) {
            if(b ~ /^RUN[ \t]+(\/bin\/)?(sh|bash|zsh|ash)[ \t]+-c[ \t]/) {
                script=t;sub(/^RUN[ \t]+(\/bin\/)?(sh|bash|zsh|ash)[ \t]+-c[ \t]+/,"",script)
                if(script ~ /^".*"$/ || script ~ /^\047.*\047$/) {strip(unquote(script));b=masked}
                else return "keep" # executed command string, not printable text
            } else if(t ~ /^RUN[ \t]+\[[ \t]*"(\/bin\/)?(sh|bash|zsh|ash)"[ \t]*,[ \t]*"-c"/) return "keep"
            if(b !~ /(curl|wget)[ \t]+[^|]*\|[ \t]*(sudo[ \t]+)?(sh|bash|zsh|ash)/) return "drop"
        }
        if(check ~ /REMOTE_ADD/ && t ~ /--checksum=sha256:[0-9a-fA-F]+/) {
            v=t;sub(/^.*--checksum=sha256:/,"",v);sub(/[ \t].*$/,"",v);if(length(v)==64) return "drop"
        }
        if(check ~ /UNPINNED_DIGEST|LATEST_TAG/) {
            if(internal[stage] || base[stage] ~ /@sha256:[0-9a-fA-F]+/) return "drop"
        }
        if(check ~ /ROOT_USER/) {
            if(stage!=stages) return "drop"
            u=user[stage];if(u!="" && u !~ /^(root|0)(:|$)/) return (u ~ /\$/ ? "review" : "drop")
        }
        return "keep"
    }
    if(hcl) {
        # Credential literals remain eligible even in comments. The source
        # lane owns lexical exclusions; this pack never weakens real secrets.
        if(check ~ /HARDCODED_SECRET/) return "keep"
        if(trim(clean[n])=="" || col>length(clean[n])) return "drop"
        b=hcl_owner(n,col)
        if(check ~ /OPEN_CIDR/) {
            for(p=b;p;p=parent[p]) if(key[p] ~ /(^|[ \t])egress([ \t]|$)|aws_vpc_security_group_egress_rule/) return "drop"
        }
        if(check ~ /KEY_ROTATION_DISABLED/) {
            # This candidate begins at 'resource', before its opening brace.
            for(j=1;j<=nn;j++) if(at[j]==n && column[j]>=col && key[j] ~ /^resource[ \t]+"aws_kms_key"/) {b=j;break}
            if(hcl_attribute(b,"enable_key_rotation")=="true" || hcl_attribute(b,"key_usage")=="SIGN_VERIFY" || hcl_attribute(b,"key_spec") ~ /^(RSA_|ECC_)/) return "drop"
            v=hcl_attribute(b,"enable_key_rotation")
            if(v!="" && v!="false") return "review"
            v=hcl_attribute(b,"key_spec");if(v!="" && v!="SYMMETRIC_DEFAULT") return "review"
        }
        return "keep"
    }
    id=field(n,col);if(!id) return "drop"
    if(check ~ /^IAC-COMPOSE-/) {
        p=ancestor(id,"services");if(!p) return "drop"
        if(check ~ /EXPOSED_PORT/ && !ancestor(id,"ports")) return "drop"
        if(check ~ /SENSITIVE_MOUNT/ && !ancestor(id,"volumes")) return "drop"
        if(check ~ /PRIVILEGED/ && parent[parent[id]]!=p) return "drop"
        if(check ~ /PLAINTEXT_SECRET/) {
            if(!ancestor(id,"environment")) return "drop"
            if(secret_path(key[id],value[id])) return "drop"
        }
        return "keep"
    }
    if(check ~ /^IAC-CFN-/) {
        r=ancestor(id,"Resources");if(!r) return "drop"
        p=id;while(parent[p] && parent[p]!=r) p=parent[p]
        typ=childval(p,"Type");if(typ !~ /^AWS::/) return "drop"
        if(check ~ /OPEN_CIDR/ && typ !~ /^AWS::EC2::SecurityGroup(Ingress)?$/) return "drop"
        if(check ~ /S3_PUBLIC_ACCESS/ && typ!="AWS::S3::Bucket") return "drop"
        if(check ~ /UNENCRYPTED/ && typ !~ /^AWS::(RDS::DB(Instance|Cluster)|EC2::Volume)$/) return "drop"
        if(check ~ /PUBLIC_IP/ && typ !~ /^AWS::EC2::(Instance|LaunchTemplate)$/) return "drop"
        if(check ~ /RDS_PUBLIC/ && typ!="AWS::RDS::DBInstance") return "drop"
        if(check ~ /ECS_PRIVILEGED/ && typ!="AWS::ECS::TaskDefinition") return "drop"
        props=child[p SUBSEP "Properties"]
        if(check ~ /KEY_ROTATION_DISABLED/) {
            if(typ!="AWS::KMS::Key") return "drop"
            if(childval(props,"EnableKeyRotation")=="true" || childval(props,"KeySpec") ~ /^(RSA_|ECC_)/ || childval(props,"KeyUsage")=="SIGN_VERIFY") return "drop"
            v=childval(props,"EnableKeyRotation");if(v!="" && v!="false") return "review"
            if(value[props]!="" || child[props SUBSEP "Fn::If"]) return "review"
            v=childval(props,"KeySpec");if(v!="" && v!="SYMMETRIC_DEFAULT") return "review"
            return "keep"
        }
        if(!below(id,props)) return "drop"
        if(check ~ /OPEN_CIDR/ && (typ ~ /Egress$/ || ancestor(id,"SecurityGroupEgress"))) return "drop"
        if(check ~ /HARDCODED_SECRET/ && value[id] ~ /^(!Ref|!Sub|!GetAtt|[{][{]resolve:)/) return "drop"
        return "keep"
    }
    r=resource(id)
    if(check ~ /^IAC-HELM-/) {
        if(check ~ /HARDCODED_SECRET/) {
            if(secret_path(key[id],value[id]) || value[id] ~ /^\/(run\/secrets|var\/run\/secrets)\//) return "drop"
            return "keep"
        }
        if(!r || !workload(r)) {
            if(path ~ /(^|\/)values[.]yaml$/) return "review"
            return "drop"
        }
        s=podspec(r)
        if(check ~ /HOST_PORT/) return (container(id,s) && key[parent[id]]=="#" && key[parent[parent[id]]]=="ports" ? "keep":"drop")
        if(check ~ /HOST_MOUNT/) return (ancestor(id,"volumes") && key[parent[id]]=="hostPath" && below(id,s) ? "keep":"drop")
    }
    if(check ~ /^IAC-K8S-/) {
        if(!r) return "drop"
        if(check ~ /RBAC_WILDCARD/) return (childval(r,"kind") ~ /^(Role|ClusterRole)$/ && childval(r,"apiVersion") ~ /^rbac[.]authorization[.]k8s[.]io\// && ancestor(id,"rules") && (ancestor(id,"verbs") || ancestor(id,"resources")) ? "keep":"drop")
        if(!workload(r)) return "drop"
        s=podspec(r);c=container(id,s)
        if(check ~ /SA_TOKEN_DEFAULT/) {
            if(id!=child[r SUBSEP "kind"]) return "drop"
            p=child[s SUBSEP "automountServiceAccountToken"]
            if(computed[s] || computed[p] || value[p] ~ /^\*/) return "review"
            if(childval(s,"automountServiceAccountToken")=="false") return "drop"
            if(value[p]=="true") return "keep" # Pod override beats ServiceAccount
            account=childval(s,"serviceAccountName")
            if(account!="") {
                if(computed[child[s SUBSEP "serviceAccountName"]] || account ~ /^\*/) return "review"
                namespace=childval(child[r SUBSEP "metadata"],"namespace");found=0
                if(computed[child[child[r SUBSEP "metadata"] SUBSEP "namespace"]]) return "review"
                for(j=1;j<=nn;j++) if(childval(j,"kind")=="ServiceAccount" && childval(j,"apiVersion")=="v1" && resource(child[j SUBSEP "kind"])==j && childval(child[j SUBSEP "metadata"],"name")==account && childval(child[j SUBSEP "metadata"],"namespace")==namespace) {
                    found=1
                    if(childval(j,"automountServiceAccountToken")=="false") return "drop"
                }
                if(!found) return "review" # no cross-file/cluster lookup
            }
            return "keep"
        }
        if(check ~ /HOST_NAMESPACE/) return (parent[id]==s ? "keep":"drop")
        if(check ~ /RUN_AS_ROOT/) {
            if(parent[id]!=s) return "drop"
            uncertain=0
            for(j=1;j<=nn;j++) if(parent[j]==id && key[j]=="#") {
                t=child[j SUBSEP "securityContext"];p=child[t SUBSEP "runAsNonRoot"]
                q=child[s SUBSEP "securityContext"]
                if(computed[j] || computed[t] || (p && (computed[p] || value[p] ~ /^\*/)) || (!p && (computed[q] || value[q] ~ /^\*/ || computed[child[q SUBSEP "runAsNonRoot"]]))) {uncertain=1;continue}
                if(p ? value[p]!="true" : !nonroot(s)) return "keep"
            }
            return (uncertain?"review":"drop")
        }
        if(!c) return "drop"
        if(check ~ /PRIVILEGED/) return (key[parent[id]]=="securityContext" && parent[parent[id]]==c ? "keep":"drop")
        if(check ~ /MISSING_RESOURCE_LIMITS/) {
            p=child[c SUBSEP "resources"]
            if(computed[c] || computed[p] || value[p] ~ /^(\*|[{][{])/) return "review"
            q=child[p SUBSEP "limits"];t=child[p SUBSEP "requests"]
            if(computed[q] || computed[t] || value[q] ~ /^\*/ || value[t] ~ /^\*/) return "review"
            if(child[p SUBSEP "limits"] || child[p SUBSEP "requests"]) return "drop"
            if(value[p] ~ /[{]/) return "review"
            return "keep"
        }
        if(check ~ /MUTABLE_TAG/ && value[id] ~ /@sha256:/) return "drop"
        if(check ~ /SECRET_ENV/) {
            if(!ancestor(id,"env")) return "drop"
            p=parent[id];k=childval(p,"name")
            if(k !~ /(PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|CREDENTIAL)/ || secret_path(k,value[id]) || secret_setting(k)) return "drop"
        }
        return "keep"
    }
    return "keep"
}
BEGIN { hcl=(path ~ /[.]tf$/); docker=(check ~ /^IAC-DOCKER-/); if(limit=="") limit=200 }
FILENAME==ARGV[1] {
    raw[++lines]=$0;start[lines]=bytes;bytes+=length($0)+1
    if(hcl) terraform($0,lines)
    else if(docker) {
        strip($0);clean[lines]=stripped;bare[lines]=masked;t=trim(stripped)
        if(t ~ /^FROM[ \t]/) {
            stages++;split(t,a,/[ \t]+/);i=2;while(a[i] ~ /^--/) i++
            base[stages]=a[i];internal[stages]=(a[i]=="scratch" || a[i] in aliases)
            user[stages]=(a[i] in aliases?user[aliases[a[i]]]:"")
            if(t ~ /[ \t][Aa][Ss][ \t]/) aliases[a[i+2]]=stages
        }
        stageof[lines]=stages
        if(t ~ /^USER[ \t]/) {sub(/^USER[ \t]+/,"",t);user[stages]=trim(t)}
    } else {
        if(!doc) doc=node(0,"document","",lines,1)
        if(!format && $0 ~ /^[ \t]*[^ \t#]/) format=($0 ~ /^[ \t]*[{\[]/?"json":"yaml")
        if(format=="json") json($0,lines);else yaml($0,lines)
    }
    next
}
{
    record=$0;n=$0+0;sub(/^[^:]*:/,"",$0);off=$0+0;col=off-start[n]+1
    if(++candidates>limit) {print "keep:" record;exit}
    result=decide(n,col)
    print result ":" record
}
