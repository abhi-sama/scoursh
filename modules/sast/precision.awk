# Owns: conservative lexical/call proofs for native non-credential findings.
# Input 1 is source; input 2 is the engine's byte-exact candidate stream.
# Output adds keep/review, retaining original match bytes and source locations.
# This is not a compiler or cross-function taint engine. Unknown expressions
# stay findings; only complete local proofs are discarded. See FOUNDATION 3.
function trim(s) { sub(/^[ \t\r\n]+/, "", s); sub(/[ \t\r\n]+$/, "", s); return s }
function blank(s) { gsub(/./, " ", s); return s }
function lex(s, n,    i,c,p,t,out,mask,q,esc) {
    out = mask = ""; q = ""; esc = 0
    for (i = 1; i <= length(s); i++) {
        c = substr(s,i,1); p = substr(s,i,2); t = substr(s,i,3)
        if (triple != "") {
            if (t == triple) { out = out "   "; mask = mask "   "; triple = ""; i += 2 }
            else { out = out " "; mask = mask " " }; continue
        }
        if (block) {
            if (p == "*/") { block = 0; out = out "  "; mask = mask "  "; i++ }
            else { out = out " "; mask = mask " " }; continue
        }
        if (q != "") {
            out = out c; mask = mask " "
            if (esc) esc = 0
            else if (c == "\\") esc = 1
            else if (c == q) q = ""
            continue
        }
        if (python && (t == "\"\"\"" || t == "\047\047\047")) {
            # Triple strings used as an expression are data, not docstrings.
            # Preserve them in calls/assignments; only standalone docstrings
            # can be removed without changing the meaning of a sink.
            if (trim(out) == "") { triple = t; out = out "   "; mask = mask "   "; i += 2; continue }
        }
        if ((!python && p == "//") || (python && c == "#")) {
            out = out blank(substr(s,i)); mask = mask blank(substr(s,i)); break
        }
        if (!python && p == "/*") { block = 1; out = out "  "; mask = mask "  "; i++; continue }
        out = out c
        if (c == "\"" || c == "\047" || c == "`") { q = c; mask = mask " " }
        else mask = mask c
    }
    clean[n] = out; bare[n] = mask
}
# Read the current call, balanced across physical lines. Stop at the closing
# parenthesis, never at an unrelated SafeLoader/sanitizer in a sibling call.
function call(n, col,    s,b,i,c,q,e,d,j,k) {
    s = substr(clean[n],col); b = index(s,"(")
    if (!b) return ""
    s = substr(s,b+1); d = 1; q = ""; e = 0
    for (j = n; j <= lines; j++) {
        if (j > n) s = s "\n" clean[j]
        k = (j == n ? 1 : k)
        for (i = k; i <= length(s); i++) {
            c = substr(s,i,1)
            if (q != "") {
                if (e) e = 0; else if (c == "\\") e = 1; else if (c == q) q = ""
            } else if (c == "\"" || c == "\047" || c == "`") q = c
            else if (c == "(") d++
            else if (c == ")" && --d == 0) return substr(s,1,i-1)
        }
        k = length(s)+1
    }
    return s
}
function first(s,    i,c,q,e,d) {
    q = ""; e = d = 0
    for (i = 1; i <= length(s); i++) {
        c = substr(s,i,1)
        if (q != "") { if (e) e=0; else if(c=="\\") e=1; else if(c==q) q="" }
        else if(c=="\"" || c=="\047" || c=="`") q=c
        else if(c=="(" || c=="[" || c=="{") d++
        else if(c==")" || c=="]" || c=="}") d--
        else if(c=="," && !d) return trim(substr(s,1,i-1))
    }
    return trim(s)
}
# A literal expression consists entirely of quoted constants and punctuation;
# interpolation, method calls, identifiers and unknown syntax never prove safe.
function literal(s,    i,c,q,e,out,strings) {
    s = trim(s); if(s=="") return 0
    out = ""; q = ""; e = strings = 0
    for(i=1;i<=length(s);i++) {
        c=substr(s,i,1)
        if(q!="") {
            if(q=="`" && substr(s,i,2)=="${") return 0
            if(e) e=0; else if(c=="\\") e=1; else if(c==q) {q=""; strings++}
        } else if(c=="\"" || c=="\047" || c=="`") q=c
        else if((c=="b" || c=="r" || c=="u") && substr(s,i+1,1) ~ /["\047]/) continue
        else out=out c
    }
    gsub(/(True|False|None|null|true|false)/,"",out)
    return q=="" && (strings || out ~ /[0-9]/) && out !~ /[^0-9 \t\n+%.,:{}()\[\]-]/
}
# Last assignment in the current lexical scope, up to the candidate byte.
# Stop at function boundaries/parameters; do not borrow another function's
# constant or sanitizer. Reassignment invalidates an earlier safe binding.
function closed_scope(code,pos,    i,c,depth,opens) {
    depth=0
    for(i=1;i<=length(code);i++) {
        c=substr(code,i,1)
        if(c=="{") opens[++depth]=i
        else if(c=="}" && depth>0) {
            if(opens[depth]<pos && pos<i) return 1
            depth--
        }
    }
    return 0
}
function binding(name,n,col,    j,s,re,p,last,start,code,matched,segment,name_re,mut_re,dirty,scope_dirty,indent) {
    if(name !~ /^[A-Za-z_$][A-Za-z0-9_$.]*$/) return ""
    re=name; gsub(/[.]/,"[.]",re);gsub(/[$]/,"[$]",re);name_re=re
    mut_re=name_re "[.][A-Za-z_][A-Za-z0-9_]*[ \t]*\\(|" name_re "[ \t]*\\[[^]]*\\][ \t]*=[^=]|[(,][ \t]*" name_re "[ \t]*[,)]|=[ \t]*" name_re "[ \t]*(;|$)"
    re="(^|[;{} \t])(const[ \t]+|let[ \t]+|var[ \t]+|String[ \t]+)?" re "[ \t]*(=[^=]|[+*/%&|^-]=|[+][+]|--)"
    dirty=scope_dirty=0;indent=match(bare[n],/[^ \t]/)-1
    for(j=n;j>=1;j--) {
        s=clean[j];code=bare[j]
        if(j==n) {s=substr(s,1,col-1);code=substr(code,1,col-1)}
        if(!python && j<n && code ~ /^[ \t]*}/) break
        last=""
        while(match(code,re)) {
            start=RSTART;p=RSTART+RLENGTH-1;matched=substr(code,RSTART,RLENGTH)
            # Nested match() calls overwrite awk's global RSTART/RLENGTH.
            # Capture the assignment cursor before inspecting indentation.
            if((!python && closed_scope(code,start)) || (python && match(bare[j],/[^ \t]/)-1>indent)) scope_dirty=1
            if(p<=1) exit 2 # a cursor that cannot advance must fail, not hang
            code=substr(code,p);s=substr(s,p)
            last=(matched ~ /[+*\/%&|^-]=|[+][+]|--/ ? "?":s)
        }
        if(last!="") {
            if(scope_dirty || dirty || code ~ mut_re) return "?"
            sub(/;.*$/,"",last); return trim(last)
        }
        if(code ~ mut_re) dirty=1
        if(bare[j] ~ /(^|[;{} \t])(def|function|func)[ \t]/ || bare[j] ~ /[)][ \t]*\{/) break
    }
    return ""
}
function constant(s,n,col,    b) {
    if(literal(s)) return 1
    b=binding(trim(s),n,col)
    return b!="" && literal(b)
}
function safe_markup(s,n,col,    b,j,header,args,pos,opens,closes,tmp) {
    b=trim(s)
    if(b !~ /^DOMPurify[.]sanitize[ \t]*\(/) b=binding(b,n,col)
    if(b !~ /^DOMPurify[.]sanitize[ \t]*\(/) return 0
    # A locally shadowed sanitizer is not a trusted sanitizer.
    if(binding("DOMPurify",n,col)!="") return 0
    for(j=n;j>=1;j--) {
        header=bare[j];if(j==n) header=substr(header,1,col-1)
        if(j<n && header ~ /^[ \t]*}/) break
        if(header ~ /(^|[;{} \t])(function|func|def)[ \t]|=>/) {
            tmp=header;opens=gsub(/[{]/,"",tmp);tmp=header;closes=gsub(/[}]/,"",tmp)
            if(j<n && opens<=closes) continue
            pos=1
            if(match(header,/(function|func|def)[ \t]/)) pos=RSTART
            args=call(j,pos)
            if(args ~ /(^|[({,:])[ \t]*DOMPurify[ \t]*([,)}:?=]|$)/) return 0
            break
        }
    }
    return 1
}
function scoped_before(n,col,    j,s,d) {
    s=substr(clean[n],1,col-1)
    for(j=n-1;j>=1;j--) {
        if(bare[j] ~ /(^|[;{} \t])(def|function|func)[ \t]/) break
        s=clean[j] "\n" s
        if(bare[j] ~ /^[ \t]*}/) break
    }
    return s
}
function function_header(n,    j) {
    for(j=n;j>=1;j--) {
        if(bare[j] ~ /(^|[;{} \t])(def|function|func)[ \t]/) return bare[j]
        if(j<n && bare[j] ~ /^[ \t]*}/) break
    }
    return ""
}
function verdict(n,col,    s,b,a,v,p,prior,obj,re,j,tail,scope,safe_pos,use_pos,stmt,code,decl_indent) {
    # Custom pattern records keep their declared regex/context semantics.
    if(check !~ /^SAST-(CRY|GO|INJ|JAVA|JS|LDAP|NOSQL|PY)-/) return "keep"
    s=clean[n]; b=bare[n]; prior=scoped_before(n,col)
    if(trim(substr(s,col,1))=="" && trim(substr(raw[n],col,1))!="") return "drop"
    # Non-code prose is outside the non-secret executable-sink catalog.
    if(path ~ /[.](md|rst|txt)$/) return "drop"
    if(b ~ /^[ \t]*(def|function)[ \t]/ && index(b,"(") >= col) return "drop"
    a=call(n,col); v=first(a)
    if(check ~ /SSTI|EVAL|OS_COMMAND|OS_SYSTEM|SUBPROCESS_SHELL|DOCUMENT_WRITE|DYNAMIC_REQUIRE|SPEL_INJECTION|OGNL_INJECTION|JDBC_SQL_CONCAT/) {
        if(constant(v,n,col)) return "drop"
        if(check ~ /EVAL/ && v ~ /^compile[ \t]*\(/ && a !~ /request[.]|req[.]/) return "review"
    }
    if(check ~ /SQL_CONCAT|FILTER_CONCAT|DN_CONCAT|QUERY_CONCAT|WHERE_JS/) {
        # Replace only constant operands. The full RHS is inspected: the
        # candidate token often stops at '+' before the unsafe operand.
        tail=substr(s,col)
        # LDAP filter regex begins inside the first quoted operand.
        if(check ~ /FILTER_CONCAT/ && col>1 && substr(s,col-1,1) ~ /["\047]/) tail=substr(s,col-1)
        sub(/[;\n].*$/,"",tail)
        if(check ~ /QUERY_CONCAT/) tail=first(a)
        else if(match(tail,/["\047]/)) {
            tail=substr(tail,RSTART)
            # End at unmatched call closure (quoted ')' remains data).
            if(literal(tail)) return "drop"
        }
        if(literal(tail)) return "drop"
    }
    if(check ~ /PICKLE_LOAD/ && v ~ /^b["\047]N[.]["\047]$/) return "drop"
    if(check ~ /YAML_UNSAFE_LOAD/) {
        if(a ~ /(^|,)[ \t\n]*Loader[ \t]*=[ \t]*(yaml[.])?(SafeLoader|CSafeLoader|BaseLoader)([ \t\n,]|$)/) return "drop"
    }
    if(check ~ /DANGEROUSLY_SET_INNER_HTML/) {
        tail=substr(s,col)
        for(j=n+1;j<=lines && tail !~ /__html[ \t]*:/;j++) tail=tail " " clean[j]
        sub(/^.*__html[ \t]*:[ \t]*/,"",tail); sub(/[}].*$/,"",tail)
        if(safe_markup(trim(tail),n,col)) return "drop"
    }
    if(check ~ /TEMPLATE_LITERAL_SQL/) {
        # A tag is a function call, not JavaScript interpolation. Without an
        # import/type proof it is a review of tag semantics, not proven SQLi.
        if(substr(b,1,col-1) ~ /[A-Za-z_$][A-Za-z0-9_$]*[ \t]*$/) return "review"
    }
    if(check ~ /PROTO_ASSIGN/) {
        obj=substr(b,1,col-1); sub(/^.*[;{} \t]/,"",obj)
        if(binding(obj,n,col) ~ /^Object[.]create[ \t]*\([ \t]*null[ \t]*\)$/ && prior !~ /(Object|Reflect)[.]setPrototypeOf/) return "drop"
    }
    if(check ~ /UNSAFE_MERGE/) {
        # Guard must be a continue in the enclosing loop, before this write;
        # no arbitrary neighboring mention of a protected key can suppress it.
        if(prior ~ /for[ \t]*\([ \t]*const[ \t]+key[ \t]+in[ \t]/ &&
           prior ~ /if[ \t]*\([ \t]*key[ \t]*===[ \t]*["\047]__proto__["\047][ \t]*\|\|[ \t]*key[ \t]*===[ \t]*["\047]constructor["\047][ \t]*\|\|[ \t]*key[ \t]*===[ \t]*["\047]prototype["\047][ \t]*\)[ \t]*continue[ \t]*;/) return "drop"
    }
    if(check ~ /MASS_ASSIGNMENT|OPERATOR_INJECTION|UNESCAPED_FILTER_INPUT/) {
        obj=(check ~ /UNESCAPED_FILTER_INPUT/ ? "request.args" : trim(v))
        sub(/^\*\*/,"",obj)
        if(obj ~ /^request[.](args|form|json)(\[.*\])?$/) {
            sub(/\[.*$/,"",obj)
            if(literal(binding(obj,n,col))) return "drop"
            # An explicitly constructed mapping with scalar get() projections
            # cannot add attacker-selected model fields.
            tail=binding(obj,n,col)
            if(check ~ /MASS_ASSIGNMENT/ && tail ~ /^[{]["\047][^"\047]+["\047]:[ \t]*[A-Za-z_]+[.]get\(["\047][^"\047]+["\047],[ \t]*["\047]["\047]\)[}]$/) return "drop"
        }
    }
    if(check ~ /SERVER_JS/ && v ~ /^function[ \t]*\(/) return "drop"
    if(check ~ /OPEN_REDIRECT/ && v ~ /^request[.](path|url|full_path)$/) return "drop"
    if(check ~ /HOST_HEADER_TRUST/) {
        if(s ~ /(logger|logging)[.]/ || s ~ /["\047]HTTP_HOST["\047][ \t]*:/) return "drop"
        if(s !~ /(https?:|redirect|[Uu][Rr][Ll]|[Ll]ink|[Rr]eset)/) return "review"
    }
    if(check ~ /CRLF_HEADER/ && a ~ /req[.]id[ \t]*$/) return "review"
    if(check ~ /FLASK_DEBUG/) {
        if(a ~ /host[ \t]*=[ \t]*["\047](127[.]0[.]0[.]1|localhost|::1)["\047]/) return "drop"
        if(a !~ /host[ \t]*=[ \t]*["\047](0[.]0[.]0[.]0|::)["\047]/) return "review"
    }
    if(check ~ /TLS_VERIFY_DISABLED/ && b ~ /^[ \t]*verify[ \t]*=[ \t]*False/ && b !~ /[(]/) return "review"
    if(check ~ /TLS_VERIFY_DISABLED|TLS_SKIP_VERIFY/ && path ~ /_test[.]go$/) return "review"
    if(check ~ /WEAK_HASH/) {
        if(b !~ /[Pp]assword|[Ss]ecret|[Aa]uth|[Ss]ign|[Tt]oken/) return "review"
    }
    if(check ~ /HARDCODED_IV/) {
        tail=substr(s,1,col-1); sub(/^.*[^A-Za-z0-9_]/,"",tail)
        if(tail!="") {
            obj=tail substr(s,col,2);p=0
            for(j=1;j<=lines;j++) if(j!=n && bare[j] ~ ("(^|[^A-Za-z0-9_])" obj "([^A-Za-z0-9_]|$)")) p=1
            if(!p) return "review" # unused/public constant, security use unproven
        }
    }
    if(check ~ /WEAK_RANDOM_TOKEN/ && (b " " function_header(n)) !~ /[Tt]oken|[Ss]ession|[Pp]assword|[Ss]ecret|[Aa]uth/) return "drop"
    if(check ~ /GO-EXEC_CONCAT/) {
        if(constant(first(a),n,col) && a !~ /^[ \t]*["\047](sh|bash|zsh|ash|cmd|powershell|python[0-9.]*|node|perl|ruby)["\047][ \t]*,/) return "drop"
    }
    if(check ~ /GO-TEMPLATE_HTML/) {
        tail=""; for(j=1;j<=lines;j++) tail=tail " " bare[j]
        if(tail !~ /ResponseWriter/ || tail !~ /[.]Execute(Template)?[ \t]*\(/) return "drop"
    }
    if(check ~ /GO-WEAK_RANDOM/) {
        tail=""; for(j=1;j<=lines;j++) if(bare[j] ~ /rand[.]/ && (bare[j] " " function_header(j)) ~ /[Tt]oken|[Ss]ession|[Pp]assword|[Ss]ecret|[Aa]uth/) tail=bare[j]
        if(tail=="") return "drop"
    }
    if(check ~ /JINJA_AUTOESCAPE_FALSE/) {
        # Lack of an HTML consumer is not proof of XSS. Keep a policy review
        # when no local from_string/render response can be established.
        obj=substr(b,1,col-1);sub(/[ \t]*=[^=]*$/,"",obj);sub(/^.*[^A-Za-z0-9_]/,"",obj)
        if(obj=="") return "review"
        for(j=n;j<=lines;j++) {
            code=bare[j];if(j==n) code=substr(code,col)
            if(j>n && code ~ /(^|[;{} \t])(def|function|func)[ \t]/) break
            if(code ~ (obj "[.]from_string[ \t]*\\(")) return "keep"
            if(code ~ (obj "[ \t]*=[^=]")) break
        }
        return "review"
    }
    if(check ~ /JAVA-XXE_DISALLOW_DOCTYPE/) {
        obj=substr(b,1,col-1); sub(/[ \t]*=[ \t]*$/,"",obj); sub(/^.*[^A-Za-z0-9_]/,"",obj)
        if(obj!="") {
            decl_indent=match(b,/[^ \t]/)-1
            for(j=n;j<=lines;j++) {
                stmt=clean[j];code=bare[j]
                if(j==n) {stmt=substr(stmt,col);code=substr(code,col)}
                if(j>n && code ~ /^[ \t]*}/ && match(code,/[^ \t]/)-1<=decl_indent) break
                safe_pos=match(stmt,obj "[.]setFeature\\([\"\047]http://apache.org/xml/features/disallow-doctype-decl[\"\047],[ \t]*true\\)")
                use_pos=match(code,obj "[.](newDocumentBuilder|newSAXParser|createXMLStreamReader|newTransformer)[ \t]*\\(")
                if(safe_pos && (!use_pos || safe_pos<use_pos)) return "drop"
                if(use_pos || code ~ (obj "[ \t]*=")) break
            }
        }
    }
    if(check ~ /UNSAFE_DESERIALIZATION/) {
        obj=substr(b,1,col-1);sub(/^.*[^A-Za-z0-9_]/,"",obj)
        if(binding(obj,n,col) ~ /^new[ \t]+ObjectInputStream[ \t]*\(new[ \t]+ByteArrayInputStream[ \t]*\(new[ \t]+byte[ \t]*\[[ \t]*0[ \t]*\]\)\)$/) return "drop"
    }
    return "keep"
}
BEGIN { python=(path ~ /[.]pyi?$/); if(limit=="") limit=200 }
FILENAME == ARGV[1] {
    raw[++lines]=$0; start[lines]=bytes; bytes+=length($0)+1
    lex($0,lines); next
}
{
    record=$0; n=$0+0; sub(/^[^:]*:/,"",$0); off=$0+0
    # One overflow sentinel reaches the caller; do not classify an unbounded
    # stream before the configured raw-match cap can take effect.
    if(++candidates>limit) {print "keep:" record;exit}
    col=off-start[n]+1
    result=verdict(n,col)
    print result ":" record
}
