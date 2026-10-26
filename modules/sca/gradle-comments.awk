# Owns: Gradle lexical comments, without executing Groovy/Kotlin.
# Keep quoted markers and live code on either side of a block comment.
{
    out = ""; quote = ""; escaped = 0
    for (i = 1; i <= length($0); i++) {
        c = substr($0, i, 1); pair = substr($0, i, 2); triple = substr($0, i, 3)
        if (multiquote != "") {
            if (triple == multiquote) { multiquote = ""; i += 2 }
            continue
        }
        if (block) { if (pair == "*/") { block = 0; i++ }; continue }
        if (quote != "") {
            out = out c
            if (escaped) escaped = 0
            else if (c == "\\") escaped = 1
            else if (c == quote) quote = ""
        } else if (pair == "//") break
        else if (pair == "/*") { block = 1; i++; out = out " " }
        else if (triple == "\"\"\"" || triple == "\047\047\047") { multiquote = triple; i += 2 }
        else { out = out c; if (c == "\"" || c == "\047") quote = c }
    }
    print out
}
