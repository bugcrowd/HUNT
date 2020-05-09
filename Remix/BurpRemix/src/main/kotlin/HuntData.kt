package burp

class HuntData {
    val insecureDirectObjectReference = mutableSetOf(
        "account",
        "doc",
        "edit",
        "email",
        "group",
        "id",
        "key",
        "no",
        "number",
        "order",
        "profile",
        "report",
        "user"
    )

    val osCommandInjection = mutableSetOf(
        "cli",
        "cmd",
        "daemon",
        "dir",
        "download",
        "execute",
        "ip",
        "log",
        "upload"
    )

    val fileInclusionPathTraversal = mutableSetOf(
        "doc",
        "document",
        "file",
        "folder",
        "path",
        "pdf",
        "pg",
        "php_path",
        "root",
        "style",
        "template"
    )

    val sqlInjection = mutableSetOf(
        "column",
        "delete",
        "fetch",
        "field",
        "filter",
        "from",
        "id",
        "keyword",
        "name",
        "number",
        "order",
        "params",
        "process",
        "query",
        "report",
        "results",
        "role",
        "row",
        "search",
        "sel",
        "select",
        "sleep",
        "sort",
        "string",
        "table",
        "update",
        "user",
        "view",
        "where"
    )

    val serverSideRequestForgery = mutableSetOf(
        "callback",
        "continue",
        "data",
        "dest",
        "dir",
        "domain",
        "feed",
        "host",
        "html",
        "navigation",
        "next",
        "open",
        "out",
        "page",
        "path",
        "port",
        "redirect",
        "reference",
        "return",
        "show",
        "site",
        "to",
        "uri",
        "url",
        "val",
        "validate",
        "view",
        "window"
    )


    val serverSideTemplateInjection = mutableSetOf(
        "activity",
        "content",
        "id",
        "name",
        "preview",
        "redirect",
        "template",
        "view"
    )

    val debugLogicParameters = mutableSetOf(
        "access",
        "adm",
        "admin",
        "alter",
        "cfg",
        "clone",
        "config",
        "create",
        "dbg",
        "debug",
        "delete",
        "disable",
        "edit",
        "enable",
        "exec",
        "execute",
        "grant",
        "load",
        "make",
        "modify",
        "rename",
        "reset",
        "root",
        "shell",
        "test",
        "toggle"
    )
}