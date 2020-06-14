package burp

class HuntData {
    private val insecureDirectObjectReference =
        HuntDetail(
            name = "Insecure Direct Object Reference",
            shortName = "IDOR",
            params = mutableSetOf(
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
            ),
            checkLocation = HuntLocation.REQUEST,
            enabled = true,
            detail = """
                    HUNT located the <b>%PARAM%</b> parameter on %URL% inside of your application traffic.
                    The %PARAM% parameter is most often susceptible to Insecure Direct Object Reference Vulnerabilities.
                    Direct object reference vulnerabilities occur when there are insufficient authorization checks performed against object identifiers used in requests.  
                    This could occur when database keys, filenames, or other identifiers are used to directly access resources within an application. 
                    These identifiers would likely be predictable (an incrementing counter, the name of a file, etc), making it easy for an attacker to detect this vulnerability class. 
                    If further authorization checks are not performed, this could lead to unauthorized access to the underlying data.
                    HUNT recommends further manual analysis of the parameter in question.
                    For Insecure Direct Object Reference Vulnerabilities HUNT recommends the following resources to aid in manual testing:
                    - The Web Application Hacker's Handbook: Chapter 8
                    - Testing for Insecure Direct Object References (OTG-AUTHZ-004): https://www.owasp.org/index.php/Testing_for_Insecure_Direct_Object_References_(OTG-AUTHZ-004)
                    - Using Burp to Test for Insecure Direct Object References: https://support.portswigger.net/customer/portal/articles/1965691-using-burp-to-test-for-insecure-direct-object-references
                    - IDOR Examples from ngalongc/bug-bounty-reference: https://github.com/ngalongc/bug-bounty-reference#insecure-direct-object-reference-idor
                """.trimIndent(),
            level = "Information"
        )

    private val osCommandInjection = HuntDetail(
        name = "OS Command Injection",
        shortName = "OSCI",
        params = mutableSetOf(
            "cli",
            "cmd",
            "daemon",
            "dir",
            "download",
            "execute",
            "ip",
            "log",
            "upload"
        ),
        checkLocation = HuntLocation.REQUEST,
        enabled = true,
        detail = """
                HUNT located the %PARAM% parameter on %URL% inside of your application traffic.
                The %PARAM% parameter is most often susceptible to OS Command Injection.
                HUNT recommends further manual analysis of the parameter in question.
                For OS Command Injection HUNT recommends the following resources to aid in manual testing:
                - OWASP Testing for OS Command Injection: https://www.owasp.org/index.php/Testing_for_Command_Injection_(OTG-INPVAL-013)
                - Jobert's How To Command Injection: https://www.hackerone.com/blog/how-to-command-injections
                - Commix Command Injection Tool: https://github.com/commixproject/commix
                - The FuzzDB OS CMD Exec section: https://github.com/fuzzdb-project/fuzzdb/tree/master/attack/os-cmd-execution
                - Ferruh Mavituna's CMDi Cheat Sheet: https://ferruh.mavituna.com/unix-command-injection-cheat-sheet-oku/
                - The Web Application Hacker's Handbook: Chapter 10
            """.trimIndent(),
        level = "Information"
    )

    private val fileInclusionPathTraversal = HuntDetail(
        name = "File Inclusion and Path Traversal",
        shortName = "FI/PT",
        params = mutableSetOf(
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
        ), checkLocation = HuntLocation.REQUEST,
        enabled = true,
        detail = """
            HUNT located the %PARAM% parameter on %URL% inside of your application traffic.
            The %PARAM% parameter is most often susceptible to File Inclusion or Path Traversal.
            HUNT recommends further manual analysis of the parameter in question. 
            Also note that several parameters from this section and SSRF might overlap or need testing for both vulnerability categories.
            For File Inclusion or Path Traversal HUNT recommends the following resources to aid in manual testing:
            - The Web Application Hacker's Handbook: Chapter 10
            - Arr0way LFI Cheat Sheet: https://highon.coffee/blog/lfi-cheat-sheet/
            - Graceful's Path Traversal Cheat Sheet: Windows: https://www.gracefulsecurity.com/path-traversal-cheat-sheet-windows/
            - Graceful's Path Traversal Cheat Sheet: Linux: https://www.gracefulsecurity.com/path-traversal-cheat-sheet-linux
        """.trimIndent(),
        level = "Information"
    )

    private val sqlInjection = HuntDetail(
        name = "SQL Injection",
        shortName = "SQLI",
        params = mutableSetOf(
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
        ), checkLocation = HuntLocation.REQUEST,
        enabled = true,
        detail = """
            HUNT located the %PARAM% parameter on %URL% inside of your application traffic.
            The %PARAM%  parameter is most often susceptible to SQL Injection. 
            HUNT recommends further manual analysis of the parameter in question.
            For SQL Injection HUNT references The Bug Hunters Methodology SQL Injection references table:
            - PentestMonkey's MySQL Injection Cheat Sheet: http://pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet
            - Reiner's MySQL Injection Filter Evasion: https://websec.wordpress.com/2010/12/04/sqli-filter-evasion-cheat-sheet-mysql
            - EvilSQL's Error/Union/Blind MSSQL Cheat Sheet: http://evilsql.com/main/page2.php
            - PentestMonkey's MSSQL SQL Injection Cheat Sheet: http://pentestmonkey.net/cheat-sheet/sql-injection/mssql-sql-injection-cheat-sheet
            - PentestMonkey's Oracle SQL Cheat Sheet: http://pentestmonkey.net/cheat-sheet/sql-injection/oracle-sql-injection-cheat-sheet
            - PentestMonkey's PostgreSQL Cheat Sheet: http://pentestmonkey.net/cheat-sheet/sql-injection/postgres-sql-injection-cheat-sheet
            - Access SQL Injection Cheat Sheet: http://nibblesec.org/files/MSAccessSQLi/MSAccessSQLi.html
            - PentestMonkey's Ingres SQL Injection Cheat Sheet: http://pentestmonkey.net/cheat-sheet/sql-injection/ingres-sql-injection-cheat-sheet
            - PentestMonkey's DB2 SQL Injection Cheat Sheet: http://pentestmonkey.net/cheat-sheet/sql-injection/db2-sql-injection-cheat-sheet
            - PentestMonkey's Informix SQL Injection Cheat Sheet: http://pentestmonkey.net/cheat-sheet/sql-injection/informix-sql-injection-cheat-sheet
            - SQLite3 Injection Cheat Sheet: https://sites.google.com/site/0x7674/home/sqlite3injectioncheatsheet'></a><br>
            - Ruby on Rails (ActiveRecord) SQL Injection Guide: https://sites.google.com/site/0x7674/home/sqlite3injectioncheatsheet
        """.trimIndent(),
        level = "Information"
    )

    private val serverSideRequestForgery = HuntDetail(
        name = "Server Side Request Forgery",
        shortName = "SSRF",
        params = mutableSetOf(
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
        ), checkLocation = HuntLocation.REQUEST,
        enabled = true,
        detail = """
            HUNT located the %PARAM% parameter on %URL% inside of your application traffic.
            The %PARAM% parameter is most often susceptible to Server Side Request Forgery (and sometimes URL redirects).
            HUNT recommends further manual analysis of the parameter in question.
            For Server Side Request Forgery HUNT recommends the following resources to aid in manual testing:
            - Server-side browsing considered harmful - Nicolas Grégoire: http://www.agarri.fr/docs/AppSecEU15-Server_side_browsing_considered_harmful.pdf
            - How To: Server-Side Request Forgery (SSRF) - Jobert Abma: https://www.hackerone.com/blog-How-To-Server-Side-Request-Forgery-SSRF
            - SSRF Examples from ngalongc/bug-bounty-reference: https://github.com/ngalongc/bug-bounty-reference#server-side-request-forgery-ssrf
            - safebuff SSRF Tips: http://blog.safebuff.com/2016/07/03/SSRF-Tips/
            - The SSRF Bible: https://docs.google.com/document/d/1v1TkWZtrhzRLy0bYXBcdLUedXGb9njTNIJXa3u9akHM/edit
        """.trimIndent(),
        level = "Information"
    )


    private val serverSideTemplateInjection = HuntDetail(
        name = "Server Side Template Injection",
        shortName = "SSTI",
        params = mutableSetOf(
            "activity",
            "content",
            "id",
            "name",
            "preview",
            "redirect",
            "template",
            "view"
        ), checkLocation = HuntLocation.REQUEST,
        enabled = true,
        detail = """
            HUNT located the %PARAM% parameter on %URL% inside of your application traffic.
            The %PARAM% parameter is most often susceptible to Server Side Template Injection.
            HUNT recommends further manual analysis of the parameter in question.
        """.trimIndent(),
        level = "Information"
    )

    private val debugLogicParameters = HuntDetail(
        name = "Debug and Logic Parameters",
        shortName = "DLP",
        params = mutableSetOf(
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
        ), checkLocation = HuntLocation.REQUEST,
        enabled = true,
        detail = """
            HUNT located the %PARAM% parameter on %URL% inside of your application traffic.
            The parameter is most often associated to debug,  access, or critical functionality in applications.
            HUNT recommends further manual analysis of the parameter in question.
        """.trimIndent(),
        level = "Information"
    )

    private val issues =
        mutableListOf(
            insecureDirectObjectReference,
            osCommandInjection,
            fileInclusionPathTraversal,
            sqlInjection,
            serverSideRequestForgery,
            serverSideTemplateInjection,
            debugLogicParameters
        )

    val huntParams = issues.map { HuntParams(it.name, it.params) }
    val namesDetails = issues.map { it.shortName to it.detail }.toMap()
    val nameToShortName = issues.map { it.name to it.shortName }.toMap()
    val shortToName = issues.map { it.shortName to it.name }.toMap()


}

data class HuntDetail(
    val name: String,
    val shortName: String?,
    val params: Set<String>,
    val checkLocation: HuntLocation,
    var enabled: Boolean = true,
    val detail: String,
    val level: String
)

data class HuntParams(val name: String, val params: Set<String>)

enum class HuntLocation {
    REQUEST, RESPONSE, BOTH
}