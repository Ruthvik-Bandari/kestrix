# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Phase 4: Go, Java, Kotlin, C# and Ruby rules, the shared C-family tokenizer and the Ruby tokenizer. A positive and
a negative case for every rule, request sources, propagation and sanitizers, suppression, and pathological inputs."""

import textwrap
import time
from pathlib import Path

import pytest

from kestrix_scan import c_tokens, ruby_tokens
from kestrix_scan.analyze import scan_text
from kestrix_scan.registry import RULES, Hit
from kestrix_scan.server_rules import SERVER_SUFFIXES, check_server
from kestrix_scan.walk import Candidate

P4_LANGUAGES = ("go", "java", "csharp", "ruby")


def hits(body: str, rel: str) -> list[Hit]:
    result = check_server(textwrap.dedent(body), rel)
    assert isinstance(result, list), result
    return result


def found(body: str, rel: str) -> dict[str, list[Hit]]:
    out: dict[str, list[Hit]] = {}
    for item in hits(body, rel):
        out.setdefault(item.rule_id, []).append(item)
    return out


def ids(body: str, rel: str) -> set[str]:
    return set(found(body, rel))


# ----- C-family tokenizer


def toks(source: str, language: str) -> list[tuple[str, str, tuple[str, ...]]]:
    tokens = c_tokens.tokenize(source, language)
    assert tokens is not None
    return [(t.kind, t.value, t.vars) for t in tokens]


def test_go_raw_strings_runes_and_comments() -> None:
    assert toks("x := `a\n\"b\"` // c\n/* d */ r := 'x'", "go") == [
        ("name", "x", ()),
        ("punct", ":=", ()),
        ("str", 'a\n"b"', ()),
        ("name", "r", ()),
        ("punct", ":=", ()),
        ("str", "x", ()),
    ]


def test_java_text_blocks_and_generics_close_one_bracket_at_a_time() -> None:
    assert toks('String s = """\n  a "q" b\n  """;', "java")[3] == ("str", '\n  a "q" b\n  ', ())
    values = [v for _, v, _ in toks("List<List<String>> x;", "java")]
    assert values == ["List", "<", "List", "<", "String", ">", ">", "x", ";"]


def test_kotlin_templates_record_the_names_they_start_with() -> None:
    kind, body, names = toks('val s = "a $id and ${req.getParameter("q")} \\$not"', "kotlin")[3]
    assert kind == "istr" and names == ("id", "req") and "$not" in body
    assert toks('val t = "${1 + 2}"', "kotlin")[3][0] == "str"  # no name: a constant
    assert toks("/* a /* nested */ still */ val x = 1", "kotlin")[0] == ("name", "val", ())


def test_csharp_interpolated_verbatim_and_raw_strings() -> None:
    assert toks('$"id = {Request.Query["id"]} {{x}}"', "csharp") == [
        ("istr", 'id = {Request.Query["id"]} {{x}}', ("Request",))
    ]
    assert toks('@"C:\\dir ""q"""', "csharp") == [("str", 'C:\\dir ""q""', ())]
    assert toks('$@"{a}\\{b}"', "csharp")[0][2] == ("a", "b")
    assert toks('$"{value:N2} {width,10}"', "csharp")[0][2] == ("value", "width")
    assert toks("var @class = 1;", "csharp")[1] == ("name", "class", ())


def test_c_tokenizer_never_raises_on_unterminated_input() -> None:
    for language in c_tokens.LANGUAGES:
        for source in ('"abc', "/* x", "`raw", "'c", '$"{a', '"""x', '@"x', "${"):
            assert c_tokens.tokenize(source, language) is not None


def test_c_tokenizer_bounds() -> None:
    assert c_tokens.tokenize("(" * (c_tokens.MAX_NESTING + 2), "java") is None
    assert c_tokens.tokenize("x " * (c_tokens.MAX_TOKENS + 2), "go") is None
    assert c_tokens.tokenize("x" * (c_tokens.MAX_CHARS + 1), "csharp") is None


# ----- Ruby tokenizer


def rtoks(source: str) -> list[tuple[str, str, tuple[str, ...]]]:
    tokens = ruby_tokens.tokenize(source)
    assert tokens is not None
    return [(t.kind, t.value, t.vars) for t in tokens]


def test_ruby_interpolation_symbols_and_comments() -> None:
    out = rtoks("User.where(\"id = #{params[:id]}\", key: :val) # note\n'#{x}'")
    assert ("istr", "id = #{params[:id]}", ("params",)) in out
    assert ("str", "val", ()) in out and ("str", "#{x}", ()) in out
    assert all(value != "note" for _, value, _ in out)


def test_ruby_heredocs_skip_their_bodies_and_keep_the_line_going() -> None:
    out = rtoks("sql = <<~SQL, other\n  SELECT #{params[:a]}\nSQL\nnext_line")
    assert out[2] == ("istr", "  SELECT #{params[:a]}\n", ("params",))
    assert [v for _, v, _ in out[3:]] == [",", "other", "next_line"]
    assert rtoks("x = <<~'RAW'\n#{y}\nRAW\n")[2] == ("str", "#{y}\n", ())


def test_ruby_regex_division_percent_literals_and_backticks() -> None:
    assert rtoks("a = b / 2")[3] == ("punct", "/", ())
    assert rtoks("r = /a#{c}/i")[2] == ("istr", "a#{c}", ("c",))
    assert rtoks("x = %w[a b]")[2] == ("str", "a b", ())
    assert rtoks("x = %x(ls #{d})")[2] == ("shell", "ls #{d}", ("d",))
    assert rtoks("`cat #{f}`")[0] == ("shell", "cat #{f}", ("f",))
    assert rtoks("y = 10 % 3")[3] == ("punct", "%", ())


def test_ruby_embedded_docs_end_marker_and_names() -> None:
    assert rtoks("=begin\nx = 1\n=end\ny") == [("name", "y", ())]
    assert rtoks("a\n__END__\nb = 1") == [("name", "a", ())]
    assert [v for _, v, _ in rtoks("@a ||= @@b.empty? && $c")] == ["@a", "||=", "@@b", ".", "empty?", "&&", "$c"]


def test_ruby_tokenizer_never_raises_and_is_bounded() -> None:
    for source in ('"abc #{', "%w[", "<<~A\nno end", "`x", "/re", "=begin", ':"x', "?", "\\"):
        assert ruby_tokens.tokenize(source) is not None
    assert ruby_tokens.tokenize("(" * (ruby_tokens.MAX_NESTING + 2)) is None
    assert ruby_tokens.tokenize("x = <<~A\nA\n" * (ruby_tokens.MAX_HEREDOCS + 2)) is None


# ----- pathological inputs


def _wrap(text: str, width: int = 60) -> str:
    return "\n".join(text[i : i + width] for i in range(0, len(text), width))


@pytest.mark.parametrize(
    ("rel", "source"),
    [
        ("a.kt", _wrap('"' * 200_000)),
        ("a.cs", _wrap('$"{' * 50_000)),
        ("a.kt", _wrap('"${' * 50_000)),
        ("a.go", _wrap("\\" * 200_000)),
        ("a.kt", _wrap("/*" * 100_000)),
        ("a.rb", _wrap('"#{' * 60_000)),
        ("a.rb", _wrap("x = %w[" * 30_000)),
        ("a.rb", "<<~A\n" * 1_500),
        ("a.cs", "class A {\n" + "{\n" * 400 + "}\n" * 400 + "}\n"),
    ],
)
def test_pathological_inputs_are_bounded_and_fast(rel: str, source: str) -> None:
    start = time.perf_counter()
    result = check_server(source, rel)
    assert time.perf_counter() - start < 5
    assert isinstance(result, (list, str))


@pytest.mark.parametrize(
    ("rel", "line"),
    [
        ("a.java", "String a{i} = a{j} + a{j};\n"),
        ("a.rb", "a{i} = a{j} + params[:x]\n"),
        ("a.go", "a{i} := a{j} + a{j}\n"),
    ],
)
def test_long_assignment_chains_stay_bounded(rel: str, line: str) -> None:
    body = "".join(line.format(i=i, j=i - 1) for i in range(1, 20_000))
    source = {"a.java": "class A { void f() {\n" + body + "}}", "a.rb": "def f\n" + body + "end\n"}.get(
        rel, "func f() {\n" + body + "}\n"
    )
    start = time.perf_counter()
    result = check_server(source, rel)
    assert time.perf_counter() - start < 10
    assert result == "too_complex" or isinstance(result, list)


def test_minified_and_oversized_files_are_skipped() -> None:
    assert check_server("x" * 2_000, "a.go") == "minified"
    assert check_server("(\n" * (c_tokens.MAX_NESTING + 2), "a.java") == "too_complex"


# ----- Go

GO_HANDLER = """
package main

func handler(w http.ResponseWriter, r *http.Request, db *sql.DB) {{
{body}
}}
"""


def go(body: str) -> set[str]:
    return ids(GO_HANDLER.format(body=textwrap.indent(textwrap.dedent(body), "\t")), "main.go")


def test_go_exec_command() -> None:
    assert "go.exec.command" in go('exec.Command("sh", "-c", "echo "+r.FormValue("x")).Run()')
    assert "go.exec.command" in go('name := r.URL.Query().Get("n")\ncmd := exec.CommandContext(ctx, "git", name)')
    assert "go.exec.command" not in go('exec.Command("ls", "-l").Run()')
    assert "go.exec.command" not in go('n, _ := strconv.Atoi(r.FormValue("n"))\nexec.Command("seq", n)')


def test_go_sql_injection() -> None:
    assert "go.sql.injection" in go('db.Query("SELECT * FROM t WHERE a = \'" + r.FormValue("a") + "\'")')
    assert "go.sql.injection" in go('q := fmt.Sprintf("DELETE FROM t WHERE id = %s", mux.Vars(r)["id"])\ndb.Exec(q)')
    assert "go.sql.injection" in go('db.Where("name = " + r.FormValue("n")).First(&u)')
    hit = found(GO_HANDLER.format(body='\tid := lookup()\n\tdb.Query("SELECT * FROM t WHERE id = " + id)'), "a.go")
    assert hit["go.sql.injection"][0].severity == "medium"
    assert "go.sql.injection" not in go('db.Query("SELECT * FROM t WHERE a = ?", r.FormValue("a"))')
    assert "go.sql.injection" not in go('db.Query("SELECT * FROM " + tableName + " WHERE x = 1")')
    assert "go.sql.injection" not in go('tmpl.Exec(r.FormValue("a"))')


def test_go_xss_unescaped() -> None:
    assert "go.xss.unescaped" in go('t := template.HTML(r.FormValue("bio"))')
    assert "go.xss.unescaped" in go('fmt.Fprintf(w, "<p>%s</p>", r.URL.Query().Get("q"))')
    assert "go.xss.unescaped" in go('w.Write([]byte(r.FormValue("q")))')
    low = found(GO_HANDLER.format(body="\tt := template.HTML(user.Bio)"), "a.go")["go.xss.unescaped"][0]
    assert (low.severity, low.confidence) == ("low", "low")
    assert "go.xss.unescaped" not in go('t := template.HTML("<b>fixed</b>")')
    assert "go.xss.unescaped" not in go('fmt.Fprintf(w, "%s", html.EscapeString(r.FormValue("q")))')
    assert "go.xss.unescaped" not in go('fmt.Fprintf(os.Stdout, "%s", r.FormValue("q"))')


def test_go_insecure_skip_verify() -> None:
    assert "go.tls.insecure_skip_verify" in go("cfg := &tls.Config{InsecureSkipVerify: true}")
    assert "go.tls.insecure_skip_verify" in go("cfg.InsecureSkipVerify = true")
    assert "go.tls.insecure_skip_verify" not in go("cfg := &tls.Config{InsecureSkipVerify: false}")
    assert "go.tls.insecure_skip_verify" not in go("cfg := &tls.Config{InsecureSkipVerify: insecure}")


def test_go_path_traversal() -> None:
    assert "go.path.traversal" in go('f, _ := os.Open(filepath.Join("/data", r.FormValue("f")))')
    assert "go.path.traversal" in go('http.ServeFile(w, r, "static/"+r.URL.Path)')
    assert "go.path.traversal" in go("for _, entry := range zr.File {\n\tos.Create(filepath.Join(dst, entry.Name))\n}")
    assert "go.path.traversal" not in go('os.Open(filepath.Join("/data", filepath.Base(r.FormValue("f"))))')
    assert "go.path.traversal" not in go('os.Open("/etc/app.conf")')


def test_go_ssrf_request() -> None:
    assert "go.ssrf.request" in go('http.Get(r.FormValue("url"))')
    assert "go.ssrf.request" in go('req, _ := http.NewRequest("GET", r.Header.Get("X-Target"), nil)')
    assert "go.ssrf.request" not in go('http.Get("https://example.com/health")')


def test_go_frameworks_and_closures() -> None:
    gin = 'func h(c *gin.Context) {\n\tdb.Query("SELECT * FROM t WHERE a = " + c.Query("a"))\n}\n'
    assert "go.sql.injection" in ids(gin, "a.go")
    closure = 'func h(r *http.Request) {\n\tq := r.FormValue("q")\n\tgo func() {\n\t\texec.Command(q).Run()\n\t}()\n}\n'
    assert "go.exec.command" in ids(closure, "a.go")
    other = 'func a(r *http.Request) {\n\tq := r.FormValue("q")\n}\nfunc b() {\n\texec.Command(q).Run()\n}\n'
    assert "go.exec.command" not in ids(other, "a.go")
    assert "go.exec.command" not in ids("func h(ctx context.Context, q string) {\n\texec.Command(q).Run()\n}\n", "a.go")


# ----- Java and Kotlin

JAVA_CLASS = """
class C {{
    {annotations}
    public String handle({params}) throws Exception {{
{body}
        return "ok";
    }}
}}
"""


def java(body: str, params: str = "HttpServletRequest request, Connection c", annotations: str = "") -> set[str]:
    source = JAVA_CLASS.format(
        annotations=annotations, params=params, body=textwrap.indent(textwrap.dedent(body), " " * 8)
    )
    return ids(source, "C.java")


def test_java_sql_injection() -> None:
    assert "java.sql.injection" in java(
        'c.createStatement().executeQuery("SELECT * FROM t WHERE a = " + request.getParameter("a"));'
    )
    assert "java.sql.injection" in java(
        'StringBuilder sb = new StringBuilder("SELECT * FROM t WHERE a = ");\nsb.append(id);\nc.prepareStatement(sb.toString());',
        params='@RequestParam("id") String id, Connection c',
    )
    assert "java.sql.injection" in java(
        "jdbc.query(String.format(\"SELECT * FROM t WHERE n = '%s'\", name), mapper);",
        params="String name, JdbcTemplate jdbc",
        annotations='@GetMapping("/x")',
    )
    built = found(
        JAVA_CLASS.format(
            annotations="",
            params="Connection c",
            body='String q = "SELECT a FROM b WHERE c = " + compute();\nc.createStatement().execute(q);',
        ),
        "C.java",
    )
    assert built["java.sql.injection"][0].severity == "medium"
    assert "java.sql.injection" not in java('PreparedStatement ps = c.prepareStatement("SELECT * FROM t WHERE a = ?");')
    assert "java.sql.injection" not in java(
        'c.createStatement().executeQuery("SELECT * FROM " + TABLE_NAME + " WHERE x = 1");'
    )
    assert "java.sql.injection" not in java(
        'c.createStatement().executeQuery("SELECT * FROM t WHERE id = " + id);',
        params="@RequestParam int id, Connection c",
    )


def test_java_exec_command() -> None:
    assert "java.exec.command" in java('Runtime.getRuntime().exec("ping " + request.getParameter("host"));')
    assert "java.exec.command" in java('new ProcessBuilder("git", "clone", request.getParameter("repo")).start();')
    assert "java.exec.command" not in java('Runtime.getRuntime().exec(new String[] {"ls", "-l"});')


def test_java_deserialize_unsafe() -> None:
    assert "java.deserialize.unsafe" in java("ObjectInputStream in = new ObjectInputStream(request.getInputStream());")
    assert "java.deserialize.unsafe" in java("mapper.enableDefaultTyping();")
    assert "java.deserialize.unsafe" in java("Object o = new XStream().fromXML(body);")
    assert "java.deserialize.unsafe" in ids(
        "class A { @JsonTypeInfo(use = JsonTypeInfo.Id.CLASS) Object payload; }", "A.java"
    )
    assert "java.deserialize.unsafe" in java("Object o = new Yaml().load(text);")
    filtered = "ObjectInputStream in = new ObjectInputStream(s);\nin.setObjectInputFilter(filter);"
    assert "java.deserialize.unsafe" not in java(filtered)
    assert "java.deserialize.unsafe" not in java(
        "Object o = new Yaml(new SafeConstructor(new LoaderOptions())).load(t);"
    )
    assert "java.deserialize.unsafe" not in java(
        "XStream x = new XStream();\nx.allowTypes(new Class[] {A.class});\nx.fromXML(b);"
    )


def test_java_xxe_parser() -> None:
    assert "java.xxe.parser" in java("DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();")
    assert "java.xxe.parser" in java("SAXReader reader = new SAXReader();")
    hardened = 'DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();\nf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);'
    assert "java.xxe.parser" not in java(hardened)
    assert "java.xxe.parser" not in java(
        "XMLInputFactory f = XMLInputFactory.newInstance();\nf.setProperty(XMLInputFactory.SUPPORT_DTD, false);"
    )


def test_java_path_traversal() -> None:
    assert "java.path.traversal" in java('File f = new File("/uploads", request.getParameter("name"));')
    assert "java.path.traversal" in java('byte[] b = Files.readAllBytes(Paths.get(base, request.getParameter("f")));')
    assert "java.path.traversal" in java(
        "for (ZipEntry entry : entries) {\n    new FileOutputStream(new File(dir, entry.getName()));\n}"
    )
    assert "java.path.traversal" not in java(
        'File f = new File("/uploads", FilenameUtils.getName(request.getParameter("name")));'
    )
    assert "java.path.traversal" not in java('File f = new File("/etc/app.conf");')


def test_java_ssrf_request() -> None:
    assert "java.ssrf.request" in java('URL u = new URL(request.getParameter("url"));')
    assert "java.ssrf.request" in java(
        "rest.getForObject(url, String.class);", params="@QueryParameter String url, RestTemplate rest"
    )
    assert "java.ssrf.request" not in java('URL u = new URL("https://example.com/api");')


def test_java_xss_response() -> None:
    assert "java.xss.response" in java(
        'response.getWriter().println("<p>" + request.getParameter("q") + "</p>");',
        params="HttpServletRequest request, HttpServletResponse response",
    )
    assert "java.xss.response" not in java(
        'response.getWriter().println(Encode.forHtml(request.getParameter("q")));',
        params="HttpServletRequest request, HttpServletResponse response",
    )
    assert "java.xss.response" not in java('System.out.println(request.getParameter("q"));')


def test_kotlin_shares_the_java_rules() -> None:
    source = """
    fun Route.users(db: Connection) {
        get("/u") {
            val name = call.parameters["name"]
            db.createStatement().executeQuery("SELECT * FROM u WHERE n = '$name'")
            Runtime.getRuntime().exec("ls ${call.request.queryParameters["d"]}")
            val f = DocumentBuilderFactory.newInstance()
        }
    }
    fun safe(db: Connection) {
        db.prepareStatement("SELECT * FROM u WHERE n = ?")
    }
    """
    got = found(source, "Routes.kt")
    assert {h.line for h in got["java.sql.injection"]} == {5}
    assert set(got) == {"java.sql.injection", "java.exec.command", "java.xxe.parser"}
    spring = """
    @RestController
    class C(val jdbc: JdbcTemplate) {
        @GetMapping("/x")
        fun x(@RequestParam q: String): List<Any> = jdbc.queryForList("SELECT * FROM t WHERE q = '" + q + "'")
        fun y(@RequestParam q: String) {
            jdbc.queryForList("SELECT * FROM t WHERE q = '" + q + "'")
        }
    }
    """
    assert "java.sql.injection" in ids(spring, "C.kt")


# ----- C#

CS_CONTROLLER = """
public class UsersController : Controller {{
    [HttpGet]
    public IActionResult Find(string name, int id) {{
{body}
        return Ok();
    }}
}}
"""


def cs(body: str) -> set[str]:
    return ids(CS_CONTROLLER.format(body=textwrap.indent(textwrap.dedent(body), " " * 8)), "UsersController.cs")


def test_csharp_sql_injection() -> None:
    assert "cs.sql.injection" in cs(
        'var cmd = new SqlCommand("SELECT * FROM Users WHERE Name = \'" + name + "\'", conn);'
    )
    assert "cs.sql.injection" in cs('cmd.CommandText = $"DELETE FROM t WHERE x = \'{Request.Query["x"]}\'";')
    assert "cs.sql.injection" in cs("db.Database.ExecuteSqlRaw($\"UPDATE t SET a = '{name}'\");")
    assert "cs.sql.injection" in cs('conn.Query<User>("SELECT * FROM Users WHERE Name = \'" + name + "\'");')
    assert "cs.sql.injection" not in cs('var cmd = new SqlCommand("SELECT * FROM Users WHERE Id = @id", conn);')
    assert "cs.sql.injection" not in cs('var cmd = new SqlCommand($"SELECT * FROM Users WHERE Id = {id}", conn);')
    assert "cs.sql.injection" not in cs('db.Users.FromSqlInterpolated($"SELECT * FROM Users WHERE Name = {name}");')


def test_csharp_exec_process() -> None:
    assert "cs.exec.process" in cs('Process.Start("cmd.exe", "/c " + Request.Query["x"]);')
    assert "cs.exec.process" in cs('var psi = new ProcessStartInfo("git");\npsi.Arguments = "clone " + name;')
    assert "cs.exec.process" not in cs('Process.Start("notepad.exe");')


def test_csharp_deserialize_unsafe() -> None:
    assert "cs.deserialize.unsafe" in cs("var bf = new BinaryFormatter();")
    assert "cs.deserialize.unsafe" in cs(
        "var s = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.Auto };"
    )
    assert "cs.deserialize.unsafe" in cs("var js = new JavaScriptSerializer(new SimpleTypeResolver());")
    assert "cs.deserialize.unsafe" not in cs(
        "var s = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.None };"
    )
    bound = (
        "var s = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.Auto, SerializationBinder = binder };"
    )
    assert "cs.deserialize.unsafe" not in cs(bound)


def test_csharp_path_traversal() -> None:
    assert "cs.path.traversal" in cs("var text = File.ReadAllText(Path.Combine(root, name));")
    assert "cs.path.traversal" in cs(
        "foreach (var entry in archive.Entries) {\n    entry.ExtractToFile(Path.Combine(dest, entry.FullName));\n}"
    )
    assert "cs.path.traversal" not in cs("var text = File.ReadAllText(Path.Combine(root, Path.GetFileName(name)));")


def test_csharp_ssrf_request() -> None:
    assert "cs.ssrf.request" in cs('var body = await client.GetStringAsync(Request.Query["url"]);')
    assert "cs.ssrf.request" not in cs('var body = await client.GetStringAsync("https://example.com/");')


def test_csharp_sources_need_a_web_context() -> None:
    plain = 'class Repo {\n    public void Find(string name) {\n        var cmd = new SqlCommand("SELECT * FROM U WHERE N = \'" + name + "\'", conn);\n    }\n}\n'
    assert ids(plain, "Repo.cs") == set()
    bound = "class Api {\n    public void Find([FromQuery] string name) {\n        Process.Start(name);\n    }\n}\n"
    assert ids(bound, "Api.cs") == {"cs.exec.process"}


# ----- Ruby

RB_CONTROLLER = """
class UsersController < ApplicationController
  def index
{body}
  end
end
"""


def rb(body: str) -> set[str]:
    return ids(RB_CONTROLLER.format(body=textwrap.indent(textwrap.dedent(body), "    ")), "users_controller.rb")


def test_ruby_sql_injection() -> None:
    assert "rb.sql.injection" in rb("User.where(\"name = '#{params[:name]}'\")")
    assert "rb.sql.injection" in rb('User.find_by_sql("SELECT * FROM users WHERE id = #{params[:id]}")')
    assert "rb.sql.injection" in rb("User.order(params[:sort])")
    assert "rb.sql.injection" in rb(
        'sql = "SELECT * FROM t WHERE a = "\nsql << params[:a]\nActiveRecord::Base.connection.execute(sql)'
    )
    assert "rb.sql.injection" not in rb("User.where(name: params[:name])")
    assert "rb.sql.injection" not in rb('User.where("name = ?", params[:name])')
    assert "rb.sql.injection" not in rb("User.where(id: params[:id].to_i)")
    built = found(RB_CONTROLLER.format(body="    x = current_user.name\n    User.where(\"name = '#{x}'\")"), "a.rb")
    assert built["rb.sql.injection"][0].severity == "medium"


def test_ruby_xss_html_safe() -> None:
    assert "rb.xss.html_safe" in rb("@bio = params[:bio].html_safe")
    assert "rb.xss.html_safe" in rb("render html: raw(params[:q])")
    assert "rb.xss.html_safe" not in rb('@x = "<br>".html_safe')
    assert "rb.xss.html_safe" not in rb("@x = sanitize(params[:q])")


def test_erb_templates() -> None:
    got = found(
        '<p><%== params[:q] %></p>\n<p><%= raw @user.bio %></p>\n<p><%= @user.name %></p>\n<p><%= raw "<br>" %></p>\n<%= x.html_safe %>\n',
        "show.html.erb",
    )
    assert sorted(h.line for h in got["rb.xss.html_safe"]) == [1, 2, 5]
    assert got["rb.xss.html_safe"][0].confidence == "high"
    assert ids('<%= render "form" %>\n<%= t("title") %>\n', "a.html.erb") == set()


def test_ruby_reflection() -> None:
    assert "rb.reflection.constantize" in rb("klass = params[:type].constantize")
    assert "rb.reflection.constantize" in rb("Object.const_get(params[:kind])")
    assert "rb.reflection.constantize" not in rb('klass = "User".constantize')
    assert "rb.reflection.send" in rb("@user.send(params[:method])")
    assert "rb.reflection.send" in rb("@user.public_send(params[:attr], 1)")
    assert "rb.reflection.send" not in rb("@user.send(:name)")


def test_ruby_exec_command() -> None:
    assert "rb.exec.command" in rb('system("ls #{params[:dir]}")')
    assert "rb.exec.command" in rb("`cat #{params[:file]}`")
    assert "rb.exec.command" in rb('out, s = Open3.capture2("grep #{params[:q]} log")')
    assert "rb.exec.command" not in rb('system("ls", params[:dir])')
    assert "rb.exec.command" not in rb('system("ls -l")')


def test_ruby_path_traversal() -> None:
    assert "rb.path.traversal" in rb("send_file params[:path]")
    assert "rb.path.traversal" in rb('data = File.read(File.join(Rails.root, "files", params[:f]))')
    assert "rb.path.traversal" in rb("render file: params[:template]")
    assert "rb.path.traversal" not in rb('data = File.read(File.join(Rails.root, "files", File.basename(params[:f])))')


def test_ruby_methods_are_scopes_and_one_line_defs_close() -> None:
    source = 'class A\n  def a; x = params[:q]; end\n  def b\n    system("ls #{x}")\n  end\nend\n'
    assert ids(source, "a.rb") == set()
    blocks = (
        'def a\n  params[:ids].each do |id|\n    User.find_by_sql("SELECT * FROM u WHERE id = #{id}")\n  end\nend\n'
    )
    assert "rb.sql.injection" in ids(blocks, "a.rb")


# ----- integration


def test_traces_name_the_source_and_the_sink() -> None:
    (item,) = found(GO_HANDLER.format(body='\tq := r.FormValue("q")\n\texec.Command(q).Run()'), "a.go")[
        "go.exec.command"
    ]
    notes = [step.note for step in item.trace]
    assert notes[0].startswith("r.FormValue") and notes[-1] == "reaches exec.Command()"
    assert "assigned to q" in notes


@pytest.mark.parametrize(
    "name", ["main.go", "C.java", "Routes.kt", "build.gradle.kts", "Api.cs", "app.rb", "v.html.erb"]
)
def test_suffixes_are_routed_through_scan_text(name: str, tmp_path: Path) -> None:
    source = {
        ".go": "func f() {\n\tcfg := &tls.Config{InsecureSkipVerify: true}\n}\n",
        ".java": "class A { void f() { DocumentBuilderFactory f = DocumentBuilderFactory.newInstance(); } }\n",
        ".kt": "fun f() { val f = DocumentBuilderFactory.newInstance() }\n",
        ".kts": "val f = DocumentBuilderFactory.newInstance()\n",
        ".cs": "class A { void F() { var b = new BinaryFormatter(); } }\n",
        ".rb": 'def f\n  system("ls #{params[:d]}")\nend\n',
        ".erb": "<%== params[:q] %>\n",
    }[Path(name).suffix]
    findings, _, _, skip = scan_text(source, Candidate(path=tmp_path / name, rel=name))
    assert skip is None and findings, name
    assert all(f.rule_id in RULES for f in findings)


@pytest.mark.parametrize(
    ("name", "source"),
    [
        (
            "a.go",
            "func f() {\n\t// kestrix: ignore[go.tls.insecure_skip_verify] test server only\n\tc := &tls.Config{InsecureSkipVerify: true}\n}\n",
        ),
        (
            "a.rb",
            'def f\n  # kestrix: ignore[rb.exec.command] value is an allowlisted name\n  system("ls #{params[:d]}")\nend\n',
        ),
        ("a.erb", "<%# kestrix: ignore[rb.xss.html_safe] sanitized upstream %>\n<%== params[:q] %>\n"),
    ],
)
def test_suppression_comments(name: str, source: str, tmp_path: Path) -> None:
    findings, _, suppressed, _ = scan_text(source, Candidate(path=tmp_path / name, rel=name))
    assert findings == [] and suppressed == 1


def test_server_suffixes_cover_the_languages() -> None:
    assert set(SERVER_SUFFIXES.values()) == {"go", "java", "kotlin", "csharp", "ruby", "erb"}


@pytest.mark.parametrize("rule_id", [r.id for r in RULES.values() if r.language in P4_LANGUAGES])
def test_every_phase4_rule_has_docs(rule_id: str) -> None:
    rule = RULES[rule_id]
    assert rule.cwe.startswith("CWE-") and rule.fix and rule.why and rule.sources
    assert all(src.startswith("https://") for src in rule.sources)
