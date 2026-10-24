# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Phase 2: PHP rules and the PHP tokenizer. A positive and a negative case for every rule, request sources, sanitizers,
suppression, and pathological inputs."""

import textwrap
import time
from pathlib import Path

import pytest

from kestrix_scan.analyze import scan_text
from kestrix_scan.php_rules import PHP_SUFFIXES, check_php
from kestrix_scan.php_tokens import MAX_NESTING, MAX_TOKENS, tokenize
from kestrix_scan.registry import RULES, Hit
from kestrix_scan.walk import Candidate


def hits(body: str, rel: str = "app/x.php", *, wrap: bool = True) -> list[Hit]:
    source = textwrap.dedent(body)
    if wrap and "<?php" not in source and "<?=" not in source:
        source = "<?php\n" + source
    result = check_php(source, rel)
    assert isinstance(result, list), result
    return result


def ids(body: str, rel: str = "app/x.php", *, wrap: bool = True) -> set[str]:
    return {h.rule_id for h in hits(body, rel, wrap=wrap)}


def lines_of(body: str, rule: str) -> list[int]:
    return [h.line for h in hits(body) if h.rule_id == rule]


# ----- tokenizer


def kinds(source: str) -> list[tuple[str, str]]:
    tokens = tokenize(source)
    assert tokens is not None
    return [(t.kind, t.value) for t in tokens]


def test_inline_html_is_dropped_and_short_echo_reads_like_echo() -> None:
    assert kinds("<html><?= $x ?></html>") == [("name", "echo"), ("var", "x"), ("punct", ";")]
    assert kinds("just text, no php") == []
    assert kinds("<?php $a = 1; ?> text <?php $b = 2;") == [
        ("var", "a"),
        ("punct", "="),
        ("num", "1"),
        ("punct", ";"),
        ("punct", ";"),
        ("var", "b"),
        ("punct", "="),
        ("num", "2"),
        ("punct", ";"),
    ]


def test_comments_are_dropped_and_a_line_comment_ends_at_the_close_tag() -> None:
    source = "<?php // note ?> text <?php\n# hash\n/* block $x */ $a;"
    assert kinds(source) == [("punct", ";"), ("var", "a"), ("punct", ";")]
    assert kinds("<?php #[Route('/x')]\n$a;") == [("var", "a"), ("punct", ";")]
    assert kinds("<?php /* never closed $x") == []


def test_strings_record_interpolated_variables() -> None:
    tokens = tokenize('<?php "a $b {$c->d} ${e} \\$no" . \'$lit\' . "plain";')
    assert tokens is not None
    assert (tokens[0].kind, tokens[0].vars) == ("istr", ("b", "c", "e"))
    assert [(t.kind, t.vars) for t in tokens[2:3]] == [("str", ())]
    assert (tokens[4].kind, tokens[4].value) == ("str", "plain")


def test_heredoc_nowdoc_and_backticks() -> None:
    source = "<?php\n$a = <<<EOT\nhello $name\n  EOT;\n$b = <<<'RAW'\n$notvar\nRAW;\n$c = `ls $dir`;\n"
    tokens = tokenize(source)
    assert tokens is not None
    heredoc = tokens[2]
    assert (heredoc.kind, heredoc.vars) == ("istr", ("name",))
    nowdoc = tokens[6]
    assert (nowdoc.kind, nowdoc.vars) == ("str", ())
    shell = tokens[10]
    assert (shell.kind, shell.vars) == ("shell", ("dir",))
    assert tokens[7].value == ";" and tokens[3].value == ";"


def test_unterminated_constructs_do_not_raise() -> None:
    for source in (
        '<?php $a = "open',
        "<?php $a = 'open",
        "<?php $a = <<<EOT\nnever closed",
        "<?php $a = `open",
        "<?php $",
    ):
        assert tokenize(source) is not None


def test_casts_variable_variables_and_namespaced_names() -> None:
    assert kinds("<?php $x = (int)$_GET['a'];")[2:5] == [("punct", "("), ("name", "int"), ("punct", ")")]
    assert kinds("<?php \\Foo\\bar($$x);")[:2] == [("name", "\\Foo\\bar"), ("punct", "(")]


def test_pathological_inputs_are_bounded_and_fast() -> None:
    started = time.perf_counter()
    assert tokenize("<?php " + "(" * (MAX_NESTING + 5)) is None
    assert tokenize("<?php " + "$a;" * (MAX_TOKENS // 2 + 5)) is None
    assert tokenize("<?php " + '"' * 200_000) is not None
    assert tokenize("<?php " + "<<<X\n" * 50_000) is not None
    assert tokenize("<?php " + "/*" * 200_000) is not None
    assert tokenize("<?php " + "`$a" * 100_000) is not None
    assert tokenize("<?php " + "// ?" * 100_000) is not None
    assert tokenize("<?php " + "\\" * 300_000) is not None
    assert tokenize("<?php " + "'" + "\\'" * 200_000) is not None
    assert tokenize("<?php " + "$$" * 100_000) is not None
    assert tokenize("<?php " + "{" * 300 + "}" * 300 + "x" * 3_000_000) is not None
    assert time.perf_counter() - started < 20


def test_check_php_skips_files_past_the_bounds() -> None:
    assert check_php("<?php\n" + "(\n" * (MAX_NESTING + 5), "a.php") == "too_complex"
    assert check_php("<?php\n" + "$a;\n" * (MAX_TOKENS // 2 + 5), "a.php") == "too_complex"
    minified = "<?php " + "$a=1;" * 4000
    assert check_php(minified, "a.php") == "minified"


def test_pathological_assignment_chains_stay_bounded() -> None:
    chain = "<?php\n" + "$a = $a = $a = $a =\n" * 20_000 + "$_GET['x'];\necho $a;\n"
    started = time.perf_counter()
    result = check_php(chain, "a.php")
    assert result == "too_complex" or isinstance(result, list)
    nested = "<?php\n$a = " + "[" * 400 + "$_GET['x']" + "]" * 400 + ";\necho $a;\n"
    assert isinstance(check_php(nested, "a.php"), list)
    many = "<?php\n" + "".join(f"$v{i} = $_GET['k'];\n$w{i} = $v{i} . 'x';\n" for i in range(3000)) + "echo $w2999;\n"
    result = check_php(many, "a.php")
    assert isinstance(result, list) and {h.rule_id for h in result} == {"php.xss.echo"}
    appended = "<?php\n$s = $_GET['q'];\n" + "$s .= 'x';\n" * 20_000 + "echo $s;\n"
    assert isinstance(check_php(appended, "a.php"), list)
    assert time.perf_counter() - started < 30


# ----- php.exec.command


def test_command_execution_from_request_values() -> None:
    assert ids("system('ls ' . $_GET['dir']);") == {"php.exec.command"}
    assert ids('$out = shell_exec("ping -c1 $_POST[host]");') == {"php.exec.command"}
    assert ids("passthru($_REQUEST['cmd']);") == {"php.exec.command"}
    assert ids("$h = popen('tar ' . $_COOKIE['f'], 'r');") == {"php.exec.command"}
    assert ids("$o = `ls {$_GET['d']}`;") == {"php.exec.command"}
    assert ids("$cmd = $_GET['c']; exec($cmd);") == {"php.exec.command"}


def test_command_execution_negatives() -> None:
    assert ids("system('ls /tmp');") == set()
    assert ids("system('ls ' . escapeshellarg($_GET['d']));") == set()
    assert ids("exec('kill ' . (int)$_GET['pid']);") == set()
    assert ids("$cmd = escapeshellcmd($_GET['c']); exec($cmd);") == set()
    assert ids("proc_open(['ls', $_GET['d']], $spec, $pipes);") == set()
    assert ids("$ssh->exec('ls');") == set()
    assert ids("function exec($x) { return 1; }") == set()


def test_command_built_from_a_non_literal_is_not_reported_without_request_data() -> None:
    assert ids('function run($file) { system("gzip $file"); }') == set()
    assert ids("function run($file) { system('gzip ' . $file); }") == set()


# ----- php.include.dynamic


def test_include_of_request_paths() -> None:
    assert ids("include($_GET['page'] . '.php');") == {"php.include.dynamic"}
    assert ids("require_once 'lib/' . $_POST['m'];") == {"php.include.dynamic"}
    assert ids("$p = $_GET['p']; include $p;") == {"php.include.dynamic"}


def test_include_negatives() -> None:
    assert ids("include 'config.php';") == set()
    assert ids("include __DIR__ . '/x.php';") == set()
    assert ids("include 'pages/' . basename($_GET['p']) . '.php';") == set()
    assert ids("$allowed = ['a' => 'a.php']; include $allowed[$k];") == set()


# ----- php.sql.injection


def test_sql_from_request_values() -> None:
    assert ids("mysqli_query($c, \"SELECT * FROM t WHERE id = '\" . $_GET['id'] . \"'\");") == {"php.sql.injection"}
    assert ids("$id = $_GET['id']; $r = $db->query(\"SELECT * FROM t WHERE id = $id\");") == {"php.sql.injection"}
    assert ids("pg_query($conn, 'DELETE FROM t WHERE n = ' . $_POST['n']);") == {"php.sql.injection"}
    assert ids("$wpdb->query(\"DELETE FROM x WHERE id = \" . $_GET['id']);") == {"php.sql.injection"}
    assert ids("$rows = $wpdb->get_results(\"SELECT * FROM t WHERE a = '$_GET[a]'\");") == {"php.sql.injection"}
    assert ids(
        "function f(Request $request) { return DB::select(\"select * from u where n = '\" . $request->input('n') . \"'\"); }"
    ) == {"php.sql.injection"}
    assert ids("function f($request) { $q->whereRaw(\"id = \" . $request->get('id')); }") == {"php.sql.injection"}
    assert ids("$q->orderByRaw($_GET['sort']);") == {"php.sql.injection"}
    assert ids("$stmt = $pdo->prepare(\"SELECT * FROM t WHERE a = '\" . $_GET['a'] . \"'\");") == {"php.sql.injection"}


def test_sql_negatives() -> None:
    assert ids("$stmt = $pdo->prepare('SELECT * FROM t WHERE id = ?'); $stmt->execute([$_GET['id']]);") == set()
    assert ids("mysqli_query($c, 'SELECT * FROM t WHERE id = ' . (int)$_GET['id']);") == set()
    assert (
        ids("mysqli_query($c, \"SELECT * FROM t WHERE n = '\" . mysqli_real_escape_string($c, $_GET['n']) . \"'\");")
        == set()
    )
    assert ids("$id = intval($_GET['id']); $db->query(\"SELECT * FROM t WHERE id = $id\");") == set()
    assert ids("$wpdb->query($wpdb->prepare('DELETE FROM x WHERE id = %d', $_GET['id']));") == set()
    assert ids('$wpdb->get_results("SELECT * FROM {$wpdb->prefix}posts");') == set()
    assert ids("$q->whereRaw('id = ?', [$_GET['id']]);") == set()
    assert ids("$db->query('SELECT 1');") == set()
    assert ids("$sql = 'SELECT 1'; $db->query($sql);") == set()


def test_sql_built_from_non_literals_without_request_data() -> None:
    (found,) = hits("$db->query('SELECT * FROM t WHERE a = ' . get_id());")
    assert (found.rule_id, found.severity, found.confidence) == ("php.sql.injection", "medium", "low")
    assert ids("$name = get_name(); $db->query(\"SELECT * FROM t WHERE n = '$name'\");") == {"php.sql.injection"}
    assert ids("$q->whereRaw('id = ' . get_id());") == {"php.sql.injection"}
    # the strict reading leaves out parameters, table and column names, a lone variable and values that are not built
    assert ids("function f($db, $table) { return $db->query('SELECT * FROM ' . $table . ' WHERE a = 1'); }") == set()
    assert ids('function f($db, $id) { return $db->query("SELECT * FROM t WHERE id = $id"); }') == set()
    assert ids("function f($db, $sql) { return $db->query($sql); }") == set()
    assert ids('$table = get_table(); $db->query("SELECT * FROM $table");') == set()
    assert ids("$sql = 'SELECT * FROM t WHERE a = ' . get_id(); $db->query($sql);") == set()
    assert ids("function f($db) { return $db->exec('make coffee ' . get_x()); }") == set()  # no SQL keyword


def test_sql_trace_names_the_source_and_the_sink() -> None:
    (found,) = hits("$id = $_GET['id'];\n$r = $db->query(\"SELECT * FROM t WHERE id = $id\");\n")
    assert found.confidence == "high"
    notes = [step.note for step in found.trace]
    assert notes[0] == "$_GET (source)" and "assigned to $id" in notes and notes[-1].startswith("reaches")


# ----- php.xss.echo


def test_echo_of_request_values() -> None:
    assert ids("echo 'Hello ' . $_GET['name'];") == {"php.xss.echo"}
    assert ids("print $_POST['q'];") == {"php.xss.echo"}
    assert ids("<p><?= $_GET['q'] ?></p>") == {"php.xss.echo"}
    assert ids("<form action=\"<?php echo $_SERVER['PHP_SELF']; ?>\">") == {"php.xss.echo"}
    assert ids("$q = $_GET['q'];\necho \"<h1>$q</h1>\";") == {"php.xss.echo"}
    assert ids("die('Bad: ' . $_REQUEST['x']);") == {"php.xss.echo"}
    assert ids("echo 'a', $_GET['b'];") == {"php.xss.echo"}
    assert ids("echo <<<HTML\n<b>{$_GET['x']}</b>\nHTML;\n") == {"php.xss.echo"}
    assert ids("function f(Request $request) { echo $request->input('q'); }") == {"php.xss.echo"}
    assert ids("function f(Request $request) { echo $request->query->get('q'); }") == {"php.xss.echo"}
    assert ids("function f($request) { echo \"v: {$request->input('q')}\"; }") == {"php.xss.echo"}
    assert ids("echo file_get_contents('php://input');") == {"php.xss.echo"}


def test_echo_negatives() -> None:
    assert ids("echo htmlspecialchars($_GET['q'], ENT_QUOTES);") == set()
    assert ids("echo esc_html($_GET['q']);") == set()
    assert ids("echo (int)$_GET['n'];") == set()
    assert ids("echo intval($_GET['n']) + 1;") == set()
    assert ids("$q = htmlspecialchars($_GET['q']); echo $q;") == set()
    assert ids("echo 'static';") == set()
    assert ids("echo $_SERVER['REMOTE_ADDR'];") == set()
    assert ids("echo $_SESSION['user'];") == set()
    assert ids("echo isset($_GET['a']) ? 'yes' : 'no';") == set()
    assert ids("echo strlen($_GET['a']);") == set()
    assert ids("echo json_encode($_GET);") == set()
    assert ids("$x = $_GET['a']; $x = (int)$x; echo $x;") == set()
    assert ids("function f(Request $request) { echo $request->user()->name; }") == set()
    assert ids("$message = 'ok'; echo $message;") == set()


def test_echo_through_a_branch_and_a_loop() -> None:
    assert ids("$v = isset($_GET['v']) ? $_GET['v'] : 'd';\necho $v;") == {"php.xss.echo"}
    assert ids("foreach ($_POST as $k => $v) { echo $k; }") == {"php.xss.echo"}
    assert ids("$v = $_GET['v'] ?? 'x'; echo $v;") == {"php.xss.echo"}
    assert ids("[$a, $b] = [$_GET['a'], 'x']; echo $a;") == {"php.xss.echo"}
    assert ids("$x = $_GET['a'];\nif ($c) { $x = 'safe'; }\necho $x;") == {"php.xss.echo"}
    assert ids("$x = $_GET['a'];\n$x = 'safe';\necho $x;") == set()


def test_self_referencing_assignments_terminate() -> None:
    assert ids("$x = $_GET['a'];\n$x = $x . 'suffix';\necho $x;") == {"php.xss.echo"}
    assert ids("$x = 'a';\n$x = $x . 'b';\necho $x;") == set()
    assert ids("$s = '';\nforeach ($_GET as $k => $v) { $s .= $s . $v; }\necho $s;") == {"php.xss.echo"}
    assert ids("$a = $a;\necho $a;") == set()
    assert ids("$i = $i + 1; $j = $j ?? $_GET['j']; echo $j;") == {"php.xss.echo"}


def test_taint_does_not_cross_functions() -> None:
    assert ids("function a() { $x = $_GET['a']; }\nfunction b() { echo $x; }") == set()
    assert ids("function a() { $x = $_GET['a']; $f = function() use ($x) { echo $x; }; }") == {"php.xss.echo"}


# ----- php.deserialize.unserialize


def test_unserialize_of_request_values() -> None:
    assert ids("$o = unserialize($_COOKIE['data']);") == {"php.deserialize.unserialize"}
    assert ids("$o = unserialize(base64_decode($_POST['d']));") == {"php.deserialize.unserialize"}
    assert ids("$o = unserialize(file_get_contents('php://input'));") == {"php.deserialize.unserialize"}
    assert ids("$o = maybe_unserialize($_REQUEST['o']);") == {"php.deserialize.unserialize"}


def test_unserialize_negatives() -> None:
    assert ids("$o = unserialize($_COOKIE['d'], ['allowed_classes' => false]);") == set()
    assert ids("$o = unserialize($stored);") == set()
    assert ids("$o = json_decode($_COOKIE['d']);") == set()


# ----- php.ssrf.request and php.path.traversal


def test_ssrf_sinks() -> None:
    assert ids("$ch = curl_init($_GET['url']);") == {"php.ssrf.request"}
    assert ids("curl_setopt($ch, CURLOPT_URL, $_POST['u']);") == {"php.ssrf.request"}
    assert ids("$r = file_get_contents($_GET['u']);") == {"php.ssrf.request"}
    assert ids("$r = file_get_contents('http://' . $_GET['h'] . '/x');") == {"php.ssrf.request"}
    assert ids("$h = get_headers($_REQUEST['u']);") == {"php.ssrf.request"}
    assert ids("curl_setopt_array($ch, [CURLOPT_URL => $_GET['u'], CURLOPT_RETURNTRANSFER => true]);") == {
        "php.ssrf.request"
    }
    assert ids("$r = wp_remote_get($_POST['u']);") == {"php.ssrf.request"}
    assert ids("function f(Request $request) { $u = $request->input('u'); return fopen($u, 'r'); }") == {
        "php.ssrf.request"
    }


def test_ssrf_negatives() -> None:
    assert ids("$ch = curl_init('https://api.example.com/x');") == set()
    assert ids("$ch = curl_init('https://api.example.com/?q=' . urlencode($_GET['q']));") == set()
    assert ids("curl_setopt($ch, CURLOPT_URL, $url);") == set()
    assert ids("curl_setopt($ch, CURLOPT_TIMEOUT, $_GET['t']);") == set()
    assert ids("$r = file_get_contents('config.json');") == set()


def test_path_traversal_sinks() -> None:
    assert ids("$d = file_get_contents('uploads/' . $_GET['f']);") == {"php.path.traversal"}
    assert ids("unlink('/tmp/' . $_POST['name']);") == {"php.path.traversal"}
    assert ids("move_uploaded_file($_FILES['f']['tmp_name'], 'up/' . $_FILES['f']['name']);") == {"php.path.traversal"}
    assert ids("file_put_contents($_GET['p'], 'x');") == {"php.path.traversal"}
    assert ids("readfile('/data/' . $_GET['f']);") == {"php.path.traversal"}


def test_path_traversal_negatives() -> None:
    assert ids("unlink('/tmp/' . basename($_POST['name']));") == set()
    assert ids("move_uploaded_file($_FILES['f']['tmp_name'], 'up/' . uniqid());") == set()
    assert ids("file_put_contents('/tmp/log', $_GET['x']);") == set()
    assert ids("move_uploaded_file($_FILES['f']['tmp_name'], 'up/' . md5($_FILES['f']['name']));") == set()


# ----- php.exec.eval, php.regex.preg_replace_e, php.extract.request


def test_eval_assert_and_create_function() -> None:
    assert ids("eval($_GET['code']);") == {"php.exec.eval"}
    assert ids("eval('return ' . $_POST['x'] . ';');") == {"php.exec.eval"}
    assert ids("assert($_GET['a']);") == {"php.exec.eval"}
    assert ids('assert("is_int($_GET[a])");') == {"php.exec.eval"}
    assert ids("$f = create_function('$a', $_GET['body']);") == {"php.exec.eval"}
    assert ids("$f = create_function('$a', 'return $a * 2;');") == set()
    assert ids("eval('return 1;');") == set()
    assert ids("assert($a > 0);") == set()
    assert ids("assert(is_int($x));") == set()


def test_eval_of_a_non_literal_is_not_reported_without_request_data() -> None:
    assert ids("eval($code);") == set()
    assert ids('assert("is_int($x)");') == set()
    assert ids("$f = create_function('$a', $body);") == set()


def test_preg_replace_e_modifier() -> None:
    (found,) = hits("$s = preg_replace('/(a)/e', 'strtoupper(\"\\\\1\")', $text);")
    assert found.rule_id == "php.regex.preg_replace_e"
    assert ids("$s = preg_replace('#x#ie', $r, $t);") == {"php.regex.preg_replace_e"}
    assert ids("$s = preg_replace('{x}e', $r, $t);") == {"php.regex.preg_replace_e"}
    assert ids("$s = preg_replace('/(a)/', 'b', $text);") == set()
    assert ids("$s = preg_replace('/e/i', 'b', $text);") == set()
    assert ids("$s = preg_replace_callback('/(a)/', fn($m) => $m[1], $text);") == set()
    assert ids("$s = preg_replace('/a/ei' . $x, 'b', $text);") == set()


def test_extract_of_request_arrays() -> None:
    assert ids("extract($_REQUEST);") == {"php.extract.request"}
    assert ids("extract($_GET);") == {"php.extract.request"}
    assert ids("extract($_POST, EXTR_OVERWRITE);") == {"php.extract.request"}
    assert ids("function f(Request $request) { extract($request->all()); }") == {"php.extract.request"}
    assert ids("extract($_POST, EXTR_PREFIX_ALL, 'p');") == set()
    assert ids("extract($config);") == set()


# ----- php.crypto.weak_password_hash


def test_md5_and_sha1_of_passwords() -> None:
    assert ids("$h = md5($password);") == {"php.crypto.weak_password_hash"}
    assert ids("$h = sha1($_POST['password']);") == {"php.crypto.weak_password_hash"}
    assert ids("$h = md5($user_pass . $salt);") == {"php.crypto.weak_password_hash"}
    assert ids("$h = md5($userPassword);") == {"php.crypto.weak_password_hash"}
    assert ids("$h = hash('md5', $pwd);") == {"php.crypto.weak_password_hash"}
    assert ids("$h = sha1(md5($_GET['pass']));") == {"php.crypto.weak_password_hash"}


def test_weak_hash_negatives() -> None:
    assert ids("$h = md5($filename);") == set()
    assert ids("$h = md5($bypass);") == set()
    assert ids("$h = sha1($compass);") == set()
    assert ids("$h = password_hash($password, PASSWORD_DEFAULT);") == set()
    assert ids("$h = hash('sha256', $password);") == set()
    assert ids("$h = md5_file($passwordfile);") == set()


# ----- php.blade.unescaped


def test_blade_unescaped_output() -> None:
    found = hits("<div>{!! $post->body !!}</div>", "resources/views/p.blade.php", wrap=False)
    assert [(h.rule_id, h.severity, h.confidence) for h in found] == [("php.blade.unescaped", "low", "low")]
    (tainted,) = hits("{!! $request->input('q') !!}", "resources/views/s.blade.php", wrap=False)
    assert (tainted.severity, tainted.confidence) == (None, "high")
    (old,) = hits("<input value='{!! old('q') !!}'>", "v.blade.php", wrap=False)
    assert old.confidence == "high"
    assert hits("\n\n{!!\n $html\n!!}", "v.blade.php", wrap=False)[0].line == 3


def test_blade_negatives() -> None:
    for expr in (
        "{{ $post->body }}",
        "{!! csrf_field() !!}",
        "{!! method_field('PUT') !!}",
        "{!! '<b>x</b>' !!}",
        "{!! e($x) !!}",
        "{!! nl2br(e($x)) !!}",
        "{!! json_encode($data) !!}",
        "{!! $slot !!}",
        "{!! $errors->first('a') !!}",
        "{!! $users->links() !!}",
        "{{-- {!! $commented !!} --}}",
        "@verbatim {!! $x !!} @endverbatim",
        "{!! strip_tags($x) !!}",
    ):
        assert hits(expr, "v.blade.php", wrap=False) == [], expr
    assert hits("{!! $x !!}", "plain.php", wrap=False) == []  # only Blade templates


def test_blade_templates_also_run_php_blocks() -> None:
    body = "<p>{{ $a }}</p>\n<?php echo $_GET['q']; ?>\n{!! $b !!}"
    assert {h.rule_id for h in hits(body, "v.blade.php", wrap=False)} == {"php.xss.echo", "php.blade.unescaped"}


# ----- framework sources


def test_request_object_parameters_and_methods() -> None:
    assert ids("function f(Request $r) { echo $r->input('a'); }") == {"php.xss.echo"}
    assert ids("function f(\\Illuminate\\Http\\Request $r) { echo $r->input('a'); }") == {"php.xss.echo"}
    assert ids("function f(ServerRequestInterface $r) { echo $r->getQueryParams()['a']; }") == {"php.xss.echo"}
    assert ids("function f($req) { echo $req->cookie('a'); }") == {"php.xss.echo"}
    assert ids("function f() { echo request('a'); }") == {"php.xss.echo"}
    assert ids("function f() { echo request()->input('a'); }") == {"php.xss.echo"}
    assert ids("function f() { echo Request::get('a'); }") == {"php.xss.echo"}
    assert ids("function f() { echo $this->input->post('a'); }") == {"php.xss.echo"}
    assert ids("function f() { echo $this->request->getQuery('a'); }") == {"php.xss.echo"}
    assert ids("function f($request) { echo $request->name; }") == {"php.xss.echo"}
    assert ids("function f($request) { echo $request->user(); }") == set()
    assert ids("function f($other) { echo $other->input('a'); }") == set()
    assert ids("function f() { $this->title = $_GET['t']; echo $this->title; }") == {"php.xss.echo"}
    assert ids("function f() { $this->title = $_GET['t']; echo $this->other; }") == set()


def test_server_fields() -> None:
    assert ids("echo $_SERVER['QUERY_STRING'];") == {"php.xss.echo"}
    assert ids("echo $_SERVER['REQUEST_URI'];") == {"php.xss.echo"}
    assert ids("echo $_SERVER['HTTP_USER_AGENT'];") == {"php.xss.echo"}
    assert ids("echo \"x {$_SERVER['REQUEST_URI']}\";") == {"php.xss.echo"}
    assert ids("echo $_SERVER['SERVER_NAME'];") == set()
    assert ids("echo $_SERVER['SCRIPT_FILENAME'];") == set()


def test_filter_input_and_headers() -> None:
    assert ids("echo filter_input(INPUT_GET, 'a');") == {"php.xss.echo"}
    assert ids("echo filter_input(INPUT_GET, 'a', FILTER_VALIDATE_INT);") == set()
    assert ids("echo filter_input(INPUT_GET, 'a', FILTER_SANITIZE_SPECIAL_CHARS);") == set()
    assert ids("$h = getallheaders(); echo $h['X-A'];") == {"php.xss.echo"}
    assert ids("echo filter_var($_GET['a'], FILTER_VALIDATE_EMAIL);") == set()


# ----- suppression and scan integration


def test_php_files_are_scanned_with_suppression_comments(tmp_path: Path) -> None:
    source = "<?php\necho $_GET['a'];\n// kestrix: ignore[php.xss.echo] value is escaped by the caller\necho $_GET['b'];\necho $_GET['c']; # kestrix: ignore[php.xss.echo]\n"
    path = tmp_path / "a.php"
    path.write_text(source)
    findings, notes, suppressed, skip = scan_text(source, Candidate(path, "a.php"))
    assert [f.line for f in findings if f.rule_id == "php.xss.echo"] == [2, 5]
    assert suppressed == 1 and skip is None
    assert [n.line for n in notes] == [5]


def test_blade_comment_suppression(tmp_path: Path) -> None:
    source = (
        "{{-- kestrix: ignore[php.blade.unescaped] HTML comes from the purifier --}}\n{!! $html !!}\n{!! $other !!}\n"
    )
    path = tmp_path / "v.blade.php"
    path.write_text(source)
    findings, _, suppressed, _ = scan_text(source, Candidate(path, "v.blade.php"))
    assert [f.line for f in findings] == [3] and suppressed == 1


def test_phtml_and_php_suffixes() -> None:
    assert {".php", ".phtml"} == PHP_SUFFIXES
    source = "<?php echo $_GET['a'];"
    for name in ("a.phtml", "a.PHP"):
        findings, *_ = scan_text(source, Candidate(Path(name), name))
        assert {f.rule_id for f in findings} == {"php.xss.echo"}, name


def test_findings_carry_registry_text_and_cwe() -> None:
    for rule_id, code, cwe in (
        ("php.exec.command", "system($_GET['c']);", "CWE-78"),
        ("php.include.dynamic", "include $_GET['p'];", "CWE-98"),
        ("php.sql.injection", "$db->query('SELECT * FROM t WHERE a=' . $_GET['a']);", "CWE-89"),
        ("php.xss.echo", "echo $_GET['a'];", "CWE-79"),
        ("php.deserialize.unserialize", "unserialize($_GET['a']);", "CWE-502"),
        ("php.ssrf.request", "curl_init($_GET['a']);", "CWE-918"),
        ("php.path.traversal", "unlink($_GET['a']);", "CWE-22"),
        ("php.exec.eval", "eval($_GET['a']);", "CWE-95"),
        ("php.extract.request", "extract($_GET);", "CWE-621"),
        ("php.crypto.weak_password_hash", "md5($password);", "CWE-916"),
    ):
        assert RULES[rule_id].cwe == cwe
        findings, *_ = scan_text("<?php " + code, Candidate(Path("a.php"), "a.php"))
        (found,) = [f for f in findings if f.rule_id == rule_id]
        assert found.fix and found.why and found.cwe == cwe


@pytest.mark.parametrize(
    "rule_id",
    [r for r in RULES if r.startswith(("php.", "sql."))],
)
def test_every_php_and_sql_rule_has_docs(rule_id: str) -> None:
    rule = RULES[rule_id]
    assert rule.language in ("php", "sql")
    assert rule.sources and all(s.startswith("https://") for s in rule.sources)
    assert rule.fix and rule.why and rule.title
