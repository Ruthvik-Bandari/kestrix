# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Phase 1 Node and Next.js sources and sinks: App Router, Pages API, server actions, Fastify, Koa and NestJS.

Each source has a positive case (it reaches an existing sink) and a negative case."""

import textwrap

import pytest

from kestrix_scan.js_rules import check_js

CP = "import { exec } from 'node:child_process';\n"


def fired(source: str, rel: str = "app.ts") -> list[tuple[str, int]]:
    result = check_js(textwrap.dedent(source), rel)
    assert isinstance(result, list), result
    return sorted((h.rule_id, h.line) for h in result)


def shell(source: str, rel: str = "app.ts") -> bool:
    """True when request data (a traced finding, not just a built command) reaches exec."""
    result = check_js(textwrap.dedent(CP + source), rel)
    assert isinstance(result, list), result
    return any(h.rule_id == "js.child_process.shell" and h.trace for h in result)


@pytest.mark.parametrize(
    "body",
    [
        "export async function GET(req: NextRequest) { exec('ls ' + req.nextUrl.searchParams.get('d')); }",
        "export async function POST(request: Request) { const { dir } = await request.json(); exec(`ls ${dir}`); }",
        "export async function POST(request: Request) { const f = await request.formData(); exec('x ' + f.get('a')); }",
        "export async function GET(req, { params }) { exec('ls ' + params.id); }",
        "export async function GET(req, context) { exec('ls ' + context.params.id); }",
        "export default function Page({ searchParams }) { exec('ls ' + searchParams.q); }",
        "export async function GET(req, { params }) { const { id } = await params; exec('ls ' + id); }",
        "export async function GET(request) { exec('ls ' + new URL(request.url).searchParams.get('d')); }",
    ],
)
def test_app_router_request_sources(body: str) -> None:
    assert shell(f"import {{ NextRequest }} from 'next/server';\n{body}")


@pytest.mark.parametrize(
    "body",
    [
        "export async function GET(req: NextRequest) { exec('ls ' + 'fixed'); }",
        "export async function GET(req, { params }) { const params2 = { id: 'a' }; exec('ls ' + params2.id); }",
        "export async function GET(req) { const n = Number(req.nextUrl.searchParams.get('n')); exec('sleep ' + n); }",
    ],
)
def test_app_router_negatives(body: str) -> None:
    assert not shell(f"import {{ NextRequest }} from 'next/server';\n{body}")


def test_params_are_sources_only_in_next_files() -> None:
    assert not shell("export function f({ params }) { exec('ls ' + params.id); }")
    assert shell("'use server'\nexport function f({ params }) { exec('ls ' + params.id); }")


def test_pages_api_routes() -> None:
    assert shell("export default function handler(req, res) { exec('ls ' + req.query.d); }", "pages/api/x.ts")
    assert shell("export default function handler(req, res) { exec('ls ' + req.body.d); }", "pages/api/x.ts")
    assert not shell("export default function handler(req, res) { exec('ls ' + process.env.D); }", "pages/api/x.ts")


@pytest.mark.parametrize(
    "body",
    [
        "'use server'\nexport async function run(formData: FormData) { exec('x ' + formData.get('cmd')); }",
        "export async function run(formData) {\n  'use server'\n  exec('x ' + formData.get('cmd'));\n}",
        "'use server'\nexport async function run(prev: unknown, input: FormData) { exec('x ' + input.get('cmd')); }",
        "'use server'\nexport async function run(formData) { const d = Object.fromEntries(formData); exec('x ' + d.cmd); }",
    ],
)
def test_server_action_form_data(body: str) -> None:
    assert shell(body)


def test_form_data_is_not_a_source_outside_server_actions() -> None:
    assert not shell("export function run(formData) { exec('x ' + formData.get('cmd')); }")
    assert not shell("'use server'\nexport async function run(formData) { exec('x ' + 'fixed'); }")


@pytest.mark.parametrize(
    ("body", "fires"),
    [
        (
            "import { redirect } from 'next/navigation';\nexport function GET(req) { redirect(req.nextUrl.searchParams.get('n')); }",
            True,
        ),
        (
            "import { permanentRedirect } from 'next/navigation';\nexport function GET(req) { permanentRedirect(req.nextUrl.searchParams.get('n')); }",
            True,
        ),
        (
            "import { NextResponse } from 'next/server';\nexport function GET(req) { return NextResponse.redirect(new URL(req.nextUrl.searchParams.get('n'), req.url)); }",
            True,
        ),
        (
            "import { NextResponse } from 'next/server';\nexport function GET(req) { return NextResponse.redirect(req.nextUrl.searchParams.get('n')); }",
            True,
        ),
        ("export function GET(req) { return Response.redirect(req.nextUrl.searchParams.get('n')); }", True),
        (
            "'use server'\nimport { redirect } from 'next/navigation';\nexport async function go(formData: FormData) { redirect(formData.get('to') as string); }",
            True,
        ),
        ("import { redirect } from 'next/navigation';\nexport function GET(req) { redirect('/login'); }", False),
        (
            "import { redirect } from 'next/navigation';\nexport function GET(req) { redirect(`/users/${req.nextUrl.searchParams.get('id')}`); }",
            False,
        ),
        (
            "import { NextResponse } from 'next/server';\nexport function GET(req) { return NextResponse.redirect(new URL('/login', req.url)); }",
            False,
        ),
        (
            "import { NextResponse } from 'next/server';\nexport function GET(req) { return NextResponse.redirect(new URL(`/a/${req.nextUrl.search}`, req.url)); }",
            False,
        ),
    ],
)
def test_next_redirects(body: str, fires: bool) -> None:
    assert ("js.redirect.open" in {rule for rule, _ in fired(body)}) is fires


def test_use_search_params_from_next_navigation_is_a_dom_source() -> None:
    source = "import { useSearchParams } from 'next/navigation';\nfunction C() {\n  const sp = useSearchParams();\n  return <div dangerouslySetInnerHTML={{ __html: sp.get('h') }} />;\n}\n"
    assert ("js.dom.xss_sink", 4) in fired(source, "app/page.tsx")


def test_dangerously_set_inner_html_still_fires() -> None:
    assert fired("export const A = ({ h }) => <div dangerouslySetInnerHTML={{ __html: h }} />;", "a.tsx") == [
        ("js.dom.xss_sink", 1)
    ]


@pytest.mark.parametrize(
    "body",
    [
        "fastify.get('/', async (request, reply) => { exec('x ' + request.query.d); });",
        "fastify.post('/', async (request, reply) => { exec('x ' + request.body.d); });",
        "fastify.get('/:id', async (request, reply) => { exec('x ' + request.params.id); });",
        "fastify.get('/', async (request, reply) => { reply.redirect(request.query.next); });",
    ],
)
def test_fastify(body: str) -> None:
    assert {"js.child_process.shell", "js.redirect.open"} & {rule for rule, _ in fired(CP + body)}


@pytest.mark.parametrize(
    "body",
    [
        "router.get('/', async (ctx) => { exec('x ' + ctx.query.d); });",
        "router.get('/:id', async (ctx) => { exec('x ' + ctx.params.id); });",
        "router.post('/', async (ctx) => { exec('x ' + ctx.request.body.d); });",
        "router.get('/', async (ctx) => { exec('x ' + ctx.get('x-cmd')); });",
        "router.get('/', async (ctx) => { exec('x ' + ctx.headers['x-cmd']); });",
        "router.get('/', async (ctx) => { exec('x ' + ctx.request.headers.cmd); });",
    ],
)
def test_koa(body: str) -> None:
    assert shell(body)


def test_koa_negatives() -> None:
    assert not shell("router.get('/', async (ctx) => { exec('x ' + ctx.state.user); });")
    assert not shell("router.get('/', async (ctx) => { exec('x ' + ctx.status); });")


@pytest.mark.parametrize(
    "params",
    [
        "@Query('d') d: string",
        "@Query() q: QueryDto",
        "@Body() b: BodyDto",
        "@Param('id') id: string",
        "@Headers('x-cmd') d: string",
    ],
)
def test_nestjs_decorators(params: str) -> None:
    name = params.rsplit(" ", 2)[-2].split(":", maxsplit=1)[0]
    use = name if params.startswith("@Query('") or "'id'" in params or "Headers" in params else f"{name}.cmd"
    body = f"@Controller()\nclass C {{\n  @Get()\n  run({params}) {{ exec('x ' + {use}); }}\n}}"
    assert shell(body)


@pytest.mark.parametrize(
    "params",
    [
        "@Param('id', ParseIntPipe) id: number",
        "@Query('n') n: number",
        "@Body() b: BodyDto, other: string",
    ],
)
def test_nestjs_negatives(params: str) -> None:
    name = "other" if "other" in params else params.rsplit(" ", 2)[-2].split(":", maxsplit=1)[0]
    assert not shell(f"@Controller()\nclass C {{\n  @Get()\n  run({params}) {{ exec('x ' + {name}); }}\n}}")


def test_nestjs_req_decorator_makes_req_a_parameter() -> None:
    assert shell("@Controller()\nclass C {\n  @Get()\n  run(@Req() req: Request) { exec('x ' + req.query.d); }\n}")


def test_decorated_constructor_parameters_are_not_sources() -> None:
    assert not shell(
        "@Injectable()\nclass S {\n  constructor(@Inject(TOKEN) private cfg: Config) { exec('x ' + cfg.cmd); }\n}"
    )
