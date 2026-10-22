# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
import textwrap

import pytest

from kestrix_scan.python_rules import check_python, secret_like
from kestrix_scan.registry import RULES, Hit


def hits(source: str, rel: str = "app.py") -> list[Hit]:
    result = check_python(textwrap.dedent(source), rel)
    assert isinstance(result, list), result
    return result


def ids(source: str, rel: str = "app.py") -> set[str]:
    return {hit.rule_id for hit in hits(source, rel)}


POSITIVE = [
    ("py.exec.eval", "def f(x):\n    return eval(x)\n"),
    ("py.exec.eval", "import builtins\ndef f(req):\n    eval(req.body + '1')\n"),
    ("py.exec.exec", "def f(code):\n    exec(code)\n"),
    ("py.exec.exec", "def f(name):\n    exec(f'import {name}')\n"),
    ("py.exec.compile", "def f(src):\n    return compile(src, '<x>', 'exec')\n"),
    ("py.subprocess.shell_true", "import subprocess\ndef f(h):\n    subprocess.run(f'ping {h}', shell=True)\n"),
    ("py.subprocess.shell_true", "import subprocess as sp\ndef f(h):\n    sp.Popen('ping ' + h, shell=True)\n"),
    (
        "py.subprocess.shell_true",
        "from subprocess import check_output\ndef f(c):\n    check_output(args=c, shell=True)\n",
    ),
    ("py.subprocess.shell_true", "import subprocess\ndef f(c):\n    subprocess.getoutput(c)\n"),
    ("py.os.system", "import os\ndef f(name):\n    os.system('rm ' + name)\n"),
    ("py.os.system", "from os import system\ndef f(n):\n    system(f'ls {n}')\n"),
    ("py.os.system", "import os as o\ndef f(n):\n    o.popen(n)\n"),
    ("py.deserialize.pickle", "import pickle\ndef f(b):\n    return pickle.loads(b)\n"),
    ("py.deserialize.pickle", "import pickle as p\ndef f(fh):\n    return p.load(fh)\n"),
    ("py.deserialize.pickle", "from pickle import Unpickler\ndef f(fh):\n    return Unpickler(fh).load()\n"),
    ("py.deserialize.pickle", "import dill\ndef f(b):\n    return dill.loads(b)\n"),
    ("py.deserialize.pickle", "import shelve\ndb = shelve.open('x')\n"),
    ("py.deserialize.pickle", "import marshal\ndef f(b):\n    return marshal.loads(b)\n"),
    ("py.deserialize.yaml_unsafe", "import yaml\ndef f(t):\n    return yaml.load(t)\n"),
    ("py.deserialize.yaml_unsafe", "import yaml\ndef f(t):\n    return yaml.load(t, Loader=yaml.Loader)\n"),
    ("py.deserialize.yaml_unsafe", "import yaml\ndef f(t):\n    return yaml.load(t, yaml.UnsafeLoader)\n"),
    ("py.deserialize.yaml_unsafe", "import yaml\ndef f(t):\n    return yaml.unsafe_load(t)\n"),
    ("py.deserialize.yaml_unsafe", "import yaml\ndef f(t):\n    return yaml.full_load(t)\n"),
    (
        "py.deserialize.yaml_unsafe",
        "import yaml\nclass L(yaml.FullLoader):\n    pass\ndef f(t):\n    return yaml.load(t, Loader=L)\n",
    ),
    ("py.sql.string_built", "def f(cur, uid):\n    cur.execute(f'SELECT * FROM users WHERE id = {uid}')\n"),
    ("py.sql.string_built", "def f(cur, uid):\n    cur.execute('SELECT * FROM users WHERE id = %s' % uid)\n"),
    ("py.sql.string_built", "def f(cur, n):\n    cur.execute('DELETE FROM t WHERE name = \"' + n + '\"')\n"),
    ("py.sql.string_built", "def f(cur, n):\n    cur.executemany('INSERT INTO t VALUES ({})'.format(n), [])\n"),
    ("py.sql.string_built", "def f(cur, n):\n    q = f'UPDATE t SET a = {n}'\n    cur.execute(q)\n"),
    (
        "py.sql.string_built",
        "from sqlalchemy import text\ndef f(n):\n    return text(f'SELECT a FROM t WHERE b = {n}')\n",
    ),
    ("py.sql.string_built", "def f(n):\n    return User.objects.raw(f'SELECT * FROM u WHERE n = {n}')\n"),
    ("py.tls.verify_disabled", "import requests\nrequests.get('https://a.example', verify=False)\n"),
    ("py.tls.verify_disabled", "import httpx\nhttpx.Client(verify=False)\n"),
    ("py.tls.verify_disabled", "import requests\ns = requests.Session()\ns.get('https://a.example', verify=False)\n"),
    ("py.tls.verify_disabled", "import requests\ns = requests.Session()\ns.verify = False\n"),
    ("py.tls.verify_disabled", "import ssl\nctx = ssl._create_unverified_context()\n"),
    ("py.tls.verify_disabled", "import ssl\nctx = ssl.create_default_context()\nctx.verify_mode = ssl.CERT_NONE\n"),
    ("py.tls.verify_disabled", "import ssl\nctx = ssl.create_default_context()\nctx.check_hostname = False\n"),
    ("py.tls.verify_disabled", "from ssl import CERT_NONE\nmode = CERT_NONE\n"),
    ("py.crypto.weak_hash", "import hashlib\ndigest = hashlib.md5(b'x').hexdigest()\n"),
    ("py.crypto.weak_hash", "import hashlib\ndigest = hashlib.sha1(b'x')\n"),
    ("py.crypto.weak_hash", "import hashlib\ndigest = hashlib.new('MD5')\n"),
    ("py.crypto.weak_hash", "from hashlib import md5\ndigest = md5(b'x')\n"),
    ("py.crypto.insecure_random", "import random\napi_token = ''.join(random.choice('ab') for _ in range(32))\n"),
    (
        "py.crypto.insecure_random",
        "import random\nclass A:\n    def f(self):\n        self.reset_key = random.getrandbits(64)\n",
    ),
    ("py.crypto.insecure_random", "from random import randint\nsession = {}\nsession['csrf'] = randint(0, 10**9)\n"),
    ("py.crypto.insecure_random", "import random\ndef make_password():\n    return str(random.random())\n"),
    ("py.crypto.insecure_random", "import random\nsaltValue = random.randbytes(16)\n"),
    ("py.tempfile.mktemp", "import tempfile\npath = tempfile.mktemp()\n"),
    ("py.tempfile.mktemp", "from tempfile import mktemp\npath = mktemp(suffix='.txt')\n"),
    ("py.flask.debug", "from flask import Flask\napp = Flask(__name__)\napp.run(debug=True)\n"),
    ("py.flask.debug", "import flask\napp = flask.Flask(__name__)\napp.debug = True\n"),
    ("py.flask.debug", "from flask import Flask\napp = Flask(__name__)\napp.config['DEBUG'] = True\n"),
    ("py.jwt.no_verify", "import jwt\ndef f(t):\n    return jwt.decode(t, options={'verify_signature': False})\n"),
    ("py.jwt.no_verify", "import jwt\ndef f(t, k):\n    return jwt.decode(t, k, algorithms=['HS256', 'none'])\n"),
    ("py.jwt.no_verify", "import jwt\ndef f(t, k):\n    return jwt.decode(t, k, verify=False)\n"),
    (
        "py.jwt.no_verify",
        "from jose import jwt\ndef f(t):\n    return jwt.decode(t, None, options={'verify_signature': False})\n",
    ),
    ("py.xml.unsafe_parser", "from lxml import etree\np = etree.XMLParser(resolve_entities=True)\n"),
    ("py.xml.unsafe_parser", "import lxml.etree\np = lxml.etree.XMLParser(no_network=False)\n"),
    ("py.xml.unsafe_parser", "from lxml import etree\ndef f(fh):\n    return etree.iterparse(fh, huge_tree=True)\n"),
    (
        "py.xml.unsafe_parser",
        "import xml.sax\nfrom xml.sax.handler import feature_external_ges\np = xml.sax.make_parser()\np.setFeature(feature_external_ges, True)\n",
    ),
    (
        "py.xml.unsafe_parser",
        "import xml.sax\np = xml.sax.make_parser()\np.setFeature('http://xml.org/sax/features/external-parameter-entities', 1)\n",
    ),
    ("py.assert.security", "def view(user):\n    assert user.is_admin\n    return 1\n"),
    ("py.assert.security", "def view(user):\n    assert has_permission(user, 'x'), 'denied'\n"),
    (
        "py.path.traversal",
        "from flask import request, send_file\n@app.route('/f')\ndef f():\n    return send_file(request.args['name'])\n",
    ),
    (
        "py.path.traversal",
        "import os\nfrom flask import request\ndef f():\n    name = request.args.get('n')\n    p = os.path.join('/data', name)\n    return open(p).read()\n",
    ),
    ("py.path.traversal", "def view(request):\n    return open('/srv/' + request.GET['file']).read()\n"),
    (
        "py.path.traversal",
        "from pathlib import Path\nfrom flask import request\ndef f():\n    return (Path('/d') / request.args['n']).read_text()\n",
    ),
    (
        "py.path.traversal",
        "from fastapi import FastAPI\nfrom fastapi.responses import FileResponse\napp = FastAPI()\n@app.get('/f')\ndef f(name: str):\n    return FileResponse('/srv/' + name)\n",
    ),
    (
        "py.ssrf.request",
        "import requests\nfrom flask import request\ndef f():\n    return requests.get(request.args['u'])\n",
    ),
    (
        "py.ssrf.request",
        "import httpx\ndef view(request):\n    url = request.POST['u']\n    return httpx.request('GET', url)\n",
    ),
    (
        "py.ssrf.request",
        "from urllib.request import urlopen\nfrom flask import request\ndef f():\n    return urlopen(request.form.get('u')).read()\n",
    ),
    (
        "py.redirect.open",
        "from flask import redirect, request\ndef f():\n    return redirect(request.args.get('next'))\n",
    ),
    (
        "py.redirect.open",
        "from django.http import HttpResponseRedirect\ndef view(request):\n    return HttpResponseRedirect(request.GET['next'])\n",
    ),
    (
        "py.redirect.open",
        "from flask import redirect, request\ndef f():\n    return redirect('/' + request.args['p'])\n",
    ),
    (
        "py.xss.markup",
        "from markupsafe import Markup\nfrom flask import request\ndef f():\n    return Markup(request.args['m'])\n",
    ),
    (
        "py.xss.markup",
        "from django.utils.safestring import mark_safe\ndef view(request):\n    return mark_safe('<b>%s</b>' % request.GET['n'])\n",
    ),
    (
        "py.xss.markup",
        "from flask import render_template_string, request\ndef f():\n    return render_template_string('Hi ' + request.args['n'])\n",
    ),
    (
        "py.llm.output_to_sink",
        "import anthropic\nc = anthropic.Anthropic()\ndef f(p):\n    r = c.messages.create(model='m', max_tokens=9, messages=p)\n    return eval(r.content[0].text)\n",
    ),
    (
        "py.llm.output_to_sink",
        "import os\nfrom openai import OpenAI\nclient = OpenAI()\ndef f(p):\n    out = client.chat.completions.create(model='m', messages=p)\n    os.system(out.choices[0].message.content)\n",
    ),
    (
        "py.xss.reflected",
        "from flask import request\ndef f():\n    return f\"<p>{request.args['q']}</p>\"\n",
    ),
    (
        "py.xss.reflected",
        "from django.http import HttpResponse\ndef view(request):\n    return HttpResponse('<b>' + request.GET['n'] + '</b>')\n",
    ),
    (
        "py.ldap.injection",
        "import ldap\nfrom flask import request\ndef f(c):\n    c.search_s('dc=x', ldap.SCOPE_SUBTREE, '(cn=%s)' % request.args['n'])\n",
    ),
    (
        "py.ldap.injection",
        "import ldap3\nfrom flask import request\ndef f(c):\n    c.search('dc=x', search_filter=f\"(mail={request.form['m']})\")\n",
    ),
    (
        "py.xpath.injection",
        "from lxml import etree\nfrom flask import request\ndef f(t):\n    return t.xpath(\"//a[@id='\" + request.args['i'] + \"']\")\n",
    ),
    (
        "py.xpath.injection",
        "import xml.etree.ElementTree as ET\ndef view(request, root):\n    return root.findall(f\".//item[@sku='{request.GET['s']}']\")\n",
    ),
    ("py.cookie.insecure", "from flask import make_response\nr = make_response('')\nr.set_cookie('sid', 'v')\n"),
    (
        "py.cookie.insecure",
        "from django.http import HttpResponse\nr = HttpResponse()\nr.set_cookie('sid', 'v', secure=False, httponly=True)\n",
    ),
    (
        "py.trust_boundary.session",
        "from flask import request, session\ndef f():\n    session['plan'] = request.form['plan']\n",
    ),
    (
        "py.trust_boundary.session",
        "def view(request):\n    request.session['owner'] = request.GET.get('owner')\n",
    ),
    ("py.ml.unsafe_model_load", "import torch\nm = torch.load('model.pt')\n"),
    ("py.ml.unsafe_model_load", "import torch\nm = torch.load('model.pt', weights_only=False)\n"),
    ("py.ml.unsafe_model_load", "import joblib\nclf = joblib.load('clf.joblib')\n"),
    (
        "py.ml.unsafe_model_load",
        "import pickle\nwith open('model.pkl', 'rb') as fh:\n    model = pickle.load(open('model.pkl', 'rb'))\n",
    ),
    (
        "py.ml.unsafe_model_load",
        "from tensorflow import keras\nm = keras.models.load_model('m.keras', safe_mode=False)\n",
    ),
    (
        "py.ml.unsafe_model_load",
        "from transformers import AutoModel\nm = AutoModel.from_pretrained('org/m', trust_remote_code=True)\n",
    ),
    # py.archive.extract
    (
        "py.archive.extract",
        "import tarfile\ndef f(p):\n    with tarfile.open(p) as tar:\n        tar.extractall('out')\n",
    ),
    (
        "py.archive.extract",
        "import tarfile\ndef f(p):\n    tar = tarfile.open(p, 'r:gz')\n    tar.extractall(path='out')\n",
    ),
    ("py.archive.extract", "import tarfile\ndef f(p, m):\n    tarfile.open(p).extract(m, 'out')\n"),
]

NEGATIVE = [
    ("py.exec.eval", "x = eval('1 + 2')\n"),
    ("py.exec.eval", "EXPR = '40 + 2'\nx = eval(EXPR)\n"),
    ("py.exec.eval", "import ast\ndef f(x):\n    return ast.literal_eval(x)\n"),
    ("py.exec.eval", "def eval(x):\n    return x\ndef g(y):\n    return eval(y)\n"),
    ("py.exec.eval", "def f(model, x):\n    return model.eval(x)\n"),
    ("py.exec.exec", "exec('print(1)')\n"),
    ("py.exec.compile", "import re\ndef f(p):\n    return re.compile(p)\n"),
    ("py.exec.compile", "code = compile('1 + 1', '<x>', 'eval')\n"),
    ("py.subprocess.shell_true", "import subprocess\ndef f(h):\n    subprocess.run(['ping', h], check=True)\n"),
    ("py.subprocess.shell_true", "import subprocess\ndef f(h):\n    subprocess.run(['ping', h], shell=False)\n"),
    ("py.subprocess.shell_true", "import subprocess\ndef f(c, flag):\n    subprocess.run(c, shell=flag)\n"),
    ("py.subprocess.shell_true", "def run(c, shell):\n    pass\ndef f(c):\n    run(c, shell=True)\n"),
    ("py.os.system", "import os\nos.system('clear')\n"),
    ("py.os.system", "def system(x):\n    return x\ndef f(n):\n    system(n)\n"),
    ("py.deserialize.pickle", "import json\ndef f(b):\n    return json.loads(b)\n"),
    ("py.deserialize.pickle", "def f(store, b):\n    return store.loads(b)\n"),
    ("py.deserialize.yaml_unsafe", "import yaml\ndef f(t):\n    return yaml.safe_load(t)\n"),
    ("py.deserialize.yaml_unsafe", "import yaml\ndef f(t):\n    return yaml.load(t, Loader=yaml.SafeLoader)\n"),
    ("py.deserialize.yaml_unsafe", "import yaml\ndef f(t):\n    return yaml.load(t, Loader=yaml.CSafeLoader)\n"),
    (
        "py.deserialize.yaml_unsafe",
        "import yaml\nclass Strict(yaml.SafeLoader):\n    pass\ndef f(t):\n    return list(yaml.load_all(t, Loader=Strict))\n",
    ),
    ("py.sql.string_built", "def f(cur, uid):\n    cur.execute('SELECT * FROM users WHERE id = ?', (uid,))\n"),
    ("py.sql.string_built", "def f(cur, uid):\n    cur.execute('SELECT * FROM users WHERE id = %s', (uid,))\n"),
    ("py.sql.string_built", "TABLE = 'users'\ndef f(cur):\n    cur.execute(f'SELECT * FROM {TABLE}')\n"),
    ("py.sql.string_built", "def f(runner, n):\n    runner.execute(f'build {n} now')\n"),
    ("py.sql.string_built", "def f(cur):\n    cur.execute('PRAGMA journal_mode=WAL')\n"),
    ("py.tls.verify_disabled", "import requests\nrequests.get('https://a.example', verify=True)\n"),
    ("py.tls.verify_disabled", "import requests\nrequests.get('https://a.example', verify='/etc/ca.pem')\n"),
    ("py.tls.verify_disabled", "def f(form):\n    form.get('x', verify=False)\n"),
    ("py.tls.verify_disabled", "import ssl\ndef f(ctx):\n    return ctx.verify_mode == ssl.CERT_NONE\n"),
    ("py.tls.verify_disabled", "import ssl\nctx = ssl.create_default_context()\nctx.check_hostname = True\n"),
    ("py.crypto.weak_hash", "import hashlib\ndigest = hashlib.sha256(b'x')\n"),
    ("py.crypto.weak_hash", "import hashlib\ndigest = hashlib.new('sha256')\n"),
    ("py.crypto.insecure_random", "import random\njitter = random.random()\n"),
    ("py.crypto.insecure_random", "import secrets\ntoken = secrets.token_urlsafe(32)\n"),
    ("py.crypto.insecure_random", "import random\napi_token = random.SystemRandom().getrandbits(128)\n"),
    ("py.crypto.insecure_random", "import random\nsort_key = random.random()\n"),
    ("py.crypto.insecure_random", "import random\ndef pick_color():\n    return random.choice(['red'])\n"),
    ("py.tempfile.mktemp", "import tempfile\nfd, path = tempfile.mkstemp()\n"),
    ("py.flask.debug", "from flask import Flask\napp = Flask(__name__)\napp.run(debug=False)\n"),
    (
        "py.flask.debug",
        "import os\nfrom flask import Flask\napp = Flask(__name__)\napp.run(debug=os.environ.get('D') == '1')\n",
    ),
    ("py.flask.debug", "import uvicorn\nuvicorn.run('a:app', debug=True)\n"),
    ("py.flask.debug", "DEBUG = True\n"),
    ("py.jwt.no_verify", "import jwt\ndef f(t, k):\n    return jwt.decode(t, k, algorithms=['RS256'])\n"),
    (
        "py.jwt.no_verify",
        "import jwt\ndef f(t, k):\n    return jwt.decode(t, k, options={'verify_exp': False}, algorithms=['RS256'])\n",
    ),
    ("py.xml.unsafe_parser", "import xml.etree.ElementTree as ET\nroot = ET.fromstring('<a/>')\n"),
    ("py.xml.unsafe_parser", "import defusedxml.ElementTree as ET\ndef f(d):\n    return ET.fromstring(d)\n"),
    # The standard-library parsers do not resolve external entities by default (Python docs, XML vulnerabilities).
    ("py.xml.unsafe_parser", "import xml.etree.ElementTree as ET\ndef f(data):\n    return ET.fromstring(data)\n"),
    (
        "py.xml.unsafe_parser",
        "from xml.dom import minidom, pulldom\ndef f(d):\n    return minidom.parseString(d), pulldom.parseString(d)\n",
    ),
    ("py.xml.unsafe_parser", "import xml.sax\ndef f(fh, h):\n    xml.sax.parse(fh, h)\n"),
    ("py.xml.unsafe_parser", "from lxml import etree\np = etree.XMLParser(resolve_entities=False, no_network=True)\n"),
    ("py.xml.unsafe_parser", "from lxml import etree\ndef f(d):\n    return etree.fromstring(d)\n"),
    (
        "py.xml.unsafe_parser",
        "import xml.sax\nfrom xml.sax.handler import feature_external_ges\np = xml.sax.make_parser()\np.setFeature(feature_external_ges, False)\n",
    ),
    (
        "py.xml.unsafe_parser",
        "import xml.sax\np = xml.sax.make_parser()\np.setFeature('http://xml.org/sax/features/namespaces', True)\n",
    ),
    ("py.assert.security", "def f(x):\n    assert x is not None\n"),
    ("py.path.traversal", "def f(name):\n    return open(name).read()\n"),
    (
        "py.path.traversal",
        "from flask import request\nfrom werkzeug.utils import secure_filename\ndef f():\n    return open(secure_filename(request.args['n']))\n",
    ),
    (
        "py.path.traversal",
        "import os\nfrom flask import request\ndef f():\n    p = os.path.realpath(os.path.join('/d', request.args['n']))\n    if not p.startswith('/d/'):\n        raise ValueError\n    return open(p)\n",
    ),
    (
        "py.path.traversal",
        "from flask import request, send_from_directory\ndef f():\n    return send_from_directory('/d', request.args['n'])\n",
    ),
    ("py.path.traversal", "import sys\ndef main():\n    return open(sys.argv[1]).read()\n"),
    ("py.path.traversal", "def f():\n    return open(input('file? ')).read()\n"),
    (
        "py.path.traversal",
        "from pathlib import Path\nfrom flask import request\ndef f():\n    p = (Path('/d') / request.args['n']).resolve()\n    if not p.is_relative_to('/d'):\n        raise ValueError\n    return p.read_text()\n",
    ),
    (
        "py.path.traversal",
        "import os\nfrom flask import request\ndef f():\n    name = os.path.basename(request.args['n'])\n    return open(os.path.join('/d', name))\n",
    ),
    ("py.ssrf.request", "import os, requests\ndef f():\n    return requests.get(os.environ.get('API_URL'))\n"),
    (
        "py.ssrf.request",
        "import requests\nfrom flask import request\ndef f():\n    return requests.get(f'https://api.example.com/items/{request.args[\"id\"]}')\n",
    ),
    ("py.ssrf.request", "import requests\ndef f(url):\n    return requests.get(url, timeout=5)\n"),
    (
        "py.ssrf.request",
        "import requests\nfrom flask import request\ndef f():\n    return requests.post('https://api.example.com', json=request.json)\n",
    ),
    ("py.redirect.open", "from flask import redirect, url_for\ndef f():\n    return redirect(url_for('index'))\n"),
    (
        "py.redirect.open",
        "from flask import redirect, request\ndef f():\n    return redirect('/profile/' + request.args['user'])\n",
    ),
    (
        "py.xss.markup",
        "from markupsafe import Markup, escape\nfrom flask import request\ndef f():\n    return Markup(escape(request.args['m']))\n",
    ),
    ("py.xss.markup", "from markupsafe import Markup\ndef f(name):\n    return Markup('<b>%s</b>' % name)\n"),
    (
        "py.xss.markup",
        "from flask import render_template, request\ndef f():\n    return render_template('p.html', name=request.args['n'])\n",
    ),
    ("py.llm.output_to_sink", "import anthropic\ndef f(r):\n    return eval(r)\n"),
    (
        "py.llm.output_to_sink",
        "import json\nimport anthropic\nc = anthropic.Anthropic()\ndef f(p):\n    r = c.messages.create(model='m', max_tokens=9, messages=p)\n    return json.loads(r.content[0].text)\n",
    ),
    (
        "py.llm.output_to_sink",
        "def f(client, p):\n    r = client.messages.create(messages=p)\n    return eval(r.content[0].text)\n",
    ),
    (
        "py.xss.reflected",
        "from flask import request\nfrom markupsafe import escape\ndef f():\n    return f\"<p>{escape(request.args['q'])}</p>\"\n",
    ),
    ("py.xss.reflected", "from flask import request\ndef f():\n    return f\"Hello {request.args['q']}\"\n"),
    (
        "py.xss.reflected",
        "from fastapi import FastAPI\napp = FastAPI()\n@app.get('/h')\ndef h(name: str):\n    return f'<p>{name}</p>'\n",
    ),
    (
        "py.ldap.injection",
        "import ldap\nfrom ldap.filter import escape_filter_chars\nfrom flask import request\ndef f(c):\n    c.search_s('dc=x', ldap.SCOPE_SUBTREE, '(cn=%s)' % escape_filter_chars(request.args['n']))\n",
    ),
    (
        "py.ldap.injection",
        "import ldap\nfrom ldap.filter import filter_format\nfrom flask import request\ndef f(c):\n    c.search_s('dc=x', ldap.SCOPE_SUBTREE, filter_format('(cn=%s)', [request.args['n']]))\n",
    ),
    (
        "py.xpath.injection",
        "from lxml import etree\nfrom flask import request\ndef f(t):\n    return t.xpath('//a[@id=$i]', i=request.args['i'])\n",
    ),
    (
        "py.xpath.injection",
        "import xml.etree.ElementTree as ET\nfrom flask import request\ndef f(text):\n    return text.find(request.args['needle'])\n",
    ),
    (
        "py.cookie.insecure",
        "from flask import make_response\nr = make_response('')\nr.set_cookie('sid', 'v', secure=True, httponly=True)\n",
    ),
    (
        "py.cookie.insecure",
        "from flask import make_response\nr = make_response('')\nr.set_cookie('sid', '', expires=0)\n",
    ),
    ("py.cookie.insecure", "from flask import make_response\ndef f(r, opts):\n    r.set_cookie('sid', 'v', **opts)\n"),
    (
        "py.trust_boundary.session",
        "from flask import request, session\ndef f():\n    session['uid'] = int(request.form['uid'])\n",
    ),
    (
        "py.trust_boundary.session",
        "from flask import abort, request, session\nPLANS = {'free', 'pro'}\ndef f():\n    plan = request.form['plan']\n    if plan not in PLANS:\n        abort(400)\n    session['plan'] = plan\n",
    ),
    ("py.ml.unsafe_model_load", "import torch\nm = torch.load('model.pt', weights_only=True)\n"),
    ("py.ml.unsafe_model_load", "import tensorflow as tf\nm = tf.keras.models.load_model('m.keras')\n"),
    ("py.ml.unsafe_model_load", "from transformers import AutoModel\nm = AutoModel.from_pretrained('org/m')\n"),
    ("py.ml.unsafe_model_load", "import pickle\ndef f(fh):\n    return pickle.load(fh)\n"),
    (
        "py.archive.extract",
        "import tarfile\ndef f(p):\n    with tarfile.open(p) as tar:\n        tar.extractall('out', filter='data')\n",
    ),
    (
        "py.archive.extract",
        "import tarfile\ndef f(p, safe):\n    with tarfile.open(p) as tar:\n        tar.extractall('out', members=safe(tar))\n",
    ),
    (
        "py.archive.extract",
        "import zipfile\ndef f(p):\n    with zipfile.ZipFile(p) as z:\n        z.extractall('out')\n",
    ),
    ("py.archive.extract", "import tarfile\ndef f(box):\n    box.extractall('out')\n"),
]


@pytest.mark.parametrize(("rule_id", "source"), POSITIVE)
def test_rule_fires(rule_id: str, source: str) -> None:
    assert rule_id in ids(source)


@pytest.mark.parametrize(("rule_id", "source"), NEGATIVE)
def test_rule_stays_quiet(rule_id: str, source: str) -> None:
    assert rule_id not in ids(source)


def test_every_python_rule_has_positive_and_negative_cases() -> None:
    python_rules = {rule.id for rule in RULES.values() if rule.language == "python"}
    assert {rule_id for rule_id, _ in POSITIVE} == python_rules
    assert {rule_id for rule_id, _ in NEGATIVE} == python_rules


def severity_of(source: str, rule_id: str) -> str | None:
    (hit,) = [hit for hit in hits(source) if hit.rule_id == rule_id]
    return hit.severity


def test_fixed_shell_command_is_not_reported() -> None:
    # A command that is provably constant cannot be injected into, as for os.system and eval.
    assert "py.subprocess.shell_true" not in ids("import subprocess\nsubprocess.run('ls -l', shell=True)\n")
    assert (
        severity_of("import subprocess\ndef f(c):\n    subprocess.run(c, shell=True)\n", "py.subprocess.shell_true")
        is None
    )


def test_weak_hash_declared_as_checksum_is_not_reported() -> None:
    assert ids("import hashlib\nh = hashlib.md5(b'x', usedforsecurity=False)\n") == set()
    assert ids("import hashlib\nh = hashlib.new('sha1', b'x', usedforsecurity=False)\n") == set()
    assert "py.crypto.weak_hash" in ids("import hashlib\nh = hashlib.md5(b'x', usedforsecurity=True)\n")


def test_settings_module_debug_flag() -> None:
    assert "py.flask.debug" in ids("DEBUG = True\n", rel="mysite/settings.py")
    assert "py.flask.debug" in ids("DEBUG = True\n", rel="mysite/settings/production.py")
    assert "py.flask.debug" not in ids("def f():\n    DEBUG = True\n", rel="mysite/settings.py")
    assert "py.flask.debug" not in ids("DEBUG = False\n", rel="settings.py")


def test_asserts_in_tests_are_ignored() -> None:
    source = "def test_admin(user):\n    assert user.is_admin\n"
    assert "py.assert.security" not in ids(source, rel="tests/test_views.py")
    assert "py.assert.security" not in ids(source, rel="pkg/test_views.py")


def test_location_and_snippet() -> None:
    (hit,) = hits("import os\n\ndef f(n):\n    os.system('rm ' + n)\n")
    assert (hit.line, hit.column, hit.end_line) == (4, 5, 4)
    assert hit.snippet == "os.system('rm ' + n)"


def test_one_hit_per_rule_per_line() -> None:
    source = "import os\nfrom flask import request\ndef f():\n    return open(os.path.join('/d', request.args['n']))\n"
    assert [hit.rule_id for hit in hits(source)] == ["py.path.traversal"]


def test_syntax_error_is_reported_not_raised() -> None:
    assert check_python("def broken(:\n", "x.py") == "syntax_error"
    assert check_python("x = 1\0\n", "x.py") == "syntax_error"


def test_deep_nesting_is_bounded() -> None:
    deep = "x = " + "(" * 400 + "1" + ")" * 400 + "\n"
    assert check_python(deep, "x.py") in ("too_complex", "syntax_error", [])
    chain = "import os\ndef f(n):\n    os.system(" + " + ".join(["'a'"] * 3000) + " + n)\n"
    result = check_python(chain, "x.py")
    assert result == "too_complex" or isinstance(result, list)


def test_secret_like_names() -> None:
    assert secret_like("api_token") and secret_like("resetKey") and secret_like("OTP")
    assert not secret_like("sort_key") and not secret_like("monkey") and not secret_like("tokenizer")
