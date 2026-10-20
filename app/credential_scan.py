"""共享凭据检查；只豁免有限数值代次语法，字符串与日志赋值继续拦截。"""
import re
import ast
import unicodedata
from pathlib import PurePosixPath

# 值使用有界前瞻：匹配游标停在字段头之后，继续扫描同一表达式内的其他凭据字段。
# 最长运算符优先，避免把 !== 的最后一个等号算进值。
ASSIGNMENT = re.compile(
    rb"""(?im)(?<![A-Za-z0-9_-])["']?(?P<field>[A-Za-z_][A-Za-z0-9_-]*?(?:password|passwd|secret|token|api[_-]?key|access[_-]?key)|password|passwd|secret|token|api[_-]?key|access[_-]?key)["']?[ \t]*(?P<separator>===|!==|==|!=|<=|>=|:|=(?!=))(?:[ \t]*(?:(?:\\[ \t]*|(?:\#|//)[^\r\n]*\r?\n)[ \t]*))*\s*(?=(?P<value>["']?[^\r\n,;]{1,2048}))"""
)
COMPARISONS = {b'===', b'!==', b'==', b'!=', b'<=', b'>='}

FIXED = re.compile(rb'(?im)(-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]{0,65536}?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\Z)|Bearer\s+[A-Za-z0-9._~+/-]{12,}|://[^\s/:]+:[^\s/@]+@|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|(?<![A-Za-z0-9_-])sk-[A-Za-z0-9_-]{20,})')
FENCING_SCALAR = re.compile(rb"""(?:[+-]?[0-9]+|True|False|true|false|None|null|Infinity|-Infinity|NaN|float\(["'](?:inf|-inf|nan)["']\))\s*[)}\]]*$""")
ANNOTATION = re.compile(rb'(?:int|bool|float)\s*(?:[)}\]]*)$')
TYPE_NAME = rb'(?:string|str|number|int|integer|float|boolean|bool|bytes|byte|bytearray|object|unknown|any|never|undefined|null|none|void|bigint|symbol|u(?:8|16|32|64|128|size)|i(?:8|16|32|64|128|size)|f(?:32|64)|list|dict|tuple|set|frozenset|type|array|readonlyarray)'
TYPE_ATOM = rb'(?:' + TYPE_NAME + rb')(?:\s*(?:\[\s*\]|\[\s*' + TYPE_NAME + rb'\s*\]|<\s*' + TYPE_NAME + rb'\s*>))*\??'
TYPE_ANNOTATION = re.compile(
    rb'^\s*(?:readonly\s+)?' + TYPE_ATOM +
    rb'(?:\s*(?:\||&)\s*' + TYPE_ATOM + rb')*\s*[)}\]]*\s*'
    rb'(?:(?:->\s*' + TYPE_ATOM + rb'\s*:?)|)$', re.I
)


def _source_language(path):
    suffix = PurePosixPath(str(path or '')).suffix.lower()
    if suffix == '.py':
        return 'python'
    if suffix in {'.ts', '.tsx', '.js', '.jsx'}:
        return 'typescript'
    return 'text'


def _skip_source_trivia(data, index, limit, language):
    while index < limit:
        if data[index:index + 1] in b' \t\r\n':
            index += 1
            continue
        if language == 'python' and data[index:index + 2] == b'\\\n':
            index += 2
            continue
        if language == 'python' and data[index:index + 3] == b'\\\r\n':
            index += 3
            continue
        if language == 'python' and data[index:index + 1] == b'#':
            newline = data.find(b'\n', index, limit)
            if newline < 0:
                return limit
            index = newline + 1
            continue
        if language == 'typescript' and data[index:index + 2] == b'//':
            newline = data.find(b'\n', index, limit)
            if newline < 0:
                return limit
            index = newline + 1
            continue
        if language == 'typescript' and data[index:index + 2] == b'/*':
            close = data.find(b'*/', index + 2, limit)
            if close < 0:
                return limit
            index = close + 2
            continue
        break
    return index


def _scan_source_expression(data, start, language, comparison=False):
    """Bound one value by syntax separators, including balanced multiline expressions."""
    limit = min(len(data), start + 2 * 1024 * 1024)
    start = _skip_source_trivia(data, start, limit, language)
    if start >= limit:
        return start, start
    pairs = {ord('('): ord(')'), ord('['): ord(']'), ord('{'): ord('}')}
    stack = []
    quote = None
    index = start
    previous = None
    continuation = b'+-*/%&|^=<>?:,.\\'
    while index < limit:
        current = data[index]
        if quote is not None:
            if current == ord('\\'):
                index += 2
                continue
            if current == quote:
                quote = None
            index += 1
            previous = current
            continue
        if language == 'python' and current == ord('#'):
            newline = data.find(b'\n', index, limit)
            if newline < 0:
                break
            if not stack:
                break
            index = newline + 1
            previous = ord('\n')
            continue
        if language == 'typescript' and data[index:index + 2] == b'//':
            newline = data.find(b'\n', index, limit)
            if newline < 0:
                break
            if not stack:
                break
            index = newline + 1
            previous = ord('\n')
            continue
        if language == 'typescript' and data[index:index + 2] == b'/*':
            close = data.find(b'*/', index + 2, limit)
            if close < 0:
                break
            index = close + 2
            continue
        if comparison and not stack:
            if data[index:index + 2] in {b'||', b'&&'}:
                break
            if language == 'python':
                word = re.match(rb'(?:and|or)\b', data[index:limit])
                if word and (index == start or data[index - 1:index] not in
                             b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_'):
                    break
        if current in (ord('"'), ord("'"), ord('`')):
            quote = current
        elif current in pairs:
            stack.append(pairs[current])
        elif current in (ord(')'), ord(']'), ord('}')):
            if not stack:
                break
            if stack[-1] != current:
                break
            stack.pop()
            index += 1
            previous = current
            continue
        elif current in (ord(','), ord(';')) and not stack:
            break
        elif current in (ord('\n'), ord('\r')) and not stack:
            if language != 'python' and previous not in continuation:
                break
            if language == 'python' and previous not in continuation:
                following = _skip_source_trivia(data, index + 1, limit, language)
                if data[following:following + 2] not in {b'and', b'or', b'==', b'!=', b'+ ', b'| ', b'& '}:
                    break
        previous = current
        index += 1
    end = index
    if not comparison:
        while end > start and data[end - 1:end] in b' \t\r\n':
            end -= 1
    return start, max(start, end)


class _SourceMatch:
    """Expose a syntax-bounded value while retaining the original field offsets."""
    def __init__(self, data, match, path):
        self._data = data
        self._match = match
        self._language = _source_language(path)
        self._value_start, self._value_end = _scan_source_expression(
            data, match.start('value'), self._language,
            comparison=match['separator'] in COMPARISONS)

    def __getitem__(self, name):
        if name == 'value':
            return self._data[self._value_start:self._value_end]
        return self._match[name]

    def group(self, name):
        return self[name]

    def start(self, name=None):
        return self._value_start if name == 'value' else self._match.start(0 if name is None else name)

    def end(self, name=None):
        return self._value_end if name == 'value' else self._match.end(0 if name is None else name)

    def span(self, name=None):
        return (self.start(name), self.end(name))


def _literal_token(data, start, end, language):
    index = start
    if language == 'python':
        prefix = re.match(rb'(?i:(?:br|rb|fr|rf|b|r|f|u))(?=["\'])', data[index:end])
        if prefix:
            index += prefix.end()
    if index >= end or data[index:index + 1] not in (b'"', b"'", b'`'):
        return None
    quote = data[index:index + 1]
    triple = language == 'python' and data[index:index + 3] == quote * 3
    width = 3 if triple else 1
    content_start = index + width
    cursor = content_start
    while cursor < end:
        if data[cursor:cursor + 1] == b'\\':
            cursor += 2
            continue
        if data[cursor:cursor + width] == quote * width:
            return index, content_start, cursor, cursor + width
        if not triple and data[cursor:cursor + 1] in (b'\n', b'\r'):
            break
        cursor += 1
    return index, content_start, end, end


def _single_literal(data, start, end, language):
    token = _literal_token(data, start, end, language)
    if token is None:
        return None
    _, content_start, content_end, token_end = token
    tail = _skip_source_trivia(data, token_end, end, language)
    if tail != end:
        return None
    return content_start, content_end


def _literal_boundary(data, token_end, end, language):
    cursor = _skip_source_trivia(data, token_end, end, language)
    return data[cursor:cursor + 2], data[cursor:cursor + 1]


def _safe_empty_literal(match, path):
    language = _source_language(path)
    value = match['value']
    start, end = match.span('value')
    token = _literal_token(match._data, start, end, language)
    if token is None:
        return False
    _, content_start, content_end, token_end = token
    if content_start != content_end:
        return False
    pair, one = _literal_boundary(match._data, token_end, end, language)
    separator = match['separator']
    if separator in COMPARISONS:
        return pair in {b'||', b'&&'} or one in {b',', b')', b'}', b']', b';'} or not one
    if separator in {b'=', b':'}:
        return one in {b',', b')', b'}', b']', b';'} or not one
    return False


PLACEHOLDER_LITERAL = re.compile(
    rb'(?i)(?:test|example|sample|dummy|fake|placeholder)'
    rb'[-_](?:token|secret|password|api[-_]?key)\Z'
)


def _safe_placeholder_literal(match, path):
    start, end = match.span('value')
    language = _source_language(path)
    if language not in {'python', 'typescript'}:
        return False
    literal = _single_literal(match._data, start, end, language)
    if literal is None:
        return False
    content_start, content_end = literal
    value = match._data[content_start:content_end]
    return PLACEHOLDER_LITERAL.fullmatch(value) is not None


def _is_ui_label(value):
    try:
        text = value.decode('utf-8').strip()
    except UnicodeDecodeError:
        return False
    if not text or len(text) > 40 or not any('\u3400' <= char <= '\u9fff' for char in text):
        return False
    return all(char.isspace() or unicodedata.category(char)[0] in {'L', 'M', 'N'}
               for char in text)


def _typescript_object_label_fields(data, field_start):
    masked = _mask_typescript_literals(data).decode('latin-1')
    stack = []
    for index, character in enumerate(masked[:field_start]):
        if character == '{':
            stack.append(index)
        elif character == '}' and stack:
            stack.pop()
    if not stack:
        return None
    opening = stack[-1]
    depth = 1
    closing = opening + 1
    while closing < len(masked) and depth:
        if masked[closing] == '{':
            depth += 1
        elif masked[closing] == '}':
            depth -= 1
        closing += 1
    if depth:
        return None
    boundaries = [(masked.rfind(token, 0, opening), token)
                  for token in (';', '}', '=', ':', 'return')]
    prefix_start, boundary = max(boundaries, key=lambda item: item[0])
    if boundary not in {'=', ':', 'return'}:
        return None

    entries = {}
    cursor = opening + 1
    while cursor < closing - 1:
        cursor = _skip_source_trivia(data, cursor, closing - 1, 'typescript')
        while cursor < closing - 1 and data[cursor:cursor + 1] == b',':
            cursor = _skip_source_trivia(data, cursor + 1, closing - 1, 'typescript')
        if cursor >= closing - 1:
            break
        key = re.match(rb'[A-Za-z_$][A-Za-z0-9_$]*', data[cursor:closing - 1])
        if key is None:
            return None
        name = key.group().decode('ascii')
        cursor += key.end()
        cursor = _skip_source_trivia(data, cursor, closing - 1, 'typescript')
        if data[cursor:cursor + 1] != b':':
            return None
        value_start = _skip_source_trivia(data, cursor + 1, closing - 1, 'typescript')
        token = _literal_token(data, value_start, closing - 1, 'typescript')
        if token is None:
            value_start, value_end = _scan_source_expression(data, value_start, 'typescript')
            value = None
        else:
            _, content_start, content_end, token_end = token
            value = data[content_start:content_end]
            value_end = token_end
        entries[name] = value
        cursor = _skip_source_trivia(data, value_end, closing - 1, 'typescript')
        if cursor < closing - 1 and data[cursor:cursor + 1] != b',':
            return None
    return entries


def _safe_typescript_ui_label(data, match):
    if match['field'].lower() != b'password':
        return False
    entries = _typescript_object_label_fields(data, match.start('field'))
    if not entries or not {'email', 'password', 'totp'} <= entries.keys():
        return False
    labels = [entries[name] for name in ('email', 'password', 'totp')]
    if not all(value is not None and _is_ui_label(value) for value in labels):
        return False
    password_label = entries['password'].decode('utf-8').strip()
    if password_label not in {'密码', '口令', '登录密码', '账户密码', '用户密码'}:
        return False
    start, end = match.span('value')
    literal = _single_literal(data, start, end, 'typescript')
    return (literal is not None and entries.get('password') is not None
            and data[literal[0]:literal[1]] == entries['password'])


def is_type_annotation(value):
    """Recognize only primitive type declarations, never arbitrary identifier values."""
    return TYPE_ANNOTATION.fullmatch(value) is not None


def non_secret_scalar(value):
    if FENCING_SCALAR.fullmatch(value):
        return True
    if len(value) > 512:
        return False
    text = value.decode('ascii', errors='replace').split('#', 1)[0].strip()
    def numeric(node):
        if isinstance(node, ast.Constant):
            return type(node.value) in {int, float, bool} or node.value is None
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub)):
            return numeric(node.operand)
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Sub, ast.Mult, ast.Pow, ast.Div, ast.FloorDiv)):
            return numeric(node.left) and numeric(node.right)
        return False
    # 不求值数值表达式，避免溢出样例本身消耗资源。
    for _ in range(4):
        try:
            return numeric(ast.parse(text, mode='eval').body)
        except (SyntaxError, ValueError, RecursionError):
            if text.endswith((')', '}', ']')):
                text = text[:-1].rstrip()
            else:
                return False
    return False


def counter_declaration(data, match):
    """返回数值 ++/-- 的标识符；仅识别有限 const/let 声明，不做 JS 类型推断。"""
    if match['separator'] != b'=' or match['field'].lower() not in {b'token', b'retrytoken', b'generationtoken'}:
        return None
    start = data.rfind(b'\n', 0, match.start()) + 1
    if not re.fullmatch(rb'[ \t]*(?:const|let)[ \t]+', data[start:match.start()]):
        return None
    found = re.fullmatch(rb'(?:\+\+|--)([A-Za-z_$][A-Za-z0-9_$]*)(?:[ \t]*[)}\]]*)?', match['value'].strip())
    return found.group(1) if found else None


def non_secret_counter_declaration(data, match):
    return counter_declaration(data, match) is not None


def non_secret_counter_comparison(match, prior):
    # 普通 token 日志、密码比较和字符串比较不豁免；必须先有上述明确数值声明。
    if match['separator'] not in COMPARISONS or match['field'].lower() not in {b'token', b'retrytoken', b'generationtoken'}:
        return False
    if prior is None:
        return False
    # 只允许独立数值或先前 ++/-- 的同一个符号；禁止拼接、调用、属性和字符串。
    atom = re.match(rb'(?:[+-]?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?n?|'+re.escape(prior)+rb')(?=\s*(?:[)}\];,]|$))', match['value'].strip())
    return atom is not None


PYTHON_TYPE_NAMES = {
    'str', 'string', 'bytes', 'byte', 'bytearray', 'int', 'integer', 'float',
    'bool', 'boolean', 'object', 'type', 'none', 'mapped', 'list', 'dict', 'tuple',
    'set', 'frozenset', 'optional', 'union', 'sequence', 'iterable',
}


def _safe_python_type(node):
    if isinstance(node, ast.Name):
        return node.id.lower() in PYTHON_TYPE_NAMES
    if isinstance(node, ast.Constant):
        return node.value is None
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        return _safe_python_type(node.left) and _safe_python_type(node.right)
    if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name):
        return node.value.id.lower() in PYTHON_TYPE_NAMES and _safe_python_type(node.slice)
    if isinstance(node, ast.Tuple):
        return all(_safe_python_type(item) for item in node.elts)
    return False


def _safe_object_reference(node):
    """Recognize an object receiver for a known method, without approving a value."""
    if isinstance(node, ast.Name):
        return True
    if isinstance(node, ast.Attribute):
        return _safe_object_reference(node.value)
    if isinstance(node, ast.Subscript):
        return (_safe_object_reference(node.value) and isinstance(node.slice, ast.Constant)
                and isinstance(node.slice.value, (str, int)))
    return False


def _safe_runtime_call(node):
    """Allow only known runtime transformations used to create or encode values."""
    function = node.func
    if isinstance(function, ast.Name):
        return function.id in {'new_totp_secret', 'password_hash', 'len'}
    if not isinstance(function, ast.Attribute):
        return False
    if function.attr == 'removeprefix':
        return (_safe_object_reference(function.value) and len(node.args) == 1
                and not node.keywords and isinstance(node.args[0], ast.Constant)
                and node.args[0].value == 'Bearer ')
    if function.attr in {'encode', 'decode', 'encrypt', 'decrypt'}:
        return (_safe_object_reference(function.value)
                or function.attr in {'encode', 'decode'}
                and _safe_runtime_expression(function.value))
    if function.attr == 'token_urlsafe':
        return isinstance(function.value, ast.Name) and function.value.id == 'secrets'
    if function.attr == 'from_bytes':
        return isinstance(function.value, ast.Name) and function.value.id == 'int'
    if function.attr == 'b32decode':
        return isinstance(function.value, ast.Name) and function.value.id == 'base64'
    if function.attr == 'new':
        return isinstance(function.value, ast.Name) and function.value.id == 'hmac'
    if function.attr == 'sha1':
        return isinstance(function.value, ast.Name) and function.value.id == 'hashlib'
    return False


def _safe_runtime_argument(node):
    """Allow data references only inside an explicitly approved runtime call."""
    if _safe_object_reference(node):
        return True
    if isinstance(node, ast.Slice):
        return all(part is None or _safe_runtime_argument(part)
                   for part in (node.lower, node.upper, node.step))
    if isinstance(node, ast.Subscript):
        return (_safe_object_reference(node.value)
                and _safe_runtime_argument(node.slice))
    if isinstance(node, ast.BinOp) and isinstance(
            node.op, (ast.Add, ast.Sub, ast.Mult, ast.Pow, ast.Div, ast.FloorDiv,
                      ast.Mod, ast.BitAnd, ast.BitOr, ast.BitXor, ast.LShift, ast.RShift)):
        return _safe_runtime_argument(node.left) and _safe_runtime_argument(node.right)
    return _safe_runtime_expression(node, True)


def _safe_runtime_expression(node, allow_format_constants=False):
    """Accept references and narrow computations without embedded credential text."""
    if isinstance(node, ast.Constant):
        if type(node.value) in {int, float, bool} or node.value is None:
            return True
        return (allow_format_constants and isinstance(node.value, str)
                and node.value in {'=', 'big', 'little', 'Bearer '})
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub, ast.Invert)):
        return _safe_runtime_expression(node.operand, allow_format_constants)
    if isinstance(node, ast.Slice):
        return all(part is None or _safe_runtime_expression(part, allow_format_constants)
                   for part in (node.lower, node.upper, node.step))
    if isinstance(node, ast.Subscript):
        return (_safe_object_reference(node.value)
                and _safe_runtime_expression(node.slice, allow_format_constants))
    if isinstance(node, ast.BinOp) and isinstance(
            node.op, (ast.Add, ast.Sub, ast.Mult, ast.Pow, ast.Div, ast.FloorDiv,
                      ast.Mod, ast.BitAnd, ast.BitOr, ast.BitXor, ast.LShift, ast.RShift)):
        def operand(value):
            return (_safe_runtime_expression(value, True)
                    or _safe_object_reference(value))
        return operand(node.left) and operand(node.right)
    if isinstance(node, ast.Call) and _safe_runtime_call(node):
        if (isinstance(node.func, ast.Attribute) and node.func.attr == 'removeprefix'
                and len(node.args) == 1 and not node.keywords):
            return True
        if not all(_safe_runtime_argument(argument) for argument in node.args):
            return False
        return all(keyword.arg is not None and
                   _safe_runtime_argument(keyword.value)
                   for keyword in node.keywords)
    return False


def _safe_mapped_column(node):
    """Accept a typed ORM column declaration with only static non-secret metadata."""
    if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
        return False
    if node.func.id != 'mapped_column' or not node.args:
        return False
    column_types = {'Text', 'String', 'Integer', 'Boolean', 'LargeBinary',
                    'JSON', 'DateTime', 'UUID', 'Float', 'Numeric'}
    first = node.args[0]
    if not isinstance(first, ast.Name) or first.id not in column_types:
        return False
    if any(not isinstance(value, (ast.Constant, ast.List, ast.Tuple, ast.Set))
           for value in node.args[1:]):
        return False
    if any(keyword.arg not in {'nullable', 'unique', 'index', 'primary_key', 'autoincrement'}
           for keyword in node.keywords):
        return False

    def static_metadata(value):
        if isinstance(value, ast.Constant):
            return type(value.value) in {int, float, bool} or value.value is None
        if isinstance(value, (ast.List, ast.Tuple, ast.Set)):
            return all(static_metadata(item) for item in value.elts)
        return False

    return (all(static_metadata(value) for value in node.args[1:])
            and all(static_metadata(keyword.value) for keyword in node.keywords))


def _safe_field_metadata(node):
    if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name) or node.func.id != 'Field':
        return False

    def scalar(value):
        if isinstance(value, ast.Constant):
            return type(value.value) in {int, float, bool} or value.value is None
        if isinstance(value, (ast.List, ast.Tuple, ast.Set)):
            return all(scalar(item) for item in value.elts)
        return False

    for argument in node.args:
        if not scalar(argument):
            return False
    for keyword in node.keywords:
        if keyword.arg is None or re.search(r'password|passwd|secret|token|api[_-]?key|access[_-]?key', keyword.arg, re.I):
            return False
        if not scalar(keyword.value):
            return False
    return True


def _canonical_field(value):
    return value.lower().lstrip('_').encode()


def _python_source_nodes(tree):
    by_line = {}
    functions = {}
    relevant = (ast.arg, ast.AnnAssign, ast.Assign, ast.keyword, ast.If, ast.While,
                ast.Dict, ast.Attribute, ast.Name, ast.Compare, ast.ExceptHandler)
    parents = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parents[id(child)] = parent

    def owner_class(node):
        parent = parents.get(id(node))
        while parent is not None and not isinstance(parent, ast.ClassDef):
            parent = parents.get(id(parent))
        return parent

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            positional = node.args.posonlyargs + node.args.args
            defaults = [None] * (len(positional) - len(node.args.defaults)) + list(node.args.defaults)
            safe_args = set()
            for argument, default in zip(positional, defaults):
                if (_safe_python_type(argument.annotation)
                        and (default is None or isinstance(default, ast.Constant) and default.value is None)):
                    safe_args.add(_canonical_field(argument.arg))
            for argument, default in zip(node.args.kwonlyargs, node.args.kw_defaults):
                if (_safe_python_type(argument.annotation)
                        and (default is None or isinstance(default, ast.Constant) and default.value is None)):
                    safe_args.add(_canonical_field(argument.arg))
            for argument in (node.args.vararg, node.args.kwarg):
                if argument is not None and _safe_python_type(argument.annotation):
                    safe_args.add(_canonical_field(argument.arg))
            aliases = set()
            if node.name == '__init__':
                for child in ast.walk(node):
                    if not isinstance(child, ast.Assign) or len(child.targets) != 1:
                        continue
                    parent = parents.get(id(child))
                    nested_scope = False
                    while parent is not None and parent is not node:
                        if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
                            nested_scope = True
                            break
                        parent = parents.get(id(parent))
                    if nested_scope or parent is not node:
                        continue
                    target, value = child.targets[0], child.value
                    if (isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name)
                            and target.value.id == 'self' and isinstance(value, ast.Name)):
                        name = _canonical_field(value.id)
                        if name in safe_args and _canonical_field(target.attr) == name:
                            aliases.add(name)
            functions[id(node)] = {'node': node, 'owner': owner_class(node),
                                   'safeArgs': safe_args, 'aliases': aliases}
        if isinstance(node, relevant):
            first_line = getattr(node, 'lineno', -1)
            last_line = getattr(node, 'end_lineno', first_line) if isinstance(node, ast.Dict) else first_line
            for line in range(first_line, last_line + 1):
                by_line.setdefault(line, []).append(node)
    class_aliases = {}
    for entry in functions.values():
        if entry['owner'] is not None:
            class_aliases.setdefault(id(entry['owner']), set()).update(entry['aliases'])
    for entry in functions.values():
        entry['classAliases'] = class_aliases.get(id(entry['owner']), set())
    return by_line, functions, parents


def _node_start(node):
    return (getattr(node, 'lineno', -1), getattr(node, 'col_offset', -1))


def _node_end(node):
    return (getattr(node, 'end_lineno', getattr(node, 'lineno', -1)),
            getattr(node, 'end_col_offset', getattr(node, 'col_offset', -1)))


def _within_node(node, line, column):
    start_line, start_column = _node_start(node)
    end_line, end_column = _node_end(node)
    return (start_line, start_column) <= (line, column) <= (end_line, end_column)


def _python_source_match_is_safe(data, match, nodes, functions, parents):
    field = match['field'].decode('ascii', errors='ignore').lower()
    canonical = _canonical_field(field)
    field_start = match.start('field')
    separator_start = match.start('separator')
    line = data.count(b'\n', 0, field_start) + 1
    line_start = data.rfind(b'\n', 0, field_start) + 1
    field_column = field_start - line_start
    separator_column = separator_start - line_start
    separator = match['separator']
    candidates = [node for node in nodes if _within_node(node, line, field_column)]
    current = min(candidates, key=lambda node: (_node_end(node)[0] - _node_start(node)[0],
                                                _node_end(node)[1] - _node_start(node)[1])) if candidates else None
    while current is not None and id(current) not in functions:
        current = parents.get(id(current))
    context = functions.get(id(current)) if current is not None else None

    def target_matches(target):
        if isinstance(target, ast.Name):
            return _canonical_field(target.id) == canonical
        if isinstance(target, ast.Attribute):
            return _canonical_field(target.attr) == canonical
        return False

    def same_reference(value):
        return isinstance(value, ast.Name) and _canonical_field(value.id) == canonical

    def empty_string(value):
        return isinstance(value, ast.Constant) and value.value == ''

    for node in nodes:
        if isinstance(node, ast.ExceptHandler) and node.type is not None:
            if (_within_node(node.type, line, field_column)
                    and isinstance(node.type, (ast.Name, ast.Attribute))
                    and _node_end(node.type) == (line, field_column + len(match['field']))):
                return True

        if isinstance(node, ast.Compare):
            operands = [node.left, *node.comparators]
            for index, operand in enumerate(operands):
                if not isinstance(operand, (ast.Name, ast.Attribute)):
                    continue
                if not (_within_node(operand, line, field_column)
                        and target_matches(operand)
                        and _node_end(operand) == (line, field_column + len(match['field']))):
                    continue
                if index < len(operands) - 1:
                    other = operands[index + 1]
                elif index > 0:
                    other = operands[index - 1]
                else:
                    continue
                operator = node.ops[min(index, len(node.ops) - 1)]
                if isinstance(operator, (ast.Eq, ast.NotEq)) and empty_string(other):
                    return True

    for node in nodes:
        if isinstance(node, ast.arg):
            if (node.arg.lower().encode() == canonical and node.col_offset == field_column
                    and separator == b':' and _safe_python_type(node.annotation)
                    and context is not None and canonical in context['safeArgs']):
                return True
        if isinstance(node, ast.AnnAssign) and node.lineno == line and separator == b':':
            target = node.target
            target_end = _node_end(target)
            field_bytes = match['field']
            target_field_column = target_end[1] - len(field_bytes) if target_end[0] == line else -1
            empty_value = (node.value is None or isinstance(node.value, ast.Constant)
                           and (node.value.value is None or node.value.value == ''))
            mapped_column = (_safe_python_type(node.annotation)
                            and _safe_mapped_column(node.value))
            safe_default = empty_value or _safe_field_metadata(node.value) or mapped_column
            if (target_matches(target) and target_field_column == field_column and safe_default
                    and _safe_python_type(node.annotation)):
                return True

        if isinstance(node, ast.Assign) and node.lineno == line and separator == b'=':
            if (context is not None and node.lineno >= context['node'].lineno
                    and context['node'].name == '__init__' and canonical in context['aliases']
                    and len(node.targets) == 1 and target_matches(node.targets[0])
                    and _node_end(node.targets[0]) == (line, field_column + len(match['field']))
                    and (same_reference(node.value) or _safe_runtime_expression(node.value))):
                return True

        if isinstance(node, ast.Assign) and node.lineno == line and separator == b'=':
            if (len(node.targets) == 1 and target_matches(node.targets[0])
                    and _node_end(node.targets[0]) == (line, field_column + len(match['field']))
                    and _safe_runtime_expression(node.value)):
                return True

        if isinstance(node, ast.Dict) and separator == b':':
            for key, value in zip(node.keys, node.values):
                if not isinstance(key, ast.Constant) or not isinstance(key.value, str):
                    continue
                key_start, key_end = _node_start(key), _node_end(key)
                key_line = data.splitlines()[key_start[0] - 1]
                key_text = key_line[key_start[1]:key_end[1]] if key_start[0] == key_end[0] else b''
                field_offset = key_text.find(match['field'])
                if (isinstance(key, ast.Constant) and isinstance(key.value, str)
                        and _canonical_field(key.value) == canonical
                        and key_start[0] == line and field_offset >= 0
                        and key_start[1] + field_offset == field_column
                    and (_safe_runtime_expression(value)
                         or _safe_object_reference(value))):
                    return True

        if isinstance(node, ast.keyword) and node.lineno == line and separator == b'=':
            if (node.arg is not None and _canonical_field(node.arg) == canonical
                    and node.col_offset == field_column
                    and (same_reference(node.value)
                         or _safe_object_reference(node.value)
                         or _safe_runtime_expression(node.value))):
                return True

        if isinstance(node, (ast.If, ast.While)) and node.lineno == line and separator == b':':
            if context is None or canonical not in (context['aliases'] | context['classAliases']):
                continue
            test_end = _node_end(node.test)
            if test_end[0] == line and test_end[1] <= separator_column:
                line_bytes = data.splitlines()[line - 1]
                if line_bytes[test_end[1]:separator_column].strip() == b'':
                    for child in ast.walk(node.test):
                        if (isinstance(child, ast.Attribute) and _canonical_field(child.attr) == canonical
                                and _within_node(child, line, field_column)):
                            return True
                        if (isinstance(child, ast.Name) and _canonical_field(child.id) == canonical
                                and _within_node(child, line, field_column)):
                            return True
    return False


def _mask_typescript_literals(data):
    # Latin-1 保持字节偏移稳定，掩码字符串、注释与正则字面量
    text = data.decode('latin-1')
    chars = list(text)
    index = 0
    state = 'code'
    # 当 '/' 前面是运算符或关键词时，'/' 为正则表达式字面量起始，而不是除法运算符
    regex_prev_chars = set('=,;:([{!&|?+-*%^~<>')
    in_char_class = False
    while index < len(text):
        current = text[index]
        following = text[index + 1] if index + 1 < len(text) else ''
        if state == 'code':
            if current == '/' and following == '/':
                chars[index] = chars[index + 1] = ' '
                index += 2
                state = 'line_comment'
                continue
            if current == '/' and following == '*':
                chars[index] = chars[index + 1] = ' '
                index += 2
                state = 'block_comment'
                continue
            if current == '/':
                lookback = index - 1
                while lookback >= 0 and text[lookback] in ' \t\r\n':
                    lookback -= 1
                is_regex = False
                if lookback < 0:
                    is_regex = True
                elif text[lookback] in regex_prev_chars:
                    is_regex = True
                else:
                    word_start = lookback
                    while word_start >= 0 and (text[word_start].isalnum() or text[word_start] in '_$'):
                        word_start -= 1
                    word = text[word_start + 1:lookback + 1]
                    if word in {'return', 'case', 'typeof', 'void', 'delete', 'throw', 'yield', 'in', 'instanceof'}:
                        is_regex = True
                if is_regex:
                    state = 'regex'
                    in_char_class = False
                    chars[index] = ' '
                    index += 1
                    continue
            if current in {'"', "'", '`'}:
                state = {'"': 'double', "'": 'single', '`': 'template'}[current]
                chars[index] = ' '
        elif state == 'line_comment':
            if current == '\n':
                state = 'code'
            else:
                chars[index] = ' '
        elif state == 'block_comment':
            if current == '*' and following == '/':
                chars[index] = chars[index + 1] = ' '
                index += 2
                state = 'code'
                continue
            if current != '\n':
                chars[index] = ' '
        elif state == 'regex':
            chars[index] = ' '
            if current == '\\':
                if index + 1 < len(text):
                    chars[index + 1] = ' '
                index += 2
                continue
            if current == '[' and not in_char_class:
                in_char_class = True
            elif current == ']' and in_char_class:
                in_char_class = False
            elif current == '/' and not in_char_class:
                state = 'code'
        else:
            quote = {'double': '"', 'single': "'", 'template': '`'}[state]
            chars[index] = ' ' if current != '\n' else '\n'
            if current == '\\':
                if index + 1 < len(text):
                    if text[index + 1] != '\n':
                        chars[index + 1] = ' '
                    index += 2
                    continue
            elif current == quote:
                state = 'code'
        index += 1
    return ''.join(chars).encode('latin-1')


def _typescript_declaration_ranges(data):
    masked = _mask_typescript_literals(data).decode('latin-1')
    declaration = re.compile(
        r'\b(?:interface\s+[A-Za-z_$][\w$]*(?:\s+extends\s+[^{}]+)?|'
        r'type\s+[A-Za-z_$][\w$]*(?:\s*<[^{}]*>)?\s*=|'
        r'class\s+[A-Za-z_$][\w$]*(?:\s+extends\s+[^{}]+)?)\s*\{'
    )
    ranges = []
    for header in declaration.finditer(masked):
        opening = masked.find('{', header.start(), header.end())
        depth = 1
        cursor = opening + 1
        while cursor < len(masked) and depth:
            if masked[cursor] == '{':
                depth += 1
            elif masked[cursor] == '}':
                depth -= 1
            cursor += 1
        if depth == 0:
            ranges.append((opening + 1, cursor - 1, masked))
    return ranges


def _typescript_source_match_is_safe(data, match, ranges):
    source_match = _SourceMatch(data, match, '.ts')
    if (_safe_empty_literal(source_match, '.ts')
            or _safe_placeholder_literal(source_match, '.ts')
            or _safe_typescript_ui_label(data, match)):
        return True
    start = match.start('field')
    end = match.end('field')
    raw = data.decode('latin-1')
    value = source_match['value'].strip()
    expression = value.decode('latin-1').strip()
    if match['separator'] in {b'=', b':'}:
        jsx = re.fullmatch(r'\{\s*([A-Za-z_$][A-Za-z0-9_$]*(?:(?:\?\.|\.)[A-Za-z_$][A-Za-z0-9_$]*)*)\s*\}\s*/?>?', expression)
        reference = re.fullmatch(r'[A-Za-z_$][A-Za-z0-9_$]*(?:(?:\?\.|\.)[A-Za-z_$][A-Za-z0-9_$]*)*\s*[)}\]]*', expression)
        if jsx or match['separator'] == b':' and reference and not is_type_annotation(value):
            return True
        if match['separator'] == b'=' and reference:
            return True
    if match['separator'] != b':':
        return False
    if is_type_annotation(value):
        for left, right, masked in ranges:
            if left <= start < right and masked[start:end] == raw[start:end]:
                prefix_body = masked[left:start]
                # Only direct fields; nested executable blocks and object values do not qualify.
                if prefix_body.count('{') != prefix_body.count('}'):
                    continue
                line_start = max(masked.rfind('\n', left, start), masked.rfind(';', left, start), left - 1) + 1
                prefix = masked[line_start:start]
                if re.fullmatch(r'\s*(?:(?:readonly|public|private|protected)\s+)*', prefix):
                    return True
    masked = _mask_typescript_literals(data).decode('latin-1')
    type_start = re.match(rb'\s*(' + TYPE_ATOM + rb')(?:\s*[),{]|$)', value)
    if not type_start:
        return False
    stack = []
    for position, character in enumerate(masked[:start]):
        if character == '(':
            stack.append(position)
        elif character == ')' and stack:
            stack.pop()
    if stack:
        opening = stack[-1]
        boundary = max(masked.rfind('{', 0, opening), masked.rfind(';', 0, opening), masked.rfind('}', 0, opening))
        owner = masked[boundary + 1:opening].rstrip()
        if re.search(r'(?:function\s+[\w$]+|(?:async\s+)?[\w$]+(?:\s*<[^;{}]*>)?|(?:const|let|var)\s+[\w$]+\s*=\s*(?:async)?)\s*$', owner):
            return True
    return False


def _safe_source_match_offsets(data, path):
    if not path or ASSIGNMENT.search(data) is None:
        return set()
    suffix = PurePosixPath(str(path)).suffix.lower()
    safe = set()
    if suffix == '.py':
        try:
            tree = ast.parse(data.decode('utf-8'), filename='<source>')
        except (UnicodeDecodeError, SyntaxError, ValueError, RecursionError):
            return safe
        nodes_by_line, functions, parents = _python_source_nodes(tree)
        for raw_match in ASSIGNMENT.finditer(data):
            match = _SourceMatch(data, raw_match, path)
            line = data.count(b'\n', 0, match.start('field')) + 1
            if _python_source_match_is_safe(data, match, nodes_by_line.get(line, ()), functions, parents):
                safe.add(match.start())
    elif suffix in {'.ts', '.tsx', '.js', '.jsx'}:
        ranges = _typescript_declaration_ranges(data)
        for match in ASSIGNMENT.finditer(data):
            if _typescript_source_match_is_safe(data, match, ranges):
                safe.add(match.start())
    return safe


def findings(data, path=None):
    safe_source_matches = _safe_source_match_offsets(data, path)
    for match in FIXED.finditer(data):
        yield match, 'secret.signature', 'credential_signature'
    numeric_counters = {}
    for raw_match in ASSIGNMENT.finditer(data):
        match = _SourceMatch(data, raw_match, path)
        if match.start() in safe_source_matches:
            continue
        if _safe_empty_literal(match, path):
            continue
        if _safe_placeholder_literal(match, path):
            continue
        field = match['field'].lower()
        value = match['value'].strip()
        counter = counter_declaration(data, match)
        if match['separator'] not in COMPARISONS:
            numeric_counters.pop(match['field'], None)
            if counter is not None:
                numeric_counters[match['field']] = counter
        if counter is not None or non_secret_counter_comparison(match, numeric_counters.get(match['field'])):
            continue
        if field == b'fencing_token':
            if non_secret_scalar(value):
                continue
            if match['separator'] == b':' and ANNOTATION.fullmatch(value):
                continue
            if match['separator'] == b':' and b'=' in value:
                annotation, scalar = value.split(b'=', 1)
                if ANNOTATION.fullmatch(annotation.strip()) and non_secret_scalar(scalar.strip()):
                    continue
        # 完整识别比较符；字符串凭据在比较中也不能输出。
        # 保留原有最短值阈值；JSON 及带前缀字段采用同一规则。
        if len(value.strip(b'"\'')) >= 4:
            rule = 'secret.comparison' if match['separator'] in COMPARISONS else 'secret.assignment'
            yield match, rule, 'credential_field'


class Scanner:
    def search(self, data, path=None):
        return next((match for match, _, _ in findings(data, path)), None)


SECRET = Scanner()


def first_finding(data, path=None):
    item = next(findings(data, path), None)
    if item is None:
        return None
    match, rule, category = item
    return {'rule_id': rule, 'field_category': category,
            'line': data.count(b'\n', 0, match.start()) + 1}
