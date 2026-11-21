"""Find returned Kotlin calls on paths without evidence of an ownership check."""
import re
from collections.abc import Callable
from dataclasses import dataclass, field, replace

from tree_sitter import Node

from garden.jdbc_format import static_string
from garden.kotlin_checks import walk, words


def parts(node: Node) -> list[Node]:
    return [c for c in node.named_children if "comment" not in c.type]


def one(node: Node, kind: str) -> Node | None:
    return next((c for c in node.named_children if c.type == kind), None)


@dataclass
class Path:
    locals: dict[str, Node] = field(default_factory=dict)
    facts: dict[tuple, bool] = field(default_factory=dict)
    aliases: dict[tuple, tuple] = field(default_factory=dict)
    # A returned local may have captured a receiver or SQL literal from an inner block.
    call_scopes: dict[Node, dict[str, Node]] = field(default_factory=dict)
    # An otherwise unused call in a val initializer could itself enforce access.
    effects: frozenset[Node] = frozenset()

    def assume(self, fact: tuple, truth: bool):
        if fact[0] == "equals":
            left, right = sorted(self.aliases.get(term, term) for term in fact[1:])
            if left == right:
                return [self] if truth else []
            if truth and left[0] == right[0] == "input":
                # Both names now describe one value, including constraints learned before the comparison.
                aliases = {name: (left if term == right else term) for name, term in self.aliases.items()}
                aliases[right] = left
                joined = replace(self, aliases=aliases, facts={})
                for previous, value in self.facts.items():
                    states = joined.assume(previous, value)
                    if not states:
                        return []
                    joined = states[0]
                return [joined]
            fact = ("equals", left, right)
        elif fact[0] == "below":
            fact = ("below", self.aliases.get(fact[1], fact[1]), fact[2])
        if fact in self.facts:
            return [self] if self.facts[fact] == truth else []
        for other, value in self.facts.items():
            if fact[0] not in {"equals", "below"} or other[0] not in {"equals", "below"} or fact[1] != other[1]:
                continue
            if fact[0] == other[0] == "equals":
                if truth and value and fact[2][0] == other[2][0] == "literal" and fact[2] != other[2]:
                    return []
            elif fact[0] == other[0] == "below":
                if truth != value and (fact[2] <= other[2] if truth else other[2] <= fact[2]):
                    return []
            else:
                equal, below = ((fact, truth), (other, value)) if fact[0] == "equals" else ((other, value), (fact, truth))
                operand = equal[0][2]
                if equal[1] and operand[0] == "literal" and type(operand[1]) is int and (operand[1] < below[0][2]) != below[1]:
                    return []
        return [replace(self, facts=self.facts | {fact: truth})]


OWNERSHIP = {"owns", "isOwner", "isOwnedBy", "canAccess", "canRead", "hasAccess", "hasPermission"}
OWNER_KEYS = {"ownerId", "userId", "tenantId", "accountId", "customerId",
              '"owner_id"', '"user_id"', '"tenant_id"', '"account_id"', '"customer_id"'}
CONSTANTS = {"true", "false", "null"}
RETURN = object()
Unwrap = Callable[[Node, set[str]], Node | None]


@dataclass(frozen=True)
class Binding:
    name: str
    declared_type: bytes | None


class Flow:
    def __init__(self, body: Node, input_name: str, unwrap: Unwrap | None):
        self.input = input_name
        self.unwrap = unwrap
        self.results = []
        self.steps = 0
        self.inputs = {input_name}
        self.integer_inputs = set()
        self.identities = set()
        self.parameter_types = {}
        params = one(body.parent, "function_value_parameters")
        modifiers = []
        for item in parts(params) if params else ():
            if item.type == "parameter_modifiers":
                modifiers = words(item)
            elif item.type == "parameter":
                name = parts(item)[0].text.decode()
                tokens = words(item)[2:]
                self.parameter_types[name] = parts(item)[1].text
                if "AuthenticationPrincipal" in modifiers or set(tokens) & {"Authentication", "Principal", "UserDetails"}:
                    self.identities.add(name)
                elif not modifiers or set(modifiers) & {"RequestParam", "PathVariable", "RequestHeader"}:
                    self.inputs.add(name)
                if len(tokens) == 1 and tokens[0] in {"Long", "Int", "Short", "Byte"}:
                    self.integer_inputs.add(name)
                modifiers = []

    def resolve(self, node: Node, path: Path) -> Node:
        # Local val bindings are immutable and cannot shadow previous bindings in this traversal.
        while node.type in {"identifier", "parenthesized_expression"}:
            if node.type == "identifier":
                value = path.locals.get(node.text.decode())
                if value is None:
                    break
            else:
                value = parts(node)[0]
            node = value
        return node

    def related(self, node: Node, path: Path, depth=0) -> bool:
        value = self.resolve(node, path)
        if value.type == "identifier":
            return value.text.decode() == self.input
        if value.type == "call_expression" and depth < 2:
            args = one(value, "value_arguments")
            target = parts(value)[0]
            if target.type == "navigation_expression":
                receiver = parts(target)[0]
                if receiver.type == "unary_expression" and receiver.children[0].type == "!":
                    receiver = receiver.child_by_field_name("argument")
                if self.related(receiver, path, depth + 1):
                    return True
            return args is not None and any(self.related(parts(a)[-1], path, depth + 1)
                                            for a in parts(args) if a.type == "value_argument")
        return False

    def owner_field(self, node: Node, path: Path) -> bool:
        value = self.resolve(node, path)
        values = parts(value)
        return (value.type in {"navigation_expression", "index_expression"} and len(values) == 2
                and values[-1].text.decode() in OWNER_KEYS and self.related(values[0], path))

    def ordinary(self, node: Node, path: Path):
        value = self.resolve(node, path)
        raw = value.text.decode()
        if value.type == "identifier":
            if raw in CONSTANTS:
                return "literal", raw
            if raw in self.inputs:
                return "input", raw
        if value.type in {"string_literal", "multiline_string_literal"}:
            literal = static_string(value)
            return ("literal", ("string", literal)) if literal is not None else None
        if value.type == "number_literal" or (value.type == "unary_expression" and value.children[0].type == "-"
                                              and value.child_by_field_name("argument").type == "number_literal"):
            normalized = raw.replace("_", "").removesuffix("L")
            if re.fullmatch(r"-?[0-9]{1,20}", normalized):
                return "literal", int(normalized)
        if value.type == "character_literal":
            return "literal", raw
        return None

    def equality(self, left: Node, right: Node, truth: bool, path: Path):
        for a, b in ((left, right), (right, left)):
            if self.owner_field(a, path):
                identity = "".join(words(self.resolve(b, path)))
                name, _, member = identity.partition(".")
                if (name in self.identities and member in {"", "name", "username", "getName()", "getUsername()"}
                        or re.fullmatch(r"(?:org\.springframework\.security\.core\.context\.)?"
                                        r"SecurityContextHolder\.getContext\(\)\.(?:authentication|getAuthentication\(\))"
                                        r"\.(?:name|getName\(\))", identity)):
                    return [] if truth else [path]
        a, b = self.ordinary(left, path), self.ordinary(right, path)
        for predicate, literal, operand in ((left, b, a), (right, a, b)):
            if literal in {("literal", "true"), ("literal", "false")} and (not operand or operand[0] == "input"):
                return self.condition(predicate, truth == (literal[1] == "true"), path)
        if a and b:
            if a == b:
                return [path] if truth else []
            if a[0] == b[0] == "literal":
                return [] if truth else [path]
            a, b = sorted((a, b))
            return path.assume(("equals", a, b), truth)
        return []

    def condition(self, condition: Node, truth: bool, path: Path):
        self.steps += 1
        if self.steps > 2048:
            return []
        node = self.resolve(condition, path)
        if node.type == "unary_expression" and node.children[0].type == "!":
            return self.condition(node.child_by_field_name("argument"), not truth, path)
        if node.type == "binary_expression":
            left, right = node.child_by_field_name("left"), node.child_by_field_name("right")
            op = node.child_by_field_name("operator").text.decode()
            if op in {"&&", "||"}:
                first = op == "&&"
                both = [p for previous in self.condition(left, first, path)
                        for p in self.condition(right, truth, previous)]
                return both if truth == first else self.condition(left, not first, path) + both
            if op in {"==", "!="}:
                return self.equality(left, right, truth == (op == "=="), path)
            a, b = self.ordinary(left, path), self.ordinary(right, path)
            if a and b and op in {"<", "<=", ">", ">="}:
                if op in {">", "<="}:
                    a, b = b, a
                if a == b:
                    return [path] if truth == (op in {"<=", ">="}) else []
                if a[0] == b[0] == "literal":
                    if type(a[1]) is not int or type(b[1]) is not int:
                        return []
                    return [path] if (a[1] < b[1]) == (truth == (op in {"<", ">"})) else []
                less = truth == (op in {"<", ">"})
                if a[0] == "input" and a[1] in self.integer_inputs and b[0] == "literal" and type(b[1]) is int:
                    return path.assume(("below", a, b[1]), less)
                if b[0] == "input" and b[1] in self.integer_inputs and a[0] == "literal" and type(a[1]) is int:
                    return path.assume(("below", b, a[1] + 1), not less)
                return path.assume(("less", a, b), less)
            return []
        if node.type == "call_expression":
            target = words(parts(node)[0])
            # Kotlin's grammar places ! on the callee/receiver in !acl.owns(id).
            if target and target[-1] in OWNERSHIP:
                granted = truth != (target.count("!") % 2 == 1)
                if self.related(node, path):
                    return [] if granted else [path]
                args = one(node, "value_arguments")
                values = [parts(a)[-1] for a in parts(args) if a.type == "value_argument"] if args else []
                if len(values) == 1 and (checked := self.ordinary(values[0], path)):
                    states = path.assume(("other-owner", tuple(words(node))), truth)
                    if not granted:
                        return states
                    key, subject = sorted((("input", self.input), checked))
                    return [next_state for state in states for next_state in state.assume(("equals", key, subject), False)]
            return []
        value = self.ordinary(node, path)
        if value in {("literal", "true"), ("literal", "false")}:
            return [path] if truth == (value[1] == "true") else []
        if value and value[0] == "input":
            return path.assume(("equals", value, ("literal", "true")), truth)
        return []

    def run(self, node: Node, paths: list[Path], use=None):
        """Apply a statement, return its value, or bind it to an immutable local."""
        self.steps += len(paths)
        if not paths or self.steps > 2048:
            return []
        items = parts(node)
        if node.type == "parenthesized_expression":
            return self.run(items[0], paths, use)
        if node.type == "return_expression":
            return self.run(items[0], paths, RETURN) if len(items) == 1 else []
        if node.type == "throw_expression":
            return []
        if node.type == "block":
            # Names introduced in a block must not escape when control rejoins its parent.
            for i, statement in enumerate(items):
                paths = self.run(statement, paths, use if i == len(items) - 1 else None)
                if not paths:
                    break
            return [replace(p, locals={k: v for k, v in p.locals.items()
                                       if (isinstance(use, Binding) and k == use.name)
                                       or not (node.start_byte <= v.start_byte < node.end_byte)})
                    for p in paths]
        if node.type == "if_expression":
            test = node.child_by_field_name("condition")
            branches = [c for c in items if c != test]
            if test is None or not branches:
                return []
            yes = [p for prev in paths for p in self.condition(test, True, prev)]
            no = [p for prev in paths for p in self.condition(test, False, prev)]
            if len(branches) == 1 and any(c.type == "else" for c in node.children):
                return yes + self.run(branches[0], no, use)
            return self.run(branches[0], yes, use) + (self.run(branches[1], no, use) if len(branches) == 2 else no)
        if node.type == "when_expression":
            subject = one(node, "when_subject")
            if subject and len(parts(subject)) != 1:
                return []
            joined = []
            for entry in (i for i in items if i.type == "when_entry"):
                if one(entry, "when_guard") is not None:
                    return []
                tests = entry.children_by_field_name("condition")
                matched = []
                for test in tests:
                    def split(truth, prev):
                        if subject:
                            return self.equality(parts(subject)[0], test, truth, prev)
                        return self.condition(test, truth, prev)
                    matched.extend(p for prev in paths for p in split(True, prev))
                    paths = [p for prev in paths for p in split(False, prev)]
                if not tests:
                    if entry.children[0].type != "else":
                        return []
                    matched, paths = paths, []
                joined.extend(self.run(parts(entry)[-1], matched, use))
            return joined + paths
        if node.type == "property_declaration" and use is None:
            var = one(node, "variable_declaration")
            if (var is None or node.children[0].type != "val" or not any(c.type == "=" for c in node.children)):
                return []
            name = parts(var)[0].text.decode()
            declared = parts(var)[1].text if len(parts(var)) == 2 else None
            return self.run(items[-1], [p for p in paths if name not in self.inputs and name not in p.locals],
                            Binding(name, declared))
        result = []
        for path in paths:
            value = self.resolve(node, path)
            if use is RETURN:
                locals_at_call = path.call_scopes.get(value, path.locals)
                inner = self.unwrap(value, set(locals_at_call)) if self.unwrap and value.type == "call_expression" else None
                if inner is not None:
                    self.run(inner, [replace(path, locals=locals_at_call, effects=path.effects - {value})], RETURN)
                elif value.type == "call_expression" and not path.effects - {value}:
                    self.results.append((value, locals_at_call))
            elif isinstance(use, Binding):
                effects = path.effects
                scopes = path.call_scopes
                # Widening an identifier can change the applicable overload or extension.
                if use.declared_type and value.type == "identifier" and value.text.decode() in self.inputs:
                    if self.parameter_types.get(value.text.decode()) != use.declared_type:
                        continue
                if (use.declared_type and value.type in {"string_literal", "multiline_string_literal"}
                        and use.declared_type not in {b"String", b"kotlin.String"}):
                    continue
                if value.type == "call_expression":
                    if value not in scopes:
                        scopes = scopes | {value: path.locals}
                    if words(parts(value)[0])[-1] not in OWNERSHIP:
                        effects = effects | {value}
                elif value.type in {"binary_expression", "unary_expression"}:
                    if any(words(parts(call)[0])[-1] not in OWNERSHIP for call in walk(value, "call_expression")):
                        effects = effects | {value}
                elif not self.ordinary(value, path):
                    continue
                result.append(replace(path, locals=path.locals | {use.name: value}, effects=effects, call_scopes=scopes))
            elif value.type == "call_expression":
                target = words(parts(value)[0])
                args = one(value, "value_arguments")
                if target in (["require"], ["check"], ["kotlin", ".", "require"], ["kotlin", ".", "check"]) and args:
                    arguments = parts(args)
                    if len(arguments) == 1:
                        result.extend(self.condition(parts(arguments[0])[-1], True, path))
            elif self.ordinary(value, path):
                result.append(path)
        return result


def returned_calls(body: Node, input_name: str, unwrap: Unwrap | None = None):
    """Return a call and its lexical locals for each unprotected result path."""
    items = parts(body)
    if len(items) != 1:
        return []
    flow = Flow(body, input_name, unwrap)
    try:
        flow.run(items[0], [Path()], None if items[0].type == "block" else RETURN)
    except RecursionError:
        return []  # Deeply nested submissions exceed the static walker's budget.
    return flow.results
