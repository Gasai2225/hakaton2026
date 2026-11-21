"""Resolve Kotlin member bodies and Spring injection for object-authorization checks."""
from collections import defaultdict, deque
from functools import cached_property

from tree_sitter import Node

from garden.jdbc_project import (
    BEAN, CONDITIONAL, CONSUMERS, FALLBACK, INJECTION_ANNOTATIONS, PRIMARY, PRIORITY, PROFILE, QUALIFIER,
    STEREOTYPES, annotations, bean_candidate, constructor_names_available, select_candidate,
)
from garden.kotlin_checks import kotlin_imports, walk, words
from garden.kotlin_types import KotlinTypes, package


SPRING_TYPES = CONSUMERS | INJECTION_ANNOTATIONS | PRIORITY | {BEAN, CONDITIONAL, FALLBACK, PRIMARY, PROFILE}
CONTROLLER = "org.springframework.web.bind.annotation.RestController"
ROLES = {CONTROLLER, "org.springframework.stereotype.Service", "org.springframework.stereotype.Repository"}


def child(node, kind):
    return next((c for c in node.named_children if c.type == kind), None) if node is not None else None


class Hierarchy:
    def __init__(self, types, classes, access_conditions, build=None):
        self.types = types
        self.classes = {}
        self.parents = defaultdict(dict)
        self.declarations = defaultdict(lambda: defaultdict(list))
        self.roles = {}
        self.beans = defaultdict(list)
        self.unknown_factories = set()
        self.opaque = set()
        self.security = {}
        self.signatures = {}
        self.lineages = {}
        self.bodies = {}
        self.constructor_names = constructor_names_available(build)
        for root, resolver in types.items():
            imports = {alias: path for path, alias in kotlin_imports(root) if alias != "*"}
            for cls in root.named_children:
                if cls.type != "class_declaration":
                    continue
                qualified = ".".join(filter(None, (package(root), cls.child_by_field_name("name").text.decode())))
                if classes[qualified] != 1:
                    continue
                self.classes[qualified] = cls
                self.security[cls] = access_conditions(child(cls, "modifiers"), imports)
                bases = child(cls, "delegation_specifiers")
                for spec in bases.named_children if bases else ():
                    typ = next(walk(spec, "user_type"), None)
                    if typ is None:
                        continue
                    base = resolver.resolve("".join(words(typ)).split("<", 1)[0], cls)
                    if base:
                        self.parents[qualified][base] = spec
                    if child(typ, "type_arguments") or child(spec, "explicit_delegation"):
                        self.opaque.add(qualified)
                body = child(cls, "class_body")
                for fun in body.named_children if body else ():
                    if fun.type != "function_declaration":
                        continue
                    label = fun.child_by_field_name("name")
                    if label.prev_sibling.type == ".":
                        continue  # Member extensions require a separate extension receiver.
                    name = label.text.decode()
                    self.declarations[qualified][name].append(fun)
                    self.security[fun] = access_conditions(child(fun, "modifiers"), imports)
                    params = child(fun, "function_value_parameters")
                    signature = []
                    for param in params.named_children if params else ():
                        if param.type == "parameter":
                            typ = next((c for c in param.named_children if c.type in {"user_type", "nullable_type"}), None)
                            spelling = "".join(words(typ)) if typ else ""
                            resolved = resolver.resolve(spelling.removesuffix("?"), param)
                            signature.append((resolved or (root, spelling), spelling.endswith("?")))
                    self.signatures[fun] = tuple(signature)
        for name, cls in self.classes.items():
            tags = annotations(cls, types[cls.parent])
            roles = ROLES.intersection(tags)
            mods = child(cls, "modifiers")
            if any(c.type == "interface" for c in cls.children) or mods and {"abstract", "sealed", "expect"}.intersection(words(mods)):
                continue
            if len(roles) == 1:
                self.roles[name] = next(iter(roles))
            for stereotype in STEREOTYPES.intersection(tags):
                simple = name.rpartition(".")[2]
                default = simple if simple[:2].isupper() else simple[:1].lower() + simple[1:]
                candidate = bean_candidate(name, default, tags[stereotype], tags)
                for parent, _ in self.lineage(name):
                    self.beans[parent].append(candidate)
        # Factory methods can contribute an alternative implementation, including an external one.
        for root, resolver in types.items():
            for fun in walk(root, "function_declaration"):
                if BEAN not in annotations(fun, resolver):
                    continue
                typ = child(fun, "user_type") or child(child(fun, "nullable_type"), "user_type")
                body = child(fun, "function_body")
                call = child(body, "call_expression")
                result = typ or (call.named_children[0] if call else None)
                if result:
                    produced = resolver.resolve("".join(words(result)), fun)
                    self.unknown_factories.update(parent for parent, _ in self.lineage(produced))

    def lineage(self, name):
        if name not in self.lineages:
            result, seen = [], set()
            work = deque([(name, 0)])
            while work:
                current, depth = work.popleft()
                if current in seen:
                    continue
                seen.add(current)
                result.append((current, depth))
                work.extend((p, depth + 1) for p in self.parents.get(current, ()))
            self.lineages[name] = result
        return self.lineages[name]

    def is_subtype(self, actual, expected):
        return bool(actual and expected) and any(name == expected for name, _ in self.lineage(actual))

    def _decls(self, runtime, name):
        for owner, depth in self.lineage(runtime):
            for fun in self.declarations.get(owner, {}).get(name, ()):
                yield owner, depth, fun

    def contracts(self, runtime, fun):
        name = fun.child_by_field_name("name").text.decode()
        return [(self.classes[owner], method) for owner, _, method in self._decls(runtime, name)
                if self.signatures[method] == self.signatures[fun]]

    def _guarded(self, runtime, fun):
        # Nearest method annotation of each type overrides its inherited forms and class defaults.
        method_rules, class_rules = {}, {}
        for owner, depth in self.lineage(runtime):
            cls = self.classes.get(owner)
            if cls is not None:
                for key, value in self.security[cls].items():
                    if key not in class_rules:
                        class_rules[key] = (depth, value)
                    elif class_rules[key][0] == depth and value:
                        class_rules[key] = (depth, True)
        name = fun.child_by_field_name("name").text.decode()
        for _, depth, method in self._decls(runtime, name):
            if self.signatures[method] != self.signatures[fun]:
                continue
            for key, value in self.security[method].items():
                if key not in method_rules:
                    method_rules[key] = (depth, value)
                elif method_rules[key][0] == depth and value:
                    method_rules[key] = (depth, True)
        return any(value for _, value in (class_rules | method_rules).values())

    def _methods(self, runtime, name, *, require_unguarded=True):
        key = runtime, name, require_unguarded
        if key in self.bodies:
            return self.bodies[key]
        groups = defaultdict(list)
        for owner, _, fun in self._decls(runtime, name):
            groups[self.signatures[fun]].append((owner, fun))
        methods = []
        opaque = any(owner in self.opaque for owner, _ in self.lineage(runtime))
        for decls in groups.values():
            # A concrete override supersedes ancestors. Unrelated conflicting defaults are ambiguous.
            visible = [(a, fun) for a, fun in decls if not any(a != b and self.is_subtype(b, a) for b, _ in decls)]
            if len(visible) != 1:
                continue
            owner, fun = visible[0]
            mods = child(fun, "modifiers")
            modifiers = set(words(mods)) if mods else set()
            if {"private", "protected"}.intersection(modifiers):
                continue
            if opaque and (runtime != owner or "override" in modifiers):
                continue
            if not require_unguarded or not self._guarded(runtime, fun):
                methods.append((owner, fun))
        self.bodies[key] = methods
        return methods

    @cached_property
    def summaries(self):
        rows = []
        for runtime, role in self.roles.items():
            names = dict.fromkeys(n for owner, _ in self.lineage(runtime) for n in self.declarations.get(owner, {}))
            for name in names:
                overloads = {self.signatures[f] for _, _, f in self._decls(runtime, name)}
                if role != CONTROLLER and len(overloads) != 1:
                    continue
                for owner, fun in self._methods(runtime, name):
                    if child(fun, "function_body") is not None:
                        rows.append((role, runtime, self.classes[owner], fun))
        return rows

    def bean_methods(self, roles):
        return (row for row in self.summaries if row[0] in roles)

    def receiver(self, declared, site: Node, resolver: KotlinTypes, runtime=None):
        if declared not in self.beans:
            return None
        injection_type = declared
        if runtime:
            cls = site
            while cls and cls.type != "class_declaration":
                cls = cls.parent
            if cls is None:
                return None
            owner = ".".join(filter(None, (package(cls.parent), cls.child_by_field_name("name").text.decode())))
            if owner != runtime:
                site = self._constructor_input(runtime, owner, site)
                if site is None:
                    return None
                cls = self.classes[runtime]
                resolver = self.types[cls.parent]
                typ = child(site, "user_type")
                if typ is None:
                    return None
                injection_type = resolver.resolve("".join(words(typ)), site)
                if not self.is_subtype(injection_type, declared):
                    return None
        if injection_type not in self.beans or injection_type in self.unknown_factories:
            return None
        tags = annotations(site, resolver, b"param:")
        if tags.keys() - INJECTION_ANNOTATIONS:
            return None
        injected = child(site, "identifier").text.decode()
        selected = select_candidate(self.beans[injection_type], tags.get(QUALIFIER), injected, self.constructor_names)
        if selected:
            return declared, selected
        return None

    def _constructor_input(self, runtime, owner, site):
        # Follow only direct constructor arguments; an expression may manually supply a different bean.
        chain = []
        step = runtime
        seen = set()
        while step != owner and step not in seen:
            seen.add(step)
            matches = [(p, spec) for p, spec in self.parents[step].items()
                       if child(spec, "constructor_invocation") and self.is_subtype(p, owner)]
            if len(matches) != 1:
                return None
            parent, spec = matches[0]
            chain.append((self.classes[step], self.classes[parent], spec))
            step = parent
        if step != owner:
            return None
        field_name = child(site, "identifier").text
        for cls, base, spec in reversed(chain):
            parent_params = child(child(base, "primary_constructor"), "class_parameters")
            own_params = child(child(cls, "primary_constructor"), "class_parameters")
            args = child(child(spec, "constructor_invocation"), "value_arguments")
            if not parent_params or not own_params or not args:
                return None
            body = child(cls, "class_body")
            members = [*own_params.named_children, *(body.named_children if body else ())]
            for member in members:
                if member.type not in {"class_parameter", "property_declaration"}:
                    continue
                name = child(child(member, "variable_declaration") or member, "identifier")
                mods = child(member, "modifiers")
                if name and name.text == field_name and mods and "override" in words(mods):
                    return None
            params = [p for p in parent_params.named_children if p.type == "class_parameter"]
            wanted = child(site, "identifier").text
            bound = []
            for index, arg in enumerate(c for c in args.named_children if c.type == "value_argument"):
                parts = arg.named_children
                if len(parts) == 1 and index < len(params):
                    arg_name = child(params[index], "identifier").text
                elif len(parts) == 2 and any(c.type == "=" for c in arg.children):
                    arg_name = parts[0].text
                else:
                    continue
                if wanted == arg_name and parts[-1].type == "identifier":
                    bound.append(parts[-1].text)
            if len(bound) != 1:
                return None
            site = next((p for p in own_params.named_children if p.type == "class_parameter"
                         and child(p, "identifier").text == bound[0]), None)
            if site is None:
                return None
        return site

    def target(self, receiver, method):
        if not receiver or not isinstance(receiver, tuple):
            return None
        declared, runtime = receiver
        contract = self._methods(declared, method, require_unguarded=False)
        actual = self._methods(runtime, method)
        if len(contract) != 1 or len(actual) != 1 or self.signatures[contract[0][1]] != self.signatures[actual[0][1]]:
            return None
        params = child(contract[0][1], "function_value_parameters")
        args = [p for p in params.named_children if p.type == "parameter"]
        if len(args) == 1:
            return (runtime, method), child(args[0], "identifier").text.decode()
        return None
