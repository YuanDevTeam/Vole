//! Optional size proof over an already accepted AST. This emits no code and
//! never turns a supported JavaScript program into a configuration error.
use oxc_ast::ast::*;
use std::collections::{BTreeMap, BTreeSet};

use super::super::OutputBound;

const MAX_PROOF_NODES: usize = 4096;
const MAX_PROOF_BINDINGS: usize = 128;
const MAX_PROOF_DEPENDENCIES: usize = 32;

#[derive(Clone)]
struct StringProof {
    literal_bytes: usize,
    original_input: bool,
    dependencies: BTreeSet<String>,
}

pub(super) fn analyze(function: &Function<'_>) -> OutputBound {
    let Some(parameter) = function.params.items.first() else {
        return OutputBound::Maximum;
    };
    let BindingPattern::BindingIdentifier(parameter) = &parameter.pattern else {
        return OutputBound::Maximum;
    };
    let Some(body) = function.body.as_ref() else {
        return OutputBound::Maximum;
    };
    let mut analysis = Analysis {
        parameter: parameter.name.as_str().to_owned(),
        safe: true,
        nodes: 0,
        declared: BTreeSet::new(),
        bindings: BTreeMap::new(),
        writes: BTreeSet::new(),
        root_strings: BTreeSet::new(),
        audited_writes: BTreeSet::new(),
        other_writes: BTreeSet::new(),
        returns: Vec::new(),
    };
    let always_returns = analysis.statements(&body.statements, true);
    if !analysis.safe || !always_returns || analysis.returns.is_empty() {
        return OutputBound::Maximum;
    }
    let mut maximum_literal_bytes = 0;
    for proof in &analysis.returns {
        if proof.dependencies.iter().any(|name| {
            analysis.writes.contains(name)
                && (!analysis.audited_writes.contains(name) || analysis.other_writes.contains(name))
        }) {
            return OutputBound::Maximum;
        }
        maximum_literal_bytes = maximum_literal_bytes.max(proof.literal_bytes);
    }
    if maximum_literal_bytes > super::super::super::body_budget::MAX_BODY {
        return OutputBound::Maximum;
    }
    OutputBound::InputOrConstant {
        maximum_literal_bytes,
    }
}

struct Analysis {
    parameter: String,
    safe: bool,
    nodes: usize,
    declared: BTreeSet<String>,
    bindings: BTreeMap<String, StringProof>,
    writes: BTreeSet<String>,
    root_strings: BTreeSet<String>,
    audited_writes: BTreeSet<String>,
    other_writes: BTreeSet<String>,
    returns: Vec<StringProof>,
}

impl Analysis {
    fn enter(&mut self) -> bool {
        self.nodes += 1;
        self.safe &= self.nodes <= MAX_PROOF_NODES;
        self.safe
    }

    fn statements(&mut self, statements: &[Statement<'_>], root: bool) -> bool {
        let mut always_returns = false;
        for statement in statements {
            // Do not prune dead/unreachable statements: their unknown effects
            // must also force the whole optional proof back to Maximum.
            always_returns |= self.statement(statement, root);
        }
        always_returns
    }

    fn statement(&mut self, statement: &Statement<'_>, root: bool) -> bool {
        if !self.enter() {
            return false;
        }
        match statement {
            Statement::BlockStatement(block) => self.statements(&block.body, false),
            Statement::EmptyStatement(_) => false,
            Statement::VariableDeclaration(declaration) => {
                self.declaration(declaration, root);
                false
            }
            Statement::ExpressionStatement(statement) => {
                self.expression_at(&statement.expression, root);
                false
            }
            Statement::ReturnStatement(statement) => {
                if let Some(argument) = &statement.argument {
                    self.expression(argument);
                    if !self.safe {
                        return true;
                    }
                    if let Some(proof) = self.return_proof(argument) {
                        self.returns.push(proof);
                    } else {
                        self.safe = false;
                    }
                } else {
                    self.safe = false;
                }
                true
            }
            Statement::IfStatement(statement) => {
                self.expression(&statement.test);
                let consequent = self.statement(&statement.consequent, false);
                let alternate = statement
                    .alternate
                    .as_ref()
                    .is_some_and(|s| self.statement(s, false));
                consequent && alternate
            }
            Statement::WhileStatement(statement) => {
                self.expression(&statement.test);
                self.statement(&statement.body, false);
                false
            }
            Statement::DoWhileStatement(statement) => {
                self.statement(&statement.body, false);
                self.expression(&statement.test);
                false
            }
            Statement::ForStatement(statement) => {
                if let Some(init) = &statement.init {
                    match init {
                        ForStatementInit::VariableDeclaration(declaration) => {
                            self.declaration(declaration, false)
                        }
                        _ => match init.as_expression() {
                            Some(expression) => self.expression(expression),
                            None => self.safe = false,
                        },
                    }
                }
                if let Some(test) = &statement.test {
                    self.expression(test);
                }
                if let Some(update) = &statement.update {
                    self.expression(update);
                }
                self.statement(&statement.body, false);
                false
            }
            Statement::BreakStatement(statement) if statement.label.is_none() => false,
            Statement::ContinueStatement(statement) if statement.label.is_none() => false,
            _ => {
                self.safe = false;
                false
            }
        }
    }

    fn declaration(&mut self, declaration: &VariableDeclaration<'_>, root: bool) {
        for binding in &declaration.declarations {
            let BindingPattern::BindingIdentifier(identifier) = &binding.id else {
                self.safe = false;
                return;
            };
            let name = identifier.name.as_str();
            if name == self.parameter
                || !self.declared.insert(name.to_owned())
                || self.declared.len() > MAX_PROOF_BINDINGS
            {
                self.safe = false;
                return;
            }
            if let Some(init) = &binding.init {
                self.expression(init);
                if !self.safe {
                    return;
                }
                if let Some(proof) = self.string_proof(init) {
                    if root && matches!(declaration.kind, VariableDeclarationKind::Let) {
                        self.root_strings.insert(name.to_owned());
                    }
                    self.bindings.insert(name.to_owned(), proof);
                }
            }
        }
    }

    fn expression(&mut self, expression: &Expression<'_>) {
        self.expression_at(expression, false);
    }

    fn expression_at(&mut self, expression: &Expression<'_>, root_statement: bool) {
        if !self.enter() {
            return;
        }
        match expression {
            Expression::BooleanLiteral(_)
            | Expression::NullLiteral(_)
            | Expression::NumericLiteral(_)
            | Expression::StringLiteral(_)
            | Expression::Identifier(_) => {}
            Expression::ParenthesizedExpression(value) => self.expression(&value.expression),
            Expression::ArrayExpression(array) => {
                for element in &array.elements {
                    match element.as_expression() {
                        Some(value) => self.expression(value),
                        None => self.safe = false,
                    }
                }
            }
            Expression::ObjectExpression(object) => {
                for property in &object.properties {
                    let ObjectPropertyKind::ObjectProperty(property) = property else {
                        self.safe = false;
                        return;
                    };
                    if property.kind != PropertyKind::Init || property.method || property.computed {
                        self.safe = false;
                    }
                    self.expression(&property.value);
                }
            }
            Expression::StaticMemberExpression(member) if !member.optional => {
                self.expression(&member.object)
            }
            Expression::ComputedMemberExpression(member) if !member.optional => {
                self.expression(&member.object);
                self.expression(&member.expression);
            }
            Expression::BinaryExpression(value) => {
                self.expression(&value.left);
                self.expression(&value.right);
            }
            Expression::LogicalExpression(value) => {
                self.expression(&value.left);
                self.expression(&value.right);
            }
            Expression::ConditionalExpression(value) => {
                self.expression(&value.test);
                self.expression(&value.consequent);
                self.expression(&value.alternate);
            }
            Expression::UnaryExpression(value) => self.expression(&value.argument),
            Expression::AssignmentExpression(value) => {
                match &value.left {
                    AssignmentTarget::AssignmentTargetIdentifier(identifier) => {
                        let name = identifier.name.as_str();
                        let audited = root_statement
                            && self.root_strings.contains(name)
                            && ascii_self_assignment(value, name);
                        self.record_write(name, audited);
                    }
                    // Includes writes through aliases, computed keys, argument
                    // expressions and unreachable branches.
                    _ => self.safe = false,
                }
                self.expression(&value.right);
            }
            Expression::UpdateExpression(value) => match &value.argument {
                SimpleAssignmentTarget::AssignmentTargetIdentifier(identifier) => {
                    let name = identifier.name.as_str();
                    self.record_write(name, false);
                }
                _ => self.safe = false,
            },
            Expression::CallExpression(call) if !call.optional => {
                self.safe &= safe_call(call);
                if let Expression::StaticMemberExpression(member) = &call.callee {
                    self.expression(&member.object);
                }
                for argument in &call.arguments {
                    match argument.as_expression() {
                        Some(value) => self.expression(value),
                        None => self.safe = false,
                    }
                }
            }
            _ => self.safe = false,
        }
    }

    fn record_write(&mut self, name: &str, audited: bool) {
        self.writes.insert(name.to_owned());
        if audited {
            self.audited_writes.insert(name.to_owned());
        } else {
            self.other_writes.insert(name.to_owned());
        }
        self.safe &= name != self.parameter
            && self.writes.len() <= MAX_PROOF_BINDINGS
            && self.audited_writes.len() <= MAX_PROOF_BINDINGS
            && self.other_writes.len() <= MAX_PROOF_BINDINGS;
    }

    fn return_proof(&self, expression: &Expression<'_>) -> Option<StringProof> {
        let fields = object_fields(expression)?;
        if fields.keys().any(|key| {
            !matches!(
                key.as_str(),
                "type" | "url" | "method" | "status" | "headers" | "body"
            )
        }) {
            return None;
        }
        let kind = literal(fields.get("type")?)?;
        if !matches!(kind, "pass" | "abort" | "modify" | "respond") {
            return None;
        }
        let Some(body) = fields.get("body") else {
            return Some(constant_proof(0));
        };
        if matches!(kind, "pass" | "abort") {
            return None;
        }
        let body = object_fields(body)?;
        if body.len() != 2 || literal(body.get("kind")?)? != "text" {
            return None;
        }
        self.string_proof(body.get("data")?)
    }

    fn string_proof(&self, expression: &Expression<'_>) -> Option<StringProof> {
        match unparenthesized(expression) {
            Expression::StringLiteral(value) => Some(constant_proof(value.value.as_str()?.len())),
            Expression::Identifier(identifier) => {
                let name = identifier.name.as_str();
                let mut proof = self.bindings.get(name)?.clone();
                proof.dependencies.insert(name.to_owned());
                (proof.dependencies.len() <= MAX_PROOF_DEPENDENCIES).then_some(proof)
            }
            value if original_data(value, &self.parameter) => Some(StringProof {
                literal_bytes: 0,
                original_input: true,
                dependencies: BTreeSet::new(),
            }),
            Expression::CallExpression(call) if !call.optional && call.arguments.len() == 2 => {
                let Expression::StaticMemberExpression(member) = &call.callee else {
                    return None;
                };
                if member.optional || member.property.name != "replaceAll" {
                    return None;
                }
                let receiver = self.string_proof(&member.object)?;
                if !receiver.original_input {
                    return None;
                }
                let search = literal(call.arguments[0].as_expression()?)?;
                let replacement = literal(call.arguments[1].as_expression()?)?;
                if search.len() != 1
                    || replacement.len() != 1
                    || !search.is_ascii()
                    || !replacement.is_ascii()
                    || replacement == "$"
                {
                    return None;
                }
                Some(receiver)
            }
            _ => None,
        }
    }
}

// A constant-size syntax check inside the existing counted AST walk. The
// initial proof is never replaced: every successful string version has the
// same byte bound, including aliases and returns before a later assignment.
fn ascii_self_assignment(assignment: &AssignmentExpression<'_>, name: &str) -> bool {
    if assignment.operator.as_str() != "=" {
        return false;
    }
    let Expression::CallExpression(call) = &assignment.right else {
        return false;
    };
    let Expression::StaticMemberExpression(member) = &call.callee else {
        return false;
    };
    if call.optional
        || member.optional
        || member.property.name != "replaceAll"
        || call.arguments.len() != 2
        || !matches!(&member.object, Expression::Identifier(receiver) if receiver.name == name)
    {
        return false;
    }
    let Some(Expression::StringLiteral(search)) = call.arguments[0].as_expression() else {
        return false;
    };
    let Some(Expression::StringLiteral(replacement)) = call.arguments[1].as_expression() else {
        return false;
    };
    let (Some(search), Some(replacement)) = (search.value.as_str(), replacement.value.as_str())
    else {
        return false;
    };
    search.len() == 1
        && search.is_ascii()
        && replacement.len() == 1
        && replacement.is_ascii()
        && replacement != "$"
}

fn constant_proof(literal_bytes: usize) -> StringProof {
    StringProof {
        literal_bytes,
        original_input: false,
        dependencies: BTreeSet::new(),
    }
}

fn unparenthesized<'a, 'b>(mut expression: &'b Expression<'a>) -> &'b Expression<'a> {
    while let Expression::ParenthesizedExpression(value) = expression {
        expression = &value.expression;
    }
    expression
}

fn literal<'a, 'b>(expression: &'b Expression<'a>) -> Option<&'b str> {
    let Expression::StringLiteral(value) = unparenthesized(expression) else {
        return None;
    };
    value.value.as_str()
}

fn object_fields<'a, 'b>(
    expression: &'b Expression<'a>,
) -> Option<BTreeMap<String, &'b Expression<'a>>> {
    let Expression::ObjectExpression(object) = unparenthesized(expression) else {
        return None;
    };
    let mut fields = BTreeMap::new();
    for property in &object.properties {
        let ObjectPropertyKind::ObjectProperty(property) = property else {
            return None;
        };
        if property.kind != PropertyKind::Init || property.method || property.computed {
            return None;
        }
        let key = match &property.key {
            PropertyKey::StaticIdentifier(key) => key.name.as_str(),
            PropertyKey::StringLiteral(key) => key.value.as_str()?,
            _ => return None,
        };
        if fields.insert(key.to_owned(), &property.value).is_some() {
            return None;
        }
    }
    Some(fields)
}

fn original_data(expression: &Expression<'_>, parameter: &str) -> bool {
    fn member<'a, 'b>(expression: &'b Expression<'a>, name: &str) -> Option<&'b Expression<'a>> {
        match unparenthesized(expression) {
            Expression::StaticMemberExpression(value)
                if !value.optional && value.property.name == name =>
            {
                Some(&value.object)
            }
            Expression::ComputedMemberExpression(value)
                if !value.optional && literal(&value.expression) == Some(name) =>
            {
                Some(&value.object)
            }
            _ => None,
        }
    }
    let Some(body) = member(expression, "data").and_then(|value| member(value, "body")) else {
        return false;
    };
    matches!(unparenthesized(body), Expression::Identifier(value) if value.name == parameter)
}

// Audited independently of frontend's allowlist: any future method addition
// remains Maximum until its effects are reviewed. Primitive conversions reject
// objects; no callbacks/accessors are expressible. Array mutators only change
// array indices/length (or fixed-size typed-array elements), never the fresh
// plain input.body record's data property. Member writes are forbidden above.
fn safe_call(call: &CallExpression<'_>) -> bool {
    match &call.callee {
        Expression::Identifier(identifier) => {
            matches!(identifier.name.as_str(), "String" | "Number" | "Boolean")
        }
        Expression::StaticMemberExpression(member) if !member.optional => {
            let name = member.property.name.as_str();
            if let Expression::Identifier(receiver) = &member.object {
                match receiver.name.as_str() {
                    "JSON" => return matches!(name, "parse" | "stringify"),
                    "Object" => return matches!(name, "keys" | "values" | "entries"),
                    "Array" => return name == "isArray",
                    "Number" => return matches!(name, "isFinite" | "isInteger"),
                    "Math" => {
                        return matches!(
                            name,
                            "abs" | "floor" | "ceil" | "round" | "trunc" | "min" | "max"
                        );
                    }
                    "Uint8Array" => return name == "from",
                    _ => {}
                }
            }
            matches!(
                name,
                "slice"
                    | "subarray"
                    | "substring"
                    | "charAt"
                    | "at"
                    | "includes"
                    | "startsWith"
                    | "endsWith"
                    | "indexOf"
                    | "lastIndexOf"
                    | "trim"
                    | "toLowerCase"
                    | "toUpperCase"
                    | "split"
                    | "replace"
                    | "replaceAll"
                    | "push"
                    | "pop"
                    | "concat"
                    | "join"
                    | "reverse"
            )
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hint(source: &str) -> OutputBound {
        super::super::compile_with_output_bound(source).unwrap().1
    }

    #[test]
    fn top_level_ascii_self_assignment_bounds_output_without_changing_emitted_js() {
        let source = "function rewrite(input){let payload=input.body.data;payload=payload.replaceAll('q','z');return {type:'modify',body:{kind:'text',data:payload}};}";
        let prepared = super::super::compile_prepared(source).unwrap();
        assert_eq!(
            prepared.code,
            r#"function rewrite(input){"use strict";__voleTick();__voleFreezeParameters(input);let payload=__voleGet(__voleGet(input,"body"),"data");(payload=__voleCall(payload,"replaceAll",["q","z"]));return __voleValue({"type":"modify","body":__voleValue({"kind":"text","data":payload})});}"#
        );
        #[cfg(target_vendor = "apple")]
        assert!(
            prepared.plan.is_some(),
            "the independent closed Plan proof now accepts this source"
        );
        assert_eq!(
            prepared.output_bound,
            OutputBound::InputOrConstant {
                maximum_literal_bytes: 0
            }
        );
    }

    #[test]
    fn frozen_guarded_pressure_sources_keep_input_sized_output_and_closed_plans() {
        // Freeze the actual pure/request and mixed/response source shapes.
        // No guard, witness, assignment or body workload is simplified here.
        for source in [
            r#"function rewrite(input) { if (!input.body || input.body.kind !== "text" || typeof input.body.data !== "string" || input.body.data.length !== 65536) { return {type: "abort"}; } let data = input.body.data; data = data.replaceAll("a", "c"); return {type: "modify", headers: [{op: "set", name: "X-Benchmark-Request-JS", values: ["js-v1"]}], body: {kind: "text", data: data}}; }"#,
            r#"function rewrite(input) { let found = false; for (let i = 0; i < input.response.headers.length; i++) { if (input.response.headers[i].name === "x-benchmark-native" && input.response.headers[i].value === "native-v1") { found = true; } } if (!found) { return {type: "abort"}; } if (!input.body || input.body.kind !== "text" || typeof input.body.data !== "string" || input.body.data.length !== 65536) { return {type: "abort"}; } let data = input.body.data; data = data.replaceAll("b", "c"); return {type: "modify", headers: [{op: "set", name: "X-Benchmark-JS", values: ["native-v1>js-v1"]}], body: {kind: "text", data: data}}; }"#,
        ] {
            let prepared = super::super::compile_prepared(source).unwrap();
            #[cfg(target_vendor = "apple")]
            assert!(
                prepared.plan.is_some(),
                "complete guard and tail proof required"
            );
            assert_eq!(
                prepared.output_bound,
                OutputBound::InputOrConstant {
                    maximum_literal_bytes: 0
                },
                "self assignment lost a complete output bound for {source}"
            );
        }
    }

    #[test]
    fn audited_self_writes_are_generic_in_names_and_decoded_ascii_literals() {
        for name in ["result", "_copy9", "$payload", "a"] {
            for (search, replacement) in [("q", "z"), ("A", "B"), ("\0", "\x7f"), ("$", "!")] {
                let source = format!(
                    "function rewrite(input){{let {name}=input.body.data;{name}={name}.replaceAll({},{});return {{type:'modify',body:{{kind:'text',data:{name}}}}};}}",
                    serde_json::to_string(search).unwrap(),
                    serde_json::to_string(replacement).unwrap(),
                );
                let prepared = super::super::compile_prepared(&source).unwrap();
                #[cfg(target_vendor = "apple")]
                assert!(prepared.plan.is_some());
                assert_eq!(
                    prepared.output_bound,
                    OutputBound::InputOrConstant {
                        maximum_literal_bytes: 0
                    }
                );
            }
        }
    }

    #[test]
    fn all_string_versions_aliases_and_early_returns_keep_the_initial_bound() {
        for (index, source) in [
            "function rewrite(input){let s=input.body.data;const old=s;s=s.replaceAll('a','b');s=s.replaceAll('b','c');return {type:'modify',body:{kind:'text',data:old}};}",
            "function rewrite(input){let s=input.body.data;s=s.replaceAll('a','c');const after=s;return {type:'modify',body:{kind:'text',data:after}};}",
            "function rewrite(input){let s=input.body.data;if(input.phase==='request')return {type:'modify',body:{kind:'text',data:s}};s=s.replaceAll('a','c');return {type:'modify',body:{kind:'text',data:s}};}",
            "function rewrite(input){let s=input.body.data;return {type:'modify',body:{kind:'text',data:s}};s=s.replaceAll('a','c');}",
            "function rewrite(input){let a=input.body.data;a=a.replaceAll('a','b');let s=a;s=s.replaceAll('b','c');return {type:'modify',body:{kind:'text',data:s}};}",
            "function rewrite(input){const initial=input.body.data;let s=initial;s=s.replaceAll('a','c');return {type:'modify',body:{kind:'text',data:s}};}",
        ]
        .into_iter()
        .enumerate()
        {
            let prepared = super::super::compile_prepared(source).unwrap();
            #[cfg(target_vendor = "apple")]
            assert_eq!(
                prepared.plan.is_some(),
                !matches!(index, 2 | 3),
                "arbitrary branches and statements after return remain unproved"
            );
            assert_eq!(
                prepared.output_bound,
                OutputBound::InputOrConstant {
                    maximum_literal_bytes: 0
                },
                "{source}"
            );
        }
        // ASCII substitution preserves UTF-8 bytes even in a Unicode/NUL
        // literal. The proof retains the full initial bound at every return.
        assert_eq!(
            hint(
                "function rewrite(input){let s='é😀\\u0000';s=s.replaceAll('\\u0000','!');return {type:'modify',body:{kind:'text',data:s}};}"
            ),
            OutputBound::InputOrConstant {
                maximum_literal_bytes: 7
            }
        );
    }

    #[test]
    fn an_audited_write_never_hides_other_contexts_shapes_or_effects() {
        for mutation in [
            "s='EXPANDED';",
            "s+='EXPANDED';",
            "s++;",
            "if(false)s=s.replaceAll('b','c');",
            "while(false){s=s.replaceAll('b','c');}",
            "do{s=s.replaceAll('b','c');}while(false);",
            "for(s=s.replaceAll('b','c');false;){}",
            "for(let i=0;i<0;s=s.replaceAll('b','c')){}",
            "{s=s.replaceAll('b','c');}",
            "false&&(s=s.replaceAll('b','c'));",
            "false?(s=s.replaceAll('b','c')):s;",
            "String(s=s.replaceAll('b','c'));",
            "(s=s.replaceAll('b','c'));",
            "s=input.body.data.replaceAll('b','c');",
            "s=s.replaceAll('b','c').replaceAll('c','d');",
            "s=s.replaceAll('b','cc');",
            "s=s.replaceAll('bb','cc');",
            "s=s.replaceAll('é','c');",
            "s=s.replaceAll('b','界');",
            "s=s.replaceAll('b','$');",
            "s=s.replaceAll('b','$&');",
            "s=s.replaceAll('','c');",
            "let replacement='c';s=s.replaceAll('b',replacement);",
            "input.body.data='EXPANDED';",
            "if(false)input.body['data']='EXPANDED';",
            "const body=input.body;body.data='EXPANDED';",
            "{let s='EXPANDED';}",
        ] {
            let source = format!(
                "function rewrite(input){{let s=input.body.data;s=s.replaceAll('a','b');{mutation}return {{type:'modify',body:{{kind:'text',data:s}}}};}}"
            );
            assert_eq!(hint(&source), OutputBound::Maximum, "{mutation}");
        }
    }

    #[test]
    fn audited_locals_keep_all_initial_dependencies_and_unreachable_writes() {
        for source in [
            "function rewrite(input){let a=input.body.data;a='EXPANDED';let s=a;s=s.replaceAll('x','y');return {type:'modify',body:{kind:'text',data:s}};}",
            "function rewrite(input){let a=input.body.data;let s=a;a='EXPANDED';s=s.replaceAll('x','y');return {type:'modify',body:{kind:'text',data:s}};}",
            "function rewrite(input){let a=input.body.data;let s=a;a=a.replaceAll('a','b');a='EXPANDED';s=s.replaceAll('x','y');return {type:'modify',body:{kind:'text',data:s}};}",
            "function rewrite(input){let s=input.body.data;let alias=s;s=s.replaceAll('a','b');alias='EXPANDED';return {type:'modify',body:{kind:'text',data:alias}};}",
            "function rewrite(input){let s=input.body.data;s=s.replaceAll('a','b');return {type:'modify',body:{kind:'text',data:s}};s='EXPANDED';}",
            "function rewrite(input){let s;s=s.replaceAll('a','b');return {type:'modify',body:{kind:'text',data:s}};}",
            "function rewrite(input){let s=3;s=s.replaceAll('a','b');return {type:'modify',body:{kind:'text',data:s}};}",
        ] {
            assert_eq!(hint(source), OutputBound::Maximum, "{source}");
        }
    }

    #[test]
    fn audited_writes_cannot_bypass_binding_node_or_dependency_caps() {
        let mut bindings = String::from("function rewrite(input){let s=input.body.data;");
        for index in 0..MAX_PROOF_BINDINGS {
            bindings.push_str(&format!("let unused{index};"));
        }
        bindings
            .push_str("s=s.replaceAll('a','c');return {type:'modify',body:{kind:'text',data:s}};}");
        assert_eq!(hint(&bindings), OutputBound::Maximum);

        let mut nodes = String::from(
            "function rewrite(input){let s=input.body.data;s=s.replaceAll('a','c');return {type:'modify',body:{kind:'text',data:s}};",
        );
        for _ in 0..=MAX_PROOF_NODES / 2 {
            nodes.push_str("0;");
        }
        nodes.push('}');
        assert_eq!(hint(&nodes), OutputBound::Maximum);

        let mut dependencies = String::from("function rewrite(input){let seed=input.body.data;");
        let mut previous = "seed".to_owned();
        for index in 0..=MAX_PROOF_DEPENDENCIES {
            let name = format!("alias{index}");
            dependencies.push_str(&format!("let {name}={previous};"));
            previous = name;
        }
        dependencies.push_str(&format!("{previous}={previous}.replaceAll('a','c');return {{type:'modify',body:{{kind:'text',data:{previous}}}}};}}"));
        assert_eq!(hint(&dependencies), OutputBound::Maximum);
    }

    #[test]
    fn readonly_aliases_are_independent_of_local_names_and_ascii_values() {
        for name in ["result", "_copy9", "$payload", "a"] {
            for (search, replacement) in [("q", "z"), ("A", "B"), ("\0", "\x7f"), ("$", "!")] {
                let source = format!(
                    "function rewrite(input){{const original=input['body']['data'];let {name}=original.replaceAll({},{});return {{type:'modify',body:{{kind:'text',data:{name}}}}};}}",
                    serde_json::to_string(search).unwrap(),
                    serde_json::to_string(replacement).unwrap(),
                );
                assert_eq!(
                    hint(&source),
                    OutputBound::InputOrConstant {
                        maximum_literal_bytes: 0
                    }
                );
            }
        }
    }

    #[test]
    fn fresh_return_paths_join_decoded_utf8_literal_bounds() {
        let text = "é😀\0";
        let source = format!(
            "function rewrite(input){{if(input.phase==='request')return {{type:'pass'}};if(input.response.status===201)return {{type:'modify',body:{{kind:'text',data:'cat'}}}};return {{type:'respond',status:200,body:{{kind:'text',data:{}}}}};}}",
            serde_json::to_string(text).unwrap()
        );
        assert_eq!(
            hint(&source),
            OutputBound::InputOrConstant {
                maximum_literal_bytes: text.len()
            }
        );
        let code = crate::http_processing::scripts::validate_source(&source).unwrap();
        assert_eq!(code.maximum_output_bytes(0), 7);
        assert_eq!(code.maximum_output_bytes(4096), 4096);
    }

    #[test]
    fn read_only_metadata_loops_and_array_mutators_do_not_change_plain_body_data() {
        let source = "function rewrite(input){let found=false;for(let index=0;index<input.response.headers.length;index++){if(input.response.headers[index].name==='anything')found=true;}const fields=Object.values(input);fields.push(input.body);fields.reverse();fields.pop();const ops=[];if(found)ops.push({op:'set',name:'x-any',values:['v']});JSON.stringify(input.response.headers);return {type:'modify',headers:ops,body:{kind:'text',data:input.body.data.replaceAll('u','v')}};}";
        assert_eq!(
            hint(source),
            OutputBound::InputOrConstant {
                maximum_literal_bytes: 0
            }
        );
    }

    #[test]
    fn every_legal_unknown_or_unsafe_program_falls_back_without_rejection() {
        for source in [
            "function rewrite(input){let d=input.body.data;d='long';return {type:'modify',body:{kind:'text',data:d}};}",
            "function rewrite(input){let d=input.body.data;const alias=d;d+='long';return {type:'modify',body:{kind:'text',data:alias}};}",
            "function rewrite(input){let d=input.body.data;String(d='long');return {type:'modify',body:{kind:'text',data:d}};}",
            "function rewrite(input){let d=input.body.data;d++;return {type:'modify',body:{kind:'text',data:d}};}",
            "function rewrite(input){const d=input.body.data;{const d='long';return {type:'modify',body:{kind:'text',data:d}};}return {type:'pass'};}",
            "function rewrite(input){const b=input.body;b.data='long';return {type:'modify',body:{kind:'text',data:input.body.data}};}",
            "function rewrite(input){if(false)input.body['data']='long';return {type:'modify',body:{kind:'text',data:input.body.data}};}",
            "function rewrite(input){for(let i=0;i<0;input.body.data='long'){}return {type:'modify',body:{kind:'text',data:input.body.data}};}",
            "function rewrite(input){String(input.body.data='long');return {type:'modify',body:{kind:'text',data:input.body.data}};}",
            "function rewrite(input){return {type:'modify',body:{kind:'text',data:input.body.data,data:'long'}};}",
            "function rewrite(input){return {type:'modify',body:{kind:'text',data:input.body.data},body:{kind:'text',data:'long'}};}",
            "function rewrite(input){return {type:'modify',type:'respond',body:{kind:'text',data:input.body.data}};}",
            "function rewrite(input){const result={type:'modify',body:{kind:'text',data:input.body.data}};return result;}",
            "function rewrite(input){return {type:'modify',body:{kind:'text',data:input.body.data.toUpperCase()}};}",
            "function rewrite(input){return {type:'modify',body:{kind:'text',data:input.body.data.replaceAll('ab','cd')}};}",
            "function rewrite(input){return {type:'modify',body:{kind:'text',data:input.body.data.replaceAll('é','x')}};}",
            "function rewrite(input){return {type:'modify',body:{kind:'text',data:input.body.data.replaceAll('q','$')}};}",
            "function rewrite(input){return {type:'modify',body:{kind:'text',data:input.body.data.replaceAll('q','$&')}};}",
            "function rewrite(input){return {type:'modify',body:{kind:'bytes',data:Uint8Array.from([1,2,3])}};}",
            "function rewrite(input){if(input.phase)return {type:'pass'};}",
            "function rewrite(input){return input;}",
            "function rewrite(input){return;}",
        ] {
            assert_eq!(
                hint(source),
                OutputBound::Maximum,
                "unsafe hint for {source}"
            );
        }
    }

    #[test]
    fn unsupported_public_syntax_stays_rejected_and_emitted_js_stays_identical() {
        for source in [
            "function rewrite(renamed){return {type:'modify',body:{kind:'text',data:renamed.body.data}};}",
            "function rewrite(input){input={};return {type:'pass'};}",
            "function rewrite(input){{let input={};}return {type:'pass'};}",
            "function rewrite(input){Object.setPrototypeOf(input.body,{});return {type:'pass'};}",
            "function rewrite(input){return {type:'modify',['body']:{kind:'text',data:input.body.data}};}",
        ] {
            assert!(
                super::super::compile_with_output_bound(source).is_err(),
                "changed language acceptance: {source}"
            );
        }
        let source = "function rewrite(input){return {type:'modify',body:{kind:'text',data:input.body.data}};}";
        let (code, _) = super::super::compile_with_output_bound(source).unwrap();
        assert_eq!(
            code,
            r#"function rewrite(input){"use strict";__voleTick();__voleFreezeParameters(input);return __voleValue({"type":"modify","body":__voleValue({"kind":"text","data":__voleGet(__voleGet(input,"body"),"data")})});}"#
        );
    }

    #[test]
    fn optional_analysis_caps_and_raw_trusted_sources_default_to_maximum() {
        let mut source = String::from("function rewrite(input){let ");
        for index in 0..=MAX_PROOF_BINDINGS {
            if index != 0 {
                source.push(',');
            }
            source.push_str(&format!("item{index}"));
        }
        source.push_str(";return {type:'modify',body:{kind:'text',data:input.body.data}};}");
        assert_eq!(hint(&source), OutputBound::Maximum);
        // No initializers: 129 '=' operators would correctly exceed the
        // existing lexical preflight cap before optional proof analysis.
        // Uninitialized let bindings are valid and exceed only the proof cap.
        let mut nodes = String::from("function rewrite(input){");
        for _ in 0..=MAX_PROOF_NODES / 2 {
            nodes.push_str("0;");
        }
        nodes.push_str("return {type:'pass'};}");
        assert_eq!(hint(&nodes), OutputBound::Maximum);
        let raw = crate::http_processing::scripts::CompiledSource {
            code: "function rewrite(input){return {type:'pass'};}".into(),
            ..Default::default()
        };
        assert_eq!(raw.output_bound, OutputBound::Maximum);
        assert_eq!(
            raw.maximum_output_bytes(1),
            super::super::super::super::body_budget::MAX_BODY
        );
    }

    #[test]
    fn an_unknown_future_call_cannot_inherit_a_previously_proved_output_hint() {
        let source = "function rewrite(input){input.body.data.padEnd(100000,'q');return {type:'modify',body:{kind:'text',data:input.body.data}};}";
        let allocator = oxc_allocator::Allocator::default();
        let parsed =
            oxc_parser::Parser::new(&allocator, source, oxc_span::SourceType::script()).parse();
        assert!(parsed.diagnostics.is_empty());
        let Statement::FunctionDeclaration(function) = &parsed.program.body[0] else {
            panic!("expected test function");
        };
        assert_eq!(analyze(function), OutputBound::Maximum);
        assert!(super::super::compile_with_output_bound(source).is_err());
    }
}
