//! Parse real JavaScript syntax and emit the explicitly supported subset.
//! No unvalidated source fragments are copied into the generated program.
use oxc_allocator::Allocator;
use oxc_ast::ast::*;
use oxc_parser::Parser;
use oxc_span::SourceType;
use std::{collections::BTreeMap, io};

const MAX_NODES: usize = 16_384;
const MAX_DEPTH: usize = 128;
const MAX_GENERATED: usize = super::super::config::MAX_ADDENDUM * 8;
const MAX_LEX_WORK: usize = 8 * 1024 * 1024;
const MAX_LEX_BRANCHES: usize = 256;

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "unsupported HTTP script syntax",
    )
}

mod output_bound;

#[cfg(test)]
pub(super) fn compile(source: &str) -> io::Result<String> {
    compile_with_output_bound(source).map(|(code, _)| code)
}

#[cfg(test)]
pub(super) fn compile_with_output_bound(source: &str) -> io::Result<(String, super::OutputBound)> {
    let prepared = compile_prepared(source)?;
    Ok((prepared.code, prepared.output_bound))
}

pub(super) struct PreparedSource {
    pub(super) code: String,
    pub(super) output_bound: super::OutputBound,
    #[cfg(target_vendor = "apple")]
    pub(super) plan: Option<super::static_literal_plan::Plan>,
}

pub(super) fn compile_prepared(source: &str) -> io::Result<PreparedSource> {
    if source.len() > super::super::config::MAX_ADDENDUM {
        return Err(invalid());
    }
    lexical_budget(source)?;
    let allocator = Allocator::default();
    let parsed = Parser::new(&allocator, source, SourceType::script()).parse();
    if !parsed.diagnostics.is_empty()
        || parsed.fatal_error
        || parsed.program.hashbang.is_some()
        || !parsed.program.directives.is_empty()
        || parsed.program.body.len() != 1
    {
        return Err(invalid());
    }
    let Statement::FunctionDeclaration(function) = &parsed.program.body[0] else {
        return Err(invalid());
    };
    if function.r#async
        || function.generator
        || function.id.as_ref().is_none_or(|id| id.name != "rewrite")
        || function.params.rest.is_some()
        || function.params.items.len() != 1
    {
        return Err(invalid());
    }
    let parameter = &function.params.items[0];
    let BindingPattern::BindingIdentifier(parameter_name) = &parameter.pattern else {
        return Err(invalid());
    };
    if parameter_name.name != "input" || parameter.initializer.is_some() {
        return Err(invalid());
    }
    let body = function.body.as_ref().ok_or_else(invalid)?;
    if !body.directives.is_empty() {
        return Err(invalid());
    }
    let mut emitter = Emitter {
        nodes: 0,
        depth: 0,
        loops: 0,
        temporaries: 0,
        reads_original_url: false,
        scopes: vec![BTreeMap::from([("input".to_owned(), false)])],
    };
    let mut body_output = String::new();
    for statement in &body.statements {
        body_output.push_str(&emitter.statement(statement)?);
        if body_output.len() > MAX_GENERATED {
            return Err(invalid());
        }
    }
    let mut output = String::from(
        "function rewrite(input){\"use strict\";__voleTick();__voleFreezeParameters(input);",
    );
    if emitter.reads_original_url {
        output.push_str("const __voleOriginalURL=input.original.url;");
    }
    if emitter.temporaries > 0 {
        output.push_str("let ");
        for index in 0..emitter.temporaries {
            if index != 0 {
                output.push(',');
            }
            output.push_str(&format!("__voleTmp{index}"));
        }
        output.push(';');
    }
    output.push_str(&body_output);
    output.push('}');
    let code = emitter.bounded(output)?;
    // Analyze the same already accepted AST. An inconclusive/capped proof
    // returns Maximum and never changes JavaScript or public acceptance.
    Ok(PreparedSource {
        code,
        output_bound: output_bound::analyze(function),
        #[cfg(target_vendor = "apple")]
        plan: super::static_literal_plan::analyze(function),
    })
}

struct Emitter {
    nodes: usize,
    depth: usize,
    loops: usize,
    temporaries: usize,
    reads_original_url: bool,
    scopes: Vec<BTreeMap<String, bool>>,
}

impl Emitter {
    fn enter(&mut self) -> io::Result<()> {
        self.nodes += 1;
        self.depth += 1;
        if self.nodes > MAX_NODES || self.depth > MAX_DEPTH {
            return Err(invalid());
        }
        Ok(())
    }

    fn bounded(&self, output: String) -> io::Result<String> {
        if output.len() > MAX_GENERATED {
            return Err(invalid());
        }
        Ok(output)
    }

    fn statement(&mut self, statement: &Statement<'_>) -> io::Result<String> {
        self.enter()?;
        let output = self.statement_inner(statement);
        self.depth -= 1;
        self.bounded(output?)
    }

    fn statement_inner(&mut self, statement: &Statement<'_>) -> io::Result<String> {
        Ok(match statement {
            Statement::BlockStatement(block) => {
                self.scopes.push(BTreeMap::new());
                let mut output = String::from("{");
                for statement in &block.body {
                    output.push_str(&self.statement(statement)?);
                    if output.len() > MAX_GENERATED {
                        return Err(invalid());
                    }
                }
                self.scopes.pop();
                output.push('}');
                output
            }
            Statement::EmptyStatement(_) => ";".into(),
            Statement::VariableDeclaration(declaration) => {
                format!("{};", self.declaration(declaration)?)
            }
            Statement::ExpressionStatement(statement) => {
                format!("{};", self.expression(&statement.expression)?)
            }
            Statement::ReturnStatement(statement) => match &statement.argument {
                Some(argument) => format!("return {};", self.expression(argument)?),
                None => "return;".into(),
            },
            Statement::IfStatement(statement) => {
                let test = self.expression(&statement.test)?;
                let consequent = self.statement(&statement.consequent)?;
                let alternate = statement
                    .alternate
                    .as_ref()
                    .map(|statement| {
                        self.statement(statement)
                            .map(|output| format!("else{{{output}}}"))
                    })
                    .transpose()?
                    .unwrap_or_default();
                format!("if({test}){{{consequent}}}{alternate}")
            }
            Statement::WhileStatement(statement) => {
                let test = self.expression(&statement.test)?;
                self.loops += 1;
                let body = self.statement(&statement.body)?;
                self.loops -= 1;
                format!("while({test}){{__voleTick();{body}}}")
            }
            Statement::DoWhileStatement(statement) => {
                self.loops += 1;
                let body = self.statement(&statement.body)?;
                self.loops -= 1;
                let test = self.expression(&statement.test)?;
                format!("do{{__voleTick();{body}}}while({test});")
            }
            Statement::ForStatement(statement) => {
                self.scopes.push(BTreeMap::new());
                let init = match &statement.init {
                    Some(ForStatementInit::VariableDeclaration(declaration)) => {
                        self.declaration(declaration)?
                    }
                    Some(init) => self.expression(init.as_expression().ok_or_else(invalid)?)?,
                    None => String::new(),
                };
                let test = statement
                    .test
                    .as_ref()
                    .map(|value| self.expression(value))
                    .transpose()?
                    .unwrap_or_default();
                let update = statement
                    .update
                    .as_ref()
                    .map(|value| self.expression(value))
                    .transpose()?
                    .unwrap_or_default();
                self.loops += 1;
                let body = self.statement(&statement.body)?;
                self.loops -= 1;
                self.scopes.pop();
                format!("for({init};{test};{update}){{__voleTick();{body}}}")
            }
            Statement::BreakStatement(statement) if self.loops > 0 && statement.label.is_none() => {
                "break;".into()
            }
            Statement::ContinueStatement(statement)
                if self.loops > 0 && statement.label.is_none() =>
            {
                "continue;".into()
            }
            _ => return Err(invalid()),
        })
    }

    fn declaration(&mut self, declaration: &VariableDeclaration<'_>) -> io::Result<String> {
        let (kind, mutable) = match declaration.kind {
            VariableDeclarationKind::Let => ("let", true),
            VariableDeclarationKind::Const => ("const", false),
            _ => return Err(invalid()),
        };
        let mut output = Vec::new();
        for binding in &declaration.declarations {
            self.nodes += 1;
            if self.nodes > MAX_NODES {
                return Err(invalid());
            }
            let BindingPattern::BindingIdentifier(identifier) = &binding.id else {
                return Err(invalid());
            };
            let name = identifier.name.as_str();
            validate_binding(name)?;
            let init = binding
                .init
                .as_ref()
                .map(|value| self.expression(value))
                .transpose()?;
            if !mutable && init.is_none() {
                return Err(invalid());
            }
            if self
                .scopes
                .last_mut()
                .ok_or_else(invalid)?
                .insert(name.to_owned(), mutable)
                .is_some()
            {
                return Err(invalid());
            }
            output.push(match init {
                Some(init) => format!("{name}={init}"),
                None => name.to_owned(),
            });
        }
        self.bounded(format!("{kind} {}", output.join(",")))
    }

    fn variable(&self, name: &str, write: bool) -> io::Result<String> {
        if name == "undefined" && !write {
            return Ok(name.to_owned());
        }
        let mutable = self
            .scopes
            .iter()
            .rev()
            .find_map(|scope| scope.get(name))
            .ok_or_else(invalid)?;
        if write && !mutable {
            return Err(invalid());
        }
        Ok(name.to_owned())
    }

    fn expression(&mut self, expression: &Expression<'_>) -> io::Result<String> {
        self.enter()?;
        let output = self.expression_inner(expression);
        self.depth -= 1;
        self.bounded(output?)
    }

    fn expression_inner(&mut self, expression: &Expression<'_>) -> io::Result<String> {
        Ok(match expression {
            Expression::BooleanLiteral(value) => value.value.to_string(),
            Expression::NullLiteral(_) => "null".into(),
            Expression::NumericLiteral(value) if value.value.is_finite() => {
                serde_json::to_string(&value.value).map_err(|_| invalid())?
            }
            Expression::StringLiteral(value) => quoted(value.value.as_str().ok_or_else(invalid)?)?,
            Expression::Identifier(identifier) => self.variable(identifier.name.as_str(), false)?,
            Expression::ParenthesizedExpression(value) => {
                format!("({})", self.expression(&value.expression)?)
            }
            Expression::ArrayExpression(array) => {
                let mut elements = Vec::new();
                for element in &array.elements {
                    elements.push(self.expression(element.as_expression().ok_or_else(invalid)?)?);
                }
                format!("__voleValue([{}])", elements.join(","))
            }
            Expression::ObjectExpression(object) => {
                let mut properties = Vec::new();
                for property in &object.properties {
                    self.nodes += 1;
                    if self.nodes > MAX_NODES {
                        return Err(invalid());
                    }
                    let ObjectPropertyKind::ObjectProperty(property) = property else {
                        return Err(invalid());
                    };
                    if property.kind != PropertyKind::Init || property.method || property.computed {
                        return Err(invalid());
                    }
                    let key = match &property.key {
                        PropertyKey::StaticIdentifier(key) => key.name.as_str().to_owned(),
                        PropertyKey::StringLiteral(key) => {
                            key.value.as_str().ok_or_else(invalid)?.to_owned()
                        }
                        PropertyKey::NumericLiteral(key) if key.value.is_finite() => {
                            key.value.to_string()
                        }
                        _ => return Err(invalid()),
                    };
                    validate_key(&key)?;
                    properties.push(format!(
                        "{}:{}",
                        quoted(&key)?,
                        self.expression(&property.value)?
                    ));
                }
                format!("__voleValue({{{}}})", properties.join(","))
            }
            Expression::StaticMemberExpression(member) if !member.optional => {
                validate_key(member.property.name.as_str())?;
                format!(
                    "__voleGet({},{})",
                    self.expression(&member.object)?,
                    quoted(member.property.name.as_str())?
                )
            }
            Expression::ComputedMemberExpression(member) if !member.optional => {
                let object = self.expression(&member.object)?;
                let key = self.key_expression(&member.expression)?;
                format!("__voleGet({object},{key})")
            }
            Expression::BinaryExpression(binary) => {
                let operator = binary.operator.as_str();
                let left = self.expression(&binary.left)?;
                let right = self.expression(&binary.right)?;
                if operator == "+" {
                    format!("__voleAdd({left},{right})")
                } else if matches!(operator, "===" | "!==") {
                    format!("({left}{operator}{right})")
                } else if matches!(
                    operator,
                    "-" | "*"
                        | "/"
                        | "%"
                        | "<"
                        | "<="
                        | ">"
                        | ">="
                        | "=="
                        | "!="
                        | "==="
                        | "!=="
                        | "|"
                        | "&"
                        | "^"
                        | "<<"
                        | ">>"
                        | ">>>"
                ) {
                    format!("__voleBinary({},{left},{right})", quoted(operator)?)
                } else {
                    return Err(invalid());
                }
            }
            Expression::LogicalExpression(logical) => format!(
                "({}{}{})",
                self.expression(&logical.left)?,
                logical.operator.as_str(),
                self.expression(&logical.right)?
            ),
            Expression::ConditionalExpression(conditional) => format!(
                "({}?{}:{})",
                self.expression(&conditional.test)?,
                self.expression(&conditional.consequent)?,
                self.expression(&conditional.alternate)?
            ),
            Expression::UnaryExpression(unary)
                if matches!(
                    unary.operator.as_str(),
                    "+" | "-" | "!" | "~" | "typeof" | "void"
                ) =>
            {
                let argument = self.expression(&unary.argument)?;
                let operator = unary.operator.as_str();
                if matches!(operator, "+" | "-" | "~") {
                    format!("__voleUnary({},{argument})", quoted(operator)?)
                } else {
                    format!("({operator} {argument})")
                }
            }
            Expression::AssignmentExpression(assignment) => self.assignment(assignment)?,
            Expression::UpdateExpression(update) => {
                let SimpleAssignmentTarget::AssignmentTargetIdentifier(identifier) =
                    &update.argument
                else {
                    return Err(invalid());
                };
                let name = self.variable(identifier.name.as_str(), true)?;
                let change = if update.operator.as_str() == "++" {
                    "1"
                } else {
                    "-1"
                };
                if update.prefix {
                    format!("({name}=__voleAdd(__voleUnary(\"+\",{name}),{change}))")
                } else {
                    let temporary = self.temporaries;
                    self.temporaries += 1;
                    format!(
                        "(__voleTmp{temporary}=__voleUnary(\"+\",{name}),{name}=__voleAdd(__voleTmp{temporary},{change}),__voleTmp{temporary})"
                    )
                }
            }
            Expression::CallExpression(call) => self.call(call)?,
            _ => return Err(invalid()),
        })
    }

    fn key_expression(&mut self, expression: &Expression<'_>) -> io::Result<String> {
        if let Expression::StringLiteral(literal) = expression {
            validate_key(literal.value.as_str().ok_or_else(invalid)?)?;
        }
        self.expression(expression)
    }

    fn assignment(&mut self, assignment: &AssignmentExpression<'_>) -> io::Result<String> {
        let operator = assignment.operator.as_str();
        match &assignment.left {
            AssignmentTarget::AssignmentTargetIdentifier(identifier) => {
                let name = self.variable(identifier.name.as_str(), true)?;
                let value = self.expression(&assignment.right)?;
                if operator == "+=" {
                    Ok(format!("({name}=__voleAdd({name},{value}))"))
                } else if operator == "=" {
                    Ok(format!("({name}={value})"))
                } else if matches!(
                    operator,
                    "-=" | "*=" | "/=" | "%=" | "|=" | "&=" | "^=" | "<<=" | ">>=" | ">>>="
                ) {
                    Ok(format!(
                        "({name}=__voleBinary({},{name},{value}))",
                        quoted(&operator[..operator.len() - 1])?
                    ))
                } else {
                    Err(invalid())
                }
            }
            AssignmentTarget::StaticMemberExpression(member)
                if operator == "=" && !member.optional =>
            {
                validate_key(member.property.name.as_str())?;
                Ok(format!(
                    "__voleSet({},{},{})",
                    self.expression(&member.object)?,
                    quoted(member.property.name.as_str())?,
                    self.expression(&assignment.right)?
                ))
            }
            AssignmentTarget::ComputedMemberExpression(member)
                if operator == "=" && !member.optional =>
            {
                Ok(format!(
                    "__voleSet({},{},{})",
                    self.expression(&member.object)?,
                    self.key_expression(&member.expression)?,
                    self.expression(&assignment.right)?
                ))
            }
            _ => Err(invalid()),
        }
    }

    fn call(&mut self, call: &CallExpression<'_>) -> io::Result<String> {
        if call.optional {
            return Err(invalid());
        }
        let mut arguments = Vec::new();
        for argument in &call.arguments {
            arguments.push(self.expression(argument.as_expression().ok_or_else(invalid)?)?);
        }
        if let Expression::Identifier(identifier) = &call.callee {
            let name = identifier.name.as_str();
            if matches!(name, "String" | "Number" | "Boolean") && arguments.len() == 1 {
                return Ok(format!(
                    "__voleConvert({}, {})",
                    quoted(name)?,
                    arguments[0]
                ));
            }
            return Err(invalid());
        }
        let Expression::StaticMemberExpression(member) = &call.callee else {
            return Err(invalid());
        };
        if member.optional {
            return Err(invalid());
        }
        let name = member.property.name.as_str();
        validate_key(name)?;
        let receiver = if let Expression::Identifier(identifier) = &member.object {
            let global = identifier.name.as_str();
            if matches!(
                global,
                "JSON" | "Object" | "Array" | "Number" | "Math" | "Uint8Array" | "Vole"
            ) {
                if !global_method(global, name) {
                    return Err(invalid());
                }
                global.to_owned()
            } else {
                if !value_method(name) {
                    return Err(invalid());
                }
                self.expression(&member.object)?
            }
        } else {
            if !value_method(name) {
                return Err(invalid());
            }
            self.expression(&member.object)?
        };
        let arguments = arguments.join(",");
        if receiver == "Vole" {
            let context = if name == "query" {
                self.reads_original_url = true;
                ",__voleOriginalURL"
            } else {
                ""
            };
            return Ok(format!(
                "__voleTool({},[{arguments}]{context})",
                quoted(name)?
            ));
        }
        Ok(format!(
            "__voleCall({receiver},{},[{arguments}])",
            quoted(name)?
        ))
    }
}

fn quoted(value: &str) -> io::Result<String> {
    serde_json::to_string(value).map_err(|_| invalid())
}

fn validate_key(key: &str) -> io::Result<()> {
    if matches!(key, "constructor" | "prototype" | "__proto__") || key.starts_with("__vole") {
        return Err(invalid());
    }
    Ok(())
}

fn validate_binding(name: &str) -> io::Result<()> {
    validate_key(name)?;
    if name.is_empty()
        || !name.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphabetic()
                || byte == b'_'
                || byte == b'$'
                || (index > 0 && byte.is_ascii_digit())
        })
        || matches!(
            name,
            "input"
                | "rewrite"
                | "undefined"
                | "JSON"
                | "Object"
                | "Array"
                | "Math"
                | "Uint8Array"
                | "Vole"
                | "String"
                | "Number"
                | "Boolean"
                | "eval"
                | "arguments"
                | "yield"
                | "await"
                | "implements"
                | "interface"
                | "package"
                | "private"
                | "protected"
                | "public"
                | "static"
                | "let"
                | "enum"
        )
    {
        return Err(invalid());
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct LexicalBracket {
    delimiter: u8,
    outer_operators: u8,
}

#[derive(Clone, Default)]
struct LexicalState {
    offset: usize,
    brackets: Vec<LexicalBracket>,
    operators: usize,
    controls: usize,
    colons: usize,
}

/// This is only parser admission. Real syntax and every executable construct
/// still go through Oxc and the AST emitter. In particular, do not guess the
/// RegExp/Division lexical goal from preceding text: explore both possible
/// slash interpretations and conservatively enforce the resource bounds.
fn lexical_budget(source: &str) -> io::Result<()> {
    let bytes = source.as_bytes();
    let mut pending = vec![LexicalState::default()];
    let mut visited: BTreeMap<(usize, Vec<LexicalBracket>), (usize, usize, usize)> =
        BTreeMap::new();
    let mut work = 0usize;
    let mut branches = 0usize;
    while let Some(mut state) = pending.pop() {
        while state.offset < bytes.len() {
            let key = (state.offset, state.brackets.clone());
            if let Some(counts) = visited.get_mut(&key) {
                if counts.0 >= state.operators
                    && counts.1 >= state.controls
                    && counts.2 >= state.colons
                {
                    break;
                }
                state.operators = state.operators.max(counts.0);
                state.controls = state.controls.max(counts.1);
                state.colons = state.colons.max(counts.2);
                *counts = (state.operators, state.controls, state.colons);
            } else {
                if visited.len() >= MAX_NODES * 4 {
                    return Err(invalid());
                }
                visited.insert(key, (state.operators, state.controls, state.colons));
            }
            lex_work(&mut work, 1)?;
            let i = state.offset;
            match bytes[i] {
                b'\'' | b'"' => {
                    let quote = bytes[i];
                    let mut end = i + 1;
                    while end < bytes.len() {
                        lex_work(&mut work, 1)?;
                        if bytes[end] == b'\\' {
                            end += 1;
                            if end >= bytes.len() {
                                break;
                            }
                            if bytes[end] == b'\r' && bytes.get(end + 1) == Some(&b'\n') {
                                end += 1;
                            }
                        } else if bytes[end] == quote {
                            end += 1;
                            break;
                        } else if matches!(bytes[end], b'\n' | b'\r') {
                            break;
                        }
                        end += 1;
                    }
                    // An impossible lexical alternative must not reject a
                    // valid division expression. At a malformed line ending,
                    // keep scanning subsequent source for parser recovery;
                    // Oxc remains responsible for reporting the string error.
                    state.offset = end;
                }
                b'/' if bytes.get(i + 1) == Some(&b'/') => {
                    let mut end = i + 2;
                    while end < bytes.len() && !lex_line_end(bytes, end) {
                        lex_work(&mut work, 1)?;
                        end += 1;
                    }
                    state.offset = end;
                }
                b'/' if bytes.get(i + 1) == Some(&b'*') => {
                    let mut end = i + 2;
                    while end + 1 < bytes.len() && &bytes[end..end + 2] != b"*/" {
                        lex_work(&mut work, 1)?;
                        end += 1;
                    }
                    state.offset = (end + 2).min(bytes.len());
                }
                b'/' => {
                    if let Some(end) = possible_regexp_end(bytes, i + 1, &mut work)? {
                        branches += 1;
                        if branches > MAX_LEX_BRANCHES {
                            return Err(invalid());
                        }
                        let mut alternative = state.clone();
                        alternative.offset = end;
                        pending.push(alternative);
                    }
                    state.operators += 1;
                    state.offset += 1;
                }
                b'(' | b'[' | b'{' => {
                    state.brackets.push(LexicalBracket {
                        delimiter: bytes[i],
                        // Every incoming lexical state passed the bound below.
                        outer_operators: state.operators as u8,
                    });
                    state.offset += 1;
                    if bytes[i] == b'{' {
                        state.colons = 0;
                    }
                }
                b')' | b']' | b'}' => {
                    let expected = match bytes[i] {
                        b')' => b'(',
                        b']' => b'[',
                        _ => b'{',
                    };
                    if let Some(bracket) = state
                        .brackets
                        .pop_if(|bracket| bracket.delimiter == expected)
                    {
                        state.operators = usize::from(bracket.outer_operators);
                    }
                    if bytes[i] == b'}' {
                        state.colons = 0;
                    }
                    state.offset += 1;
                }
                b':' => {
                    state.colons += 1;
                    state.offset += 1;
                }
                b',' | b';' => {
                    // Sibling expressions cannot add depth to each other. A
                    // delimiter inside a bracket must keep the unfinished
                    // chain outside it, including in slash alternatives.
                    state.operators = state
                        .brackets
                        .last()
                        .map_or(0, |bracket| usize::from(bracket.outer_operators));
                    state.colons = 0;
                    state.offset += 1;
                }
                b'!' | b'~' | b'+' | b'-' | b'*' | b'%' | b'<' | b'>' | b'=' | b'&' | b'|'
                | b'^' | b'?' => {
                    state.operators += 1;
                    state.offset += 1;
                }
                b'`' | b'\\' => return Err(invalid()),
                byte if byte.is_ascii_alphabetic() || matches!(byte, b'_' | b'$') => {
                    let mut end = i + 1;
                    while end < bytes.len()
                        && (bytes[end].is_ascii_alphanumeric() || matches!(bytes[end], b'_' | b'$'))
                    {
                        lex_work(&mut work, 1)?;
                        end += 1;
                    }
                    match &bytes[i..end] {
                        b"if" | b"else" | b"for" | b"while" | b"do" | b"function" | b"class"
                        | b"switch" | b"try" | b"catch" | b"finally" | b"with" => {
                            state.controls += 1;
                        }
                        b"typeof" | b"void" | b"delete" | b"new" | b"await" | b"yield" | b"in"
                        | b"instanceof" => {
                            state.operators += 1;
                        }
                        _ => {}
                    }
                    state.offset = end;
                }
                byte if byte.is_ascii_whitespace() => {
                    state.offset += 1;
                    while state.offset < bytes.len() && bytes[state.offset].is_ascii_whitespace() {
                        lex_work(&mut work, 1)?;
                        state.offset += 1;
                    }
                }
                _ => state.offset += 1,
            }
            if state.brackets.len() > MAX_DEPTH
                || state.operators > MAX_DEPTH
                || state.controls > MAX_DEPTH
                || state.colons > MAX_DEPTH
            {
                return Err(invalid());
            }
        }
    }
    Ok(())
}

fn lex_work(work: &mut usize, amount: usize) -> io::Result<()> {
    *work = work
        .checked_add(amount)
        .filter(|n| *n <= MAX_LEX_WORK)
        .ok_or_else(invalid)?;
    Ok(())
}

fn possible_regexp_end(bytes: &[u8], start: usize, work: &mut usize) -> io::Result<Option<usize>> {
    let mut i = start;
    let mut class = false;
    while i < bytes.len() {
        lex_work(work, 1)?;
        if lex_line_end(bytes, i) {
            return Ok(None);
        }
        match bytes[i] {
            b'\n' | b'\r' => return Ok(None),
            b'\\' => {
                i += 1;
                if i >= bytes.len() || lex_line_end(bytes, i) {
                    return Ok(None);
                }
            }
            b'[' => class = true,
            b']' => class = false,
            b'/' if !class => return Ok(Some(i + 1)),
            _ => {}
        }
        i += 1;
    }
    Ok(None)
}

fn lex_line_end(bytes: &[u8], offset: usize) -> bool {
    matches!(bytes[offset], b'\n' | b'\r')
        || bytes[offset..].starts_with(&[0xE2, 0x80, 0xA8])
        || bytes[offset..].starts_with(&[0xE2, 0x80, 0xA9])
}

fn global_method(receiver: &str, name: &str) -> bool {
    match receiver {
        "JSON" => matches!(name, "parse" | "stringify"),
        "Object" => matches!(name, "keys" | "values" | "entries"),
        "Array" => name == "isArray",
        "Number" => matches!(name, "isFinite" | "isInteger"),
        "Math" => matches!(
            name,
            "abs" | "floor" | "ceil" | "round" | "trunc" | "min" | "max"
        ),
        "Uint8Array" => name == "from",
        "Vole" => matches!(
            name,
            "query"
                | "percentDecode"
                | "utf8Encode"
                | "utf8Decode"
                | "base64Encode"
                | "base64Decode"
                | "copyBytes"
                | "concatBytes"
        ),
        _ => false,
    }
}

fn value_method(name: &str) -> bool {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrites_all_growth_and_member_paths_from_the_ast() {
        let output = compile("function rewrite(input) { let s = input.body.data; const a = []; for(let i=0;i<3;i++){s += 'x'; a.push(s);} a[0] = s + 'y'; return {type:'modify',body:{kind:'text',data:a.join(',')}}; }").unwrap();
        assert_eq!(output.matches("__voleTick();").count(), 2);
        assert!(output.contains("__voleAdd(s,\"x\")"));
        assert!(output.contains("__voleSet(a,0.0,__voleAdd(s,\"y\"))"));
        assert!(output.contains("__voleGet(__voleGet(input,\"body\"),\"data\")"));
        assert!(output.contains("__voleCall(a,\"push\",[s])"));
        assert!(output.contains("__voleValue({"));
    }

    #[test]
    fn rejects_escape_syntax_and_uninstrumented_invocation_paths() {
        for source in [
            "function rewrite(input){return eval('1');}",
            "function rewrite(input){return input.constructor;}",
            "function rewrite(input){return input['__proto__'];}",
            "function rewrite(input){return __voleGet(input,'x');}",
            "function rewrite(input){return [].map(x=>x);}",
            "function rewrite(input){const f=JSON.parse;return f('{}');}",
            "function rewrite(input){return JSON['parse']('{}');}",
            "function rewrite(input){const f=Vole.copyBytes;return f(input.body.data);}",
            "function rewrite(input){return Vole['query']();}",
            "function rewrite(input){return Vole.fetch('https://example.test');}",
            "function rewrite(input){const Vole={};return Vole.query();}",
            "function rewrite(input){return new Uint8Array(10);}",
            "function rewrite(input){try{return input;}catch(e){return input;}}",
            "function rewrite(input){function f(){return 1;}return f();}",
            "async function rewrite(input){return input;}",
            "function rewrite(input){return {get x(){return 1;}};}",
            "function rewrite(input){return {['__proto__']:input};}",
            "function rewrite(input){let JSON={};return JSON.parse('{}');}",
            "function rewrite(input){return /x/.test('x');}",
            "function rewrite(input){return '\\ud800';}",
            "function rewrite(input){return input;} rewrite({});",
            "function rewrite(other){return other;}",
            "function rewrite(input){const a=1;a=2;return a;}",
        ] {
            assert!(compile(source).is_err(), "accepted {source}");
        }
    }

    #[test]
    fn all_loop_forms_tick_even_when_the_body_is_empty_or_continues() {
        let output = compile("function rewrite(input){let i=0;while(i<2){i++;continue;}do{i--;}while(i>0);for(;;);return {type:'pass'};}").unwrap();
        assert_eq!(output.matches("__voleTick();").count(), 4);
    }

    #[test]
    fn approved_tools_remain_explicit_calls_without_function_values() {
        let output = compile("function rewrite(input){const a=JSON.parse(input.body.data);const b=Object.keys(a);const c=Uint8Array.from([1,2]);return {type:'respond',status:Number('200'),body:{kind:'text',data:JSON.stringify(b)}};}").unwrap();
        assert!(output.contains("__voleCall(JSON,\"parse\","));
        assert!(output.contains("__voleCall(Uint8Array,\"from\","));
        assert!(output.contains("__voleConvert(\"Number\", \"200\")"));
    }

    #[test]
    fn typed_array_views_are_routed_through_the_controlled_method() {
        let output = compile("function rewrite(input){return {type:'modify',body:{kind:'bytes',data:input.body.data.subarray(1,3)}};}").unwrap();
        assert!(output.contains(
            "__voleCall(__voleGet(__voleGet(input,\"body\"),\"data\"),\"subarray\",[1.0,3.0])"
        ));
    }
}

#[cfg(test)]
mod lexical_tests {
    use super::*;

    #[test]
    fn parser_admits_many_shallow_assignments_without_losing_outer_depth() {
        let flat = format!(
            "function rewrite(input){{let a=0;{}return {{type:'pass'}};}}",
            "a+=1;".repeat(96)
        );
        assert!(compile(&flat).is_ok());

        let nested = format!(
            "function rewrite(input){{let a;{}(0,{}0);}}",
            "a=".repeat(80),
            "a=".repeat(80)
        );
        assert!(lexical_budget(&nested).is_err());
    }

    #[test]
    fn parser_admission_rejects_deep_expressions_and_unbraced_control_flow() {
        let cases = [
            format!(
                "function rewrite(input){{return {}0{};}}",
                "(".repeat(20_000),
                ")".repeat(20_000)
            ),
            format!(
                "function rewrite(input){{return {}true;}}",
                "!".repeat(20_000)
            ),
            format!(
                "function rewrite(input){{return {}true;}}",
                "typeof ".repeat(20_000)
            ),
            format!(
                "function rewrite(input){{{}return {{type:'pass'}};}}",
                "if(true) ".repeat(20_000)
            ),
            format!("function rewrite(input){{let a;{}0;}}", "a=".repeat(20_000)),
            format!(
                "function rewrite(input){{{}return {{type:'pass'}};}}",
                "label:".repeat(20_000)
            ),
        ];
        for source in cases {
            assert!(compile(&source).is_err());
        }
    }

    #[test]
    fn lexical_admission_skips_data_and_covers_regexp_quote_ambiguity() {
        let data = "if ((( ! ".repeat(1000);
        let source = format!(
            "function rewrite(input){{/* {data} */let s={};return {{type:'pass'}};}}",
            serde_json::to_string(&data).unwrap()
        );
        assert!(compile(&source).is_ok());
        assert!(compile("function rewrite(input){let n=8 / 2;const url='https://example.test/';return {type:'pass'};}").is_ok());
        let source = format!(
            "function rewrite(input){{let r=/\"/;{}0{};}}",
            "(".repeat(20_000),
            ")".repeat(20_000)
        );
        assert!(compile(&source).is_err());
        let source = format!(
            "function rewrite(input){{// comment\u{2028}{}0{};}}",
            "(".repeat(20_000),
            ")".repeat(20_000)
        );
        assert!(compile(&source).is_err());
    }
}

#[cfg(all(test, target_vendor = "apple"))]
mod prelude_tests {
    use crate::http_processing::{
        body_budget::{Budget, BudgetedBytes},
        scripts,
    };
    use serde_json::{Value, json};
    use std::io;
    use tokio_util::sync::CancellationToken;

    async fn run(source: &str, input: Option<&[u8]>) -> io::Result<(Value, Vec<u8>)> {
        run_with_url(source, input, "https://example.test/").await
    }

    async fn run_with_url(
        source: &str,
        input: Option<&[u8]>,
        original_url: &str,
    ) -> io::Result<(Value, Vec<u8>)> {
        let program = scripts::validate_source(source)?;
        let metadata = json!({"phase":"response","original":{"url":original_url,"method":"GET"},
            "request":{"url":"https://example.test/","method":"GET","headers":[]},
            "response":{"status":200,"headers":[]},"body":{"kind":if input.is_some(){"text"}else{"not-requested"}}});
        let budget = Budget::default();
        let mut output = BudgetedBytes::new(&budget, 0).unwrap();
        let result = scripts::evaluate(
            &program,
            &metadata,
            input,
            &mut output,
            &CancellationToken::new(),
        )
        .await?;
        Ok((result, output.as_ref().to_vec()))
    }

    #[tokio::test]
    async fn p1_query_preserves_original_order_unset_values_and_plus_mode() {
        let (_, body) = run_with_url(
            r#"function rewrite(input){
                input.original.url="https://example.test/?ignored=1";
                const result=[Vole.query(),Vole.query(true),Vole.percentDecode("%E4%B8%AD+%2B",true)];
                return {type:"respond",status:200,body:{kind:"text",data:JSON.stringify(result)}};
            }"#,
            None,
            "https://example.test/p?a&a=&b=+%2B%26&&=v%3D",
        )
        .await
        .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap(),
            json!([
                [{"name":"a","value":null},{"name":"a","value":""},{"name":"b","value":"++&"},{"name":"","value":"v="}],
                [{"name":"a","value":null},{"name":"a","value":""},{"name":"b","value":" +&"},{"name":"","value":"v="}],
                "中 +"
            ])
        );
    }

    #[tokio::test]
    async fn p1_binary_tools_preserve_exact_bytes_and_unicode() {
        let (_, bytes) = run(
            r#"function rewrite(input){
                const original=Vole.base64Decode("AAEC/w==");
                const result=Vole.concatBytes([Vole.copyBytes(original,1,3),Vole.utf8Encode("中😀")]);
                return {type:"respond",status:200,body:{kind:"bytes",data:result}};
            }"#,
            None,
        )
        .await
        .unwrap();
        assert_eq!(bytes, b"\x01\x02\xe4\xb8\xad\xf0\x9f\x98\x80");

        let (_, encoded) = run(
            r#"function rewrite(input){
                const result=Vole.base64Encode(Vole.utf8Encode("中😀"));
                return {type:"respond",status:200,body:{kind:"text",data:result}};
            }"#,
            None,
        )
        .await
        .unwrap();
        assert_eq!(encoded, b"5Lit8J+YgA==");

        let input = format!("{}😀{}", "a".repeat(1023), "é".repeat(4100));
        let (_, text) = run(
            r#"function rewrite(input){
                const result=Vole.utf8Decode(Vole.utf8Encode(input.body.data));
                return {type:"respond",status:200,body:{kind:"text",data:result}};
            }"#,
            Some(input.as_bytes()),
        )
        .await
        .unwrap();
        assert_eq!(text, input.as_bytes());
    }

    #[tokio::test]
    async fn p1_tools_reject_bad_encodings_ranges_and_excess_work() {
        for expression in [
            "Vole.query('form')",
            "Vole.percentDecode('%ED%A0%80')",
            "Vole.percentDecode('%')",
            "Vole.base64Decode('Zh==')",
            "Vole.base64Decode('AA=Z')",
            "Vole.base64Decode('Zg')",
            "Vole.utf8Decode(Uint8Array.from([192,128]))",
            "Vole.utf8Decode(Uint8Array.from([240,159,152]))",
            "Vole.copyBytes(Uint8Array.from([1]),0,2)",
            "Vole.concatBytes([null])",
        ] {
            let source =
                format!("function rewrite(input){{const v={expression};return {{type:'pass'}};}}");
            assert!(run(&source, None).await.is_err(), "accepted {expression}");
        }
        let input = vec![b'a'; 200_000];
        assert!(
            run(
                "function rewrite(input){const b=Vole.utf8Encode(input.body.data);const v=Vole.base64Encode(b);return {type:'pass'};}",
                Some(&input)
            )
            .await
            .is_err()
        );
        assert!(
            run(
                "function rewrite(input){const b=Vole.utf8Encode(input.body.data);for(let i=0;i<8;i++){const c=Vole.copyBytes(b);}return {type:'pass'};}",
                Some(&input)
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn coercive_operations_cannot_expand_nested_arrays_implicitly() {
        for expression in ["a+1", "a-1", "+a", "a<1", "Math.abs(a)", "Number(a)"] {
            let source = format!(
                "function rewrite(input){{let a=['x'];for(let i=0;i<20;i++){{a=[a,a];}}const n={expression};return {{type:'pass'}};}}"
            );
            assert!(run(&source, None).await.is_err(), "accepted {expression}");
        }
        assert!(
            run(
                "function rewrite(input){let n=[['x']];n++;return {type:'pass'};}",
                None
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn array_growth_join_and_split_fail_before_large_native_results() {
        for source in [
            "function rewrite(input){const a=[];a[262143]=0;return {type:'pass'};}",
            "function rewrite(input){let a=['x'];for(let i=0;i<20;i++){a=[a,a];}const s=a.join('');return {type:'pass'};}",
        ] {
            assert!(run(source, None).await.is_err());
        }
        assert!(
            run(
                "function rewrite(input){const a=input.body.data.split('');return {type:'pass'};}",
                Some(&vec![b'x'; 100_000])
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn text_growth_is_limited_in_utf8_bytes() {
        let input = "中".repeat(50_000);
        assert!(run("function rewrite(input){const a=input.body.data+input.body.data;return {type:'pass'};}",Some(input.as_bytes())).await.is_err());
    }

    #[tokio::test]
    async fn replacement_templates_keep_js_semantics_and_preflight_expansion() {
        let (_, body) = run("function rewrite(input){return {type:'respond',status:200,body:{kind:'text',data:'aaa'.replaceAll('a','$`')}};}",None).await.unwrap();
        assert_eq!(body, b"aaa");
        assert!(run("function rewrite(input){const s=input.body.data.replaceAll('a',\"$'\");return {type:'pass'};}",Some(&vec![b'a';4096])).await.is_err());
    }

    #[tokio::test]
    async fn result_export_checks_header_records_and_utf8_totals() {
        assert!(run("function rewrite(input){const h=[];for(let i=0;i<101;i++){h.push({op:'set',name:'x-test',values:['x']});}return {type:'modify',headers:h};}",None).await.is_err());
        let input = "中".repeat(6000);
        assert!(run("function rewrite(input){return {type:'modify',headers:[{op:'set',name:'x-test',values:[input.body.data,input.body.data]}]};}",Some(input.as_bytes())).await.is_err());
        for source in [
            "function rewrite(input){return {type:'pass',url:'https://example.test/'};}",
            "function rewrite(input){return {type:'modify',headers:[{op:'remove',name:'x-test',values:['x']}]};}",
            "function rewrite(input){return {type:'modify',headers:[{op:'add',name:'proxy-authorization',values:['x']}]};}",
        ] {
            assert!(run(source, None).await.is_err());
        }
    }

    #[tokio::test]
    async fn json_tools_reject_deep_or_shared_structures_without_exporting_them() {
        let deep = format!("{}0{}", "[".repeat(70), "]".repeat(70));
        assert!(run("function rewrite(input){const x=JSON.parse(input.body.data);return {type:'pass'};}",Some(deep.as_bytes())).await.is_err());
        assert!(run("function rewrite(input){let a=['x'];for(let i=0;i<20;i++){a=[a,a];}const s=JSON.stringify(a);return {type:'pass'};}",None).await.is_err());
    }

    #[tokio::test]
    async fn postfix_and_prefix_updates_preserve_their_numeric_results() {
        let (_,body)=run("function rewrite(input){let i='1';const a=i++;const b=++i;return {type:'respond',status:200,body:{kind:'text',data:JSON.stringify([a,b,i])}};}",None).await.unwrap();
        assert_eq!(body, b"[1,3,3]");
    }
}
