//! Closed ASCII-substitution lowering over complete UTF-8 text inputs.
//! Header equality separately permits complete Unicode in a read-only prefix.
//! Unsupported source or input falls back to JSC before Plan execution.
use oxc_ast::ast::*;
use serde_json::Value;
use std::{collections::BTreeMap, io, sync::Arc, time::Instant};
use tokio_util::sync::CancellationToken;

use super::super::{
    body::BorrowedBody,
    body_budget::{BudgetedBytes, MAX_BODY, Reservation},
    rules::Phase,
};

mod body_guard;
mod header_guard;

const MAX_NODES: usize = 128;
const MAX_DEPTH: usize = 64;
const MAX_WORK: usize = 2 * 1024 * 1024;
const MAX_TICKS: usize = 100_000;

#[derive(Clone)]
enum Node {
    Input,
    Literal(Arc<str>),
    Replace {
        parent: usize,
        search: u8,
        replacement: u8,
        all: bool,
    },
}
#[derive(Clone, Copy)]
enum Action {
    Define(usize),
    Ticks(usize),
    Charge(usize),
    Size(usize),
}
enum Tree {
    Literal(String),
    Data,
    Array(Vec<Tree>),
    Object {
        fields: Vec<(String, Tree)>,
        body: bool,
    },
}

pub(crate) struct Plan {
    nodes: Vec<Node>,
    actions: Vec<Action>,
    result: usize,
    metadata: Value,
    materialization: Option<Recipe>,
    header_guard: Option<header_guard::Guard>,
    body_guard: Option<body_guard::Guard>,
}
// Immutable compiled metadata, never a body copy or invocation allocation.
// Steps are stored in base-to-result source order, not as a simultaneous map.
#[derive(Clone, Copy)]
struct Step {
    search: u8,
    replacement: u8,
}
struct Recipe {
    base: usize,
    steps: [Step; MAX_DEPTH],
    length: usize,
}
impl Recipe {
    fn compile(nodes: &[Node], result: usize) -> Option<Self> {
        let mut recipe = Self {
            base: result,
            steps: [Step {
                search: 0,
                replacement: 0,
            }; MAX_DEPTH],
            length: 0,
        };
        loop {
            match nodes.get(recipe.base)? {
                Node::Input | Node::Literal(_) => {
                    recipe.steps[..recipe.length].reverse();
                    return Some(recipe);
                }
                Node::Replace {
                    parent,
                    search,
                    replacement,
                    all: true,
                } => {
                    if recipe.length == MAX_DEPTH {
                        return None;
                    }
                    recipe.steps[recipe.length] = Step {
                        search: *search,
                        replacement: *replacement,
                    };
                    recipe.length += 1;
                    recipe.base = *parent;
                }
                // A First in the final ancestry keeps the complete old DAG.
                Node::Replace { all: false, .. } => return None,
            }
        }
    }
    fn source<'a>(&self, nodes: &'a [Node], input: &'a [u8]) -> io::Result<&'a [u8]> {
        match nodes.get(self.base) {
            Some(Node::Input) => Ok(input),
            Some(Node::Literal(value)) => Ok(value.as_bytes()),
            _ => Err(io::ErrorKind::InvalidInput.into()),
        }
    }
}

#[cfg(any(test, all(feature = "http-diagnostics", target_os = "tvos")))]
#[derive(Default)]
pub(super) struct Validation<'a> {
    pub(super) force_dag: bool,
    // Runs after a complete recipe chunk only; the original DAG loop is untouched.
    pub(super) after_chunk: Option<&'a mut (dyn FnMut(usize) + Send)>,
}
pub(super) struct Attempt {
    pub(super) result: io::Result<Value>,
    pub(super) ticks: usize,
    pub(super) allocation_work: usize,
    pub(super) backend: &'static str,
}
struct Builder {
    nodes: Vec<Node>,
    depths: Vec<usize>,
    actions: Vec<Action>,
    bindings: BTreeMap<String, Binding>,
    result: Option<usize>,
}
#[derive(Clone, Copy)]
struct Binding {
    node: usize,
    mutable: bool,
}

/// Optional proof only. Original frontend rejection/acceptance is unchanged.
/// Diagnostic/test convenience uses the same accepted frontend AST as production.
#[cfg(any(test, all(feature = "http-diagnostics", target_os = "tvos")))]
pub(super) fn compile(source: &str) -> Option<Plan> {
    super::frontend::compile_prepared(source).ok()?.plan
}

pub(super) fn analyze(function: &Function<'_>) -> Option<Plan> {
    let body = function.body.as_ref()?;
    let mut b = Builder {
        nodes: Vec::new(),
        depths: Vec::new(),
        actions: vec![Action::Ticks(1)],
        bindings: BTreeMap::new(),
        result: None,
    };
    let (last, declarations) = body.statements.split_last()?;
    let (header_guard, declarations) =
        if let Some((guard, consumed)) = header_guard::compile_prefix(declarations) {
            (Some(guard), declarations.get(consumed..)?)
        } else {
            (None, declarations)
        };
    let (body_guard, declarations) =
        if let Some((guard, consumed)) = body_guard::compile_prefix(declarations) {
            (Some(guard), declarations.get(consumed..)?)
        } else {
            (None, declarations)
        };
    for statement in declarations {
        if let Statement::ExpressionStatement(expression) = statement {
            b.rebind(&expression.expression)?;
            continue;
        }
        let Statement::VariableDeclaration(declaration) = statement else {
            return None;
        };
        if !matches!(
            declaration.kind,
            VariableDeclarationKind::Let | VariableDeclarationKind::Const
        ) {
            return None;
        }
        let mutable = declaration.kind == VariableDeclarationKind::Let;
        for declaration in &declaration.declarations {
            let BindingPattern::BindingIdentifier(name) = &declaration.id else {
                return None;
            };
            if name.name == "input"
                || b.bindings.contains_key(name.name.as_str())
                || header_guard
                    .as_ref()
                    .is_some_and(|guard| guard.conflicts_binding(name.name.as_str()))
            {
                return None;
            }
            let value = b.string(declaration.init.as_ref()?, 0)?;
            b.bindings.insert(
                name.name.as_str().to_owned(),
                Binding {
                    node: value,
                    mutable,
                },
            );
            if b.bindings.len() > MAX_NODES {
                return None;
            }
        }
    }
    let Statement::ReturnStatement(last) = last else {
        return None;
    };
    let fields = properties(last.argument.as_ref()?)?;
    if fields.len() < 2
        || fields.len() > 3
        || !fields
            .iter()
            .all(|(k, _)| matches!(*k, "type" | "body" | "headers"))
    {
        return None;
    }
    let mut tree = Vec::new();
    for (key, value) in fields {
        let value = match key {
            "type" if literal(value)? == "modify" => Tree::Literal("modify".into()),
            "body" => b.body(value)?,
            "headers" => b.static_tree(value, 0)?,
            _ => return None,
        };
        tree.push((key.to_owned(), value));
    }
    if !tree.iter().any(|(k, _)| k == "type") || !tree.iter().any(|(k, _)| k == "body") {
        return None;
    }
    b.actions.push(Action::Charge(tree.len() * 48 + 32));
    if let Some((_, headers)) = tree.iter().find(|(k, _)| k == "headers") {
        b.headers(headers)?;
    }
    let result = b.result?;
    b.actions.push(Action::Size(result)); // __voleFinish body text check.
    let tree = Tree::Object {
        fields: tree,
        body: false,
    };
    let encoded = b.measure(&tree, 0)?;
    if encoded > MAX_BODY {
        return None;
    }
    b.actions
        .push(Action::Charge(encoded.checked_mul(2)?.checked_add(32)?));
    let guard_nodes = header_guard.as_ref().map_or(0, |guard| guard.node_count())
        + body_guard.as_ref().map_or(0, |guard| guard.node_count());
    if guard_nodes + b.nodes.len() > MAX_NODES {
        return None;
    }
    let materialization = Recipe::compile(&b.nodes, result);
    Some(Plan {
        header_guard,
        body_guard,
        materialization,
        nodes: b.nodes,
        actions: b.actions,
        result,
        metadata: metadata(&tree)?,
    })
}

impl Builder {
    // Only a standalone top-level assignment to this mutable String binding
    // is proved. The old node remains immutable for every prior alias, and
    // the new call contributes its ordinary Define/tick/work actions.
    fn rebind(&mut self, value: &Expression<'_>) -> Option<()> {
        let Expression::AssignmentExpression(assignment) = value else {
            return None;
        };
        let AssignmentTarget::AssignmentTargetIdentifier(target) = &assignment.left else {
            return None;
        };
        if assignment.operator.as_str() != "=" || !self.bindings.get(target.name.as_str())?.mutable
        {
            return None;
        }
        let Expression::CallExpression(call) = &assignment.right else {
            return None;
        };
        let Expression::StaticMemberExpression(method) = &call.callee else {
            return None;
        };
        let Expression::Identifier(receiver) = &method.object else {
            return None;
        };
        if receiver.name != target.name || method.property.name != "replaceAll" {
            return None;
        }
        // string() proves non-optional calls, arity and both single ASCII
        // literals, excluding the replacement-template dollar character.
        let node = self.string(&assignment.right, 0)?;
        self.bindings.get_mut(target.name.as_str())?.node = node;
        Some(())
    }

    fn node(&mut self, node: Node, depth: usize) -> Option<usize> {
        if self.nodes.len() >= MAX_NODES || depth > MAX_DEPTH {
            return None;
        }
        let index = self.nodes.len();
        self.nodes.push(node);
        self.depths.push(depth);
        self.actions.push(Action::Define(index));
        Some(index)
    }
    fn string(&mut self, value: &Expression<'_>, depth: usize) -> Option<usize> {
        if depth > MAX_DEPTH {
            return None;
        }
        match value {
            Expression::Identifier(name) => self.bindings.get(name.name.as_str()).map(|v| v.node),
            Expression::StringLiteral(_) => self.node(Node::Literal(literal(value)?.into()), 0),
            Expression::StaticMemberExpression(data)
                if !data.optional && data.property.name == "data" =>
            {
                let Expression::StaticMemberExpression(body) = &data.object else {
                    return None;
                };
                if body.optional || body.property.name != "body" {
                    return None;
                }
                let Expression::Identifier(input) = &body.object else {
                    return None;
                };
                if input.name != "input" {
                    return None;
                }
                self.node(Node::Input, 0)
            }
            Expression::CallExpression(call) if !call.optional && call.arguments.len() == 2 => {
                let Expression::StaticMemberExpression(method) = &call.callee else {
                    return None;
                };
                if method.optional
                    || !matches!(method.property.name.as_str(), "replace" | "replaceAll")
                {
                    return None;
                }
                let search = literal(call.arguments[0].as_expression()?)?;
                let replacement = literal(call.arguments[1].as_expression()?)?;
                if search.len() != 1 || replacement.len() != 1 || replacement == "$" {
                    return None;
                }
                let parent = self.string(&method.object, depth + 1)?;
                self.node(
                    Node::Replace {
                        parent,
                        search: search.as_bytes()[0],
                        replacement: replacement.as_bytes()[0],
                        all: method.property.name == "replaceAll",
                    },
                    self.depths[parent] + 1,
                )
            }
            _ => None,
        }
    }
    fn body(&mut self, value: &Expression<'_>) -> Option<Tree> {
        let fields = properties(value)?;
        if fields.len() != 2 {
            return None;
        }
        let mut result = Vec::new();
        for (key, value) in fields {
            result.push((
                key.to_owned(),
                match key {
                    "kind" if literal(value)? == "text" => Tree::Literal("text".into()),
                    "data" => {
                        self.result = Some(self.string(value, 0)?);
                        Tree::Data
                    }
                    _ => return None,
                },
            ));
        }
        if !result.iter().any(|(k, _)| k == "kind") || !result.iter().any(|(k, _)| k == "data") {
            return None;
        }
        self.actions.push(Action::Charge(128));
        Some(Tree::Object {
            fields: result,
            body: true,
        })
    }
    fn static_tree(&mut self, value: &Expression<'_>, depth: usize) -> Option<Tree> {
        if depth > MAX_DEPTH {
            return None;
        }
        match value {
            Expression::StringLiteral(_) => Some(Tree::Literal(literal(value)?.to_owned())),
            Expression::ArrayExpression(array) if array.elements.len() <= 100 => {
                let mut values = Vec::new();
                for value in &array.elements {
                    values.push(self.static_tree(value.as_expression()?, depth + 1)?);
                }
                self.actions.push(Action::Charge(values.len() * 24 + 32));
                Some(Tree::Array(values))
            }
            Expression::ObjectExpression(_) => {
                let mut fields = Vec::new();
                for (key, value) in properties(value)? {
                    fields.push((key.to_owned(), self.static_tree(value, depth + 1)?));
                }
                self.actions.push(Action::Charge(fields.len() * 48 + 32));
                Some(Tree::Object {
                    fields,
                    body: false,
                })
            }
            _ => None,
        }
    }
    fn text(&mut self, text: &str, quoted: bool) -> Option<usize> {
        let bytes = if quoted {
            text.bytes().try_fold(2usize, |n, byte| {
                n.checked_add(match byte {
                    b'"' | b'\\' => 2,
                    8 | 9 | 10 | 12 | 13 => 2,
                    0..=31 => 6,
                    _ => 1,
                })
            })?
        } else {
            text.len()
        };
        if bytes > MAX_BODY {
            return None;
        }
        self.actions
            .push(Action::Ticks(text_ticks(text.len(), quoted)));
        Some(bytes)
    }
    fn headers(&mut self, value: &Tree) -> Option<()> {
        let Tree::Array(rows) = value else {
            return None;
        };
        let mut bytes = 0usize;
        let mut values = 0usize;
        for row in rows {
            let Tree::Object { fields, .. } = row else {
                return None;
            };
            if !fields
                .iter()
                .all(|(k, _)| matches!(k.as_str(), "op" | "name" | "values"))
            {
                return None;
            }
            let op = tree_literal(field(fields, "op")?)?;
            let name = tree_literal(field(fields, "name")?)?;
            if !header_name(name) {
                return None;
            }
            self.actions.push(Action::Ticks(1));
            self.text(name, false)?;
            match op {
                "remove" if fields.len() == 2 => bytes += name.len() + 32,
                "set" | "add" if fields.len() == 3 => {
                    let Tree::Array(items) = field(fields, "values")? else {
                        return None;
                    };
                    if items.is_empty() {
                        return None;
                    }
                    for value in items {
                        let value = tree_literal(value)?;
                        if value
                            .bytes()
                            .any(|b| b <= 8 || (10..=31).contains(&b) || b == 127)
                        {
                            return None;
                        }
                        self.text(value, false)?;
                        bytes += name.len() + value.len() + 32;
                        values += 1;
                        if bytes > 32768 || values > 100 {
                            return None;
                        }
                    }
                }
                _ => return None,
            }
            if bytes > 32768 {
                return None;
            }
        }
        Some(())
    }
    fn measure(&mut self, tree: &Tree, depth: usize) -> Option<usize> {
        if depth > MAX_DEPTH {
            return None;
        }
        self.actions.push(Action::Ticks(1));
        let size = match tree {
            Tree::Literal(text) => self.text(text, true)?,
            Tree::Array(values) => {
                let mut size = 2 + values.len().saturating_sub(1);
                for value in values {
                    size += self.measure(value, depth + 1)?;
                }
                size
            }
            Tree::Object { fields, body } => {
                let mut size = 2;
                let mut count = 0;
                for (key, value) in fields {
                    if *body && key == "data" {
                        continue;
                    }
                    size += usize::from(count > 0)
                        + self.text(key, true)?
                        + 1
                        + self.measure(value, depth + 1)?;
                    count += 1;
                }
                size
            }
            Tree::Data => return None,
        };
        (size <= MAX_BODY).then_some(size)
    }
}

fn literal<'a>(value: &'a Expression<'_>) -> Option<&'a str> {
    let Expression::StringLiteral(value) = value else {
        return None;
    };
    let value = value.value.as_str()?;
    (value.is_ascii() && value.len() <= MAX_BODY).then_some(value)
}
fn properties<'a, 'b>(value: &'b Expression<'a>) -> Option<Vec<(&'b str, &'b Expression<'a>)>> {
    let Expression::ObjectExpression(object) = value else {
        return None;
    };
    if object.properties.len() > 100 {
        return None;
    }
    let mut fields = Vec::new();
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
        if !key.is_ascii() || fields.iter().any(|(previous, _)| *previous == key) {
            return None;
        }
        fields.push((key, &property.value));
    }
    Some(fields)
}
fn field<'a>(fields: &'a [(String, Tree)], key: &str) -> Option<&'a Tree> {
    fields.iter().find(|(name, _)| name == key).map(|(_, v)| v)
}
fn tree_literal(value: &Tree) -> Option<&str> {
    if let Tree::Literal(value) = value {
        Some(value)
    } else {
        None
    }
}
fn header_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+.^_`|~-".contains(&b))
        && !matches!(
            name.to_ascii_lowercase().as_str(),
            "host"
                | "content-length"
                | "transfer-encoding"
                | "content-encoding"
                | "connection"
                | "upgrade"
                | "expect"
                | "trailer"
                | "te"
                | "http2-settings"
                | "keep-alive"
                | "proxy-connection"
                | "proxy-authorization"
                | "proxy-authenticate"
                | "content-range"
        )
}
fn metadata(tree: &Tree) -> Option<Value> {
    Some(match tree {
        Tree::Literal(value) => Value::String(value.clone()),
        Tree::Array(values) => Value::Array(values.iter().map(metadata).collect::<Option<_>>()?),
        Tree::Object { fields, body } => Value::Object(
            fields
                .iter()
                .filter(|(k, _)| !*body || k != "data")
                .map(|(k, v)| Some((k.clone(), metadata(v)?)))
                .collect::<Option<_>>()?,
        ),
        Tree::Data => return None,
    })
}
fn text_ticks(length: usize, quoted: bool) -> usize {
    if !quoted && length >= 4096 {
        1
    } else {
        length.div_ceil(256)
    }
}

// Mirrors runtime.js TextSize's UTF-16 loop, including its skipped low
// surrogate at a 256-unit boundary. ASCII substitutions preserve this shape.
fn utf8_text_ticks(text: &str, work: &Work<'_>) -> io::Result<usize> {
    if text.is_ascii() {
        return Ok(text_ticks(text.len(), false));
    }
    let mut units = 0usize;
    let mut ticks = 0usize;
    let mut next_check = 0usize;
    for (offset, character) in text.char_indices() {
        if offset >= next_check {
            work.check()?;
            next_check = offset + 256;
        }
        ticks += usize::from(units.is_multiple_of(256));
        units += character.len_utf16();
    }
    work.check()?;
    Ok(ticks)
}

// Runtime values are immutable views, not uncharged body copies. Every source
// declaration/call still executes its original preflight/tick/work actions.
// These views do not fuse calls or remove unused declarations.
struct TextState {
    length: usize,
    first: Option<usize>,
}
struct Workspace {
    values: Vec<TextState>,
    _reservation: Reservation,
}
struct Work<'a> {
    ticks: usize,
    allocated: usize,
    cancellation: &'a CancellationToken,
    deadline: Instant,
}
impl Work<'_> {
    fn check(&self) -> io::Result<()> {
        if self.cancellation.is_cancelled() {
            Err(io::ErrorKind::Interrupted.into())
        } else if self.ticks > MAX_TICKS || Instant::now() >= self.deadline {
            Err(io::ErrorKind::TimedOut.into())
        } else {
            Ok(())
        }
    }
    fn tick(&mut self) -> io::Result<()> {
        self.ticks += 1;
        self.check()
    }
    fn ticks(&mut self, count: usize) -> io::Result<()> {
        for _ in 0..count {
            self.tick()?;
        }
        Ok(())
    }
    fn charge(&mut self, bytes: usize) -> io::Result<()> {
        self.tick()?;
        self.allocated = self
            .allocated
            .checked_add(bytes)
            .filter(|n| *n <= MAX_WORK)
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
        Ok(())
    }
}

impl std::fmt::Debug for Plan {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StaticLiteralPlan")
            .field("nodes", &self.nodes.len())
            .field("actions", &self.actions.len())
            .finish_non_exhaustive()
    }
}

impl Plan {
    pub(super) fn accepts_input(&self, metadata: &Value, input: Option<BorrowedBody<'_>>) -> bool {
        metadata["body"]["kind"] == "text"
            && input.is_some_and(|body| std::str::from_utf8(body.as_bytes()).is_ok())
            && self
                .header_guard
                .as_ref()
                .is_none_or(|guard| guard.rows(metadata).is_some())
            && self
                .body_guard
                .as_ref()
                .is_none_or(|guard| guard.accepts_metadata(metadata))
    }
    // Only actual Text declarations with the same production Message phase
    // may use this proof. Message::metadata owns normalized header snapshots;
    // arbitrary diagnostic JSON retains accepts_input/Guard::rows validation.
    pub(super) fn covers_business_text_phase(&self, phase: Phase) -> bool {
        self.header_guard
            .as_ref()
            .is_none_or(|guard| guard.covers_business_phase(phase))
    }

    /// Call ONLY inside the existing lane and selected synchronous adapter,
    /// with its original
    /// absolute deadline and actual borrowed input/output owners. No JSC bridge
    /// copies exist on this backend, so no phantom JSC reservation is required.
    /// The input witness borrows the real Entity/Bytes owner; no Rust input copy.
    /// No queue/thread/VM here.
    /// None means unsupported input, not a budget rejection. After selection,
    /// every failure is Some(Err) and MUST NOT rerun JSC, including t=0 OOM.
    pub(super) fn try_execute(
        &self,
        metadata: &Value,
        input: Option<BorrowedBody<'_>>,
        output: &mut BudgetedBytes,
        cancellation: &CancellationToken,
        deadline: Instant,
    ) -> Option<Attempt> {
        self.execute(
            metadata,
            input,
            output,
            cancellation,
            deadline,
            #[cfg(any(test, all(feature = "http-diagnostics", target_os = "tvos")))]
            Validation::default(),
        )
    }
    // Existing per-call validation hook: unit tests or explicit tvOS diagnostics.
    // Source/business callers cannot request it; no process-global state.
    #[cfg(any(test, all(feature = "http-diagnostics", target_os = "tvos")))]
    pub(super) fn try_execute_for_validation(
        &self,
        metadata: &Value,
        input: Option<BorrowedBody<'_>>,
        output: &mut BudgetedBytes,
        cancellation: &CancellationToken,
        deadline: Instant,
        validation: Validation<'_>,
    ) -> Option<Attempt> {
        self.execute(metadata, input, output, cancellation, deadline, validation)
    }
    #[cfg(all(feature = "http-diagnostics", target_os = "tvos"))]
    pub(super) fn has_header_guard(&self) -> bool {
        self.header_guard.is_some()
    }
    #[cfg(all(feature = "http-diagnostics", target_os = "tvos"))]
    pub(super) fn materializer_kind(&self) -> &'static str {
        if self.materialization.is_some() {
            "recipe"
        } else {
            "dag"
        }
    }
    #[cfg(all(feature = "http-diagnostics", target_os = "tvos"))]
    pub(super) fn recipe_storage_bytes() -> usize {
        std::mem::size_of::<Option<Recipe>>()
    }
    fn execute(
        &self,
        metadata: &Value,
        input: Option<BorrowedBody<'_>>,
        output: &mut BudgetedBytes,
        cancellation: &CancellationToken,
        deadline: Instant,
        #[cfg(any(test, all(feature = "http-diagnostics", target_os = "tvos")))]
        mut validation: Validation<'_>,
    ) -> Option<Attempt> {
        let input = input?;
        let witness = input;
        let input = input.as_bytes();
        if metadata["body"]["kind"] != "text" {
            return None;
        }
        let text = std::str::from_utf8(input).ok()?;
        // Unsupported metadata is discovered before any Plan execution. It
        // cannot turn a skipped JS read into a synthetic Plan exception.
        let guard_rows = match &self.header_guard {
            Some(guard) => Some(guard.rows(metadata)?),
            None => None,
        };
        let guard_input = match &self.body_guard {
            Some(guard) => Some(guard.input(metadata, text)?),
            None => None,
        };
        if cancellation.is_cancelled() {
            return refused(io::ErrorKind::Interrupted);
        }
        if Instant::now() >= deadline {
            return refused(io::ErrorKind::TimedOut);
        }
        if input.len() > MAX_BODY {
            return refused(io::ErrorKind::FileTooLarge);
        }
        if !output.as_ref().is_empty() {
            return refused(io::ErrorKind::InvalidInput);
        }
        if !witness.same_ledger_as(output) {
            return refused(io::ErrorKind::InvalidInput);
        }
        let result_length = self.length(self.result, input.len());
        if result_length > MAX_BODY || result_length > output.remaining() {
            return refused(io::ErrorKind::FileTooLarge);
        }
        let Some(bytes) = self
            .nodes
            .len()
            .checked_mul(std::mem::size_of::<TextState>())
            .and_then(|n| n.checked_add(std::mem::size_of::<Vec<TextState>>()))
        else {
            return refused(io::ErrorKind::OutOfMemory);
        };
        let Some(reservation) = output.reserve_temporary(bytes) else {
            return refused(io::ErrorKind::OutOfMemory);
        };
        let mut values = Vec::new();
        if values.try_reserve_exact(self.nodes.len()).is_err()
            || values.capacity() > self.nodes.len()
        {
            return refused(io::ErrorKind::OutOfMemory);
        }
        let mut workspace = Workspace {
            values,
            _reservation: reservation,
        };
        let mut work = Work {
            ticks: 0,
            allocated: 0,
            cancellation,
            deadline,
        };
        let mut input_sizing_ticks = None;
        let result = (|| {
            work.check()?;
            let mut size = MetadataSize(0);
            serde_json::to_writer(&mut size, metadata)
                .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
            let guarded = self.header_guard.is_some() || self.body_guard.is_some();
            if guarded {
                work.ticks(1)?; // Exactly one whole-function entry, before guards.
            }
            if let (Some(guard), Some(rows)) = (&self.header_guard, guard_rows) {
                super::super::diagnostics::increment(
                    super::super::diagnostics::Counter::PlanHeaderGuardEntered,
                );
                if !guard.run(rows, &mut work)? {
                    let result = guard.early(&mut work)?;
                    work.check()?;
                    let counter = match result["type"].as_str() {
                        Some("pass") => super::super::diagnostics::Counter::PlanHeaderGuardPass,
                        Some("abort") => super::super::diagnostics::Counter::PlanHeaderGuardAbort,
                        _ => return Err(io::ErrorKind::InvalidInput.into()),
                    };
                    super::super::diagnostics::increment(counter);
                    return Ok(result); // No tail action or body write occurs.
                }
                super::super::diagnostics::increment(
                    super::super::diagnostics::Counter::PlanHeaderGuardTail,
                );
            }
            if let (Some(guard), Some(input)) = (&self.body_guard, guard_input)
                && guard.run(input, &mut work)?
            {
                return guard.early(&mut work); // No tail action or body write.
            }
            let actions = if guarded {
                &self.actions[1..] // Tail includes the old entry; do not repeat it.
            } else {
                &self.actions[..]
            };
            for action in actions {
                match *action {
                    Action::Ticks(count) => work.ticks(count)?,
                    Action::Charge(bytes) => work.charge(bytes)?,
                    Action::Size(node) => {
                        let ticks =
                            self.body_text_ticks(node, text, &mut input_sizing_ticks, &work)?;
                        work.ticks(ticks)?
                    }
                    Action::Define(index) => {
                        let (length, first) = match &self.nodes[index] {
                            Node::Input => {
                                work.ticks(4)?;
                                (input.len(), None)
                            }
                            Node::Literal(value) => (value.len(), None),
                            Node::Replace {
                                parent,
                                search,
                                all,
                                ..
                            } => {
                                let length = workspace.values[*parent].length;
                                work.ticks(2)?; // __voleCall + method key text.
                                let sizing_ticks = self.body_text_ticks(
                                    *parent,
                                    text,
                                    &mut input_sizing_ticks,
                                    &work,
                                )?;
                                work.ticks(sizing_ticks)?;
                                work.ticks(sizing_ticks)?;
                                work.ticks(2)?; // search/replacement text size.
                                work.charge(length * 2 + 32)?;
                                let mut first = None;
                                if !all {
                                    for offset in 0..length {
                                        if offset & 255 == 0 {
                                            work.check()?;
                                        }
                                        if self.byte(*parent, offset, input, &workspace.values)
                                            == *search
                                        {
                                            first = Some(offset);
                                            break;
                                        }
                                    }
                                }
                                (length, first)
                            }
                        };
                        workspace.values.push(TextState { length, first });
                    }
                }
            }
            work.check()?;
            output.write_initialized_output(result_length, |target| {
                #[cfg(any(test, all(feature = "http-diagnostics", target_os = "tvos")))]
                let recipe = self
                    .materialization
                    .as_ref()
                    .filter(|_| !validation.force_dag);
                #[cfg(not(any(test, all(feature = "http-diagnostics", target_os = "tvos"))))]
                let recipe = self.materialization.as_ref();
                if let Some(recipe) = recipe {
                    super::super::diagnostics::increment(
                        super::super::diagnostics::Counter::PlanFinalRecipeEntered,
                    );
                    let source = recipe.source(&self.nodes, input)?;
                    if source.len() != target.len() {
                        return Err(io::ErrorKind::InvalidInput.into());
                    }
                    // Only a generic one-step All recipe uses the single
                    // source→independent-output pass. Other recipes are exact
                    // original copy+ordered-step loops, including zero steps.
                    let single = if recipe.length == 1 {
                        super::super::diagnostics::increment(
                            super::super::diagnostics::Counter::PlanFinalSingleStepEntered,
                        );
                        Some(recipe.steps[0])
                    } else {
                        None
                    };
                    #[cfg(any(test, all(feature = "http-diagnostics", target_os = "tvos")))]
                    let mut filled = 0;
                    for (source, target) in source.chunks(256).zip(target.chunks_mut(256)) {
                        work.check()?;
                        if let Some(step) = single {
                            for (target, source) in target.iter_mut().zip(source.iter().copied()) {
                                *target = if source == step.search {
                                    step.replacement
                                } else {
                                    source
                                };
                            }
                        } else {
                            target.copy_from_slice(source);
                            for step in &recipe.steps[..recipe.length] {
                                for byte in target.iter_mut() {
                                    if *byte == step.search {
                                        *byte = step.replacement;
                                    }
                                }
                            }
                        }
                        #[cfg(any(test, all(feature = "http-diagnostics", target_os = "tvos")))]
                        {
                            filled += target.len();
                            if let Some(hook) = validation.after_chunk.as_mut() {
                                hook(filled);
                            }
                        }
                    }
                } else {
                    super::super::diagnostics::increment(
                        super::super::diagnostics::Counter::PlanFinalDagEntered,
                    );
                    for (offset, value) in target.iter_mut().enumerate() {
                        if offset & 255 == 0 {
                            work.check()?;
                        }
                        *value = self.byte(self.result, offset, input, &workspace.values);
                    }
                }
                Ok(result_length)
            })?;
            work.check()?;
            let result = self.metadata.clone();
            work.check()?;
            Ok(result)
        })();
        Some(Attempt {
            result,
            ticks: work.ticks,
            allocation_work: work.allocated,
            backend: "static-ascii-literal-prototype",
        })
    }
    // Every permitted replacement preserves its base's UTF-16 scalar starts.
    // Cache only the input summary, and only at a real TextSize action; unused
    // body aliases do not acquire a new payload scan or per-node heap state.
    fn body_text_ticks(
        &self,
        mut node: usize,
        input: &str,
        cached: &mut Option<usize>,
        work: &Work<'_>,
    ) -> io::Result<usize> {
        for _ in 0..=MAX_DEPTH {
            match self.nodes.get(node).ok_or(io::ErrorKind::InvalidData)? {
                Node::Input => {
                    if let Some(ticks) = *cached {
                        return Ok(ticks);
                    }
                    let ticks = utf8_text_ticks(input, work)?;
                    *cached = Some(ticks);
                    return Ok(ticks);
                }
                Node::Literal(value) => return Ok(text_ticks(value.len(), false)),
                Node::Replace { parent, .. } => node = *parent,
            }
        }
        Err(io::ErrorKind::InvalidData.into())
    }
    pub(super) fn maximum_output_bytes(&self, input: usize) -> Option<usize> {
        let size = self.length(self.result, input);
        (input <= MAX_BODY && size <= MAX_BODY).then_some(size)
    }
    fn length(&self, node: usize, input: usize) -> usize {
        match &self.nodes[node] {
            Node::Input => input,
            Node::Literal(value) => value.len(),
            Node::Replace { parent, .. } => self.length(*parent, input),
        }
    }
    fn byte(&self, node: usize, offset: usize, input: &[u8], states: &[TextState]) -> u8 {
        match &self.nodes[node] {
            Node::Input => input[offset],
            Node::Literal(value) => value.as_bytes()[offset],
            Node::Replace {
                parent,
                search,
                replacement,
                all,
            } => {
                let byte = self.byte(*parent, offset, input, states);
                if byte == *search && (*all || states[node].first == Some(offset)) {
                    *replacement
                } else {
                    byte
                }
            }
        }
    }
}
fn refused(kind: io::ErrorKind) -> Option<Attempt> {
    Some(Attempt {
        result: Err(kind.into()),
        ticks: 0,
        allocation_work: 0,
        backend: "static-ascii-literal-prototype",
    })
}
struct MetadataSize(usize);
impl io::Write for MetadataSize {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0 = self
            .0
            .checked_add(bytes.len())
            .filter(|n| *n <= 1024 * 1024)
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(all(test, target_vendor = "apple"))]
#[path = "static_literal_plan_tests.rs"]
mod tests;
