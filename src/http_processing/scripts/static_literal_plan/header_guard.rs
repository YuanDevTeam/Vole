//! Optional, complete three-statement read-only header guard prefix.
//! Called only after the original frontend has validated the entire function.
//! Compilation owns bounded metadata; execution borrows the actual rows.
use oxc_ast::ast::*;
use serde_json::{Value, json};
use std::io;

use super::{MAX_DEPTH, MAX_NODES, Work};
use crate::http_processing::{
    headers::{MAX_BYTES, MAX_FIELDS},
    rules::Phase,
};

// These four lowered control nodes are included in the parent's combined
// optional-plan cap: flag binding, index binding, loop, and early return.
const CONTROL_NODES: usize = 4;

#[derive(Clone, Copy, PartialEq, Eq)]
enum HeaderArray {
    Request,
    Response,
}
impl HeaderArray {
    fn key(self) -> &'static str {
        match self {
            Self::Request => "request",
            Self::Response => "response",
        }
    }
}
#[derive(Clone, Copy)]
enum Field {
    Name,
    Value,
}
enum Predicate {
    Compare {
        field: Field,
        literal: String,
        equal: bool,
    },
    And {
        left: usize,
        right: usize,
    },
    Or {
        left: usize,
        right: usize,
    },
}
#[derive(Clone, Copy)]
enum Early {
    Pass,
    Abort,
}

pub(super) struct Guard {
    flag: String,
    index: String,
    source: HeaderArray,
    predicates: Vec<Predicate>,
    root: usize,
    early: Early,
}
// No arbitrary slice/string factory is exposed. The values are qualified in
// Guard::rows before backend selection, without collecting or copying headers.
pub(super) struct Rows<'a> {
    values: &'a [Value],
    source: HeaderArray,
}

/// Recognize exactly three complete statements; the caller must still prove
/// the entire remaining tail, including binding conflicts, or retain JSC.
pub(super) fn compile_prefix<'a, 'b>(statements: &'b [Statement<'a>]) -> Option<(Guard, usize)> {
    let Statement::VariableDeclaration(flag_declaration) = statements.first()? else {
        return None;
    };
    let (flag, initial_flag) = binding(flag_declaration)?;
    if flag == "input"
        || !matches!(peel(initial_flag, 0)?.0, Expression::BooleanLiteral(value) if !value.value)
    {
        return None;
    }

    let Statement::ForStatement(loop_statement) = statements.get(1)? else {
        return None;
    };
    let Some(ForStatementInit::VariableDeclaration(index_declaration)) = &loop_statement.init
    else {
        return None;
    };
    let (index, initial_index) = binding(index_declaration)?;
    if index == "input"
        || index == flag
        || !matches!(peel(initial_index, 0)?.0, Expression::NumericLiteral(value) if value.value == 0.0)
    {
        return None;
    }

    let (test, depth) = peel(loop_statement.test.as_ref()?, 0)?;
    let Expression::BinaryExpression(test) = test else {
        return None;
    };
    if test.operator.as_str() != "<" || identifier(&test.left, depth + 1)? != index {
        return None;
    }
    let (length, depth) = peel(&test.right, depth + 1)?;
    let Expression::StaticMemberExpression(length) = length else {
        return None;
    };
    if length.optional || length.property.name != "length" {
        return None;
    }
    let source = header_array(&length.object, depth + 1)?;

    let (update, _) = peel(loop_statement.update.as_ref()?, 0)?;
    let Expression::UpdateExpression(update) = update else {
        return None;
    };
    let SimpleAssignmentTarget::AssignmentTargetIdentifier(updated) = &update.argument else {
        return None;
    };
    // Both prefix and postfix have identical discarded-result traces here.
    if update.operator.as_str() != "++" || updated.name != index {
        return None;
    }

    let Statement::IfStatement(condition) = single(&loop_statement.body)? else {
        return None;
    };
    if condition.alternate.is_some() {
        return None;
    }
    let Statement::ExpressionStatement(set_flag) = single(&condition.consequent)? else {
        return None;
    };
    let (set_flag, _) = peel(&set_flag.expression, 0)?;
    let Expression::AssignmentExpression(set_flag) = set_flag else {
        return None;
    };
    let AssignmentTarget::AssignmentTargetIdentifier(assigned) = &set_flag.left else {
        return None;
    };
    if set_flag.operator.as_str() != "="
        || assigned.name != flag
        || !matches!(peel(&set_flag.right, 0)?.0, Expression::BooleanLiteral(value) if value.value)
    {
        return None;
    }

    let Statement::IfStatement(early_statement) = statements.get(2)? else {
        return None;
    };
    if early_statement.alternate.is_some() {
        return None;
    }
    let (negation, depth) = peel(&early_statement.test, 0)?;
    let Expression::UnaryExpression(negation) = negation else {
        return None;
    };
    if negation.operator.as_str() != "!" || identifier(&negation.argument, depth + 1)? != flag {
        return None;
    }
    let Statement::ReturnStatement(early_return) = single(&early_statement.consequent)? else {
        return None;
    };
    let early = early_record(early_return.argument.as_ref()?)?;

    let mut predicates = Vec::new();
    let root = predicate(&condition.test, source, index, 0, &mut predicates)?;
    Some((
        Guard {
            flag: flag.to_owned(),
            index: index.to_owned(),
            source,
            predicates,
            root,
            early,
        },
        3,
    ))
}

impl Guard {
    /// Coverage is limited to production Message::metadata: request headers
    /// exist in both phases, and response headers only in the response phase.
    /// That private constructor checks the same field/byte bounds and emits
    /// exact name/value string rows. This never qualifies arbitrary JSON;
    /// rows() still validates each actual invocation before Plan selection.
    pub(super) fn covers_business_phase(&self, phase: Phase) -> bool {
        match self.source {
            HeaderArray::Request => matches!(phase, Phase::Request | Phase::Response),
            HeaderArray::Response => matches!(phase, Phase::Response),
        }
    }

    pub(super) fn conflicts_binding(&self, name: &str) -> bool {
        name == self.flag.as_str() || name == self.index.as_str()
    }
    pub(super) fn node_count(&self) -> usize {
        CONTROL_NODES + self.predicates.len()
    }

    pub(super) fn rows<'a>(&self, metadata: &'a Value) -> Option<Rows<'a>> {
        let rows = metadata
            .as_object()?
            .get(self.source.key())?
            .as_object()?
            .get("headers")?
            .as_array()?;
        if rows.len() > MAX_FIELDS {
            return None;
        }
        let mut bytes = 0usize;
        for row in rows {
            let row = row.as_object()?;
            if row.len() != 2 {
                return None;
            }
            let name = row.get("name")?.as_str()?;
            let value = row.get("value")?.as_str()?;
            bytes = bytes
                .checked_add(name.len())?
                .checked_add(value.len())?
                .checked_add(32)
                .filter(|size| *size <= MAX_BYTES)?;
        }
        Some(Rows {
            values: rows,
            source: self.source,
        })
    }

    /// Excludes the unique function-entry tick, which the parent executes once.
    pub(super) fn run(&self, rows: Rows<'_>, work: &mut Work<'_>) -> io::Result<bool> {
        if rows.source != self.source {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let mut found = false;
        for row in rows.values {
            work.ticks(7)?; // Three static Gets plus numeric '<'.
            work.tick()?; // Entering this loop iteration.
            if self.evaluate(self.root, row, work)? {
                found = true;
            }
            // INDEX++/++INDEX: __voleUnary('+') then __voleAdd(...,1).
            // Each helper ticks, then successful numeric __voleValue charges8.
            work.tick()?;
            work.charge(8)?;
            work.tick()?;
            work.charge(8)?;
        }
        work.ticks(7)?; // The final failed loop test still executes.
        Ok(found)
    }

    /// A fresh one-field pass/abort record and its complete Finish trace.
    pub(super) fn early(&self, work: &mut Work<'_>) -> io::Result<Value> {
        work.charge(80)?;
        work.ticks(4)?;
        work.charge(match self.early {
            Early::Pass => 62,
            Early::Abort => 64,
        })?;
        work.check()?;
        let value =
            json!({"type": match self.early { Early::Pass => "pass", Early::Abort => "abort" }});
        work.check()?;
        Ok(value)
    }

    fn evaluate(&self, index: usize, row: &Value, work: &mut Work<'_>) -> io::Result<bool> {
        match self
            .predicates
            .get(index)
            .ok_or(io::ErrorKind::InvalidInput)?
        {
            Predicate::Compare {
                field,
                literal,
                equal,
            } => {
                // Request/response, headers, numeric index and name/value each
                // execute Get plus short property-key TextSize. No value sizing.
                work.ticks(8)?;
                let key = match field {
                    Field::Name => "name",
                    Field::Value => "value",
                };
                let value = row
                    .as_object()
                    .and_then(|row| row.get(key))
                    .and_then(Value::as_str)
                    .ok_or(io::ErrorKind::InvalidInput)?;
                Ok((value == literal.as_str()) == *equal)
            }
            Predicate::And { left, right } => {
                if !self.evaluate(*left, row, work)? {
                    return Ok(false);
                }
                self.evaluate(*right, row, work)
            }
            Predicate::Or { left, right } => {
                if self.evaluate(*left, row, work)? {
                    return Ok(true);
                }
                self.evaluate(*right, row, work)
            }
        }
    }
}

fn binding<'a, 'b>(
    declaration: &'b VariableDeclaration<'a>,
) -> Option<(&'b str, &'b Expression<'a>)> {
    if declaration.kind != VariableDeclarationKind::Let || declaration.declarations.len() != 1 {
        return None;
    }
    let declaration = &declaration.declarations[0];
    let BindingPattern::BindingIdentifier(name) = &declaration.id else {
        return None;
    };
    Some((name.name.as_str(), declaration.init.as_ref()?))
}

fn peel<'a, 'b>(
    mut value: &'b Expression<'a>,
    mut depth: usize,
) -> Option<(&'b Expression<'a>, usize)> {
    loop {
        if depth > MAX_DEPTH {
            return None;
        }
        match value {
            Expression::ParenthesizedExpression(inner) => {
                value = &inner.expression;
                depth += 1;
            }
            _ => return Some((value, depth)),
        }
    }
}

fn single<'a, 'b>(mut statement: &'b Statement<'a>) -> Option<&'b Statement<'a>> {
    for _ in 0..=MAX_DEPTH {
        match statement {
            Statement::BlockStatement(block) if block.body.len() == 1 => {
                statement = &block.body[0];
            }
            Statement::BlockStatement(_) => return None,
            _ => return Some(statement),
        }
    }
    None
}

fn identifier<'a, 'b>(value: &'b Expression<'a>, depth: usize) -> Option<&'b str> {
    let Expression::Identifier(value) = peel(value, depth)?.0 else {
        return None;
    };
    Some(value.name.as_str())
}

fn header_array(value: &Expression<'_>, depth: usize) -> Option<HeaderArray> {
    let (value, depth) = peel(value, depth)?;
    let Expression::StaticMemberExpression(headers) = value else {
        return None;
    };
    if headers.optional || headers.property.name != "headers" {
        return None;
    }
    let (value, depth) = peel(&headers.object, depth + 1)?;
    let Expression::StaticMemberExpression(source) = value else {
        return None;
    };
    if source.optional || identifier(&source.object, depth + 1)? != "input" {
        return None;
    }
    match source.property.name.as_str() {
        "request" => Some(HeaderArray::Request),
        "response" => Some(HeaderArray::Response),
        _ => None,
    }
}

fn header_field(
    value: &Expression<'_>,
    source: HeaderArray,
    index: &str,
    depth: usize,
) -> Option<Field> {
    let (value, depth) = peel(value, depth)?;
    let Expression::StaticMemberExpression(field) = value else {
        return None;
    };
    if field.optional {
        return None;
    }
    let field_kind = match field.property.name.as_str() {
        "name" => Field::Name,
        "value" => Field::Value,
        _ => return None,
    };
    let (value, depth) = peel(&field.object, depth + 1)?;
    let Expression::ComputedMemberExpression(row) = value else {
        return None;
    };
    if row.optional
        || identifier(&row.expression, depth + 1)? != index
        || header_array(&row.object, depth + 1)? != source
    {
        return None;
    }
    Some(field_kind)
}

fn literal<'a, 'b>(value: &'b Expression<'a>, depth: usize) -> Option<&'b str> {
    let Expression::StringLiteral(value) = peel(value, depth)?.0 else {
        return None;
    };
    // as_str refuses incomplete UTF-16 (the original frontend also refuses it).
    // Unlike body-transform literals, guard equality permits complete Unicode.
    value.value.as_str()
}

fn predicate(
    value: &Expression<'_>,
    source: HeaderArray,
    index: &str,
    depth: usize,
    nodes: &mut Vec<Predicate>,
) -> Option<usize> {
    let (value, depth) = peel(value, depth)?;
    let node = match value {
        Expression::LogicalExpression(logical) => {
            let operator = logical.operator.as_str();
            if !matches!(operator, "&&" | "||") {
                return None;
            }
            let left = predicate(&logical.left, source, index, depth + 1, nodes)?;
            let right = predicate(&logical.right, source, index, depth + 1, nodes)?;
            if operator == "&&" {
                Predicate::And { left, right }
            } else {
                Predicate::Or { left, right }
            }
        }
        Expression::BinaryExpression(binary) => {
            let equal = match binary.operator.as_str() {
                "===" => true,
                "!==" => false,
                _ => return None,
            };
            let (field, text) = if let (Some(field), Some(text)) = (
                header_field(&binary.left, source, index, depth + 1),
                literal(&binary.right, depth + 1),
            ) {
                (field, text)
            } else {
                (
                    header_field(&binary.right, source, index, depth + 1)?,
                    literal(&binary.left, depth + 1)?,
                )
            };
            Predicate::Compare {
                field,
                literal: text.to_owned(),
                equal,
            }
        }
        _ => return None,
    };
    if nodes.len().checked_add(CONTROL_NODES)? >= MAX_NODES {
        return None;
    }
    let index = nodes.len();
    nodes.push(node);
    Some(index)
}

fn early_record(value: &Expression<'_>) -> Option<Early> {
    let Expression::ObjectExpression(record) = peel(value, 0)?.0 else {
        return None;
    };
    if record.properties.len() != 1 {
        return None;
    }
    let ObjectPropertyKind::ObjectProperty(property) = &record.properties[0] else {
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
    if key != "type" {
        return None;
    }
    match literal(&property.value, 0)? {
        "pass" => Some(Early::Pass),
        "abort" => Some(Early::Abort),
        _ => None,
    }
}
