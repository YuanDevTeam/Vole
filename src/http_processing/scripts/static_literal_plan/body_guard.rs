//! A complete read-only text-input guard before the immutable String tail.
//! Unsupported predicates keep the whole invocation on JavaScriptCore.
use oxc_ast::ast::*;
use serde_json::{Value, json};
use std::io;

use super::{MAX_DEPTH, MAX_NODES, Work};

const CONTROL_NODES: usize = 2; // The if and its fresh early-return record.

enum TextField {
    Kind,
    DataType,
}
enum Predicate {
    Body,
    Text {
        field: TextField,
        literal: String,
        equal: bool,
    },
    Length {
        literal: f64,
        equal: bool,
    },
    Not(usize),
    And(usize, usize),
    Or(usize, usize),
}
#[derive(Clone, Copy)]
enum Early {
    Pass,
    Abort,
}

pub(super) struct Guard {
    predicates: Vec<Predicate>,
    root: usize,
    early: Early,
}
// The actual backend injects this borrowed UTF-8 text as body.data. Any data
// property in diagnostic metadata is overwritten by that same construction.
pub(super) struct Input<'a> {
    kind: &'a str,
    text: &'a str,
    units: Option<usize>,
}

pub(super) fn compile_prefix(statements: &[Statement<'_>]) -> Option<(Guard, usize)> {
    let Statement::IfStatement(statement) = statements.first()? else {
        return None;
    };
    if statement.alternate.is_some() {
        return None;
    }
    let Statement::ReturnStatement(early) = single(&statement.consequent)? else {
        return None;
    };
    let (record, _) = peel(early.argument.as_ref()?, 0)?;
    let fields = super::properties(record)?;
    if fields.len() != 1 || fields[0].0 != "type" {
        return None;
    }
    let early = match literal(fields[0].1, 0)? {
        "pass" => Early::Pass,
        "abort" => Early::Abort,
        _ => return None,
    };
    let mut predicates = Vec::new();
    let root = predicate(&statement.test, 0, &mut predicates)?;
    Some((
        Guard {
            predicates,
            root,
            early,
        },
        1,
    ))
}

impl Guard {
    pub(super) fn node_count(&self) -> usize {
        CONTROL_NODES + self.predicates.len()
    }

    pub(super) fn accepts_metadata(&self, metadata: &Value) -> bool {
        text_kind(metadata).is_some()
    }

    pub(super) fn input<'a>(&self, metadata: &'a Value, text: &'a str) -> Option<Input<'a>> {
        Some(Input {
            kind: text_kind(metadata)?,
            text,
            units: None,
        })
    }

    // Only the branch's truthiness escapes; every recognized leaf is either
    // boolean or the qualified body object. Logical short-circuit order is
    // preserved without evaluating a skipped length or synthesizing Gets.
    pub(super) fn run(&self, mut input: Input<'_>, work: &mut Work<'_>) -> io::Result<bool> {
        self.evaluate(self.root, &mut input, work)
    }

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

    fn evaluate(
        &self,
        index: usize,
        input: &mut Input<'_>,
        work: &mut Work<'_>,
    ) -> io::Result<bool> {
        match self
            .predicates
            .get(index)
            .ok_or(io::ErrorKind::InvalidInput)?
        {
            Predicate::Body => {
                work.ticks(2)?; // Get(input,"body") plus its key TextSize.
                Ok(true)
            }
            Predicate::Text {
                field,
                literal,
                equal,
            } => {
                work.ticks(4)?; // Two static Gets, each with key TextSize.
                let value = match field {
                    TextField::Kind => input.kind,
                    TextField::DataType => "string",
                };
                Ok((value == literal.as_str()) == *equal)
            }
            Predicate::Length { literal, equal } => {
                work.ticks(6)?; // body, data and length Gets, no numeric helper.
                Ok(((input.length(work)? as f64) == *literal) == *equal)
            }
            Predicate::Not(child) => Ok(!self.evaluate(*child, input, work)?),
            Predicate::And(left, right) => {
                if !self.evaluate(*left, input, work)? {
                    return Ok(false);
                }
                self.evaluate(*right, input, work)
            }
            Predicate::Or(left, right) => {
                if self.evaluate(*left, input, work)? {
                    return Ok(true);
                }
                self.evaluate(*right, input, work)
            }
        }
    }
}

impl Input<'_> {
    fn length(&mut self, work: &Work<'_>) -> io::Result<usize> {
        if let Some(units) = self.units {
            return Ok(units);
        }
        work.check()?;
        let units = if self.text.is_ascii() {
            self.text.len()
        } else {
            let mut units = 0usize;
            let mut next_check = 0usize;
            for (offset, character) in self.text.char_indices() {
                if offset >= next_check {
                    work.check()?;
                    next_check = offset + 256;
                }
                units += character.len_utf16();
            }
            units
        };
        work.check()?;
        self.units = Some(units);
        Ok(units)
    }
}

fn text_kind(metadata: &Value) -> Option<&str> {
    let kind = metadata
        .as_object()?
        .get("body")?
        .as_object()?
        .get("kind")?
        .as_str()?;
    (kind == "text").then_some(kind)
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

fn member<'a, 'b>(
    value: &'b Expression<'a>,
    name: &str,
    depth: usize,
) -> Option<(&'b Expression<'a>, usize)> {
    let (value, depth) = peel(value, depth)?;
    let Expression::StaticMemberExpression(value) = value else {
        return None;
    };
    (!value.optional && value.property.name == name).then_some((&value.object, depth + 1))
}

fn body(value: &Expression<'_>, depth: usize) -> Option<()> {
    let (value, depth) = member(value, "body", depth)?;
    let Expression::Identifier(value) = peel(value, depth)?.0 else {
        return None;
    };
    (value.name == "input").then_some(())
}

fn data(value: &Expression<'_>, depth: usize) -> Option<()> {
    let (value, depth) = member(value, "data", depth)?;
    body(value, depth)
}

fn field(value: &Expression<'_>, depth: usize) -> Option<TextField> {
    let (value, depth) = peel(value, depth)?;
    if let Some((value, depth)) = member(value, "kind", depth) {
        body(value, depth)?;
        return Some(TextField::Kind);
    }
    let Expression::UnaryExpression(unary) = value else {
        return None;
    };
    if unary.operator.as_str() != "typeof" {
        return None;
    }
    data(&unary.argument, depth + 1)?;
    Some(TextField::DataType)
}

fn length(value: &Expression<'_>, depth: usize) -> Option<()> {
    let (value, depth) = member(value, "length", depth)?;
    data(value, depth)
}

fn literal<'a, 'b>(value: &'b Expression<'a>, depth: usize) -> Option<&'b str> {
    let Expression::StringLiteral(value) = peel(value, depth)?.0 else {
        return None;
    };
    value.value.as_str()
}

fn number(value: &Expression<'_>, depth: usize) -> Option<f64> {
    let Expression::NumericLiteral(value) = peel(value, depth)?.0 else {
        return None;
    };
    value.value.is_finite().then_some(value.value)
}

fn predicate(value: &Expression<'_>, depth: usize, nodes: &mut Vec<Predicate>) -> Option<usize> {
    let (value, depth) = peel(value, depth)?;
    let node = match value {
        Expression::LogicalExpression(logical) => {
            let operator = logical.operator.as_str();
            if !matches!(operator, "&&" | "||") {
                return None;
            }
            let left = predicate(&logical.left, depth + 1, nodes)?;
            let right = predicate(&logical.right, depth + 1, nodes)?;
            if operator == "&&" {
                Predicate::And(left, right)
            } else {
                Predicate::Or(left, right)
            }
        }
        Expression::UnaryExpression(unary) if unary.operator.as_str() == "!" => {
            Predicate::Not(predicate(&unary.argument, depth + 1, nodes)?)
        }
        Expression::BinaryExpression(binary) => {
            let equal = match binary.operator.as_str() {
                "===" => true,
                "!==" => false,
                _ => return None,
            };
            if let (Some(field), Some(literal)) = (
                field(&binary.left, depth + 1),
                literal(&binary.right, depth + 1),
            ) {
                Predicate::Text {
                    field,
                    literal: literal.to_owned(),
                    equal,
                }
            } else if let (Some(literal), Some(field)) = (
                literal(&binary.left, depth + 1),
                field(&binary.right, depth + 1),
            ) {
                Predicate::Text {
                    field,
                    literal: literal.to_owned(),
                    equal,
                }
            } else if let (Some(()), Some(literal)) = (
                length(&binary.left, depth + 1),
                number(&binary.right, depth + 1),
            ) {
                Predicate::Length { literal, equal }
            } else {
                let literal = number(&binary.left, depth + 1)?;
                length(&binary.right, depth + 1)?;
                Predicate::Length { literal, equal }
            }
        }
        _ => {
            body(value, depth)?;
            Predicate::Body
        }
    };
    if nodes.len().checked_add(CONTROL_NODES)? >= MAX_NODES {
        return None;
    }
    let index = nodes.len();
    nodes.push(node);
    Some(index)
}
