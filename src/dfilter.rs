//! Display filters (`-Y`): a small expression language evaluated against
//! the typed field tree from `field.rs`.
//!
//! Grammar (lowest to highest precedence):
//!
//! ```text
//!   or   := and  ( ('||' | 'or')  and )*
//!   and  := not  ( ('&&' | 'and') not )*
//!   not  := ('!' | 'not') not | primary
//!   primary := '(' or ')' | comparison | existence
//!   comparison := FIELD op VALUE
//!   existence  := FIELD
//!   op   := '==' | '!=' | '<' | '<=' | '>' | '>='  (or eq/ne/lt/le/gt/ge)
//! ```
//!
//! A FIELD is a dotted abbreviation (`ip.src`, `infiniband.bth.destqp`).
//! A VALUE is an unquoted token (`0x0a`, `443`, `10.0.0.1`) or a quoted
//! string. Field types aren't known ahead of time, so numeric vs string
//! comparison is decided per value at evaluation time: a `Uint` field
//! parses the literal as an integer (decimal or `0x` hex), a `Str` field
//! compares lexically.
//!
//! Semantics match tshark where it matters: a comparison is true if *any*
//! occurrence of the field satisfies it, and a bare field name is an
//! existence test.

use crate::field::{self, Node, Value};

/// A compiled display filter.
#[derive(Debug, Clone)]
pub struct Filter {
    root: Expr,
}

impl Filter {
    /// Compile filter source into an evaluable form, or return a
    /// human-readable error.
    pub fn compile(input: &str) -> Result<Filter, String> {
        let tokens = lex(input)?;
        let mut p = Parser { tokens, pos: 0 };
        let root = p.parse_or()?;
        if p.pos != p.tokens.len() {
            return Err(format!(
                "unexpected trailing input near token {}",
                p.pos + 1
            ));
        }
        Ok(Filter { root })
    }

    /// Evaluate the filter against a packet's field tree.
    pub fn matches(&self, tree: &[Node]) -> bool {
        self.root.eval(tree)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CmpOp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

impl CmpOp {
    fn apply(self, ord: std::cmp::Ordering) -> bool {
        use std::cmp::Ordering::*;
        match self {
            CmpOp::Eq => ord == Equal,
            CmpOp::Ne => ord != Equal,
            CmpOp::Lt => ord == Less,
            CmpOp::Le => ord != Greater,
            CmpOp::Gt => ord == Greater,
            CmpOp::Ge => ord != Less,
        }
    }
}

#[derive(Debug, Clone)]
enum Expr {
    Or(Box<Expr>, Box<Expr>),
    And(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
    Exists(String),
    Cmp {
        field: String,
        op: CmpOp,
        value: String,
    },
}

impl Expr {
    fn eval(&self, tree: &[Node]) -> bool {
        match self {
            Expr::Or(a, b) => a.eval(tree) || b.eval(tree),
            Expr::And(a, b) => a.eval(tree) && b.eval(tree),
            Expr::Not(a) => !a.eval(tree),
            Expr::Exists(name) => field::present(tree, name),
            Expr::Cmp { field, op, value } => field::collect(tree, field)
                .into_iter()
                .any(|v| value_matches(v, *op, value)),
        }
    }
}

fn value_matches(v: &Value, op: CmpOp, literal: &str) -> bool {
    match v {
        Value::Uint(u) => match parse_uint(literal) {
            Some(n) => op.apply(u.cmp(&n)),
            None => false, // numeric field, non-numeric literal → no match
        },
        Value::Str(s) => op.apply(s.as_str().cmp(literal)),
        Value::None => false,
    }
}

fn parse_uint(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        s.parse::<u64>().ok()
    }
}

// ---- lexer ----

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Word(String),
    Str(String),
    Op(CmpOp),
    And,
    Or,
    Not,
    LParen,
    RParen,
}

fn is_word_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '/' | '-')
}

fn lex(input: &str) -> Result<Vec<Tok>, String> {
    let mut toks = Vec::new();
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        match c {
            c if c.is_whitespace() => i += 1,
            '(' => {
                toks.push(Tok::LParen);
                i += 1;
            }
            ')' => {
                toks.push(Tok::RParen);
                i += 1;
            }
            '&' => {
                if chars.get(i + 1) == Some(&'&') {
                    toks.push(Tok::And);
                    i += 2;
                } else {
                    return Err("expected '&&'".into());
                }
            }
            '|' => {
                if chars.get(i + 1) == Some(&'|') {
                    toks.push(Tok::Or);
                    i += 2;
                } else {
                    return Err("expected '||'".into());
                }
            }
            '=' => {
                if chars.get(i + 1) == Some(&'=') {
                    toks.push(Tok::Op(CmpOp::Eq));
                    i += 2;
                } else {
                    return Err("expected '==' (single '=' is not valid)".into());
                }
            }
            '!' => {
                if chars.get(i + 1) == Some(&'=') {
                    toks.push(Tok::Op(CmpOp::Ne));
                    i += 2;
                } else {
                    toks.push(Tok::Not);
                    i += 1;
                }
            }
            '<' => {
                if chars.get(i + 1) == Some(&'=') {
                    toks.push(Tok::Op(CmpOp::Le));
                    i += 2;
                } else {
                    toks.push(Tok::Op(CmpOp::Lt));
                    i += 1;
                }
            }
            '>' => {
                if chars.get(i + 1) == Some(&'=') {
                    toks.push(Tok::Op(CmpOp::Ge));
                    i += 2;
                } else {
                    toks.push(Tok::Op(CmpOp::Gt));
                    i += 1;
                }
            }
            '"' => {
                let mut s = String::new();
                i += 1;
                let mut closed = false;
                while i < chars.len() {
                    if chars[i] == '"' {
                        closed = true;
                        i += 1;
                        break;
                    }
                    s.push(chars[i]);
                    i += 1;
                }
                if !closed {
                    return Err("unterminated string literal".into());
                }
                toks.push(Tok::Str(s));
            }
            c if is_word_char(c) => {
                let start = i;
                while i < chars.len() && is_word_char(chars[i]) {
                    i += 1;
                }
                let w: String = chars[start..i].iter().collect();
                toks.push(keyword(&w).unwrap_or(Tok::Word(w)));
            }
            other => return Err(format!("unexpected character '{other}'")),
        }
    }
    Ok(toks)
}

/// Map textual operator aliases to their token. Only whole words that
/// exactly equal an alias are mapped; anything else is a field/value word.
fn keyword(w: &str) -> Option<Tok> {
    match w {
        "and" => Some(Tok::And),
        "or" => Some(Tok::Or),
        "not" => Some(Tok::Not),
        "eq" => Some(Tok::Op(CmpOp::Eq)),
        "ne" => Some(Tok::Op(CmpOp::Ne)),
        "lt" => Some(Tok::Op(CmpOp::Lt)),
        "le" => Some(Tok::Op(CmpOp::Le)),
        "gt" => Some(Tok::Op(CmpOp::Gt)),
        "ge" => Some(Tok::Op(CmpOp::Ge)),
        _ => None,
    }
}

// ---- parser ----

struct Parser {
    tokens: Vec<Tok>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Tok> {
        self.tokens.get(self.pos)
    }

    fn parse_or(&mut self) -> Result<Expr, String> {
        let mut left = self.parse_and()?;
        while matches!(self.peek(), Some(Tok::Or)) {
            self.pos += 1;
            let right = self.parse_and()?;
            left = Expr::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_and(&mut self) -> Result<Expr, String> {
        let mut left = self.parse_not()?;
        while matches!(self.peek(), Some(Tok::And)) {
            self.pos += 1;
            let right = self.parse_not()?;
            left = Expr::And(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_not(&mut self) -> Result<Expr, String> {
        if matches!(self.peek(), Some(Tok::Not)) {
            self.pos += 1;
            let inner = self.parse_not()?;
            return Ok(Expr::Not(Box::new(inner)));
        }
        self.parse_primary()
    }

    fn parse_primary(&mut self) -> Result<Expr, String> {
        match self.peek() {
            Some(Tok::LParen) => {
                self.pos += 1;
                let e = self.parse_or()?;
                match self.peek() {
                    Some(Tok::RParen) => {
                        self.pos += 1;
                        Ok(e)
                    }
                    _ => Err("expected ')'".into()),
                }
            }
            Some(Tok::Word(_)) => {
                let field = match &self.tokens[self.pos] {
                    Tok::Word(w) => w.clone(),
                    _ => unreachable!(),
                };
                self.pos += 1;
                // Comparison, or bare existence test.
                if let Some(&Tok::Op(op)) = self.peek() {
                    self.pos += 1;
                    let value = match self.peek() {
                        Some(Tok::Word(w)) => w.clone(),
                        Some(Tok::Str(s)) => s.clone(),
                        _ => return Err(format!("expected a value after operator for '{field}'")),
                    };
                    self.pos += 1;
                    Ok(Expr::Cmp { field, op, value })
                } else {
                    Ok(Expr::Exists(field))
                }
            }
            Some(tok) => Err(format!("unexpected token {tok:?}")),
            None => Err("unexpected end of filter".into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::{Node, Value};

    fn tree() -> Vec<Node> {
        let mut ip = Node::proto("Internet Protocol Version 4");
        ip.add("ip.src", Value::Str("10.0.0.1".into()), "Source: 10.0.0.1");
        ip.add("ip.dst", Value::Str("10.0.0.2".into()), "Destination: 10.0.0.2");
        ip.add("ip.dsfield.ecn", Value::Uint(3), "ECN: 3");

        let mut bth = Node::proto("InfiniBand BTH");
        bth.add("infiniband.bth.opcode", Value::Uint(0x0a), "Opcode");
        bth.add("infiniband.bth.destqp", Value::Uint(0x123), "DQP");
        bth.add("infiniband.bth.psn", Value::Uint(100), "PSN");

        vec![ip, bth]
    }

    fn matches(expr: &str) -> bool {
        Filter::compile(expr).unwrap().matches(&tree())
    }

    #[test]
    fn numeric_equality_hex_and_decimal() {
        assert!(matches("infiniband.bth.destqp == 0x123"));
        assert!(matches("infiniband.bth.destqp == 291")); // 0x123
        assert!(!matches("infiniband.bth.destqp == 0x124"));
    }

    #[test]
    fn numeric_ordering() {
        assert!(matches("infiniband.bth.psn >= 100"));
        assert!(matches("infiniband.bth.psn > 99"));
        assert!(!matches("infiniband.bth.psn > 100"));
        assert!(matches("infiniband.bth.psn < 101"));
    }

    #[test]
    fn string_equality() {
        assert!(matches("ip.src == 10.0.0.1"));
        assert!(!matches("ip.src == 10.0.0.9"));
        assert!(matches("ip.dst != 10.0.0.1"));
    }

    #[test]
    fn existence_and_protocol_prefix() {
        assert!(matches("infiniband.bth.psn"));
        assert!(matches("infiniband.bth")); // protocol-prefix existence
        assert!(!matches("tcp"));
        assert!(!matches("udp.srcport"));
    }

    #[test]
    fn boolean_composition_and_precedence() {
        assert!(matches("ip.src == 10.0.0.1 && infiniband.bth.opcode == 0x0a"));
        assert!(matches("ip.src == 10.0.0.9 || infiniband.bth.psn == 100"));
        assert!(!matches("ip.src == 10.0.0.9 && infiniband.bth.psn == 100"));
        // && binds tighter than ||
        assert!(matches("tcp || ip.src == 10.0.0.1 && infiniband.bth"));
        assert!(matches("!tcp"));
        assert!(matches("not udp.srcport"));
    }

    #[test]
    fn parentheses_override_precedence() {
        assert!(!matches("(tcp || ip.src == 10.0.0.1) && udp"));
        assert!(matches("(tcp || ip.src == 10.0.0.1) && infiniband.bth"));
    }

    #[test]
    fn word_alias_operators() {
        assert!(matches("infiniband.bth.psn eq 100"));
        assert!(matches("infiniband.bth.psn ge 100 and ip.dsfield.ecn eq 3"));
    }

    #[test]
    fn ecn_marked_shortcut() {
        assert!(matches("ip.dsfield.ecn == 3"));
    }

    #[test]
    fn compile_errors() {
        assert!(Filter::compile("ip.src ==").is_err()); // missing value
        assert!(Filter::compile("(ip.src == 1").is_err()); // unbalanced paren
        assert!(Filter::compile("ip.src = 1").is_err()); // single =
        assert!(Filter::compile("&& ip").is_err()); // leading operator
    }
}
