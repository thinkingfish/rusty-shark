//! The protocol detail tree: the typed, named-field model that backs
//! verbose output (`-V`) and field extraction (`-e`).
//!
//! Each dissector, in addition to filling the summary columns, builds a
//! small tree of [`Node`]s: one protocol node per layer (Ethernet, IPv4,
//! TCP, ...) sitting at the top level, each with typed field children. A
//! node carries:
//!
//! - `abbrev` — a stable filter name (`ip.src`, `infiniband.bth.psn`),
//!   `None` for purely structural nodes. This is the hook a future display
//!   filter engine (`-Y`) will evaluate against.
//! - `value` — the typed value, used by `-e` extraction and (later) filters.
//! - `text` — the human-readable line shown by `-V`.
//!
//! Keeping abbrev + value on every field now means the display-filter
//! milestone is an additive change rather than another dissector rewrite.

use std::io::{self, Write};

/// A typed field value. Deliberately small; integers of every width fold
/// into `Uint`, and anything textual (addresses, MACs, names) into `Str`.
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    None,
    Uint(u64),
    Str(String),
}

impl std::fmt::Display for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Value::None => Ok(()),
            Value::Uint(u) => write!(f, "{u}"),
            Value::Str(s) => write!(f, "{s}"),
        }
    }
}

/// A node in the protocol detail tree.
#[derive(Clone, Debug)]
pub struct Node {
    pub abbrev: Option<&'static str>,
    pub value: Value,
    pub text: String,
    pub children: Vec<Node>,
}

impl Node {
    /// A structural / protocol node with display text but no filterable value.
    pub fn proto(text: impl Into<String>) -> Node {
        Node {
            abbrev: None,
            value: Value::None,
            text: text.into(),
            children: Vec::new(),
        }
    }

    /// A leaf field node carrying an abbreviation and typed value.
    pub fn field(abbrev: &'static str, value: Value, text: impl Into<String>) -> Node {
        Node {
            abbrev: Some(abbrev),
            value,
            text: text.into(),
            children: Vec::new(),
        }
    }

    /// Append a leaf field child.
    pub fn add(&mut self, abbrev: &'static str, value: Value, text: impl Into<String>) {
        self.children.push(Node::field(abbrev, value, text));
    }
}

/// Write the tree in tshark `-V` style: one line per node, indented four
/// spaces per level of depth.
pub fn write_verbose<W: Write>(w: &mut W, tree: &[Node]) -> io::Result<()> {
    for n in tree {
        write_node(w, n, 0)?;
    }
    Ok(())
}

fn write_node<W: Write>(w: &mut W, n: &Node, depth: usize) -> io::Result<()> {
    for _ in 0..depth {
        w.write_all(b"    ")?;
    }
    w.write_all(n.text.as_bytes())?;
    w.write_all(b"\n")?;
    for c in &n.children {
        write_node(w, c, depth + 1)?;
    }
    Ok(())
}

/// Return the first value in the tree (depth-first, pre-order) whose
/// abbreviation matches `abbrev`. This is what `-e <field>` selects.
pub fn extract<'a>(tree: &'a [Node], abbrev: &str) -> Option<&'a Value> {
    for n in tree {
        if let Some(v) = extract_node(n, abbrev) {
            return Some(v);
        }
    }
    None
}

fn extract_node<'a>(n: &'a Node, abbrev: &str) -> Option<&'a Value> {
    if n.abbrev == Some(abbrev) {
        return Some(&n.value);
    }
    for c in &n.children {
        if let Some(v) = extract_node(c, abbrev) {
            return Some(v);
        }
    }
    None
}

/// Collect every value in the tree whose abbreviation matches `abbrev`.
/// A field can occur more than once (e.g. repeated addresses); a display
/// filter comparison matches if *any* occurrence satisfies it, so the
/// evaluator needs them all.
pub fn collect<'a>(tree: &'a [Node], abbrev: &str) -> Vec<&'a Value> {
    let mut out = Vec::new();
    for n in tree {
        collect_node(n, abbrev, &mut out);
    }
    out
}

fn collect_node<'a>(n: &'a Node, abbrev: &str, out: &mut Vec<&'a Value>) {
    if n.abbrev == Some(abbrev) {
        out.push(&n.value);
    }
    for c in &n.children {
        collect_node(c, abbrev, out);
    }
}

/// True if a field or protocol named `name` is present. Matches the exact
/// abbreviation (`ip.src`) or any child path under it (`infiniband.bth`
/// matches when `infiniband.bth.opcode` exists), giving protocol-existence
/// semantics like tshark's bare `ip` / `tcp` tests.
pub fn present(tree: &[Node], name: &str) -> bool {
    fn rec(n: &Node, name: &str) -> bool {
        if let Some(a) = n.abbrev {
            if a == name
                || (a.starts_with(name) && a.as_bytes().get(name.len()) == Some(&b'.'))
            {
                return true;
            }
        }
        n.children.iter().any(|c| rec(c, name))
    }
    tree.iter().any(|n| rec(n, name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_finds_nested_field() {
        let mut ip = Node::proto("Internet Protocol Version 4");
        ip.add("ip.src", Value::Str("10.0.0.1".into()), "Source: 10.0.0.1");
        ip.add("ip.ttl", Value::Uint(64), "Time to Live: 64");
        let tree = vec![ip];

        assert_eq!(
            extract(&tree, "ip.src"),
            Some(&Value::Str("10.0.0.1".into()))
        );
        assert_eq!(extract(&tree, "ip.ttl"), Some(&Value::Uint(64)));
        assert_eq!(extract(&tree, "ip.dst"), None);
    }

    #[test]
    fn verbose_indents_by_depth() {
        let mut eth = Node::proto("Ethernet II");
        eth.add("eth.type", Value::Uint(0x0800), "Type: IPv4 (0x0800)");
        let mut out = Vec::new();
        write_verbose(&mut out, &[eth]).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert_eq!(s, "Ethernet II\n    Type: IPv4 (0x0800)\n");
    }

    #[test]
    fn value_display() {
        assert_eq!(Value::Uint(42).to_string(), "42");
        assert_eq!(Value::Str("x".into()).to_string(), "x");
        assert_eq!(Value::None.to_string(), "");
    }
}
