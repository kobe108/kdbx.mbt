///|
/// A small XML reader, just large enough for the KDBX payload.
///
/// KeePass writes a plain XML document with elements, attributes and entities —
/// no namespaces, no CDATA in the payload — so this parses that subset and
/// refuses everything else rather than guessing. A full XML implementation is
/// deliberately out of scope (see docs/DESIGN.md, "what we do not build").

///|
/// An element with its attributes, child elements and character data.
pub struct XmlElement {
  name : String
  attributes : Array[(String, String)]
  children : Array[XmlElement]
  text : String
}

///|
pub fn XmlElement::name(self : XmlElement) -> String {
  self.name
}

///|
pub fn XmlElement::children(self : XmlElement) -> Array[XmlElement] {
  self.children.copy()
}

///|
pub fn XmlElement::text(self : XmlElement) -> String {
  self.text
}

///|
pub fn XmlElement::attribute(self : XmlElement, name : String) -> String? {
  let mut found : String? = None
  let mut i = 0
  while i < self.attributes.length() && found is None {
    let (key, value) = self.attributes[i]
    if key == name {
      found = Some(value)
    }
    i = i + 1
  }
  found
}

///|
/// Direct child elements with the given name, in document order.
pub fn XmlElement::children_named(
  self : XmlElement,
  name : String,
) -> Array[XmlElement] {
  let out : Array[XmlElement] = []
  for child in self.children {
    if child.name == name {
      out.push(child)
    }
  }
  out
}

///|
/// The first direct child with the given name, if any.
pub fn XmlElement::child(self : XmlElement, name : String) -> XmlElement? {
  let mut found : XmlElement? = None
  let mut i = 0
  while i < self.children.length() && found is None {
    if self.children[i].name == name {
      found = Some(self.children[i])
    }
    i = i + 1
  }
  found
}

///|
/// The character data of a named child, trimmed. Empty when it is missing.
pub fn XmlElement::child_text(self : XmlElement, name : String) -> String {
  match self.child(name) {
    Some(element) => element.text.trim().to_owned()
    None => ""
  }
}

///|
/// A cursor over the document being parsed.
priv struct XmlCursor {
  source : String
  mut position : Int
}

///|
fn XmlCursor::at_end(self : XmlCursor) -> Bool {
  self.position >= self.source.length()
}

///|
fn XmlCursor::peek(self : XmlCursor) -> Char {
  if self.at_end() {
    '\u{0}'
  } else {
    self.source[self.position].to_int().unsafe_to_char()
  }
}

///|
fn XmlCursor::advance(self : XmlCursor) -> Unit {
  self.position = self.position + 1
}

///|
fn XmlCursor::consume(self : XmlCursor, text : String) -> Bool {
  if self.source.length() - self.position < text.length() {
    return false
  }
  let mut i = 0
  while i < text.length() {
    if self.source[self.position + i] != text[i] {
      return false
    }
    i = i + 1
  }
  self.position = self.position + text.length()
  true
}

///|
fn XmlCursor::skip_whitespace(self : XmlCursor) -> Unit {
  while !self.at_end() {
    let c = self.peek()
    if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
      self.advance()
    } else {
      break
    }
  }
}

///|
/// Parses a document and returns its root element.
pub fn parse_xml(source : String) -> XmlElement raise KdbxError {
  let cursor = { source, position: 0, }
  skip_prologue(cursor)
  let root = parse_element(cursor)
  cursor.skip_whitespace()
  if !cursor.at_end() {
    raise Malformed("trailing content after the root element")
  }
  root
}

///|
/// Skips the XML declaration, comments and processing instructions before the
/// root element.
fn skip_prologue(cursor : XmlCursor) -> Unit raise KdbxError {
  let mut busy = true
  while busy {
    cursor.skip_whitespace()
    if cursor.consume("<?") {
      skip_until(cursor, "?>")
    } else if cursor.consume("<!--") {
      skip_until(cursor, "-->")
    } else if cursor.consume("<!DOCTYPE") {
      skip_until(cursor, ">")
    } else {
      busy = false
    }
  }
}

///|
fn skip_until(cursor : XmlCursor, terminator : String) -> Unit raise KdbxError {
  let mut done = false
  while !done {
    if cursor.at_end() {
      raise Malformed("unterminated construct before the root element")
    }
    if cursor.consume(terminator) {
      done = true
    } else {
      cursor.advance()
    }
  }
}

///|
fn parse_element(cursor : XmlCursor) -> XmlElement raise KdbxError {
  if !cursor.consume("<") {
    raise Malformed(
      "expected an element at offset " + cursor.position.to_string(),
    )
  }
  let name = parse_name(cursor)
  let attributes : Array[(String, String)] = []
  let mut self_closing = false
  let mut opening_done = false
  while !opening_done {
    cursor.skip_whitespace()
    if cursor.consume("/>") {
      self_closing = true
      opening_done = true
    } else if cursor.consume(">") {
      opening_done = true
    } else {
      let key = parse_name(cursor)
      cursor.skip_whitespace()
      if !cursor.consume("=") {
        raise Malformed("attribute " + key + " has no value")
      }
      cursor.skip_whitespace()
      attributes.push((key, parse_quoted(cursor)))
    }
  }
  let children : Array[XmlElement] = []
  let text_out = StringBuilder()
  if !self_closing {
    let mut closed = false
    while !closed {
      if cursor.at_end() {
        raise Malformed("element <" + name + "> is never closed")
      }
      if cursor.consume("</") {
        let closing = parse_name(cursor)
        if closing != name {
          raise Malformed("</" + closing + "> closes <" + name + ">")
        }
        cursor.skip_whitespace()
        if !cursor.consume(">") {
          raise Malformed("malformed closing tag for <" + name + ">")
        }
        closed = true
      } else if cursor.consume("<!--") {
        skip_until(cursor, "-->")
      } else if cursor.peek() == '<' {
        children.push(parse_element(cursor))
      } else {
        text_out.write_string(parse_text(cursor))
      }
    }
  }
  { name, attributes, children, text: text_out.to_string(), }
}

///|
fn parse_name(cursor : XmlCursor) -> String raise KdbxError {
  let out = StringBuilder()
  while !cursor.at_end() {
    let c = cursor.peek()
    let code = c.to_int()
    let is_letter = (code >= 0x41 && code <= 0x5A) ||
      (code >= 0x61 && code <= 0x7A)
    let is_digit = code >= 0x30 && code <= 0x39
    if is_letter || is_digit || c == '-' || c == '_' || c == ':' || c == '.' {
      out.write_char(c)
      cursor.advance()
    } else {
      break
    }
  }
  let name = out.to_string()
  if name.length() == 0 {
    raise Malformed("expected a name at offset " + cursor.position.to_string())
  }
  name
}

///|
fn parse_quoted(cursor : XmlCursor) -> String raise KdbxError {
  let quote = cursor.peek()
  if quote != '"' && quote != '\'' {
    raise Malformed("attribute value must be quoted")
  }
  cursor.advance()
  let out = StringBuilder()
  let mut closed = false
  while !closed {
    if cursor.at_end() {
      raise Malformed("unterminated attribute value")
    }
    let c = cursor.peek()
    if c == quote {
      cursor.advance()
      closed = true
    } else if c == '&' {
      out.write_string(parse_entity(cursor))
    } else {
      out.write_char(c)
      cursor.advance()
    }
  }
  out.to_string()
}

///|
fn parse_text(cursor : XmlCursor) -> String raise KdbxError {
  let out = StringBuilder()
  while !cursor.at_end() && cursor.peek() != '<' {
    if cursor.peek() == '&' {
      out.write_string(parse_entity(cursor))
    } else {
      out.write_char(cursor.peek())
      cursor.advance()
    }
  }
  out.to_string()
}

///|
/// Decodes one entity reference: the five predefined names and numeric
/// character references.
fn parse_entity(cursor : XmlCursor) -> String raise KdbxError {
  cursor.advance() // the ampersand
  let body = StringBuilder()
  while !cursor.at_end() && cursor.peek() != ';' {
    body.write_char(cursor.peek())
    cursor.advance()
  }
  if !cursor.consume(";") {
    raise Malformed("unterminated entity reference")
  }
  let name = body.to_string()
  match name {
    "amp" => "&"
    "lt" => "<"
    "gt" => ">"
    "quot" => "\""
    "apos" => "'"
    _ =>
      if name.length() > 1 && name[0] == '#' {
        let digits = if name[1] == 'x' || name[1] == 'X' {
          name[2:].to_owned()
        } else {
          name[1:].to_owned()
        }
        let radix = if name[1] == 'x' || name[1] == 'X' { 16 } else { 10 }
        let code = parse_code_point(digits, radix)
        code.unsafe_to_char().to_string()
      } else {
        raise Malformed("unknown entity &" + name + ";")
      }
  }
}

///|
fn parse_code_point(digits : String, radix : Int) -> Int raise KdbxError {
  if digits.length() == 0 {
    raise Malformed("empty character reference")
  }
  let mut value = 0
  let mut i = 0
  while i < digits.length() {
    let c = digits[i].to_int()
    let digit = if c >= 0x30 && c <= 0x39 {
      c - 0x30
    } else if c >= 0x61 && c <= 0x66 {
      c - 0x61 + 10
    } else if c >= 0x41 && c <= 0x46 {
      c - 0x41 + 10
    } else {
      raise Malformed("bad digit in character reference")
    }
    if digit >= radix {
      raise Malformed("digit out of range in character reference")
    }
    value = value * radix + digit
    i = i + 1
  }
  value
}
