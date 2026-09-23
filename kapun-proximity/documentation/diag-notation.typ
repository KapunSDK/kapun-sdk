// Byte strings wrap without changing the source data.
#let autobreaking(content) = block(width: 100%, breakable: true)[
  #set align(left)
  #set text(hyphenate: true)
  #show regex(".+"): s => s.text.codepoints().join(sym.zws)
  #content
]

// Keep :, =, => and tags intact. Indent both map and array members.
#let diag-notation(source) = {
  let rows = ()
  let depth = 0
  for line in source.text.split("\n") {
    let parts = line.trim().split(";")
    let statement = parts.at(0).trim()
    let comment = if parts.len() > 1 { parts.slice(1).join(";").trim() } else { "" }
    if statement == "" and comment == "" { continue }
    let closing = statement.starts-with("}") or statement.starts-with("]")
    let indent = calc.max(0, depth - if closing { 1 } else { 0 })
    rows.push(table.cell[
      #text(font: "DejaVu Sans Mono", size: 8.5pt)[
        #raw("  " * indent + statement, lang: "diag-notation", block: false)
      ]
    ])
    rows.push(table.cell[
      #text(size: 8pt, fill: rgb("64748b"))[#comment]
    ])
    depth = calc.max(0, depth + statement.matches(regex("[\\{\\[]")).len()
      - statement.matches(regex("[\\}\\]]")).len())
  }
  block(width: 100%, breakable: false, fill: rgb("f6f8fb"),
    stroke: (left: 2pt + rgb("6366f1")), inset: 12pt, radius: 3pt)[
    #set raw(syntaxes: "diag-notation.sublime-syntax")
    #set align(left)
    #set par(leading: 0.55em)
    #table(columns: (1.7fr, 1fr), align: left + top, stroke: none,
      inset: (x: 3pt, y: 3pt), ..rows)
  ]
}
