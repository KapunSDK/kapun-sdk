// Reusable sequence diagrams: at most three steps per unbreakable canvas.
// Headers repeat on continuation panels. Use a single step before its walkthrough.
// Required: step, action. Wire events: sender, receiver. Local work: local_actors.
// Optional: example_ref, trace_ref, line_style.
#import "@preview/cetz:0.3.4": canvas, draw

#let _color(actor) = if actor == "wallet" { rgb("087f8c") } else { rgb("4f46e5") }

#let _sequence-panel(steps, title) = canvas({
  import draw: *
  let left = 1.65
  let right = 14.35
  let bottom = -steps.len() * 2.0
  if title != none {
    content((0, 1.2), text(size: 10pt, weight: "bold", fill: rgb("334155"))[#title], anchor: "west")
  }
  for (actor, x, name) in (("wallet", left, "Wallet / Device"), ("reader", right, "Verifier / Reader")) {
    rect((x - 1.65, bottom), (x + 1.65, 0.12), radius: 0.12,
      fill: if actor == "wallet" { rgb("f0fdfa") } else { rgb("f5f3ff") }, stroke: none)
    rect((x - 1.65, 0.12), (x + 1.65, 0.85), radius: 0.12, fill: _color(actor), stroke: none)
    content((x, 0.485), text(size: 10pt, weight: "bold", fill: white)[#name])
    line((x, 0.12), (x, bottom + 0.1), stroke: (paint: _color(actor).lighten(55%), thickness: 0.7pt, dash: "dashed"))
  }
  for (index, step) in steps.enumerate() {
    let y = -index * 2.0
    let locals = step.at("local_actors", default: ())
    let sender = step.at("sender", default: "wallet")
    let receiver = step.at("receiver", default: sender)
    let local = locals.len() > 0 or sender == receiver
    let color = if local { rgb("475569") } else { _color(sender) }
    content((8, y - 0.5), [
      #block(width: 9.5cm)[
        #set align(center)
        #text(size: 9.5pt, weight: "bold", fill: rgb("0f172a"))[#step.step · #step.action]
      ]
    ])
    let wire-y = y - 1.1
    if local {
      for actor in if locals.len() > 0 { locals } else { (sender,) } {
        let x = if actor == "wallet" { left } else { right }
        let loop-x = x + if actor == "wallet" { 0.8 } else { -0.8 }
        let stroke = (paint: _color(actor), thickness: 1.3pt)
        line((x, wire-y + 0.3), (loop-x, wire-y + 0.3), stroke: stroke)
        line((loop-x, wire-y + 0.3), (loop-x, wire-y - 0.15), stroke: stroke)
        line((loop-x, wire-y - 0.15), (x, wire-y - 0.15), stroke: stroke, mark: (end: "stealth"))
      }
      content((8, wire-y), text(size: 8pt, fill: rgb("64748b"))[Local Computation])
    } else {
      let from = if sender == "wallet" { left } else { right }
      let to = if receiver == "wallet" { left } else { right }
      line((from, wire-y), (to, wire-y), stroke: (paint: color, thickness: 1.4pt,
        dash: if step.at("line_style", default: "solid") == "dashed" { "dashed" } else { "solid" }), mark: (end: "stealth"))
    }
    content((8, y - 1.65), text(size: 8pt, fill: rgb("64748b"))[
      #if "example_ref" in step { ref(label("payload-" + step.example_ref)) }
      #if "trace_ref" in step [ · #ref(label("trace-" + step.trace_ref))]
    ])
  }
})

#let proximity_flow_graph(steps: (), title: none, steps-per-panel: 3) = {
  assert(steps-per-panel > 0)
  for start in range(0, steps.len(), step: steps-per-panel) {
    block(width: 100%, breakable: false, above: 10pt, below: 10pt)[
      #align(center)[#_sequence-panel(steps.slice(start, calc.min(start + steps-per-panel, steps.len())), title)]
    ]
  }
}
