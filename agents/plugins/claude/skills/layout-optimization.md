---
name: layout-optimization
description: Guidelines for optimizing D2 diagram layout to reduce whitespace and improve visual clarity
triggers: [layout, whitespace, aspect ratio, optimization, grid]
dependencies: [d2]
---

# Layout Optimization

Guidelines for optimizing D2 diagram layouts to reduce whitespace and improve clarity.

## Key Metrics

### Whitespace Ratio

| Ratio | Status | Action |
|-------|--------|--------|
| < 40% | Optimal | None needed |
| 40-50% | Warning | Consider optimization |
| > 50% | Needs work | Apply fixes |

### Aspect Ratio by Direction

| Direction | Target Ratio | Interpretation |
|-----------|--------------|----------------|
| right | > 1.2:1 | Wider than tall |
| left | > 1.2:1 | Wider than tall |
| down | < 0.8:1 | Taller than wide |
| up | < 0.8:1 | Taller than wide |

## Legend Positioning

### Problem: Legend Displaces Content

When legend is not positioned, it becomes part of the flow:

```d2
# ❌ Bad - legend takes space in main flow
legend: Legend {
  # No positioning
}
```

### Solution: Use `near:` Positioning

```d2
# ✅ Good - legend positioned outside flow
legend: Legend {
  near: bottom-center
}
```

**Options**:
- `bottom-center` (recommended)
- `top-center`
- `bottom-left`
- `bottom-right`

## Grid Layouts

### When to Use Grid

**Good for**:
- Legend items (horizontal arrangement)
- Data stores (compact grouping)
- Elements without interconnections

**Avoid for**:
- Elements with arrows between them
- Processing elements that communicate

### Grid Columns in Legend

```d2
legend: Legend {
  near: bottom-center
  grid-columns: 5  # Arrange items horizontally

  item1: "A" { ... }
  item2: "B" { ... }
  item3: "C" { ... }
  item4: "D" { ... }
  item5: "E" { ... }
}
```

### Grid Rows for Data Stores

```d2
localhost-zone: Localhost {
  grid-rows: 2

  processes: Processes {
    grid-columns: 2
    gateway: Gateway { ... }
    agent: Agent { ... }
  }

  stores: Data Stores {
    grid-columns: 4
    config: Config { ... }
    logs: Logs { ... }
    devices: Devices { ... }
    keys: Keys { ... }
  }
}
```

## Arrow Visibility Issues

### Problem: Adjacent Grid Elements

When elements are in the same grid container, arrows between them become very short:

```d2
container: {
  grid-columns: 2
  a: A { }
  b: B { }
}

# Arrow from a to b will be very short!
container.a -> container.b: "Connection"
```

### Solution: Remove Grid or Use Flat Layout

```d2
# ✅ Better - let D2 layout engine position elements
container: {
  # No grid-columns
  a: A { }
  b: B { }
}

container.a -> container.b: "Connection"
```

### Solution: Separate Containers

```d2
# ✅ Alternative - put connected elements in different containers
container1: {
  a: A { }
}

container2: {
  b: B { }
}

container1.a -> container2.b: "Connection"
```

## Label Length

### Problem: Short Labels Cause Compact Layout

```d2
a: A
b: B
a -> b: X
```

### Solution: Descriptive Labels Improve Spacing

```d2
gateway: Gateway
agent: AI Agent
gateway -> agent: "Forward commands"
```

## Direction Consistency

Match diagram direction to content flow:

| Content | Direction | Why |
|---------|-----------|-----|
| Time-based sequence | right | Left-to-right reading |
| Hierarchical | down | Top-down hierarchy |
| Attack chain | right | Kill chain progression |
| Organizational | down | Org chart style |

```d2
direction: right  # For horizontal flows
# or
direction: down   # For vertical hierarchies
```

## Nested Container Depth

### Problem: Deep Nesting Wastes Space

```d2
# ❌ Too much nesting
outer: {
  inner1: {
    inner2: {
      inner3: {
        element: Element
      }
    }
  }
}
```

### Solution: Flatten Where Possible

```d2
# ✅ Flatter structure
container: {
  element: Element
}
```

**Rule**: Keep nesting depth ≤ 3 levels.

## Optimization Workflow

1. **Render Initial Diagram**
   ```bash
   d2 diagram.d2 diagram.svg
   ```

2. **Check Dimensions**
   ```bash
   head -3 diagram.svg | grep viewBox
   ```

3. **Calculate Metrics**
   - Aspect ratio = width / height
   - Whitespace = 1 - (content area / total area)

4. **Apply Fixes**
   - Add `near:` to legend
   - Add `grid-columns` to legend
   - Remove grid from connected elements
   - Shorten or lengthen labels

5. **Re-render and Compare**
   ```bash
   d2 diagram.d2 diagram_v2.svg
   ```

## Before/After Example

### Before (63% whitespace)

```d2
direction: right

legend: Legend {
  # No positioning
  elements: {
    a: A
    b: B
  }
  boundaries: {
    c: C
    d: D
  }
}

container: {
  grid-columns: 2
  x: X
  y: Y
}
container.x -> container.y  # Very short arrow
```

### After (41% whitespace)

```d2
direction: right

legend: Legend {
  near: bottom-center
  grid-columns: 4
  a: A { ... }
  b: B { ... }
  c: C { ... }
  d: D { ... }
}

container: {
  # No grid - allow proper arrow spacing
  x: Element X
  y: Element Y
}
container.x -> container.y: "Connection"  # Visible arrow
```

## Checklist

- [ ] Legend uses `near: bottom-center`
- [ ] Legend uses `grid-columns`
- [ ] No grid layout on connected elements
- [ ] Direction matches content flow
- [ ] Nesting depth ≤ 3
- [ ] Labels are descriptive but not too long
- [ ] Aspect ratio matches direction
- [ ] Whitespace < 50%
