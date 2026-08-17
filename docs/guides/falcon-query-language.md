---
page_title: "Filtering with Falcon Query Language"
subcategory: ""
description: |-
  How to write the Falcon Query Language expressions that the provider's filter arguments accept.
---

# Filtering with Falcon Query Language

Several data sources in this provider take a `filter` argument that holds a Falcon
Query Language (FQL) expression, the same query syntax the Falcon APIs and console
use.

A filter expression follows the pattern:

```text
<property>:[operator]<value>
```

-> **Note:** Available FQL properties and their syntax vary between endpoints. The
individual data source page documents what that data source supports.

## Properties

Properties are the elements of Falcon data you filter and sort on. Property names
contain only letters, digits, and underscores, begin with a letter, and are
lowercase. Nested properties use dot notation, as in `author.name`.

## Operators

| Operator | Meaning | Example |
| --- | --- | --- |
| none | equal to | `environment:'prod'` |
| `!` | not equal to | `environment:!'prod'` |
| `>` | greater than | `port:>443` |
| `>=` | greater than or equal to | `created_at:>='2026-02-08'` |
| `<` | less than | `port:<1024` |
| `<=` | less than or equal to | `created_at:<='2026-02-08'` |
| `*` | wildcard match | `name:*'*prod*'` |
| `~` | text match, ignoring case | `name:~'production accounts'` |
| `!~` | does not text match | `name:!~'production accounts'` |
| `~*` | wildcard match, ignoring case | `name:~*'*PROD*'` |
| `~*!` | does not wildcard match, ignoring case | `name:~*!'*PROD*'` |

The operator goes **after** the colon: `environment:!'prod'`, not
`!environment:'prod'`.

Not every operator is available on every property. `~` and `!~` ignore spaces and
punctuation as well as case on some endpoints and only case on others.

## Values

The syntax for a value depends on its data type.

### String syntax

Strings are wrapped in single quotes.

```text
property:[operator]'STRING_VALUE'
```

```terraform
filter = "name:'GCP Projects'"
```

Which operator matches a value depends on the endpoint. Some endpoints support
equality on the full value, including values that contain spaces. Others return no
records for an equality term and require the `~` text match operator instead:

```terraform
filter = "name:~'GCP Projects'"
```

Try the other operator before concluding that no record matches. How much of the
value has to match varies as well: some properties match the full value, some match
a prefix, and some ignore case.

#### Wildcard hints

Some endpoints require a wildcard hint to inform the preprocessor that a wildcard is
being provided. The hint is an asterisk placed before the first single quote that
encapsulates the string.

```text
property:[operator]*'STRING_VALUE*'
```

```terraform
filter = "name:*'*prod*'"
```

-> **Note:** This is not a requirement for all endpoints.

`~*` and `~*!` are wildcard operators as well, and take the asterisks in the value
the same way.

#### Escaping

Escape a single quote inside a string value, which would otherwise end the value.
Other characters do not need escaping inside quotes.

HCL rejects `\'` as an invalid escape sequence, so the backslash has to be doubled in
a Terraform string:

```terraform
# Matches the value: It's mine
filter = "description:'It\\'s mine'"
```

### Date syntax

Dates are in UTC and wrapped in single quotes like strings.

```text
property:[operator]'UTC_DATE_VALUE'
```

Compare a date with `<`, `<=`, `>`, or `>=`. To select a single day, write a bounded
range:

```terraform
filter = "created_at:>='2026-02-08'+created_at:<'2026-02-09'"
```

Some endpoints accept the keyword `now` and offsets from it, as in
`created_at:>='now-15d'`.

### Boolean syntax

Booleans are lowercase and unquoted.

```text
property:[operator]BOOLEAN_VALUE
```

```terraform
filter = "enabled:true"
```

### Integer syntax

Integers are unquoted.

```text
property:[operator]INTEGER_VALUE
```

```terraform
filter = "port:>443"
```

## Complex expressions

Join terms with `+` or `,`, and group them with parentheses.

| Character | Meaning |
| --- | --- |
| `+` | AND |
| `,` | OR |

Write `+` literally. Never URL-encode part of a filter, such as `%2B` for `+`; the
provider encodes the request.

`+` binds tighter than `,`, so `a,b+c` means `a` or `b and c` together. Write the
parentheses explicitly whenever you mix the two:

```terraform
# Groups that are dev or test, and are also moderate impact.
filter = "(environment:'dev',environment:'test')+business_impact:'moderate'"
```

Repeating a property with `+` is an AND over that one property, which ranges depend
on. Two equality terms contradict each other, so
`environment:'dev'+environment:'test'` returns no records. Use `,` instead.

## Sorting

Sorting is a separate `sort` argument rather than part of the filter. Its value is a
property with the direction appended, where direction is either `asc` or `desc`:

```terraform
sort = "name.asc"
```

Some endpoints also accept the pipe character to separate the property and
direction, as in `name|asc`. The `sort:` prefix shown in the FQL reference belongs to
raw API query strings and is not written in the Terraform argument.
