package custodian

import (
	"context"
	"database/sql"
	_ "embed"
	"fmt"
	"strings"
)

//go:embed schema.sql
var schemaSQL string

// applySchema runs the embedded DDL. Idempotent across re-runs: the
// migrations in schema.sql include ALTER TABLE ADD COLUMN statements
// without IF-NOT-EXISTS guards (SQLite doesn't support the syntax),
// so we split the blob into individual statements and tolerate the
// "duplicate column" sentinel from re-runs. Other errors are real
// and propagate.
//
// Pre-NEX-291 this was a single ExecContext on the whole blob, which
// worked on first boot but failed on every subsequent one — `nexus
// init` and the broker's own startup both call this, so re-running
// installer or restarting the broker tripped it. The split-and-
// tolerate approach keeps schema.sql operator-readable as plain SQL
// while making the runtime idempotent.
func applySchema(ctx context.Context, db *sql.DB) error {
	stmts, err := splitSQLStatements(schemaSQL)
	if err != nil {
		return fmt.Errorf("custodian.applySchema: split: %w", err)
	}
	for _, stmt := range stmts {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			if isDuplicateColumnErr(err) && isAlterAddColumn(stmt) {
				// Already-applied migration. Schema converged on a
				// previous boot — keep going.
				continue
			}
			return fmt.Errorf("custodian.applySchema: %s: %w", firstLine(stmt), err)
		}
	}
	return nil
}

// splitSQLStatements breaks schema.sql into individual statements.
// Strips line-level `--` comments BEFORE splitting on semicolons —
// comments can legitimately contain `;` (e.g. "-- (not both); NULL
// on both = unassigned.") which a naive split would treat as a
// statement boundary, producing nonsense SQL.
//
// BEGIN/END-aware: SQLite triggers (CREATE TRIGGER … BEGIN …; …; END;)
// contain semicolons inside the body that must NOT split the outer
// statement. The scanner tracks nesting depth of BEGIN/END keywords at
// word boundaries and only treats `;` as a terminator when depth is 0.
//
// Still naive about string literals — a `;` inside a quoted string
// would break things — but the embedded schema.sql doesn't contain any.
// Adding a full tokenizer would be a lot of code for a single-file
// schema; the BEGIN/END handling is the one piece we actually need.
func splitSQLStatements(sql string) ([]string, error) {
	clean := stripLineComments(sql)
	out := make([]string, 0, 32)
	var current strings.Builder
	depth := 0

	flush := func() {
		s := strings.TrimSpace(current.String())
		current.Reset()
		if s != "" {
			out = append(out, s)
		}
	}

	n := len(clean)
	for i := 0; i < n; {
		c := clean[i]
		// Word boundary? Scan the word, treat BEGIN/END specially.
		if isAlpha(c) && (i == 0 || !isWordByte(clean[i-1])) {
			j := i
			for j < n && isWordByte(clean[j]) {
				j++
			}
			word := strings.ToUpper(clean[i:j])
			current.WriteString(clean[i:j])
			switch word {
			case "BEGIN":
				depth++
			case "END":
				if depth > 0 {
					depth--
				}
			}
			i = j
			continue
		}
		if c == ';' && depth == 0 {
			flush()
			i++
			continue
		}
		current.WriteByte(c)
		i++
	}
	flush()
	return out, nil
}

func isAlpha(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isWordByte(c byte) bool {
	return isAlpha(c) || (c >= '0' && c <= '9') || c == '_'
}

// stripLineComments removes `-- ... \n` content per line, preserving
// the rest of the line. Idempotent on already-clean SQL.
func stripLineComments(sql string) string {
	var sb strings.Builder
	sb.Grow(len(sql))
	for _, line := range strings.Split(sql, "\n") {
		if idx := strings.Index(line, "--"); idx >= 0 {
			line = line[:idx]
		}
		sb.WriteString(line)
		sb.WriteByte('\n')
	}
	return sb.String()
}

// firstLine returns the first non-comment, non-blank line of stmt —
// used for error context so callers see "ALTER TABLE issues ..." not
// the entire 50-line CREATE TABLE block.
func firstLine(stmt string) string {
	for _, line := range strings.Split(stmt, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "--") {
			continue
		}
		if len(line) > 80 {
			return line[:77] + "..."
		}
		return line
	}
	return "(empty statement)"
}

// isDuplicateColumnErr matches the sqlite3 driver's error string for
// `ALTER TABLE ... ADD COLUMN` against an already-present column.
// String match is fragile but the alternative requires importing the
// driver to type-assert against the sqlite-specific error — adds a
// new dep just for this check.
func isDuplicateColumnErr(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "duplicate column name")
}

// isAlterAddColumn reports whether stmt is an `ALTER TABLE … ADD
// COLUMN …` so we only tolerate the duplicate-column error for the
// exact statement type that legitimately produces it on re-run.
// Other duplicate-column errors (e.g. from CREATE INDEX naming
// collision) would slip through, but those don't happen with our
// schema; the narrower check earns us safety against unrelated
// future errors that happen to say "duplicate column".
func isAlterAddColumn(stmt string) bool {
	upper := strings.ToUpper(strings.TrimSpace(stmt))
	return strings.HasPrefix(upper, "ALTER TABLE") && strings.Contains(upper, "ADD COLUMN")
}
