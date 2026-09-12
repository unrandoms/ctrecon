package main

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

// openDeltaDB opens (or creates) ~/.ctrecon/DOMAIN.db and ensures the subdomains
// table exists with the expected schema.
func openDeltaDB(domain string) (*sql.DB, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("cannot determine home directory: %w", err)
	}
	dbDir := filepath.Join(home, ".ctrecon")
	if err := os.MkdirAll(dbDir, 0755); err != nil {
		return nil, fmt.Errorf("cannot create %s: %w", dbDir, err)
	}

	dbPath := filepath.Join(dbDir, domain+".db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("cannot open SQLite DB at %s: %w", dbPath, err)
	}

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS subdomains (
		domain     TEXT    NOT NULL,
		source     TEXT    NOT NULL,
		first_seen INTEGER NOT NULL,
		PRIMARY KEY (domain, source)
	)`)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("cannot create subdomains table: %w", err)
	}
	return db, nil
}

// applyDelta upserts the current run's subdomains into the database, then:
//   - returns only the subdomains that had never been seen before for this source,
//   - prints to stderr the count of subdomains previously stored but absent this run.
//
// source is the root domain passed to -d (used as a partition key in the DB).
func applyDelta(db *sql.DB, source string, result HuntResult) ([]string, error) {
	now := time.Now().Unix()

	// Build a set of what the DB already knows for this source
	rows, err := db.Query(`SELECT domain FROM subdomains WHERE source = ?`, source)
	if err != nil {
		return nil, fmt.Errorf("delta query error: %w", err)
	}
	previousSet := make(map[string]struct{})
	for rows.Next() {
		var sub string
		if err := rows.Scan(&sub); err != nil {
			rows.Close()
			return nil, fmt.Errorf("delta scan error: %w", err)
		}
		previousSet[sub] = struct{}{}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("delta rows error: %w", err)
	}

	// Current run as a set — for removed-domain accounting
	currentSet := make(map[string]struct{}, len(result.Subdomains))
	for _, sub := range result.Subdomains {
		currentSet[sub] = struct{}{}
	}

	// Bulk-insert with INSERT OR IGNORE to preserve first_seen timestamps
	stmt, err := db.Prepare(`INSERT OR IGNORE INTO subdomains (domain, source, first_seen) VALUES (?, ?, ?)`)
	if err != nil {
		return nil, fmt.Errorf("delta prepare error: %w", err)
	}
	defer stmt.Close()

	var newSubs []string
	for _, sub := range result.Subdomains {
		if _, execErr := stmt.Exec(sub, source, now); execErr != nil {
			return nil, fmt.Errorf("delta insert error for %s: %w", sub, execErr)
		}
		if _, seen := previousSet[sub]; !seen {
			newSubs = append(newSubs, sub)
		}
	}

	// Tally domains that vanished since the last run
	removed := 0
	for prev := range previousSet {
		if _, ok := currentSet[prev]; !ok {
			removed++
		}
	}
	if removed > 0 {
		fmt.Fprintf(os.Stderr, cYellow+"[!]"+cReset+" %d subdomain(s) previously seen but absent in this run\n", removed)
	}

	return newSubs, nil
}
