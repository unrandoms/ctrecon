package main

import (
	"fmt"
	"os"
	"sort"
	"strings"
)

// huntRecursive enumerates subdomains of rootDomain recursively up to maxDepth levels.
// Level 1 is the initial scan; level 2 scans every discovered subdomain; and so on.
// maxDepth is clamped to [1, 3].
func huntRecursive(rootDomain string, skip map[string]bool, maxDepth int) []HuntResult {
	if maxDepth < 1 {
		maxDepth = 1
	}
	if maxDepth > 3 {
		maxDepth = 3
	}

	scanned := map[string]bool{rootDomain: true}
	var allResults []HuntResult

	if !quietMode {
		fmt.Fprintf(os.Stderr, cDim+"[r] depth 1/%d → %s"+cReset+"\n", maxDepth, rootDomain)
	}

	r := huntDomain(rootDomain, skip, nil)
	allResults = append(allResults, r)

	// Seeds for next level: all subdomains just discovered
	currentLevel := make([]string, len(r.Subdomains))
	copy(currentLevel, r.Subdomains)

	for depth := 2; depth <= maxDepth; depth++ {
		var nextLevel []string
		for _, sub := range currentLevel {
			if scanned[sub] {
				continue
			}
			scanned[sub] = true
			if !quietMode {
				fmt.Fprintf(os.Stderr, cDim+"[r] depth %d/%d → %s"+cReset+"\n", depth, maxDepth, sub)
			}
			subResult := huntDomain(sub, skip, nil)
			allResults = append(allResults, subResult)
			for _, found := range subResult.Subdomains {
				if !scanned[found] {
					nextLevel = append(nextLevel, found)
				}
			}
		}
		currentLevel = nextLevel
		if len(currentLevel) == 0 {
			break
		}
	}
	return allResults
}

// mergeResults collapses a slice of HuntResults into one deduplicated HuntResult
// attributed to rootDomain. Source stats are aggregated by source name.
func mergeResults(rootDomain string, results []HuntResult) HuntResult {
	seen := make(map[string]struct{})
	var merged []string
	sources := make(map[string]SourceStats)

	timestamp := ""
	if len(results) > 0 {
		timestamp = results[0].Timestamp
	}

	for _, r := range results {
		for _, sub := range r.Subdomains {
			sub = strings.ToLower(strings.TrimSpace(sub))
			if sub == "" {
				continue
			}
			if _, ok := seen[sub]; !ok {
				seen[sub] = struct{}{}
				merged = append(merged, sub)
			}
		}
		for name, stat := range r.Sources {
			existing := sources[name]
			existing.Count += stat.Count
			existing.DurationMs += stat.DurationMs
			if stat.Error != "" {
				existing.Error = stat.Error
			}
			sources[name] = existing
		}
	}
	sort.Strings(merged)
	return HuntResult{
		Domain:     rootDomain,
		Timestamp:  timestamp,
		Total:      len(merged),
		Sources:    sources,
		Subdomains: merged,
	}
}
