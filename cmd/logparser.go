package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nudgebee/logparser"
)

func main() {
	screenWidth := flag.Int("w", 120, "terminal width")
	maxLinesPerMessage := flag.Int("l", 100, "max lines per message")
	cluster := flag.Bool("cluster", false, "use Drain3 algorithm for log clustering")
	maxPatterns := flag.Int("max-patterns", 20, "max number of patterns to display (used with -cluster)")

	flag.Parse()

	if *cluster {
		runClusterMode(*screenWidth, *maxPatterns)
		return
	}

	reader := bufio.NewReader(os.Stdin)
	ch := make(chan logparser.LogEntry)
	parser := logparser.NewParser(ch, nil, nil, time.Second, 256)
	t := time.Now()
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if !errors.Is(err, io.EOF) {
				fmt.Println(err)
			}
			break
		}
		ch <- logparser.LogEntry{Timestamp: time.Now(), Content: strings.TrimSuffix(line, "\n"), Level: logparser.LevelUnknown}
	}
	d := time.Since(t)
	defer parser.Stop()

	counters := parser.GetCounters()
	sensitiveCounter := parser.GetSensitiveCounters()

	order(counters)

	output(counters, *screenWidth, *maxLinesPerMessage, d)
	outputSensitive(sensitiveCounter, *screenWidth, *maxLinesPerMessage, d)
}

func runClusterMode(screenWidth, maxPatterns int) {
	// Create streaming pattern extractor (memory-efficient)
	extractor, err := logparser.NewPatternExtractor()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing pattern extractor: %v\n", err)
		os.Exit(1)
	}

	scanner := bufio.NewScanner(os.Stdin)

	// Increase buffer size for long log lines
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024) // 1MB max line size

	startTime := time.Now()
	lineCount := 0

	// Stream logs one at a time (memory-efficient)
	for scanner.Scan() {
		line := scanner.Text()
		lineCount++
		if err := extractor.AddLog(line); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to process line %d: %v\n", lineCount, err)
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "Error reading input: %v\n", err)
		os.Exit(1)
	}

	if lineCount == 0 {
		fmt.Println("No logs to process")
		return
	}

	// Extract patterns from processed logs
	patterns := extractor.GetPatterns(maxPatterns)
	duration := time.Since(startTime)

	// Display results
	fmt.Printf("\n=== LOG PATTERNS (Drain3 Clustering) ===\n\n")
	fmt.Printf("Processed %d log lines in %.3f seconds\n", lineCount, duration.Seconds())
	fmt.Printf("Found %d unique patterns\n\n", len(patterns))

	if len(patterns) == 0 {
		fmt.Println("No patterns found")
		return
	}

	// Calculate max count for bar chart
	maxCount := 0
	for _, p := range patterns {
		if p.Count > maxCount {
			maxCount = p.Count
		}
	}

	barWidth := 30
	lineWidth := screenWidth - barWidth - 40 // Reserve space for count and percentage

	for i, pattern := range patterns {
		// Create bar chart
		barLen := pattern.Count * barWidth / maxCount
		if barLen < 1 && pattern.Count > 0 {
			barLen = 1
		}
		bar := strings.Repeat("█", barLen) + strings.Repeat("░", barWidth-barLen)

		// Format pattern template
		template := pattern.Template
		if len(template) > lineWidth {
			template = template[:lineWidth-3] + "..."
		}

		// Display pattern
		fmt.Printf("\n[%2d] %s %5d (%5.1f%%)\n", i+1, bar, pattern.Count, pattern.Percentage)
		fmt.Printf("     Pattern: %s\n", template)

		// Show example (truncated)
		example := pattern.Example
		if len(example) > screenWidth-10 {
			example = example[:screenWidth-13] + "..."
		}
		fmt.Printf("     Example: %s\n", example)
	}

	fmt.Printf("\n" + strings.Repeat("=", screenWidth) + "\n")
}

func order(counters []logparser.LogCounter) {
	sort.Slice(counters, func(i, j int) bool {
		ci, cj := counters[i], counters[j]
		if ci.Level == cj.Level {
			return ci.Messages > cj.Messages
		}
		return ci.Level < cj.Level
	})
}

func output(counters []logparser.LogCounter, screenWidth, maxLinesPerMessage int, duration time.Duration) {
	grandTotal, total, max := 0, 0, 0
	for _, c := range counters {
		grandTotal += c.Messages
		if c.Sample == "" {
			continue
		}
		total += c.Messages
		if c.Messages > max {
			max = c.Messages
		}
	}
	barWidth := 20
	lineWidth := screenWidth - barWidth
	messagesNumFmt := fmt.Sprintf("%%%dd", len(strconv.Itoa(max)))
	for _, c := range counters {
		if c.Sample == "" {
			continue
		}
		w := c.Messages * barWidth / max
		bar := strings.Repeat("▇", w+1) + strings.Repeat(" ", barWidth-w)
		prefix := colorize(c.Level, "%s "+messagesNumFmt+" (%2d%%) ", bar, c.Messages, int(float64(c.Messages*100)/float64(total)))
		sample := ""
		for i, line := range strings.Split(c.Sample, "\n") {
			if len(line) > lineWidth {
				line = line[:lineWidth] + "..."
			}
			sample += line + "\n" + strings.Repeat(" ", len(prefix))
			if i > maxLinesPerMessage {
				sample += "...\n"
				break
			}
		}
		sample = strings.TrimRight(sample, "\n ")
		fmt.Printf("%s%s\n", prefix, sample)
	}

	byLevel := map[logparser.Level]int{}
	for _, c := range counters {
		byLevel[c.Level] += c.Messages
	}
	fmt.Println()
	fmt.Printf("%d messages processed in %.3f seconds:\n", grandTotal, duration.Seconds())
	for l, c := range byLevel {
		fmt.Printf("  %s: %d\n", l, c)
	}
	fmt.Println()
}

func colorize(level logparser.Level, format string, a ...interface{}) string {
	c := "\033[37m" // grey
	switch level {
	case logparser.LevelCritical, logparser.LevelError:
		c = "\033[31m" // red
	case logparser.LevelWarning:
		c = "\033[33m" // yellow
	case logparser.LevelInfo:
		c = "\033[32m" // green
	}
	return fmt.Sprintf(c+format+"\033[0m", a...)
}

func outputSensitive(counters []logparser.SensitiveLogCounter, screenWidth, maxLinesPerMessage int, duration time.Duration) {
	grandTotal, total, max := 0, 0, 0
	for _, c := range counters {
		grandTotal += c.Messages
		if c.Sample == "" {
			continue
		}
		total += c.Messages
		if c.Messages > max {
			max = c.Messages
		}
	}
	barWidth := 20
	lineWidth := screenWidth - barWidth
	messagesNumFmt := fmt.Sprintf("%%%dd", len(strconv.Itoa(max)))
	for _, c := range counters {
		if c.Sample == "" {
			continue
		}
		w := c.Messages * barWidth / max
		bar := strings.Repeat("▇", w+1) + strings.Repeat(" ", barWidth-w)
		prefix := colorize(logparser.LevelCritical, "%s "+messagesNumFmt+" (%2d%%) ", bar, c.Messages, int(float64(c.Messages*100)/float64(total)))
		sample := ""
		for i, line := range strings.Split(c.Sample, "\n") {
			if len(line) > lineWidth {
				line = line[:lineWidth] + "..."
			}
			sample += line + "\n" + strings.Repeat(" ", len(prefix))
			if i > maxLinesPerMessage {
				sample += "...\n"
				break
			}
		}
		sample = strings.TrimRight(sample, "\n ")
		fmt.Printf("%s%s%s%s\n", prefix, sample, c.Name, c.Regex)
	}

	byLevel := map[string]int{}
	for _, c := range counters {
		byLevel[c.Pattern] += c.Messages
	}
	fmt.Println()
	fmt.Printf("%d messages processed in %.3f seconds:\n", grandTotal, duration.Seconds())
	for l, c := range byLevel {
		fmt.Printf("  %s: %d\n", l, c)
	}
	fmt.Println()
}
