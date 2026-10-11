package main

import (
	"bytes"
	"errors"
	"strings"
	"unicode/utf8"
)

type rawSpan struct {
	kind       string
	breadcrumb []string
	start      int
	end        int
}

type spanLineRange struct {
	start int
	end   int
}

var errMarkdownSpanLimit = errors.New("markdown span count exceeds the configured bound")

var errMarkdownHeadingLabelLimit = errors.New("markdown heading label exceeds the fixed metadata bound")

// boundedExactSpans partitions parser spans into model-safe exact byte windows.
// It prefers a trailing newline inside the window, but falls back to a UTF-8
// boundary when a single source line is longer than the fixed payload bound.
// The result remains an ordered, gap-free partition of the original bytes.
func boundedExactSpans(data []byte, spans []rawSpan, maxSpans, maxBytes int) ([]rawSpan, error) {
	if maxSpans < 1 || maxBytes < 1 {
		return nil, errMarkdownSpanLimit
	}
	result := make([]rawSpan, 0, len(spans))
	previousEnd := 0
	for _, span := range spans {
		if span.start != previousEnd || span.start < 0 || span.end < span.start || span.end > len(data) {
			return nil, errors.New("input spans are not an ordered exact-byte partition")
		}
		if span.start == span.end {
			if len(result) >= maxSpans {
				return nil, errMarkdownSpanLimit
			}
			result = append(result, span)
			previousEnd = span.end
			continue
		}
		chunked := span.end-span.start > maxBytes
		for start := span.start; start < span.end; {
			end := start + maxBytes
			if end >= span.end {
				end = span.end
			} else if newline := bytes.LastIndexByte(data[start:end], '\n'); newline >= 0 {
				end = start + newline + 1
			} else {
				for end > start && !utf8.RuneStart(data[end]) {
					end--
				}
				if end == start {
					return nil, errors.New("could not find a bounded UTF-8 split point")
				}
			}
			if len(result) >= maxSpans {
				return nil, errMarkdownSpanLimit
			}
			kind := span.kind
			if chunked {
				kind += "_chunk"
			}
			result = append(result, rawSpan{
				kind:       kind,
				breadcrumb: append([]string(nil), span.breadcrumb...),
				start:      start,
				end:        end,
			})
			start = end
		}
		previousEnd = span.end
	}
	if previousEnd != len(data) {
		return nil, errors.New("input spans do not cover the complete source")
	}
	return result, nil
}

// markdownSpans recognizes only ATX headings outside CommonMark-style fenced
// code. It does not rewrite Markdown or claim a semantic parse; each output is
// an exact byte slice of the raw object.
func markdownSpans(data []byte, maxSpans int) ([]rawSpan, error) {
	if maxSpans < 1 {
		return nil, errMarkdownSpanLimit
	}
	var spans []rawSpan
	var levels [6]string
	inFence := false
	var fenceByte byte
	fenceLength := 0
	seenHeading := false
	for offset := 0; offset <= len(data); {
		if offset == len(data) {
			break
		}
		lineEnd := bytes.IndexByte(data[offset:], '\n')
		if lineEnd < 0 {
			lineEnd = len(data)
		} else {
			lineEnd += offset
		}
		line := data[offset:lineEnd]
		line = bytes.TrimSuffix(line, []byte{'\r'})
		trimmed, indent := trimMarkdownIndent(line)
		if marker, count, ok := fenceMarker(trimmed); ok && indent <= 3 {
			if !inFence {
				inFence, fenceByte, fenceLength = true, marker, count
			} else if marker == fenceByte && count >= fenceLength && fenceCloser(trimmed, count) {
				inFence = false
			}
		} else if !inFence && indent <= 3 {
			level, label, ok, headingErr := atxHeading(trimmed)
			if headingErr != nil {
				return nil, headingErr
			}
			if ok {
				needed := 1
				if !seenHeading && offset > 0 {
					needed++
				}
				if len(spans) > maxSpans-needed {
					return nil, errMarkdownSpanLimit
				}
				if seenHeading {
					spans[len(spans)-1].end = offset
				} else if offset > 0 {
					spans = append(spans, rawSpan{kind: "preamble", start: 0, end: offset})
				}
				levels[level-1] = label
				for i := level; i < len(levels); i++ {
					levels[i] = ""
				}
				crumb := make([]string, 0, level)
				for i := 0; i < level; i++ {
					if levels[i] != "" {
						crumb = append(crumb, levels[i])
					}
				}
				spans = append(spans, rawSpan{
					kind:       "markdown_section",
					breadcrumb: crumb,
					start:      offset,
					end:        len(data),
				})
				seenHeading = true
			}
		}
		if lineEnd == len(data) {
			break
		}
		offset = lineEnd + 1
	}
	if !seenHeading {
		return []rawSpan{{kind: "document", start: 0, end: len(data)}}, nil
	}
	return spans, nil
}

func trimMarkdownIndent(line []byte) ([]byte, int) {
	indent := 0
	for indent < len(line) && indent < 4 && line[indent] == ' ' {
		indent++
	}
	return line[indent:], indent
}

func fenceMarker(line []byte) (byte, int, bool) {
	if len(line) < 3 || (line[0] != '`' && line[0] != '~') {
		return 0, 0, false
	}
	marker := line[0]
	count := 0
	for count < len(line) && line[count] == marker {
		count++
	}
	return marker, count, count >= 3
}

func fenceCloser(line []byte, count int) bool {
	return len(strings.TrimSpace(string(line[count:]))) == 0
}

func atxHeading(line []byte) (int, string, bool, error) {
	level := 0
	for level < len(line) && level < 6 && line[level] == '#' {
		level++
	}
	if level == 0 || (level < len(line) && line[level] != ' ' && line[level] != '\t') {
		return 0, "", false, nil
	}
	label := bytes.TrimSpace(line[level:])
	// An optional closing sequence is recognized only when separated from the
	// heading text by whitespace. This metadata cleanup never changes payload.
	trimmed := bytes.TrimRight(label, " \t")
	lastNonHash := len(trimmed)
	for lastNonHash > 0 && trimmed[lastNonHash-1] == '#' {
		lastNonHash--
	}
	if lastNonHash < len(trimmed) && lastNonHash > 0 && (trimmed[lastNonHash-1] == ' ' || trimmed[lastNonHash-1] == '\t') {
		label = bytes.TrimSpace(trimmed[:lastNonHash])
	}
	if len(label) > maxHeadingLabelBytes {
		return 0, "", false, errMarkdownHeadingLabelLimit
	}
	return level, string(label), true, nil
}

// spanLineRanges resolves the line coordinates of an ordered span partition in
// one forward pass. It deliberately avoids rescanning the raw prefix for every
// span, which would make heading-heavy Markdown quadratic in the span count.
func spanLineRanges(data []byte, spans []rawSpan) ([]spanLineRange, error) {
	ranges := make([]spanLineRange, len(spans))
	offset, line := 0, 1
	for index, span := range spans {
		if span.start < offset || span.start < 0 || span.end < span.start || span.end > len(data) {
			return nil, errors.New("spans are not an ordered in-bounds partition")
		}
		for ; offset < span.start; offset++ {
			if data[offset] == '\n' {
				line++
			}
		}
		startLine := line
		for ; offset < span.end; offset++ {
			if data[offset] == '\n' {
				line++
			}
		}
		endLine := line
		if span.end == span.start {
			endLine = startLine
		} else if data[span.end-1] == '\n' {
			endLine--
		}
		if endLine < startLine {
			endLine = startLine
		}
		ranges[index] = spanLineRange{start: startLine, end: endLine}
	}
	return ranges, nil
}
