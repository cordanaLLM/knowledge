package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestBM25FShortExactEvidenceBeatsLongRepetition(t *testing.T) {
	short := []byte("abort rollout previous ReplicaSet active\n")
	long := []byte(strings.Repeat("abort ", 100) + "unrelated filler material\n")
	fx, result := buildBM25FChunks(t, [][]byte{short, long}, nil)
	response, err := Query(fx.queryConfig(result.ManifestPath, "abort rollout previous ReplicaSet active", "2026-07-16T00:00:00Z"))
	if err != nil {
		t.Fatal(err)
	}
	if response.LexicalProfile != bm25fLexicalProfile || len(response.Results) != 2 || response.Results[0].Evidence.RawByteStart != 0 || response.Results[0].Score <= response.Results[1].Score {
		t.Fatalf("BM25F did not prefer concise multi-term evidence: %#v", response)
	}
}

func TestBM25FIdentifierAcronymAndPluralExpansion(t *testing.T) {
	fx, result := buildBM25FChunks(t, [][]byte{[]byte("HTTPServer manages one ReplicaSet rollout\n")}, nil)
	response, err := Query(fx.queryConfig(result.ManifestPath, "http servers replicasets", "2026-07-16T00:00:00Z"))
	if err != nil {
		t.Fatal(err)
	}
	for _, term := range []string{"http", "server", "replicaset"} {
		if !containsString(response.QueryTerms, term) {
			t.Fatalf("expanded query lacks %q: %#v", term, response.QueryTerms)
		}
	}
	if response.ResultState != "ok" || len(response.Results) != 1 {
		t.Fatalf("expanded identifier query failed: %#v", response)
	}

	if got, err := expandBM25FToken("oneTwo3Four5"); err == nil || got != nil {
		t.Fatalf("v1.0 five-component identifier was not rejected: terms=%#v err=%v", got, err)
	}
}

func TestBM25FV11RetainsOverComponentIdentifier(t *testing.T) {
	if got, err := expandBM25FTokenForProfile("oneTwo3Four5", bm25fLexicalProfileV11); err != nil || !equalStrings(got, []string{"onetwo3four5"}) {
		t.Fatalf("v1.1 five-component identifier was not retained without partial expansion: terms=%#v err=%v", got, err)
	}

	v1 := newTestFixture(t, []byte("oneTwo3Four5 retained\n"), "2026-07-17T00:00:00Z")
	v1Config := v1.buildConfig(v1.outputRoot)
	v1Config.LexicalProfile = bm25fLexicalProfile
	requireBuildQuarantine(t, v1Config, "identifier_component_limit")

	v11 := newTestFixture(t, []byte("oneTwo3Four5 retained\n"), "2026-07-17T00:00:00Z")
	v11Config := v11.buildConfig(v11.outputRoot)
	v11Config.LexicalProfile = bm25fLexicalProfileV11
	result, err := Build(v11Config)
	if err != nil {
		t.Fatalf("v1.1 bounded identifier quarantined valid evidence: %v", err)
	}
	if result.Manifest.LexicalProfile != bm25fLexicalProfileV11 || result.Manifest.LexicalTokenizerID != bm25fTokenizerIDV11 || result.Manifest.LexicalScorerID != bm25fScorerID {
		t.Fatalf("v1.1 candidate carries wrong lineage: %+v", result.Manifest.CandidateManifestCore)
	}
	response, err := Query(v11.queryConfig(result.ManifestPath, "oneTwo3Four5", "2026-07-16T00:00:00Z"))
	if err != nil || response.ResultState != "ok" || len(response.Results) != 1 {
		t.Fatalf("v1.1 exact retained identifier was not queryable: response=%#v err=%v", response, err)
	}
}

func TestBM25FHeadingContributionIsBounded(t *testing.T) {
	headings := [][]string{{}, {strings.Repeat("target ", 100)}}
	fx, result := buildBM25FChunks(t, [][]byte{[]byte("target\n"), []byte("filler\n")}, headings)
	response, err := Query(fx.queryConfig(result.ManifestPath, "target", "2026-07-16T00:00:00Z"))
	if err != nil {
		t.Fatal(err)
	}
	if len(response.Results) != 2 || response.Results[0].Evidence.RawByteStart != 0 {
		t.Fatalf("repeated heading swamped body evidence: %#v", response.Results)
	}
}

func TestBM25FQueryAndIndexBoundsFailClosed(t *testing.T) {
	fx, result := buildBM25FChunks(t, [][]byte{[]byte("bounded evidence\n")}, nil)
	baseTerms := make([]string, bm25fMaxBaseTerms+1)
	for i := range baseTerms {
		baseTerms[i] = fmt.Sprintf("term%c%c", 'a'+rune(i/26), 'a'+rune(i%26))
	}
	if terms, err := bm25fQueryTerms([]byte(strings.Join(baseTerms[:bm25fMaxBaseTerms], " "))); err != nil || len(terms) < bm25fMaxBaseTerms || len(terms) > bm25fMaxQueryTerms {
		t.Fatalf("exact base-term bound was rejected: terms=%d err=%v", len(terms), err)
	}
	if _, err := Query(fx.queryConfig(result.ManifestPath, strings.Join(baseTerms, " "), "2026-07-16T00:00:00Z")); err == nil || !strings.Contains(err.Error(), "more than 32 base") {
		t.Fatalf("33 base query terms were accepted: %v", err)
	}

	expanded := make([]string, 0, 28)
	for i := 0; i < 26; i++ {
		suffix := string(rune('a'+i)) + "x"
		expanded = append(expanded, "aa"+suffix+"Bb"+suffix+"Cc"+suffix+"Dd"+suffix)
	}
	exactly128 := append([]string(nil), expanded[:25]...)
	exactly128 = append(exactly128, "plainone", "plaintwo", "plainthree")
	terms, err := bm25fQueryTerms([]byte(strings.Join(exactly128, " ")))
	if err != nil || len(terms) != bm25fMaxQueryTerms {
		t.Fatalf("exact 128-term expansion was rejected: terms=%d err=%v", len(terms), err)
	}
	if _, err := Query(fx.queryConfig(result.ManifestPath, strings.Join(expanded, " "), "2026-07-16T00:00:00Z")); err == nil || !strings.Contains(err.Error(), "expanded lexical terms") {
		t.Fatalf("expanded query bound was not enforced: %v", err)
	}

	limited := newTestFixture(t, []byte("one two\n"), "2026-07-17T00:00:00Z")
	config := limited.buildConfig(limited.outputRoot)
	config.LexicalProfile = bm25fLexicalProfile
	config.MaxPostings = 1
	requireBuildQuarantine(t, config, "posting_count_limit")

	termLimited := newTestFixture(t, []byte("one two\n"), "2026-07-17T00:00:00Z")
	config = termLimited.buildConfig(termLimited.outputRoot)
	config.LexicalProfile = bm25fLexicalProfile
	config.MaxTerms = 1
	requireBuildQuarantine(t, config, "term_count_limit")

	oversized := strings.Repeat("a", maxLexicalTokenBytes+1) + " retained"
	frequencies, problem := bm25fFrequenciesForIndex([]byte(oversized), nil, 10, 10)
	if problem != nil || len(frequencies.terms) != 1 || frequencies.terms["retained"] != 1 {
		t.Fatalf("oversized BM25F token was not skipped within its memory bound: frequencies=%#v problem=%#v", frequencies, problem)
	}

	// A field overlap remains one posting and must not consume the document's
	// remaining posting capacity twice.
	overlap := newTestFixture(t, []byte("shared\n"), "2026-07-17T00:00:00Z")
	overlap.evidence.Files[0].Spans[0].HeadingBreadcrumb = []string{"shared"}
	overlap.evidence.Files[0].Spans[0].SpanID = spanIdentity(overlap.evidence.Files[0].OccurrenceID, overlap.evidence.Files[0].ParserVersion, overlap.evidence.Files[0].ProfileVersion, overlap.evidence.Files[0].Spans[0])
	overlap.resealEvidence(t)
	overlap.policy.EvidenceManifestID = overlap.evidence.ManifestID
	overlap.resealPolicy(t)
	overlap.rewriteVerifier(t, true)
	config = overlap.buildConfig(overlap.outputRoot)
	config.LexicalProfile = bm25fLexicalProfile
	config.MaxPostings = 1
	if _, err := Build(config); err != nil {
		t.Fatalf("body/heading overlap consumed two postings: %v", err)
	}

	if _, err := checkedMulInt64(math.MaxInt64, 2); err == nil {
		t.Fatal("fixed-point multiplication overflow was accepted")
	}
	if _, err := checkedAddInt64(math.MaxInt64, 1); err == nil {
		t.Fatal("fixed-point addition overflow was accepted")
	}
	if _, err := checkedSubInt64(math.MinInt64, 1); err == nil {
		t.Fatal("fixed-point subtraction overflow was accepted")
	}
	if _, err := fixedNaturalLogRatio(math.MaxInt64, math.MaxInt64-1); err == nil {
		t.Fatal("unchecked fixed-log addition overflow was accepted")
	}
	overflowIndex := LexicalIndex{LexicalIndexCore: LexicalIndexCore{DocumentCount: 1, TotalBodyLength: 1}}
	overflowDocument := IndexedDocument{BodyLength: 1}
	overflowTerm := TermEntry{DocumentFrequency: 1}
	overflowPosting := Posting{BodyTermFrequency: math.MaxInt}
	if _, err := scoreBM25F(overflowIndex, overflowDocument, overflowTerm, overflowPosting); err == nil {
		t.Fatal("BM25F score overflow was accepted")
	}
	if _, err := normalizedFieldTF(1, 0, 0, 1); err == nil {
		t.Fatal("positive frequency with zero field length was accepted")
	}

	forgedFX, forgedResult := buildBM25FChunks(t, [][]byte{[]byte("forged field frequency\n")}, nil)
	candidateBytes, err := os.ReadFile(forgedResult.ManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	var candidate CandidateManifest
	if err := decodeStrictCanonical(candidateBytes, &candidate); err != nil {
		t.Fatal(err)
	}
	indexPath := filepath.Join(forgedFX.outputRoot, filepath.FromSlash(candidate.LexicalIndexPath))
	indexBytes, err := os.ReadFile(indexPath)
	if err != nil {
		t.Fatal(err)
	}
	var index LexicalIndex
	if err := decodeStrictCanonical(indexBytes, &index); err != nil {
		t.Fatal(err)
	}
	posting := &index.Terms[0].Postings[0]
	document := index.Documents[posting.DocumentPosition-1]
	posting.BodyTermFrequency = document.BodyLength + 1
	indexCore, _ := json.Marshal(index.LexicalIndexCore)
	index.IndexPayloadSHA256 = digestBytes(indexCore)
	index.IndexID = "lexical-index:" + index.IndexPayloadSHA256
	candidate.LexicalIndexID = index.IndexID
	if err := validateIndex(index, candidate); err == nil || !strings.Contains(err.Error(), "exceeds its retained field length") {
		t.Fatalf("forged BM25F field frequency was accepted: %v", err)
	}
}

func TestBM25FV11QueryBound(t *testing.T) {
	fx, result := buildBM25FChunksForProfile(t, bm25fLexicalProfileV11, [][]byte{[]byte("bounded evidence\n")}, nil)
	baseTerms := make([]string, bm25fMaxBaseTermsV11+1)
	for i := range baseTerms {
		baseTerms[i] = fmt.Sprintf("term%c%c", 'a'+rune(i/26), 'a'+rune(i%26))
	}
	terms, err := bm25fQueryTermsForProfile(bm25fLexicalProfileV11, []byte(strings.Join(baseTerms[:bm25fMaxBaseTermsV11], " ")))
	if err != nil || len(terms) < bm25fMaxBaseTermsV11 || len(terms) > bm25fMaxQueryTerms {
		t.Fatalf("v1.1 exact base-term bound was rejected: terms=%d err=%v", len(terms), err)
	}
	if _, err := Query(fx.queryConfig(result.ManifestPath, strings.Join(baseTerms[:bm25fMaxBaseTermsV11], " "), "2026-07-16T00:00:00Z")); err != nil {
		t.Fatalf("v1.1 exact 64-base-term query was rejected: %v", err)
	}
	if _, err := Query(fx.queryConfig(result.ManifestPath, strings.Join(baseTerms, " "), "2026-07-16T00:00:00Z")); err == nil || !strings.Contains(err.Error(), "more than 64 base") {
		t.Fatalf("v1.1 65-base-term query was accepted: %v", err)
	}
}

func TestBM25FUnequalLengthNormalizationMatchesRationalContract(t *testing.T) {
	got, err := normalizedFieldTF(1, 2, 10, 2)
	if err != nil {
		t.Fatal(err)
	}
	// tf*4*T/(T+3*L*N) = 40/22, truncated at the fixed 1e6 scale.
	if got != 1_818_181 {
		t.Fatalf("unequal-length normalization=%d, want 1818181", got)
	}
	averageLength, err := normalizedFieldTF(1, 5, 10, 2)
	if err != nil || averageLength != bm25fScoreScale {
		t.Fatalf("average-length normalization=%d err=%v", averageLength, err)
	}
	if logOne, err := fixedNaturalLogRatio(7, 7); err != nil || logOne != 0 {
		t.Fatalf("ln(1) fixed boundary=%d err=%v", logOne, err)
	}

	index := LexicalIndex{LexicalIndexCore: LexicalIndexCore{DocumentCount: 7, TotalBodyLength: 31, TotalHeadingLength: 4}}
	document := IndexedDocument{BodyLength: 5, HeadingLength: 1}
	term := TermEntry{DocumentFrequency: 3}
	posting := Posting{BodyTermFrequency: 2, HeadingTermFrequency: 1}
	direct, err := scoreBM25F(index, document, term, posting)
	if err != nil {
		t.Fatal(err)
	}
	idf, err := bm25fTermIDF(index.DocumentCount, term.DocumentFrequency)
	if err != nil {
		t.Fatal(err)
	}
	hoisted, err := scoreBM25FWithIDF(index, document, posting, idf)
	if err != nil || hoisted != direct {
		t.Fatalf("hoisted IDF changed the observable score: direct=%d hoisted=%d err=%v", direct, hoisted, err)
	}
}

func TestBM25FVersionedProfilesShareScorerSemantics(t *testing.T) {
	fx := newTestFixture(t, []byte("abort rollout previous replica active\n"), "2026-07-17T00:00:00Z")
	v1Root := filepath.Join(fx.root, "bm25f-v1")
	v1Config := fx.buildConfig(v1Root)
	v1Config.LexicalProfile = bm25fLexicalProfile
	v1, err := Build(v1Config)
	if err != nil {
		t.Fatal(err)
	}
	v11Root := filepath.Join(fx.root, "bm25f-v1.1")
	v11Config := fx.buildConfig(v11Root)
	v11Config.LexicalProfile = bm25fLexicalProfileV11
	v11, err := Build(v11Config)
	if err != nil {
		t.Fatal(err)
	}
	if v1.Manifest.ManifestID == v11.Manifest.ManifestID || v1.Manifest.LexicalTokenizerID != bm25fTokenizerID || v11.Manifest.LexicalTokenizerID != bm25fTokenizerIDV11 || v1.Manifest.LexicalScorerID != bm25fScorerID || v11.Manifest.LexicalScorerID != bm25fScorerID {
		t.Fatalf("versioned profiles do not carry distinct tokenizer and shared scorer lineage: v1=%+v v11=%+v", v1.Manifest.CandidateManifestCore, v11.Manifest.CandidateManifestCore)
	}

	v1Query := fx.queryConfig(v1.ManifestPath, "abort rollout previous replica active", "2026-07-16T00:00:00Z")
	v1Query.StoreRoot = v1Root
	v1Response, err := Query(v1Query)
	if err != nil {
		t.Fatal(err)
	}
	v11Query := fx.queryConfig(v11.ManifestPath, "abort rollout previous replica active", "2026-07-16T00:00:00Z")
	v11Query.StoreRoot = v11Root
	v11Response, err := Query(v11Query)
	if err != nil {
		t.Fatal(err)
	}
	v1Hits, _ := json.Marshal(v1Response.Results)
	v11Hits, _ := json.Marshal(v11Response.Results)
	if !equalStrings(v1Response.QueryTerms, v11Response.QueryTerms) || !bytes.Equal(v1Hits, v11Hits) {
		t.Fatalf("unchanged tokenizer domain changed scorer output: v1=%#v v11=%#v", v1Response, v11Response)
	}

	v1IndexBytes, err := os.ReadFile(filepath.Join(v1Root, filepath.FromSlash(v1.Manifest.LexicalIndexPath)))
	if err != nil {
		t.Fatal(err)
	}
	var v1Index LexicalIndex
	if err := decodeStrictCanonical(v1IndexBytes, &v1Index); err != nil {
		t.Fatal(err)
	}
	mixedCandidate := v11.Manifest
	mixedCandidate.LexicalIndexID = v1Index.IndexID
	if err := validateIndex(v1Index, mixedCandidate); err == nil || !strings.Contains(err.Error(), "profile contract") {
		t.Fatalf("v1 index was accepted under v1.1 candidate lineage: %v", err)
	}
}

func TestBM25FStableTiesCanonicalBytesAndLegacyIsolation(t *testing.T) {
	aggregates := make(map[string]*lexicalAggregate, 200)
	for i := 0; i < 200; i++ {
		spanID := fmt.Sprintf("span-%03d", 199-i)
		aggregates[spanID] = &lexicalAggregate{score: int64(i % 17), evidence: EvidenceRef{SpanID: spanID}}
	}
	selected := selectLexicalTopK(aggregates, 10)
	if len(selected) != 10 {
		t.Fatalf("top-K selected %d results, want 10", len(selected))
	}
	for i := 1; i < len(selected); i++ {
		if !lexicalAggregateBetter(selected[i-1], selected[i]) {
			t.Fatalf("top-K output order is unstable at %d: %#v", i, selected)
		}
	}
	for _, candidate := range aggregates {
		if lexicalAggregateBetter(candidate, selected[len(selected)-1]) && !containsLexicalAggregate(selected, candidate) {
			t.Fatalf("top-K omitted a better aggregate: omitted=%#v selected=%#v", candidate, selected)
		}
	}

	chunks := [][]byte{[]byte("same term\n"), []byte("same term\n")}
	fx, first := buildBM25FChunks(t, chunks, nil)
	secondRoot := filepath.Join(fx.root, "bm25f-second")
	config := fx.buildConfig(secondRoot)
	config.LexicalProfile = bm25fLexicalProfile
	second, err := Build(config)
	if err != nil {
		t.Fatal(err)
	}
	firstBytes, _ := os.ReadFile(first.ManifestPath)
	secondBytes, _ := os.ReadFile(second.ManifestPath)
	if first.Manifest.ManifestID != second.Manifest.ManifestID || !bytes.Equal(firstBytes, secondBytes) {
		t.Fatal("BM25F candidate bytes changed across fresh stores")
	}
	response, err := Query(fx.queryConfig(first.ManifestPath, "same", "2026-07-16T00:00:00Z"))
	if err != nil || len(response.Results) != 2 {
		t.Fatalf("tie query failed: response=%#v err=%v", response, err)
	}
	spanIDs := []string{response.Results[0].Evidence.SpanID, response.Results[1].Evidence.SpanID}
	if !sort.StringsAreSorted(spanIDs) || response.Results[0].Score != response.Results[1].Score {
		t.Fatalf("BM25F ties are not stable SpanID order: %#v", response.Results)
	}

	legacy := newTestFixture(t, []byte("legacy bytes\n"), "2026-07-17T00:00:00Z")
	legacyDefault, err := Build(legacy.buildConfig(legacy.outputRoot))
	if err != nil {
		t.Fatal(err)
	}
	legacyExplicitConfig := legacy.buildConfig(filepath.Join(legacy.root, "legacy-explicit"))
	legacyExplicitConfig.LexicalProfile = legacyLexicalProfile
	legacyExplicit, err := Build(legacyExplicitConfig)
	if err != nil {
		t.Fatal(err)
	}
	defaultBytes, _ := os.ReadFile(legacyDefault.ManifestPath)
	explicitBytes, _ := os.ReadFile(legacyExplicit.ManifestPath)
	if !bytes.Equal(defaultBytes, explicitBytes) || legacyDefault.Manifest.LexicalProfile != "" {
		t.Fatal("explicit legacy selection changed the immutable legacy profile")
	}
	legacyResponse, err := Query(legacy.queryConfig(legacyDefault.ManifestPath, "legacy", "2026-07-16T00:00:00Z"))
	if err != nil {
		t.Fatal(err)
	}
	legacyResponseBytes, err := marshalDocument(legacyResponse)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(legacyResponseBytes, []byte("lexical_profile")) {
		t.Fatalf("legacy query response bytes gained successor lineage: %s", legacyResponseBytes)
	}
}

func containsLexicalAggregate(values []*lexicalAggregate, target *lexicalAggregate) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func TestBM25FMixedProfileArtifactsAreRejected(t *testing.T) {
	fx, result := buildBM25FChunks(t, [][]byte{[]byte("mixed profile\n")}, nil)
	data, err := os.ReadFile(result.ManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	var candidate CandidateManifest
	if err := decodeStrictCanonical(data, &candidate); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name      string
		profile   string
		tokenizer string
		scorer    string
	}{
		{name: "v1 profile v1.1 tokenizer", profile: bm25fLexicalProfile, tokenizer: bm25fTokenizerIDV11, scorer: bm25fScorerID},
		{name: "v1.1 profile v1 tokenizer", profile: bm25fLexicalProfileV11, tokenizer: bm25fTokenizerID, scorer: bm25fScorerID},
		{name: "missing scorer", profile: bm25fLexicalProfile, tokenizer: bm25fTokenizerID},
	} {
		t.Run(test.name, func(t *testing.T) {
			forged := candidate
			forged.LexicalProfile = test.profile
			forged.LexicalTokenizerID = test.tokenizer
			forged.LexicalScorerID = test.scorer
			coreBytes, _ := json.Marshal(forged.CandidateManifestCore)
			forged.ManifestPayloadSHA256 = digestBytes(coreBytes)
			forged.ManifestID = "retrieval-candidate:" + forged.ManifestPayloadSHA256
			forgedPath := filepath.Join(fx.root, strings.ReplaceAll(test.name, " ", "-")+".json")
			writeCanonical(t, forgedPath, forged)
			config := fx.queryConfig(forgedPath, "mixed", "2026-07-16T00:00:00Z")
			response, err := Query(config)
			if err != nil {
				t.Fatal(err)
			}
			if response.ErrorCode != "candidate_invalid" || len(response.Results) != 0 {
				t.Fatalf("mixed candidate profile did not fail closed: %#v", response)
			}
		})
	}
}

func TestBM25FHybridProfileLineageIsExact(t *testing.T) {
	for _, test := range []struct {
		name      string
		profile   string
		tokenizer string
		mixed     string
	}{
		{name: "v1.0", profile: bm25fLexicalProfile, tokenizer: bm25fTokenizerID, mixed: bm25fTokenizerIDV11},
		{name: "v1.1", profile: bm25fLexicalProfileV11, tokenizer: bm25fTokenizerIDV11, mixed: bm25fTokenizerID},
	} {
		t.Run(test.name, func(t *testing.T) {
			fx := newHybridTestFixtureForProfile(t, test.profile)
			if fx.lexical.Manifest.LexicalProfile != test.profile || fx.hybrid.Manifest.LexicalProfile != test.profile || fx.hybrid.Manifest.LexicalTokenizerID != test.tokenizer || fx.hybrid.Manifest.LexicalScorerID != bm25fScorerID {
				t.Fatalf("hybrid lost BM25F lineage: lexical=%+v hybrid=%+v", fx.lexical.Manifest.CandidateManifestCore, fx.hybrid.Manifest.HybridCandidateManifestCore)
			}
			_, signalsPath, signalsHash := fx.writeSignals(t, "alpha", []int16{denseQuantizationScale, 0}, map[string]int64{fx.alphaDocID: 10, fx.semanticDocID: 0})
			response, err := QueryHybrid(fx.hybridQueryConfig(signalsPath, signalsHash, "alpha"))
			if err != nil || response.ResultState != "ok" || response.LexicalProfile != test.profile {
				t.Fatalf("BM25F hybrid query failed: response=%#v err=%v", response, err)
			}

			forged := fx.hybrid.Manifest
			forged.LexicalTokenizerID = test.mixed
			coreBytes, _ := json.Marshal(forged.HybridCandidateManifestCore)
			forged.ManifestPayloadSHA256 = digestBytes(coreBytes)
			forged.ManifestID = "hybrid-retrieval-candidate:" + forged.ManifestPayloadSHA256
			forgedPath := filepath.Join(fx.root, "mixed-hybrid.json")
			writeCanonical(t, forgedPath, forged)
			config := fx.hybridQueryConfig(signalsPath, signalsHash, "alpha")
			config.HybridCandidatePath = forgedPath
			config.HybridCandidateHash = fileDigest(forgedPath)
			response, err = QueryHybrid(config)
			if err != nil || response.ErrorCode != "hybrid_candidate_invalid" {
				t.Fatalf("mixed hybrid profile did not fail closed: response=%#v err=%v", response, err)
			}
		})
	}
}

func TestBM25FQualityGenerationAndPointerCarryProfile(t *testing.T) {
	testBM25FQualityGenerationAndPointerCarryProfile(t, bm25fLexicalProfile, bm25fTokenizerID)
}

func TestBM25FV11QualityGenerationAndPointerCarryProfile(t *testing.T) {
	testBM25FQualityGenerationAndPointerCarryProfile(t, bm25fLexicalProfileV11, bm25fTokenizerIDV11)
}

func testBM25FQualityGenerationAndPointerCarryProfile(t *testing.T, lexicalProfile, tokenizerID string) {
	t.Helper()
	fx := newLifecycleTestFixtureForProfile(t, lexicalProfile)
	running, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	fx.executable = running
	fx.executableSHA = fileDigest(running)
	fx.writeQuality(t, true)
	if fx.quality.LexicalProfile != lexicalProfile || fx.quality.LexicalTokenizerID != tokenizerID || fx.quality.LexicalScorerID != bm25fScorerID {
		t.Fatalf("quality report lost BM25F lineage: %+v", fx.quality.RetrievalQualityReportCore)
	}
	generation := fx.stage(t, "2026-07-16T01:00:00Z", nil)
	if generation.Generation.LexicalProfile != lexicalProfile || generation.Generation.LexicalTokenizerID != tokenizerID || generation.Generation.LexicalScorerID != bm25fScorerID {
		t.Fatalf("generation lost BM25F lineage: %+v", generation.Generation.RetrievalGenerationCore)
	}
	intent := fx.preparePromotion(t, generation, "2026-07-16T02:00:00Z", true, "")
	applied, err := ApplyGenerationTransition(fx.signedApplyConfig(t, intent, &generation))
	if err != nil {
		t.Fatal(err)
	}
	if applied.Pointer.CurrentLexicalProfile != lexicalProfile || applied.Pointer.CurrentLexicalTokenizerID != tokenizerID || applied.Pointer.CurrentLexicalScorerID != bm25fScorerID {
		t.Fatalf("serving pointer lost BM25F lineage: %+v", applied.Pointer.RetrievalGenerationPointerCore)
	}
	current, err := CurrentQuery(fx.currentQueryConfig("2026-07-16T03:00:00Z"))
	if err != nil {
		t.Fatal(err)
	}
	if current.State != "current" || current.Profile != "lexical" || current.LexicalProfile != lexicalProfile || current.LexicalTokenizerID != tokenizerID || current.LexicalScorerID != bm25fScorerID {
		t.Fatalf("current serving response lost BM25F lineage: %+v", current)
	}

	forgedQuality := fx.quality
	forgedQuality.LexicalScorerID = ""
	qualityCore, _ := json.Marshal(forgedQuality.RetrievalQualityReportCore)
	forgedQuality.ReportPayloadSHA256 = digestBytes(qualityCore)
	forgedQuality.ReportID = "retrieval-quality-report:" + forgedQuality.ReportPayloadSHA256
	if err := validateQualityReportDocument(forgedQuality, true); err == nil {
		t.Fatal("mixed BM25F quality lineage was accepted")
	}

	forgedPointer := applied.Pointer
	forgedPointer.CurrentLexicalScorerID = ""
	pointerCore, _ := json.Marshal(forgedPointer.RetrievalGenerationPointerCore)
	forgedPointer.PointerPayloadSHA256 = digestBytes(pointerCore)
	forgedPointer.PointerID = "retrieval-pointer:" + forgedPointer.PointerPayloadSHA256
	if err := validateGenerationPointer(forgedPointer); err == nil {
		t.Fatal("mixed BM25F serving pointer lineage was accepted")
	}
}

func TestBM25FEvaluatorEmitsExactProfileLineage(t *testing.T) {
	for _, test := range []struct {
		name      string
		profile   string
		tokenizer string
	}{
		{name: "v1.0", profile: bm25fLexicalProfile, tokenizer: bm25fTokenizerID},
		{name: "v1.1", profile: bm25fLexicalProfileV11, tokenizer: bm25fTokenizerIDV11},
	} {
		t.Run(test.name, func(t *testing.T) {
			fx := newEvaluatorTestFixtureForProfile(t, test.profile)
			result, err := EvaluateRetrieval(fx.config())
			if err != nil {
				t.Fatal(err)
			}
			report := result.QualityReport
			if report.LexicalProfile != test.profile || report.LexicalTokenizerID != test.tokenizer || report.LexicalScorerID != bm25fScorerID {
				t.Fatalf("evaluator quality report lost BM25F lineage: %+v", report.RetrievalQualityReportCore)
			}
		})
	}
}

func buildBM25FChunks(t *testing.T, chunks [][]byte, headings [][]string) (*testFixture, BuildResult) {
	return buildBM25FChunksForProfile(t, bm25fLexicalProfile, chunks, headings)
}

func buildBM25FChunksForProfile(t *testing.T, lexicalProfile string, chunks [][]byte, headings [][]string) (*testFixture, BuildResult) {
	t.Helper()
	data := bytes.Join(chunks, nil)
	fx := newTestFixture(t, data, "2026-07-17T00:00:00Z")
	if len(chunks) > 1 {
		replaceFixtureSpans(t, fx, chunks)
	}
	if headings != nil {
		file := fx.evidence.Files[0]
		for i := range file.Spans {
			file.Spans[i].HeadingBreadcrumb = append([]string(nil), headings[i]...)
			file.Spans[i].SpanID = spanIdentity(file.OccurrenceID, file.ParserVersion, file.ProfileVersion, file.Spans[i])
		}
		fx.evidence.Files[0] = file
		fx.resealEvidence(t)
		fx.policy.EvidenceManifestID = fx.evidence.ManifestID
		fx.resealPolicy(t)
		fx.rewriteVerifier(t, true)
	}
	config := fx.buildConfig(fx.outputRoot)
	config.LexicalProfile = lexicalProfile
	result, err := Build(config)
	if err != nil {
		t.Fatal(err)
	}
	return fx, result
}
