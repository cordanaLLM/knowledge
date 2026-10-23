package main

import (
	"errors"
	"math"
	"math/big"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	legacyLexicalProfile     = "deterministic_raw_term_frequency@1.0.0"
	bm25fLexicalProfile      = "deterministic_bm25f_fixed_point@1.0.0"
	bm25fLexicalProfileV11   = "deterministic_bm25f_fixed_point@1.1.0"
	bm25fTokenizerID         = "unicode_alnum_camel_acronym_conservative_plural@1.0.0" // #nosec G101 -- Public versioned tokenizer algorithm identifier; no authentication authority.
	bm25fTokenizerIDV11      = "unicode_alnum_camel_acronym_conservative_plural@1.1.0" // #nosec G101 -- Public versioned tokenizer algorithm identifier; no authentication authority.
	bm25fScorerID            = "bm25f_k1_6_5_b_3_4_heading_2_cap_half_fixed_ppm@1.0.0"
	bm25fIndexSchema         = "2.0.0"
	bm25fIndexKind           = "deterministic_bm25f_lexical_inverted_index"
	bm25fScoreScale          = int64(1_000_000)
	bm25fHeadingWeight       = int64(2)
	bm25fHeadingTFMax        = 2
	bm25fHeadingNormMax      = bm25fScoreScale / 2
	bm25fMaxBaseTerms        = 32
	bm25fMaxBaseTermsV11     = 64
	bm25fMaxQueryTerms       = 128
	bm25fMaxComponents       = 4
	bm25fBaseLimitMessage    = "query contains more than 32 base lexical terms"
	bm25fBaseLimitMessageV11 = "query contains more than 64 base lexical terms"
)

type bm25fProfileContract struct {
	lexicalProfile           string
	tokenizerID              string
	maxBaseTerms             int
	baseLimitMessage         string
	retainOverComponentToken bool
}

type bm25fFrequencies struct {
	terms     map[string]int
	baseCount int
}

func normalizeLexicalProfile(profile string) (string, error) {
	switch strings.TrimSpace(profile) {
	case "", legacyLexicalProfile:
		return legacyLexicalProfile, nil
	case bm25fLexicalProfile:
		return bm25fLexicalProfile, nil
	case bm25fLexicalProfileV11:
		return bm25fLexicalProfileV11, nil
	default:
		return "", errors.New("lexical-profile must be deterministic_raw_term_frequency@1.0.0, deterministic_bm25f_fixed_point@1.0.0, or deterministic_bm25f_fixed_point@1.1.0")
	}
}

func bm25fContractForProfile(profile string) (bm25fProfileContract, bool) {
	switch profile {
	case bm25fLexicalProfile:
		return bm25fProfileContract{
			lexicalProfile: bm25fLexicalProfile, tokenizerID: bm25fTokenizerID,
			maxBaseTerms: bm25fMaxBaseTerms, baseLimitMessage: bm25fBaseLimitMessage,
		}, true
	case bm25fLexicalProfileV11:
		return bm25fProfileContract{
			lexicalProfile: bm25fLexicalProfileV11, tokenizerID: bm25fTokenizerIDV11,
			maxBaseTerms: bm25fMaxBaseTermsV11, baseLimitMessage: bm25fBaseLimitMessageV11,
			retainOverComponentToken: true,
		}, true
	default:
		return bm25fProfileContract{}, false
	}
}

func isBM25FProfile(profile string) bool {
	_, ok := bm25fContractForProfile(profile)
	return ok
}

func validBM25FLineage(profile, tokenizerID, scorerID string) bool {
	contract, ok := bm25fContractForProfile(profile)
	return ok && tokenizerID == contract.tokenizerID && scorerID == bm25fScorerID
}

func candidateLexicalProfile(candidate CandidateManifest) string {
	if candidate.LexicalProfile == "" {
		return legacyLexicalProfile
	}
	return candidate.LexicalProfile
}

func bm25fFrequenciesForIndex(data []byte, knownTerms map[string][]Posting, maxNewTerms, maxUniqueTerms int) (bm25fFrequencies, *QuarantineIssue) {
	contract, _ := bm25fContractForProfile(bm25fLexicalProfile)
	return scanBM25FTerms(data, contract, 0, maxUniqueTerms, knownTerms, nil, maxNewTerms)
}

func bm25fQueryTerms(data []byte) ([]string, error) {
	return bm25fQueryTermsForProfile(bm25fLexicalProfile, data)
}

func bm25fQueryTermsForProfile(profile string, data []byte) ([]string, error) {
	contract, ok := bm25fContractForProfile(profile)
	if !ok {
		return nil, errors.New("BM25F lexical profile is unsupported")
	}
	result, problem := scanBM25FTerms(data, contract, contract.maxBaseTerms, bm25fMaxQueryTerms, nil, nil, bm25fMaxQueryTerms)
	if problem != nil {
		return nil, errors.New(problem.Message)
	}
	terms := make([]string, 0, len(result.terms))
	for term := range result.terms {
		terms = append(terms, term)
	}
	sort.Strings(terms)
	return terms, nil
}

// scanBM25FTerms bounds the raw token, identifier expansion and term maps while
// scanning. maxBase=0 means the evidence payload's existing byte/posting bounds
// are the controlling limit; query callers use their immutable profile bound.
func scanBM25FTerms(data []byte, contract bm25fProfileContract, maxBase, maxExpanded int, knownTerms map[string][]Posting, locallyKnown map[string]int, maxNewTerms int) (bm25fFrequencies, *QuarantineIssue) {
	result := bm25fFrequencies{terms: make(map[string]int)}
	baseTerms := make(map[string]struct{})
	token := make([]byte, 0, maxLexicalTokenBytes)
	discardToken := false
	newTerms := 0
	newUniqueTerms := 0
	flush := func() *QuarantineIssue {
		if discardToken {
			token = token[:0]
			discardToken = false
			return nil
		}
		if len(token) == 0 {
			return nil
		}
		value := string(token)
		token = token[:0]
		result.baseCount++
		baseIdentity := strings.ToLower(value)
		baseTerms[baseIdentity] = struct{}{}
		if maxBase > 0 && len(baseTerms) > maxBase {
			problem := issue("query_base_term_limit", "query", contract.baseLimitMessage)
			return &problem
		}
		expanded, err := expandBM25FTokenForContract(value, contract)
		if err != nil {
			problem := issue("identifier_component_limit", "payload", err.Error())
			return &problem
		}
		for _, term := range expanded {
			if count, exists := result.terms[term]; exists {
				if count == math.MaxInt {
					problem := issue("term_frequency_overflow", "payload", "lexical term frequency exceeds the integer bound")
					return &problem
				}
				result.terms[term] = count + 1
				continue
			}
			_, sameDocumentKnown := locallyKnown[term]
			if !sameDocumentKnown && newUniqueTerms >= maxExpanded {
				problem := issue("query_expanded_term_limit", "query", "expanded lexical terms exceed the configured bound")
				if maxBase == 0 {
					problem = issue("posting_count_limit", "payload", "lexical postings exceed the configured bound")
				}
				return &problem
			}
			_, globallyKnown := knownTerms[term]
			if !globallyKnown && !sameDocumentKnown {
				if newTerms >= maxNewTerms {
					problem := issue("term_count_limit", "payload", "unique lexical terms exceed the configured bound")
					return &problem
				}
				newTerms++
			}
			if !sameDocumentKnown {
				newUniqueTerms++
			}
			result.terms[term] = 1
		}
		return nil
	}
	for len(data) > 0 {
		r, size := utf8.DecodeRune(data)
		if r == utf8.RuneError && size == 1 {
			problem := issue("lexical_payload_invalid_utf8", "payload", "lexical payload is not valid UTF-8")
			return bm25fFrequencies{}, &problem
		}
		if unicode.IsLetter(r) || unicode.IsNumber(r) {
			if !discardToken && len(token)+size > maxLexicalTokenBytes {
				token = token[:0]
				discardToken = true
			} else if !discardToken {
				token = append(token, data[:size]...)
			}
		} else if problem := flush(); problem != nil {
			return bm25fFrequencies{}, problem
		}
		data = data[size:]
	}
	if problem := flush(); problem != nil {
		return bm25fFrequencies{}, problem
	}
	return result, nil
}

func expandBM25FToken(value string) ([]string, error) {
	contract, _ := bm25fContractForProfile(bm25fLexicalProfile)
	return expandBM25FTokenForContract(value, contract)
}

func expandBM25FTokenForProfile(value, profile string) ([]string, error) {
	contract, ok := bm25fContractForProfile(profile)
	if !ok {
		return nil, errors.New("BM25F lexical profile is unsupported")
	}
	return expandBM25FTokenForContract(value, contract)
}

func expandBM25FTokenForContract(value string, contract bm25fProfileContract) ([]string, error) {
	normalized := strings.ToLower(value)
	components := splitIdentifier(value)
	if len(components) > bm25fMaxComponents {
		if !contract.retainOverComponentToken {
			return nil, errors.New("identifier contains more than four deterministic components")
		}
		// The v1.1 component cap bounds expansion while retaining the exact
		// normalized token and one conservative singular variant.
		components = nil
	}
	result := make([]string, 0, 2+len(components))
	seen := make(map[string]struct{}, 2+len(components))
	add := func(term string) {
		term = strings.ToLower(term)
		if term == "" {
			return
		}
		if _, exists := seen[term]; exists {
			return
		}
		seen[term] = struct{}{}
		result = append(result, term)
	}
	add(normalized)
	for _, component := range components {
		add(component)
	}
	if singular := conservativeSingular(normalized); singular != "" {
		add(singular)
	}
	return result, nil
}

func splitIdentifier(value string) []string {
	runes := []rune(value)
	if len(runes) == 0 {
		return nil
	}
	start := 0
	result := make([]string, 0, bm25fMaxComponents+1)
	for i := 1; i < len(runes); i++ {
		previous, current := runes[i-1], runes[i]
		boundary := unicode.IsDigit(previous) != unicode.IsDigit(current)
		if !boundary && unicode.IsLower(previous) && unicode.IsUpper(current) {
			boundary = true
		}
		if !boundary && i+1 < len(runes) && unicode.IsUpper(previous) && unicode.IsUpper(current) && unicode.IsLower(runes[i+1]) {
			boundary = true
		}
		if boundary {
			result = append(result, string(runes[start:i]))
			start = i
		}
	}
	result = append(result, string(runes[start:]))
	return result
}

func conservativeSingular(term string) string {
	if len(term) <= 4 {
		return ""
	}
	switch {
	case strings.HasSuffix(term, "ies") && len(term) > 4:
		return term[:len(term)-3] + "y"
	case strings.HasSuffix(term, "ches"), strings.HasSuffix(term, "shes"), strings.HasSuffix(term, "xes"), strings.HasSuffix(term, "zes"), strings.HasSuffix(term, "sses"):
		return term[:len(term)-2]
	case strings.HasSuffix(term, "s") && !strings.HasSuffix(term, "ss") && !strings.HasSuffix(term, "us") && !strings.HasSuffix(term, "is"):
		return term[:len(term)-1]
	default:
		return ""
	}
}

func scoreBM25F(index LexicalIndex, document IndexedDocument, term TermEntry, posting Posting) (int64, error) {
	idf, err := bm25fTermIDF(index.DocumentCount, term.DocumentFrequency)
	if err != nil {
		return 0, err
	}
	return scoreBM25FWithIDF(index, document, posting, idf)
}

func bm25fTermIDF(documentCount, documentFrequency int) (int64, error) {
	if documentFrequency < 1 || documentFrequency > documentCount {
		return 0, errors.New("BM25F document frequency is invalid")
	}
	// Standard positive BM25 IDF: ln(1 + (N-df+0.5)/(df+0.5))
	// = ln(2*(N+1)/(2*df+1)), evaluated by a deterministic integer series.
	documentCountPlusOne, err := checkedAddInt64(int64(documentCount), 1)
	if err != nil {
		return 0, err
	}
	idfNumerator, err := checkedMulInt64(2, documentCountPlusOne)
	if err != nil {
		return 0, err
	}
	idfDenominator, err := checkedMulInt64(2, int64(documentFrequency))
	if err != nil {
		return 0, err
	}
	idfDenominator, err = checkedAddInt64(idfDenominator, 1)
	if err != nil {
		return 0, err
	}
	return fixedNaturalLogRatio(idfNumerator, idfDenominator)
}

func scoreBM25FWithIDF(index LexicalIndex, document IndexedDocument, posting Posting, idf int64) (int64, error) {
	if idf < 0 {
		return 0, errors.New("BM25F IDF is invalid")
	}
	body, err := normalizedFieldTF(posting.BodyTermFrequency, document.BodyLength, index.TotalBodyLength, index.DocumentCount)
	if err != nil {
		return 0, err
	}
	headingTF := posting.HeadingTermFrequency
	if headingTF > bm25fHeadingTFMax {
		headingTF = bm25fHeadingTFMax
	}
	heading, err := normalizedFieldTF(headingTF, document.HeadingLength, index.TotalHeadingLength, index.DocumentCount)
	if err != nil {
		return 0, err
	}
	heading, err = checkedMulInt64(heading, bm25fHeadingWeight)
	if err != nil {
		return 0, err
	}
	if heading > bm25fHeadingNormMax {
		heading = bm25fHeadingNormMax
	}
	weightedTF, err := checkedAddInt64(body, heading)
	if err != nil || weightedTF == 0 {
		return 0, err
	}
	// k1=6/5: ((k1+1)*tf)/(k1+tf) becomes
	// 11*tf*scale/(6*scale+5*tf), with tf itself fixed at scale.
	fiveTF, err := checkedMulInt64(5, weightedTF)
	if err != nil {
		return 0, err
	}
	denominator, err := checkedAddInt64(6*bm25fScoreScale, fiveTF)
	if err != nil || denominator <= 0 {
		return 0, errors.New("BM25F saturation denominator is invalid")
	}
	saturated, err := checkedPositiveMulDiv([]int64{11, weightedTF, bm25fScoreScale}, denominator)
	if err != nil {
		return 0, err
	}
	product, err := checkedMulInt64(idf, saturated)
	if err != nil {
		return 0, err
	}
	return product / bm25fScoreScale, nil
}

func normalizedFieldTF(tf, length int, totalLength int64, documentCount int) (int64, error) {
	if tf < 0 || length < 0 || totalLength < 0 || documentCount < 1 {
		return 0, errors.New("BM25F field statistics are invalid")
	}
	if tf == 0 {
		return 0, nil
	}
	if length == 0 || totalLength == 0 || tf > length {
		return 0, errors.New("BM25F positive field frequency exceeds its retained field length")
	}
	lengthPart, err := checkedMulInt64(3, int64(length))
	if err != nil {
		return 0, err
	}
	lengthPart, err = checkedMulInt64(lengthPart, int64(documentCount))
	if err != nil {
		return 0, err
	}
	denominator, err := checkedAddInt64(totalLength, lengthPart)
	if err != nil || denominator <= 0 {
		return 0, errors.New("BM25F field normalization denominator is invalid")
	}
	return checkedPositiveMulDiv([]int64{int64(tf), 4, totalLength, bm25fScoreScale}, denominator)
}

func fixedNaturalLogRatio(numerator, denominator int64) (int64, error) {
	if numerator <= 0 || denominator <= 0 || numerator < denominator {
		return 0, errors.New("BM25F IDF ratio is invalid")
	}
	exponent := int64(0)
	for {
		if denominator > numerator/2 {
			break
		}
		doubled, err := checkedMulInt64(2, denominator)
		if err != nil {
			return 0, err
		}
		denominator = doubled
		exponent++
	}
	zNumerator, err := checkedSubInt64(numerator, denominator)
	if err != nil {
		return 0, err
	}
	zDenominator, err := checkedAddInt64(numerator, denominator)
	if err != nil {
		return 0, err
	}
	zProduct, err := checkedMulInt64(zNumerator, bm25fScoreScale)
	if err != nil {
		return 0, err
	}
	z := zProduct / zDenominator
	zSquared, err := checkedMulInt64(z, z)
	if err != nil {
		return 0, err
	}
	zSquared /= bm25fScoreScale
	power := z
	sum := int64(0)
	for odd := int64(1); odd <= 47; odd += 2 {
		term := power / odd
		sum, err = checkedAddInt64(sum, term)
		if err != nil {
			return 0, err
		}
		power, err = checkedMulInt64(power, zSquared)
		if err != nil {
			return 0, err
		}
		power /= bm25fScoreScale
	}
	result, err := checkedMulInt64(2, sum)
	if err != nil {
		return 0, err
	}
	const ln2PPM = int64(693147)
	exponentPart, err := checkedMulInt64(exponent, ln2PPM)
	if err != nil {
		return 0, err
	}
	return checkedAddInt64(result, exponentPart)
}

func checkedAddInt64(left, right int64) (int64, error) {
	if (right > 0 && left > math.MaxInt64-right) || (right < 0 && left < math.MinInt64-right) {
		return 0, errors.New("fixed-point integer overflow")
	}
	return left + right, nil
}

func checkedSubInt64(left, right int64) (int64, error) {
	if (right > 0 && left < math.MinInt64+right) || (right < 0 && left > math.MaxInt64+right) {
		return 0, errors.New("fixed-point integer overflow")
	}
	return left - right, nil
}

func checkedMulInt64(left, right int64) (int64, error) {
	if left == 0 || right == 0 {
		return 0, nil
	}
	if left == -1 && right == math.MinInt64 || right == -1 && left == math.MinInt64 {
		return 0, errors.New("fixed-point integer overflow")
	}
	result := left * right
	if result/right != left {
		return 0, errors.New("fixed-point integer overflow")
	}
	return result, nil
}

func checkedPositiveMulDiv(factors []int64, denominator int64) (int64, error) {
	if denominator <= 0 {
		return 0, errors.New("fixed-point denominator is invalid")
	}
	// A fixed number of bounded factors is multiplied as an integer. big.Int is
	// used only as a checked wide accumulator; the observable score remains
	// int64 fixed point and fails closed if the exact quotient does not fit.
	product := big.NewInt(1)
	for _, factor := range factors {
		if factor < 0 {
			return 0, errors.New("fixed-point factor is invalid")
		}
		product.Mul(product, big.NewInt(factor))
	}
	product.Quo(product, big.NewInt(denominator))
	if !product.IsInt64() {
		return 0, errors.New("fixed-point integer overflow")
	}
	return product.Int64(), nil
}
