package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "build":
		runBuild(os.Args[2:])
	case "query":
		runQuery(os.Args[2:])
	case "current-query":
		runCurrentQuery(os.Args[2:])
	case "hybridize":
		runHybridize(os.Args[2:])
	case "materialize-dense-artifact":
		runMaterializeDenseArtifact(os.Args[2:])
	case "materialize-query-signal":
		runMaterializeQuerySignal(os.Args[2:])
	case "hybrid-query":
		runHybridQuery(os.Args[2:])
	case "materialize-admission-policy":
		runMaterializeAdmissionPolicy(os.Args[2:])
	case "materialize-fusion-profile":
		runMaterializeFusionProfile(os.Args[2:])
	case "materialize-situating-context":
		runMaterializeSituatingContext(os.Args[2:])
	case "materialize-fine-span-payload":
		runMaterializeFineSpanPayload(os.Args[2:])
	case "materialize-evaluation-suite":
		runMaterializeEvaluationSuite(os.Args[2:])
	case "materialize-evaluation-definition":
		runMaterializeEvaluationDefinition(os.Args[2:])
	case "materialize-paired-fusion-suite":
		runMaterializePairedFusionSuite(os.Args[2:])
	case "prepare-paired-fusion-run":
		runPreparePairedFusionRun(os.Args[2:])
	case "materialize-multidomain-evaluation-suite":
		runMaterializeMultidomainEvaluationSuite(os.Args[2:])
	case "evaluate-multidomain":
		runEvaluateMultidomain(os.Args[2:])
	case "verify-multidomain-receipt":
		runVerifyMultidomainReceipt(os.Args[2:])
	case "materialize-evaluation-freeze":
		runMaterializeEvaluationFreeze(os.Args[2:])
	case "materialize-binding-requirements":
		runMaterializeBindingRequirements(os.Args[2:])
	case "materialize-binding-closure":
		runMaterializeBindingClosure(os.Args[2:])
	case "evaluate":
		runEvaluateRetrieval(os.Args[2:])
	case "stage-generation":
		runStageGeneration(os.Args[2:])
	case "prepare-promotion":
		runPreparePromotion(os.Args[2:])
	case "prepare-rollback":
		runPrepareRollback(os.Args[2:])
	case "apply-transition":
		runApplyTransition(os.Args[2:])
	case "generation-status":
		runGenerationStatus(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage:")
	fmt.Fprintln(os.Stderr, "  knowledge-retrieval build --snapshot-manifest FILE --evidence-manifest FILE --raw-store DIR --evidence-store DIR --store DIR --spec FILE --proposal FILE --review-receipt FILE --review-signature FILE --allowed-signers FILE --admission-policy FILE --admission-policy-sha256 SHA256 --evidence-verifier FILE --evidence-verifier-sha256 SHA256 --as-of RFC3339 [--lexical-profile deterministic_raw_term_frequency@1.0.0|deterministic_bm25f_fixed_point@1.0.0|deterministic_bm25f_fixed_point@1.1.0]")
	fmt.Fprintln(os.Stderr, "  knowledge-retrieval build --lineage-set FILE  (shared multi-authority lexical candidate/index over N admitted source authorities)")
	fmt.Fprintln(os.Stderr, "  knowledge-retrieval query --candidate FILE --candidate-sha256 SHA256 --store DIR --evidence-store DIR --admission-policy FILE --admission-policy-sha256 SHA256 --query TEXT --principal-scope public --as-of RFC3339 [--lineage-set FILE] [--limit N]")
	fmt.Fprintln(os.Stderr, "  knowledge-retrieval current-query --store DIR --state DIR --evidence-store DIR --admission-policy FILE --admission-policy-sha256 SHA256 --query TEXT --principal-scope public --as-of RFC3339 [--limit N]")
	fmt.Fprintln(os.Stderr, "  knowledge-retrieval hybridize --candidate FILE --candidate-sha256 SHA256 --store DIR --dense-artifact FILE --dense-artifact-sha256 SHA256 [--fusion-profile FILE --fusion-profile-sha256 SHA256]")
	fmt.Fprintln(os.Stderr, "  knowledge-retrieval hybrid-query --hybrid-candidate FILE --hybrid-candidate-sha256 SHA256 --store DIR --evidence-store DIR --admission-policy FILE --admission-policy-sha256 SHA256 --query-artifact FILE --query-artifact-sha256 SHA256 --query TEXT --principal-scope public --as-of RFC3339 [--lineage-set FILE] [--limit N] [--rerank-window 0|N] [--fusion-profile FILE --fusion-profile-sha256 SHA256]")
	fmt.Fprintln(os.Stderr, "  knowledge-retrieval materialize-admission-policy --core FILE --store DIR")
	fmt.Fprintln(os.Stderr, "  knowledge-retrieval materialize-fusion-profile --core FILE --store DIR")
	fmt.Fprintln(os.Stderr, "  knowledge-retrieval materialize-situating-context --core FILE --store DIR")
	fmt.Fprintln(os.Stderr, "  knowledge-retrieval materialize-fine-span-payload --raw-store DIR --raw-sha256 SHA256 --raw-size N --evidence-store DIR --raw-byte-start N --raw-byte-end N")
	fmt.Fprintln(os.Stderr, "  knowledge-retrieval materialize-evaluation-suite --core FILE --store DIR")
	fmt.Fprintln(os.Stderr, "  knowledge-retrieval materialize-evaluation-definition --core FILE --store DIR")
	fmt.Fprintln(os.Stderr, "  knowledge-retrieval materialize-paired-fusion-suite --core FILE --store DIR")
	fmt.Fprintln(os.Stderr, "  knowledge-retrieval prepare-paired-fusion-run --suite FILE --suite-sha256 SHA256 --retrieval-store DIR --snapshot-store DIR --evidence-store DIR --query-signal-store DIR --baseline-scorer FILE --baseline-scorer-sha256 SHA256 --challenger-scorer FILE --challenger-scorer-sha256 SHA256")
	fmt.Fprintln(os.Stderr, "  knowledge-retrieval materialize-multidomain-evaluation-suite --core FILE --store DIR")
	fmt.Fprintln(os.Stderr, "  knowledge-retrieval evaluate-multidomain --suite FILE --suite-sha256 SHA256 --store DIR --evidence-store DIR --query-signal-store DIR --lineage-set FILE --admission-policy FILE --admission-policy-sha256 SHA256 --retrieval-executable FILE --retrieval-executable-sha256 SHA256 --evaluator-executable FILE --evaluator-executable-sha256 SHA256 --evaluator-allowed-signers FILE --evaluator-actor PRINCIPAL --evaluator-key-id SHA256:FINGERPRINT --as-of RFC3339 [--evaluator-private-key FILE]")
	fmt.Fprintln(os.Stderr, "  knowledge-retrieval verify-multidomain-receipt --receipt FILE --receipt-sha256 SHA256 --signature FILE --signature-sha256 SHA256 --evaluator-allowed-signers FILE")
	fmt.Fprintln(os.Stderr, "  knowledge-retrieval materialize-evaluation-freeze --core FILE --source-root DIR --store DIR")
	fmt.Fprintln(os.Stderr, "  knowledge-retrieval materialize-binding-requirements --core FILE --freeze FILE --freeze-sha256 SHA256 --source-root DIR --store DIR")
	fmt.Fprintln(os.Stderr, "  knowledge-retrieval materialize-binding-closure --core FILE --freeze FILE --freeze-sha256 SHA256 --source-root DIR --store DIR --admitted-artifacts FILE [--evaluation-time RFC3339] [--shared-corpus-artifacts FILE]")
	fmt.Fprintln(os.Stderr, "  knowledge-retrieval evaluate --suite FILE --suite-sha256 SHA256 --lexical-candidate FILE --lexical-candidate-sha256 SHA256 --hybrid-candidate FILE --hybrid-candidate-sha256 SHA256 --store DIR --evidence-store DIR --query-signal-store DIR --admission-policy FILE --admission-policy-sha256 SHA256 --retrieval-executable FILE --retrieval-executable-sha256 SHA256 --evaluator-executable FILE --evaluator-executable-sha256 SHA256 --evaluator-allowed-signers FILE --evaluator-actor PRINCIPAL --evaluator-key-id SHA256:FINGERPRINT [--base-generation FILE --base-generation-sha256 SHA256]")
	fmt.Fprintln(os.Stderr, "  knowledge-retrieval stage-generation --hybrid-candidate FILE --hybrid-candidate-sha256 SHA256 --store DIR --quality-report FILE --quality-report-sha256 SHA256 --quality-receipt FILE --quality-receipt-sha256 SHA256 --quality-signature FILE --quality-signature-sha256 SHA256 --evaluator-allowed-signers FILE --evaluation-dataset FILE --evaluation-dataset-sha256 SHA256 --evaluation-metrics FILE --evaluation-metrics-sha256 SHA256 --evaluation-runtime FILE --evaluation-runtime-sha256 SHA256 --admission-policy FILE --admission-policy-sha256 SHA256 --retrieval-executable FILE --retrieval-executable-sha256 SHA256 --evaluator-executable FILE --evaluator-executable-sha256 SHA256 --as-of RFC3339 [--base-generation FILE --base-generation-sha256 SHA256]")
	fmt.Fprintln(os.Stderr, "  knowledge-retrieval prepare-promotion --generation FILE --generation-sha256 SHA256 --store DIR --state DIR --admission-policy FILE --admission-policy-sha256 SHA256 --allowed-signers FILE --actor PRINCIPAL --key-id SHA256:FINGERPRINT --transitioned-at RFC3339 (--bootstrap | --expect-pointer ID)")
	fmt.Fprintln(os.Stderr, "  knowledge-retrieval prepare-rollback --store DIR --state DIR --admission-policy FILE --admission-policy-sha256 SHA256 --allowed-signers FILE --actor PRINCIPAL --key-id SHA256:FINGERPRINT --transitioned-at RFC3339 --expect-pointer ID")
	fmt.Fprintln(os.Stderr, "  knowledge-retrieval apply-transition --store DIR --state DIR --intent FILE --intent-sha256 SHA256 --signature FILE --signature-sha256 SHA256 --allowed-signers FILE --admission-policy FILE --admission-policy-sha256 SHA256 --decision promoted|rolled_back [--generation FILE --generation-sha256 SHA256]")
	fmt.Fprintln(os.Stderr, "  knowledge-retrieval generation-status --store DIR --state DIR --admission-policy FILE --admission-policy-sha256 SHA256 --as-of RFC3339")
}

func runBuild(args []string) {
	flags := flag.NewFlagSet("build", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	config := BuildConfig{}
	lineageSetPath := ""
	flags.StringVar(&lineageSetPath, "lineage-set", "", "shared multi-authority lineage-set file; supersedes the singular flat flags")
	flags.StringVar(&config.SnapshotManifestPath, "snapshot-manifest", "", "reviewed complete knowledge-snapshot manifest")
	flags.StringVar(&config.EvidenceManifestPath, "evidence-manifest", "", "complete knowledge-evidence manifest")
	flags.StringVar(&config.RawStoreRoot, "raw-store", "", "knowledge-snapshot raw/review CAS")
	flags.StringVar(&config.EvidenceStoreRoot, "evidence-store", "", "knowledge-evidence normalized CAS")
	flags.StringVar(&config.OutputStoreRoot, "store", "", "candidate retrieval output CAS")
	flags.StringVar(&config.SpecPath, "spec", "", "reviewed source spec")
	flags.StringVar(&config.ProposalPath, "proposal", "", "source inventory proposal")
	flags.StringVar(&config.ReviewReceiptPath, "review-receipt", "", "accepted source review receipt")
	flags.StringVar(&config.ReviewSignaturePath, "review-signature", "", "detached source review SSHSIG")
	flags.StringVar(&config.AllowedSignersPath, "allowed-signers", "", "operator source-review trust root")
	flags.StringVar(&config.AdmissionPolicyPath, "admission-policy", "", "explicit public ACL, deletion and freshness policy")
	flags.StringVar(&config.AdmissionPolicyHash, "admission-policy-sha256", "", "operator-pinned whole-document SHA-256 of admission policy")
	flags.StringVar(&config.EvidenceVerifierPath, "evidence-verifier", "", "exact knowledge-evidence executable")
	flags.StringVar(&config.EvidenceVerifierHash, "evidence-verifier-sha256", "", "exact SHA-256 of knowledge-evidence executable")
	flags.StringVar(&config.AsOf, "as-of", "", "explicit RFC3339 build time")
	flags.IntVar(&config.MaxFiles, "max-files", 0, "maximum evidence files")
	flags.IntVar(&config.MaxSpans, "max-spans", 0, "maximum evidence spans")
	flags.Int64Var(&config.MaxPayloadBytes, "max-payload-bytes", 0, "maximum bytes per normalized payload")
	flags.Int64Var(&config.MaxTotalBytes, "max-total-bytes", 0, "maximum logical normalized bytes")
	flags.IntVar(&config.MaxTerms, "max-terms", 0, "maximum unique lexical terms")
	flags.IntVar(&config.MaxPostings, "max-postings", 0, "maximum term-to-span postings")
	flags.StringVar(&config.LexicalProfile, "lexical-profile", legacyLexicalProfile, "immutable lexical tokenizer/scorer profile")
	flags.StringVar(&config.FineSpanExtensionPath, "fine-span-extension", "", "optional small-to-big fine-span extension file (single-authority path only)")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		os.Exit(2)
	}
	if lineageSetPath != "" {
		if config.SnapshotManifestPath != "" || config.EvidenceManifestPath != "" || config.RawStoreRoot != "" || config.AdmissionPolicyPath != "" {
			fmt.Fprintln(os.Stderr, "singular build flags cannot combine with --lineage-set")
			os.Exit(2)
		}
		parsed, err := ParseLineageSet(lineageSetPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		config = parsed
	}
	result, err := Build(config)
	if err != nil {
		var quarantined *QuarantinedError
		if errors.As(err, &quarantined) {
			fmt.Fprintln(os.Stderr, quarantined.ReportPath)
			os.Exit(1)
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	response := struct {
		State          string `json:"state"`
		Promotable     bool   `json:"promotable"`
		ManifestKind   string `json:"manifest_kind"`
		ManifestID     string `json:"manifest_id"`
		ManifestPath   string `json:"manifest_path"`
		IndexID        string `json:"index_id"`
		DocumentCount  int    `json:"document_count"`
		AuthorityCount int    `json:"authority_count"`
	}{result.Manifest.State, result.Manifest.Promotable, result.Manifest.ManifestKind, result.Manifest.ManifestID, result.ManifestPath, result.Manifest.LexicalIndexID, result.Manifest.DocumentCount, len(result.Manifest.Lineages)}
	encode(response)
}

func runQuery(args []string) {
	flags := flag.NewFlagSet("query", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	config := QueryConfig{}
	flags.StringVar(&config.CandidatePath, "candidate", "", "partial candidate manifest")
	flags.StringVar(&config.CandidateHash, "candidate-sha256", "", "caller-pinned whole-document SHA-256 of the candidate manifest")
	flags.StringVar(&config.StoreRoot, "store", "", "candidate retrieval CAS")
	flags.StringVar(&config.EvidenceStoreRoot, "evidence-store", "", "knowledge-evidence normalized CAS")
	flags.StringVar(&config.AdmissionPolicyPath, "admission-policy", "", "current public ACL, deletion and freshness policy")
	flags.StringVar(&config.AdmissionPolicyHash, "admission-policy-sha256", "", "caller-pinned whole-document SHA-256 of current admission policy")
	flags.StringVar(&config.LineageSetPath, "lineage-set", "", "per-authority admission lineage set required for a shared multidomain candidate")
	flags.StringVar(&config.Query, "query", "", "literal lexical query")
	flags.StringVar(&config.PrincipalScope, "principal-scope", "", "caller scope; v1 accepts only public")
	flags.StringVar(&config.AsOf, "as-of", "", "explicit RFC3339 query time")
	flags.IntVar(&config.Limit, "limit", 10, "maximum results (1..100)")
	flags.IntVar(&config.MaxExcerptBytes, "max-excerpt-bytes", 2048, "maximum bytes returned per untrusted excerpt (1..8192)")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		os.Exit(2)
	}
	response, err := Query(config)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	encode(response)
}

func runCurrentQuery(args []string) {
	flags := flag.NewFlagSet("current-query", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	config := CurrentQueryConfig{}
	flags.StringVar(&config.StoreRoot, "store", "", "evaluated retrieval generation CAS")
	flags.StringVar(&config.StateRoot, "state", "", "signed generation pointer state root")
	flags.StringVar(&config.EvidenceStoreRoot, "evidence-store", "", "knowledge-evidence normalized CAS")
	flags.StringVar(&config.AdmissionPolicyPath, "admission-policy", "", "current public ACL, deletion and freshness policy")
	flags.StringVar(&config.AdmissionPolicyHash, "admission-policy-sha256", "", "caller-pinned whole-document SHA-256 of current admission policy")
	flags.StringVar(&config.Query, "query", "", "literal lexical query")
	flags.StringVar(&config.PrincipalScope, "principal-scope", "", "caller scope; v1 accepts only public")
	flags.StringVar(&config.AsOf, "as-of", "", "explicit RFC3339 query time")
	flags.IntVar(&config.Limit, "limit", 10, "maximum results (1..100)")
	flags.IntVar(&config.MaxExcerptBytes, "max-excerpt-bytes", 2048, "maximum bytes returned per untrusted excerpt (1..8192)")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		os.Exit(2)
	}
	response, err := CurrentQuery(config)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	encode(response)
}

func runHybridize(args []string) {
	flags := flag.NewFlagSet("hybridize", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	config := HybridBuildConfig{}
	flags.StringVar(&config.CandidatePath, "candidate", "", "partial lexical candidate manifest")
	flags.StringVar(&config.CandidateHash, "candidate-sha256", "", "caller-pinned whole-document SHA-256 of lexical candidate")
	flags.StringVar(&config.StoreRoot, "store", "", "candidate retrieval CAS")
	flags.StringVar(&config.DenseArtifactPath, "dense-artifact", "", "strict canonical external dense-vector artifact")
	flags.StringVar(&config.DenseArtifactHash, "dense-artifact-sha256", "", "caller-pinned whole-document SHA-256 of dense artifact")
	flags.StringVar(&config.FusionProfilePath, "fusion-profile", "", "optional strict canonical deterministic fusion challenger profile")
	flags.StringVar(&config.FusionProfileHash, "fusion-profile-sha256", "", "caller-pinned whole-document SHA-256 of fusion profile")
	flags.IntVar(&config.MaxDenseDocuments, "max-dense-documents", 0, "maximum dense documents")
	flags.IntVar(&config.MaxDenseDimension, "max-dense-dimension", 0, "maximum dense vector dimension")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		os.Exit(2)
	}
	result, err := Hybridize(config)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	encode(struct {
		State        string `json:"state"`
		Promotable   bool   `json:"promotable"`
		ManifestID   string `json:"manifest_id"`
		ManifestPath string `json:"manifest_path"`
		Dense        bool   `json:"dense"`
		Fusion       bool   `json:"fusion"`
		Reranking    bool   `json:"reranking"`
	}{result.Manifest.State, result.Manifest.Promotable, result.Manifest.ManifestID, result.ManifestPath, result.Manifest.Dense, result.Manifest.Fusion, result.Manifest.Reranking})
}

func runHybridQuery(args []string) {
	flags := flag.NewFlagSet("hybrid-query", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	config := HybridQueryConfig{}
	flags.StringVar(&config.HybridCandidatePath, "hybrid-candidate", "", "partial hybrid candidate manifest")
	flags.StringVar(&config.HybridCandidateHash, "hybrid-candidate-sha256", "", "caller-pinned whole-document SHA-256 of hybrid candidate")
	flags.StringVar(&config.StoreRoot, "store", "", "candidate retrieval CAS")
	flags.StringVar(&config.EvidenceStoreRoot, "evidence-store", "", "knowledge-evidence normalized CAS")
	flags.StringVar(&config.AdmissionPolicyPath, "admission-policy", "", "current public ACL, deletion and freshness policy")
	flags.StringVar(&config.AdmissionPolicyHash, "admission-policy-sha256", "", "caller-pinned whole-document SHA-256 of current admission policy")
	flags.StringVar(&config.LineageSetPath, "lineage-set", "", "per-authority admission lineage set required for a shared multidomain hybrid candidate")
	flags.StringVar(&config.QueryArtifactPath, "query-artifact", "", "strict canonical query-vector and optional reranker-score artifact")
	flags.StringVar(&config.QueryArtifactHash, "query-artifact-sha256", "", "caller-pinned whole-document SHA-256 of query artifact")
	flags.StringVar(&config.FusionProfilePath, "fusion-profile", "", "caller-pinned challenger fusion profile; absent for immutable default RRF")
	flags.StringVar(&config.FusionProfileHash, "fusion-profile-sha256", "", "caller-pinned whole-document SHA-256 of fusion profile")
	flags.StringVar(&config.Query, "query", "", "literal query bound by the query artifact")
	flags.StringVar(&config.PrincipalScope, "principal-scope", "", "caller scope; v1 accepts only public")
	flags.StringVar(&config.AsOf, "as-of", "", "explicit RFC3339 query time")
	flags.IntVar(&config.Limit, "limit", 10, "maximum results (1..100)")
	flags.IntVar(&config.FusionWindow, "fusion-window", 100, "maximum lexical and dense ranks fused (1..100)")
	flags.IntVar(&config.RerankWindow, "rerank-window", 0, "maximum fused results requiring reranker scores; 0 disables reranking")
	flags.IntVar(&config.MaxExcerptBytes, "max-excerpt-bytes", 2048, "maximum bytes returned per untrusted excerpt (1..8192)")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		os.Exit(2)
	}
	response, err := QueryHybrid(config)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	encode(response)
}

func runMaterializeFusionProfile(args []string) {
	flags := flag.NewFlagSet("materialize-fusion-profile", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	var corePath, storeRoot string
	flags.StringVar(&corePath, "core", "", "strict canonical FusionProfileCore JSON")
	flags.StringVar(&storeRoot, "store", "", "retrieval immutable CAS")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		os.Exit(2)
	}
	profile, profilePath, err := MaterializeFusionProfile(corePath, storeRoot)
	if err != nil {
		writeCommandError(err)
	}
	encode(struct {
		ProfileID            string `json:"profile_id"`
		ProfilePayloadSHA256 string `json:"profile_payload_sha256"`
		ProfilePath          string `json:"profile_path"`
		ProfileSHA256        string `json:"profile_document_sha256"`
	}{profile.ProfileID, profile.ProfilePayloadSHA256, profilePath, mustOutputFileHash(profilePath)})
}

func runMaterializeSituatingContext(args []string) {
	flags := flag.NewFlagSet("materialize-situating-context", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	var corePath, storeRoot string
	flags.StringVar(&corePath, "core", "", "strict canonical SituatingContextCore JSON")
	flags.StringVar(&storeRoot, "store", "", "retrieval immutable CAS")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		os.Exit(2)
	}
	context, contextPath, err := MaterializeSituatingContext(corePath, storeRoot)
	if err != nil {
		writeCommandError(err)
	}
	encode(struct {
		ContextID            string `json:"context_id"`
		ContextPayloadSHA256 string `json:"context_payload_sha256"`
		ContextPath          string `json:"context_path"`
		ContextSHA256        string `json:"context_document_sha256"`
	}{context.ContextID, context.ContextPayloadSHA256, contextPath, mustOutputFileHash(contextPath)})
}

func runMaterializeFineSpanPayload(args []string) {
	flags := flag.NewFlagSet("materialize-fine-span-payload", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	var rawStore, rawSHA256, evidenceStore string
	var rawSize, byteStart, byteEnd int64
	flags.StringVar(&rawStore, "raw-store", "", "knowledge-snapshot raw CAS holding the exact admitted source file")
	flags.StringVar(&rawSHA256, "raw-sha256", "", "whole-file SHA-256 of the admitted raw source object")
	flags.Int64Var(&rawSize, "raw-size", 0, "exact byte size of the admitted raw source object")
	flags.StringVar(&evidenceStore, "evidence-store", "", "knowledge-evidence normalized CAS to commit the sliced payload into")
	flags.Int64Var(&byteStart, "raw-byte-start", 0, "inclusive raw byte offset of the fine window")
	flags.Int64Var(&byteEnd, "raw-byte-end", 0, "exclusive raw byte offset of the fine window")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		os.Exit(2)
	}
	result, err := MaterializeFineSpanPayload(rawStore, rawSHA256, rawSize, evidenceStore, byteStart, byteEnd)
	if err != nil {
		writeCommandError(err)
	}
	encode(result)
}

func runMaterializeAdmissionPolicy(args []string) {
	flags := flag.NewFlagSet("materialize-admission-policy", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	var corePath, storeRoot string
	flags.StringVar(&corePath, "core", "", "strict canonical AdmissionPolicyCore JSON")
	flags.StringVar(&storeRoot, "store", "", "retrieval immutable CAS")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		os.Exit(2)
	}
	policy, policyPath, err := MaterializeAdmissionPolicy(corePath, storeRoot)
	if err != nil {
		writeCommandError(err)
	}
	encode(struct {
		PolicyID            string `json:"policy_id"`
		PolicyPayloadSHA256 string `json:"policy_payload_sha256"`
		PolicyPath          string `json:"policy_path"`
		PolicySHA256        string `json:"policy_document_sha256"`
	}{policy.PolicyID, policy.PolicyPayloadSHA256, policyPath, mustOutputFileHash(policyPath)})
}

func runMaterializeEvaluationSuite(args []string) {
	flags := flag.NewFlagSet("materialize-evaluation-suite", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	var corePath, storeRoot string
	flags.StringVar(&corePath, "core", "", "strict canonical RetrievalEvaluationSuiteCore JSON")
	flags.StringVar(&storeRoot, "store", "", "retrieval immutable CAS")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		os.Exit(2)
	}
	suite, suitePath, err := MaterializeEvaluationSuite(corePath, storeRoot)
	if err != nil {
		writeCommandError(err)
	}
	encode(struct {
		SuiteID            string `json:"suite_id"`
		SuitePayloadSHA256 string `json:"suite_payload_sha256"`
		SuitePath          string `json:"suite_path"`
		SuiteSHA256        string `json:"suite_document_sha256"`
	}{suite.SuiteID, suite.SuitePayloadSHA256, suitePath, mustOutputFileHash(suitePath)})
}

func runMaterializeEvaluationDefinition(args []string) {
	flags := flag.NewFlagSet("materialize-evaluation-definition", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	var corePath, storeRoot string
	flags.StringVar(&corePath, "core", "", "strict canonical RetrievalExpandedEvaluationDefinitionCore JSON")
	flags.StringVar(&storeRoot, "store", "", "retrieval immutable CAS")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		os.Exit(2)
	}
	definition, definitionPath, err := MaterializeExpandedEvaluationDefinition(corePath, storeRoot)
	if err != nil {
		writeCommandError(err)
	}
	encode(struct {
		DefinitionID            string `json:"definition_id"`
		DefinitionPayloadSHA256 string `json:"definition_payload_sha256"`
		DefinitionPath          string `json:"definition_path"`
		DefinitionSHA256        string `json:"definition_document_sha256"`
	}{definition.DefinitionID, definition.DefinitionPayloadSHA256, definitionPath, mustOutputFileHash(definitionPath)})
}

func runMaterializePairedFusionSuite(args []string) {
	flags := flag.NewFlagSet("materialize-paired-fusion-suite", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	var corePath, storeRoot string
	flags.StringVar(&corePath, "core", "", "strict canonical PairedFusionSuiteCore JSON")
	flags.StringVar(&storeRoot, "store", "", "retrieval immutable CAS")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		os.Exit(2)
	}
	suite, suitePath, err := MaterializePairedFusionSuite(corePath, storeRoot)
	if err != nil {
		writeCommandError(err)
	}
	encode(struct {
		SuiteID            string `json:"suite_id"`
		SuitePayloadSHA256 string `json:"suite_payload_sha256"`
		SuitePath          string `json:"suite_path"`
		SuiteSHA256        string `json:"suite_document_sha256"`
	}{suite.SuiteID, suite.SuitePayloadSHA256, suitePath, mustOutputFileHash(suitePath)})
}

func runPreparePairedFusionRun(args []string) {
	flags := flag.NewFlagSet("prepare-paired-fusion-run", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	config := PreparePairedFusionRunConfig{}
	flags.StringVar(&config.SuitePath, "suite", "", "strict canonical candidate-bound paired-fusion suite")
	flags.StringVar(&config.SuiteHash, "suite-sha256", "", "caller-pinned suite document SHA-256")
	flags.StringVar(&config.RetrievalStoreRoot, "retrieval-store", "", "retrieval candidate CAS")
	flags.StringVar(&config.SnapshotStoreRoot, "snapshot-store", "", "reviewed source snapshot CAS")
	flags.StringVar(&config.EvidenceStoreRoot, "evidence-store", "", "normalized evidence CAS")
	flags.StringVar(&config.QuerySignalStoreRoot, "query-signal-store", "", "candidate-bound query signal CAS")
	flags.StringVar(&config.BaselineScorerPath, "baseline-scorer", "", "exact baseline scorer executable")
	flags.StringVar(&config.BaselineScorerHash, "baseline-scorer-sha256", "", "caller-pinned baseline scorer executable SHA-256")
	flags.StringVar(&config.ChallengerScorerPath, "challenger-scorer", "", "exact challenger scorer executable")
	flags.StringVar(&config.ChallengerScorerHash, "challenger-scorer-sha256", "", "caller-pinned challenger scorer executable SHA-256")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		os.Exit(2)
	}
	plan, err := PreparePairedFusionRun(config)
	if err != nil {
		writeCommandError(err)
	}
	encode(plan)
}

func runMaterializeMultidomainEvaluationSuite(args []string) {
	flags := flag.NewFlagSet("materialize-multidomain-evaluation-suite", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	var corePath, storeRoot string
	flags.StringVar(&corePath, "core", "", "strict canonical MultidomainEvaluationSuiteCore JSON")
	flags.StringVar(&storeRoot, "store", "", "retrieval immutable CAS")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		os.Exit(2)
	}
	suite, suitePath, err := MaterializeMultidomainEvaluationSuite(corePath, storeRoot)
	if err != nil {
		writeCommandError(err)
	}
	encode(struct {
		SuiteID            string `json:"suite_id"`
		SuitePayloadSHA256 string `json:"suite_payload_sha256"`
		SuitePath          string `json:"suite_path"`
		SuiteSHA256        string `json:"suite_document_sha256"`
	}{suite.SuiteID, suite.SuitePayloadSHA256, suitePath, mustOutputFileHash(suitePath)})
}

func runEvaluateMultidomain(args []string) {
	flags := flag.NewFlagSet("evaluate-multidomain", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	config := EvaluateMultidomainConfig{}
	flags.StringVar(&config.SuitePath, "suite", "", "strict canonical multidomain evaluation suite")
	flags.StringVar(&config.SuiteHash, "suite-sha256", "", "caller-pinned suite document SHA-256")
	flags.StringVar(&config.StoreRoot, "store", "", "retrieval immutable CAS")
	flags.StringVar(&config.EvidenceStoreRoot, "evidence-store", "", "merged multi-authority normalized evidence CAS")
	flags.StringVar(&config.QuerySignalStoreRoot, "query-signal-store", "", "content-addressed query signal store")
	flags.StringVar(&config.LineageSetPath, "lineage-set", "", "per-authority admission lineage set")
	flags.StringVar(&config.AdmissionPolicyPath, "admission-policy", "", "current admission policy for the recheck")
	flags.StringVar(&config.AdmissionPolicyHash, "admission-policy-sha256", "", "caller-pinned admission policy document SHA-256")
	flags.StringVar(&config.RetrievalExecutablePath, "retrieval-executable", "", "exact in-process retrieval executable")
	flags.StringVar(&config.RetrievalExecutableHash, "retrieval-executable-sha256", "", "caller-pinned retrieval executable SHA-256")
	flags.StringVar(&config.EvaluatorExecutablePath, "evaluator-executable", "", "exact running evaluator executable")
	flags.StringVar(&config.EvaluatorExecutableHash, "evaluator-executable-sha256", "", "caller-pinned evaluator executable SHA-256")
	flags.StringVar(&config.EvaluatorAllowedSignersPath, "evaluator-allowed-signers", "", "external evaluator SSH trust root")
	flags.StringVar(&config.EvaluatorActor, "evaluator-actor", "", "authorized evaluator SSH principal")
	flags.StringVar(&config.EvaluatorKeyID, "evaluator-key-id", "", "authorized evaluator Ed25519 key fingerprint")
	flags.StringVar(&config.EvaluatorPrivateKeyPath, "evaluator-private-key", "", "optional out-of-tree Ed25519 key that signs a passing receipt")
	flags.StringVar(&config.AsOf, "as-of", "", "admission recheck time; must equal the suite frozen time")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		os.Exit(2)
	}
	result, err := EvaluateMultidomainRetrieval(config)
	if err != nil {
		writeCommandError(err)
	}
	encode(struct {
		State         string                     `json:"state"`
		Promotable    bool                       `json:"promotable"`
		Executable    bool                       `json:"execution_authorized"`
		Gates         MultidomainEvaluationGates `json:"gates"`
		MetricsPath   string                     `json:"metrics_path"`
		ReceiptID     string                     `json:"receipt_id,omitempty"`
		ReceiptSHA256 string                     `json:"receipt_document_sha256,omitempty"`
		ReceiptPath   string                     `json:"receipt_path,omitempty"`
		SignaturePath string                     `json:"signature_path,omitempty"`
	}{
		State: result.State, Promotable: false, Executable: false, Gates: result.Gates,
		MetricsPath: result.MetricsPath,
		ReceiptID:   receiptIDOrEmpty(result), ReceiptSHA256: receiptHashOrEmpty(result),
		ReceiptPath: result.ReceiptPath, SignaturePath: result.SignaturePath,
	})
}

func receiptIDOrEmpty(result EvaluateMultidomainResult) string {
	if result.Receipt == nil {
		return ""
	}
	return result.Receipt.ReceiptID
}

func receiptHashOrEmpty(result EvaluateMultidomainResult) string {
	if result.ReceiptPath == "" {
		return ""
	}
	return mustOutputFileHash(result.ReceiptPath)
}

func runVerifyMultidomainReceipt(args []string) {
	flags := flag.NewFlagSet("verify-multidomain-receipt", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	var receiptPath, receiptHash, signaturePath, signatureHash, allowedSignersPath string
	flags.StringVar(&receiptPath, "receipt", "", "multidomain evaluation receipt")
	flags.StringVar(&receiptHash, "receipt-sha256", "", "caller-pinned receipt document SHA-256")
	flags.StringVar(&signaturePath, "signature", "", "detached SSHSIG over the receipt bytes")
	flags.StringVar(&signatureHash, "signature-sha256", "", "caller-pinned signature SHA-256")
	flags.StringVar(&allowedSignersPath, "evaluator-allowed-signers", "", "external evaluator SSH trust root")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		os.Exit(2)
	}
	receipt, err := VerifyMultidomainReceipt(receiptPath, receiptHash, signaturePath, signatureHash, allowedSignersPath)
	if err != nil {
		writeCommandError(err)
	}
	encode(struct {
		Verified            bool   `json:"verified"`
		ReceiptID           string `json:"receipt_id"`
		State               string `json:"state"`
		Promotable          bool   `json:"promotable"`
		ExecutionAuthorized bool   `json:"execution_authorized"`
		Actor               string `json:"actor"`
		KeyID               string `json:"key_id"`
	}{true, receipt.ReceiptID, receipt.State, receipt.Promotable, receipt.ExecutionAuthorized, receipt.Authorization.Actor, receipt.Authorization.KeyID})
}

func runMaterializeEvaluationFreeze(args []string) {
	flags := flag.NewFlagSet("materialize-evaluation-freeze", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	var corePath, sourceRoot, storeRoot string
	flags.StringVar(&corePath, "core", "", "strict canonical scorer-blind evaluation freeze core")
	flags.StringVar(&sourceRoot, "source-root", "", "content-addressed pinned official source store")
	flags.StringVar(&storeRoot, "store", "", "retrieval immutable CAS")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		os.Exit(2)
	}
	freeze, freezePath, err := MaterializeScorerBlindEvaluationFreeze(corePath, sourceRoot, storeRoot)
	if err != nil {
		writeCommandError(err)
	}
	encode(struct {
		FreezeID            string `json:"freeze_id"`
		FreezePayloadSHA256 string `json:"freeze_payload_sha256"`
		FreezePath          string `json:"freeze_path"`
		FreezeSHA256        string `json:"freeze_document_sha256"`
	}{freeze.FreezeID, freeze.FreezePayloadSHA256, freezePath, mustOutputFileHash(freezePath)})
}

func runMaterializeBindingRequirements(args []string) {
	flags := flag.NewFlagSet("materialize-binding-requirements", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	var corePath, freezePath, freezeHash, sourceRoot, storeRoot string
	flags.StringVar(&corePath, "core", "", "strict canonical multidomain binding-requirements core")
	flags.StringVar(&freezePath, "freeze", "", "exact scorer-blind multidomain freeze")
	flags.StringVar(&freezeHash, "freeze-sha256", "", "caller-pinned whole-document SHA-256 of the freeze")
	flags.StringVar(&sourceRoot, "source-root", "", "root containing the freeze's exact source blobs")
	flags.StringVar(&storeRoot, "store", "", "immutable binding-requirements CAS")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		os.Exit(2)
	}
	manifest, manifestPath, err := MaterializeMultidomainBindingRequirements(corePath, freezePath, freezeHash, sourceRoot, storeRoot)
	if err != nil {
		writeCommandError(err)
	}
	encode(struct {
		ManifestID          string `json:"manifest_id"`
		ManifestSHA256      string `json:"manifest_document_sha256"`
		ManifestPath        string `json:"manifest_path"`
		State               string `json:"state"`
		ExecutionState      string `json:"execution_state"`
		ExecutionAuthorized bool   `json:"execution_authorized"`
		GapCount            int    `json:"gap_count"`
	}{
		ManifestID:          manifest.ManifestID,
		ManifestSHA256:      mustOutputFileHash(manifestPath),
		ManifestPath:        manifestPath,
		State:               manifest.State,
		ExecutionState:      manifest.ExecutionState,
		ExecutionAuthorized: manifest.ExecutionAuthorized,
		GapCount:            manifest.GapCount,
	})
}

func runMaterializeBindingClosure(args []string) {
	flags := flag.NewFlagSet("materialize-binding-closure", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	var corePath, freezePath, freezeHash, sourceRoot, storeRoot, admittedPath, evaluationTime, sharedCorpusPath string
	flags.StringVar(&corePath, "core", "", "strict canonical multidomain binding-requirements core")
	flags.StringVar(&freezePath, "freeze", "", "exact scorer-blind multidomain freeze")
	flags.StringVar(&freezeHash, "freeze-sha256", "", "caller-pinned whole-document SHA-256 of the freeze")
	flags.StringVar(&sourceRoot, "source-root", "", "root containing the freeze's exact source blobs")
	flags.StringVar(&storeRoot, "store", "", "immutable binding-closure CAS")
	flags.StringVar(&admittedPath, "admitted-artifacts", "", "strict canonical per-authority admitted artifact references")
	flags.StringVar(&evaluationTime, "evaluation-time", "", "optional canonical RFC3339 UTC admission evaluation time")
	flags.StringVar(&sharedCorpusPath, "shared-corpus-artifacts", "", "optional strict canonical shared-corpus/comparison/evaluation-case artifact references")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		os.Exit(2)
	}
	manifest, manifestPath, err := MaterializeMultidomainBindingClosure(corePath, freezePath, freezeHash, sourceRoot, storeRoot, admittedPath, evaluationTime, sharedCorpusPath)
	if err != nil {
		writeCommandError(err)
	}
	encode(struct {
		ManifestID           string `json:"manifest_id"`
		ManifestSHA256       string `json:"manifest_document_sha256"`
		ManifestPath         string `json:"manifest_path"`
		SupersedesManifestID string `json:"supersedes_manifest_id"`
		State                string `json:"state"`
		ExecutionState       string `json:"execution_state"`
		ExecutionAuthorized  bool   `json:"execution_authorized"`
		GapCount             int    `json:"gap_count"`
		ClosedGapCount       int    `json:"closed_gap_count"`
		BlockingGapCount     int    `json:"blocking_gap_count"`
	}{
		ManifestID:           manifest.ManifestID,
		ManifestSHA256:       mustOutputFileHash(manifestPath),
		ManifestPath:         manifestPath,
		SupersedesManifestID: manifest.SupersedesManifestID,
		State:                manifest.State,
		ExecutionState:       manifest.ExecutionState,
		ExecutionAuthorized:  manifest.ExecutionAuthorized,
		GapCount:             manifest.GapCount,
		ClosedGapCount:       manifest.ClosedGapCount,
		BlockingGapCount:     manifest.BlockingGapCount,
	})
}

func runEvaluateRetrieval(args []string) {
	flags := flag.NewFlagSet("evaluate", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	config := EvaluateRetrievalConfig{}
	flags.StringVar(&config.SuitePath, "suite", "", "strict canonical frozen held-out suite")
	flags.StringVar(&config.SuiteHash, "suite-sha256", "", "caller-pinned suite document SHA-256")
	flags.StringVar(&config.LexicalCandidatePath, "lexical-candidate", "", "exact lexical candidate")
	flags.StringVar(&config.LexicalCandidateHash, "lexical-candidate-sha256", "", "caller-pinned lexical candidate document SHA-256")
	flags.StringVar(&config.HybridCandidatePath, "hybrid-candidate", "", "exact hybrid candidate")
	flags.StringVar(&config.HybridCandidateHash, "hybrid-candidate-sha256", "", "caller-pinned hybrid candidate document SHA-256")
	flags.StringVar(&config.StoreRoot, "store", "", "retrieval immutable CAS")
	flags.StringVar(&config.EvidenceStoreRoot, "evidence-store", "", "knowledge-evidence normalized CAS")
	flags.StringVar(&config.QuerySignalStoreRoot, "query-signal-store", "", "content-addressed query signal store")
	flags.StringVar(&config.AdmissionPolicyPath, "admission-policy", "", "current admission policy")
	flags.StringVar(&config.AdmissionPolicyHash, "admission-policy-sha256", "", "caller-pinned admission policy document SHA-256")
	flags.StringVar(&config.RetrievalExecutablePath, "retrieval-executable", "", "exact in-process retrieval executable")
	flags.StringVar(&config.RetrievalExecutableHash, "retrieval-executable-sha256", "", "caller-pinned retrieval executable SHA-256")
	flags.StringVar(&config.EvaluatorExecutablePath, "evaluator-executable", "", "exact running evaluator executable")
	flags.StringVar(&config.EvaluatorExecutableHash, "evaluator-executable-sha256", "", "caller-pinned evaluator executable SHA-256")
	flags.StringVar(&config.EvaluatorAllowedSignersPath, "evaluator-allowed-signers", "", "external evaluator SSH trust root")
	flags.StringVar(&config.EvaluatorActor, "evaluator-actor", "", "authorized evaluator SSH principal")
	flags.StringVar(&config.EvaluatorKeyID, "evaluator-key-id", "", "authorized evaluator Ed25519 key fingerprint")
	flags.StringVar(&config.BaseGenerationPath, "base-generation", "", "optional whole verified base generation")
	flags.StringVar(&config.BaseGenerationHash, "base-generation-sha256", "", "optional caller-pinned base generation document SHA-256")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		os.Exit(2)
	}
	result, err := EvaluateRetrieval(config)
	if err != nil {
		writeCommandError(err)
	}
	receiptID := ""
	receiptHash := ""
	if result.QualityReceipt != nil {
		receiptID = result.QualityReceipt.ReceiptID
		receiptHash = mustOutputFileHash(result.QualityReceiptPath)
	}
	encode(struct {
		State                    string `json:"state"`
		MetricsID                string `json:"metrics_id"`
		MetricsPath              string `json:"metrics_path"`
		MetricsSHA256            string `json:"metrics_document_sha256"`
		RuntimeID                string `json:"runtime_id"`
		RuntimePath              string `json:"runtime_path"`
		RuntimeSHA256            string `json:"runtime_document_sha256"`
		QualityReportID          string `json:"quality_report_id"`
		QualityReportPath        string `json:"quality_report_path"`
		QualityReportSHA256      string `json:"quality_report_document_sha256"`
		UnsignedQualityReceiptID string `json:"unsigned_quality_receipt_id,omitempty"`
		UnsignedReceiptPath      string `json:"unsigned_quality_receipt_path,omitempty"`
		UnsignedReceiptSHA256    string `json:"unsigned_quality_receipt_document_sha256,omitempty"`
	}{result.Metrics.State, result.Metrics.MetricsID, result.MetricsPath, mustOutputFileHash(result.MetricsPath), result.Runtime.RuntimeID, result.RuntimePath, mustOutputFileHash(result.RuntimePath), result.QualityReport.ReportID, result.QualityReportPath, mustOutputFileHash(result.QualityReportPath), receiptID, result.QualityReceiptPath, receiptHash})
}

func mustOutputFileHash(filePath string) string {
	data, err := os.ReadFile(filePath) // #nosec G304 -- Path comes from this command's generated output manifest/report result under the operator-selected store.
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	return digestBytes(data)
}

func runStageGeneration(args []string) {
	flags := flag.NewFlagSet("stage-generation", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	config := StageGenerationConfig{}
	flags.StringVar(&config.HybridCandidatePath, "hybrid-candidate", "", "exact hybrid candidate manifest")
	flags.StringVar(&config.HybridCandidateHash, "hybrid-candidate-sha256", "", "caller-pinned hybrid candidate document SHA-256")
	flags.StringVar(&config.StoreRoot, "store", "", "retrieval CAS")
	flags.StringVar(&config.QualityReportPath, "quality-report", "", "canonical held-out quality report")
	flags.StringVar(&config.QualityReportHash, "quality-report-sha256", "", "caller-pinned quality report document SHA-256")
	flags.StringVar(&config.QualityReceiptPath, "quality-receipt", "", "canonical evaluator receipt binding the exact report")
	flags.StringVar(&config.QualityReceiptHash, "quality-receipt-sha256", "", "caller-pinned evaluator receipt document SHA-256")
	flags.StringVar(&config.QualitySignaturePath, "quality-signature", "", "detached Ed25519 SSHSIG over the evaluator receipt")
	flags.StringVar(&config.QualitySignatureHash, "quality-signature-sha256", "", "caller-pinned evaluator SSHSIG SHA-256")
	flags.StringVar(&config.EvaluatorAllowedSignersPath, "evaluator-allowed-signers", "", "external evaluator allowed_signers trust root")
	flags.StringVar(&config.EvaluationDatasetPath, "evaluation-dataset", "", "exact frozen evaluation suite")
	flags.StringVar(&config.EvaluationDatasetHash, "evaluation-dataset-sha256", "", "caller-pinned evaluation suite document SHA-256")
	flags.StringVar(&config.EvaluationMetricsPath, "evaluation-metrics", "", "exact evaluator-recomputed metrics")
	flags.StringVar(&config.EvaluationMetricsHash, "evaluation-metrics-sha256", "", "caller-pinned evaluation metrics document SHA-256")
	flags.StringVar(&config.EvaluationRuntimePath, "evaluation-runtime", "", "exact evaluator runtime manifest")
	flags.StringVar(&config.EvaluationRuntimeHash, "evaluation-runtime-sha256", "", "caller-pinned evaluation runtime document SHA-256")
	flags.StringVar(&config.AdmissionPolicyPath, "admission-policy", "", "current public ACL, deletion and freshness policy")
	flags.StringVar(&config.AdmissionPolicyHash, "admission-policy-sha256", "", "caller-pinned admission policy document SHA-256")
	flags.StringVar(&config.RetrievalExecutablePath, "retrieval-executable", "", "exact retrieval executable evaluated by the report")
	flags.StringVar(&config.RetrievalExecutableHash, "retrieval-executable-sha256", "", "caller-pinned executable SHA-256")
	flags.StringVar(&config.EvaluatorExecutablePath, "evaluator-executable", "", "exact evaluator executable that produced the report")
	flags.StringVar(&config.EvaluatorExecutableHash, "evaluator-executable-sha256", "", "caller-pinned evaluator executable SHA-256")
	flags.StringVar(&config.BaseGenerationPath, "base-generation", "", "optional whole verified base generation")
	flags.StringVar(&config.BaseGenerationHash, "base-generation-sha256", "", "optional caller-pinned base generation document SHA-256")
	flags.StringVar(&config.AsOf, "as-of", "", "explicit canonical UTC generation time")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		os.Exit(2)
	}
	result, err := StageGeneration(config)
	if err != nil {
		writeCommandError(err)
	}
	encode(struct {
		State            string `json:"state"`
		Promotable       bool   `json:"promotable"`
		GenerationID     string `json:"generation_id"`
		GenerationPath   string `json:"generation_path"`
		GenerationSHA256 string `json:"generation_document_sha256"`
		Reranking        bool   `json:"reranking_evaluated"`
	}{"candidate", result.Generation.Promotable, result.Generation.GenerationID, result.GenerationPath, mustDocumentHash(result.Generation), result.Generation.RerankingEvaluated})
}

func runPreparePromotion(args []string) {
	flags := flag.NewFlagSet("prepare-promotion", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	config := PreparePromotionConfig{}
	flags.StringVar(&config.GenerationPath, "generation", "", "exact evaluated retrieval generation")
	flags.StringVar(&config.GenerationHash, "generation-sha256", "", "caller-pinned generation document SHA-256")
	flags.StringVar(&config.StoreRoot, "store", "", "retrieval CAS")
	flags.StringVar(&config.StateRoot, "state", "", "retrieval generation state root")
	flags.StringVar(&config.AdmissionPolicyPath, "admission-policy", "", "current admission policy")
	flags.StringVar(&config.AdmissionPolicyHash, "admission-policy-sha256", "", "caller-pinned admission policy document SHA-256")
	flags.StringVar(&config.AllowedSignersPath, "allowed-signers", "", "external SSH allowed_signers trust root")
	flags.StringVar(&config.Actor, "actor", "", "authorized SSH principal")
	flags.StringVar(&config.KeyID, "key-id", "", "authorized Ed25519 SSH fingerprint")
	flags.StringVar(&config.TransitionedAt, "transitioned-at", "", "explicit canonical UTC transition time")
	flags.BoolVar(&config.Bootstrap, "bootstrap", false, "prepare the first generation")
	flags.StringVar(&config.ExpectPointerID, "expect-pointer", "", "current pointer CAS identity")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		os.Exit(2)
	}
	intent, err := PrepareGenerationPromotion(config)
	if err != nil {
		writeCommandError(err)
	}
	writeCanonicalOutput(intent)
}

func runPrepareRollback(args []string) {
	flags := flag.NewFlagSet("prepare-rollback", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	config := PrepareRollbackConfig{}
	flags.StringVar(&config.StoreRoot, "store", "", "retrieval CAS")
	flags.StringVar(&config.StateRoot, "state", "", "retrieval generation state root")
	flags.StringVar(&config.AdmissionPolicyPath, "admission-policy", "", "current admission policy")
	flags.StringVar(&config.AdmissionPolicyHash, "admission-policy-sha256", "", "caller-pinned admission policy document SHA-256")
	flags.StringVar(&config.AllowedSignersPath, "allowed-signers", "", "external SSH allowed_signers trust root")
	flags.StringVar(&config.Actor, "actor", "", "authorized SSH principal")
	flags.StringVar(&config.KeyID, "key-id", "", "authorized Ed25519 SSH fingerprint")
	flags.StringVar(&config.TransitionedAt, "transitioned-at", "", "explicit canonical UTC transition time")
	flags.StringVar(&config.ExpectPointerID, "expect-pointer", "", "current pointer CAS identity")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		os.Exit(2)
	}
	intent, err := PrepareGenerationRollback(config)
	if err != nil {
		writeCommandError(err)
	}
	writeCanonicalOutput(intent)
}

func runApplyTransition(args []string) {
	flags := flag.NewFlagSet("apply-transition", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	config := ApplyTransitionConfig{}
	flags.StringVar(&config.StoreRoot, "store", "", "retrieval CAS")
	flags.StringVar(&config.StateRoot, "state", "", "retrieval generation state root")
	flags.StringVar(&config.IntentPath, "intent", "", "exact canonical transition intent")
	flags.StringVar(&config.IntentHash, "intent-sha256", "", "caller-pinned intent document SHA-256")
	flags.StringVar(&config.SignaturePath, "signature", "", "detached Ed25519 SSHSIG over the exact intent")
	flags.StringVar(&config.SignatureHash, "signature-sha256", "", "caller-pinned SSHSIG SHA-256")
	flags.StringVar(&config.AllowedSignersPath, "allowed-signers", "", "external SSH allowed_signers trust root")
	flags.StringVar(&config.AdmissionPolicyPath, "admission-policy", "", "current admission policy")
	flags.StringVar(&config.AdmissionPolicyHash, "admission-policy-sha256", "", "caller-pinned admission policy document SHA-256")
	flags.StringVar(&config.GenerationPath, "generation", "", "exact evaluated generation for promotion only")
	flags.StringVar(&config.GenerationHash, "generation-sha256", "", "caller-pinned generation document SHA-256")
	flags.StringVar(&config.ExpectedDecision, "decision", "", "promoted or rolled_back")
	flags.StringVar(&config.Failpoint, "failpoint", "", "test-only crash injection point")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		os.Exit(2)
	}
	result, err := ApplyGenerationTransition(config)
	if err != nil {
		writeCommandError(err)
	}
	encode(result)
}

func runGenerationStatus(args []string) {
	flags := flag.NewFlagSet("generation-status", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	config := GenerationStatusConfig{}
	flags.StringVar(&config.StoreRoot, "store", "", "retrieval CAS")
	flags.StringVar(&config.StateRoot, "state", "", "retrieval generation state root")
	flags.StringVar(&config.AdmissionPolicyPath, "admission-policy", "", "current admission policy")
	flags.StringVar(&config.AdmissionPolicyHash, "admission-policy-sha256", "", "caller-pinned admission policy document SHA-256")
	flags.StringVar(&config.AsOf, "as-of", "", "explicit canonical UTC verification time")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		os.Exit(2)
	}
	encode(GetGenerationStatus(config))
}

func mustDocumentHash(value any) string {
	hash, _, err := documentSHA256(value)
	if err != nil {
		panic(err)
	}
	return hash
}

func writeCommandError(err error) {
	var lifecycle *LifecycleError
	if errors.As(err, &lifecycle) {
		encodeTo(os.Stderr, struct {
			State string `json:"state"`
			Code  string `json:"error_code"`
			Error string `json:"error"`
		}{"error", lifecycle.Code, lifecycle.Message})
	} else {
		fmt.Fprintln(os.Stderr, err)
	}
	os.Exit(2)
}

func encodeTo(file *os.File, value any) {
	encoder := json.NewEncoder(file)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	_ = encoder.Encode(value)
}

func writeCanonicalOutput(value any) {
	data, err := marshalDocument(value)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if _, err := os.Stdout.Write(data); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}

func encode(value any) {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}
