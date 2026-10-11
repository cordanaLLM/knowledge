package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"
)

// The merged repository plus live-SBOM candidate is currently larger than
// 128 MiB.  Keep a hard ceiling, but make the default large enough to read the
// real candidate without requiring an unsafe unbounded read.
const defaultMaxRegistryBytes int64 = 512 << 20

type config struct {
	repositoryRoot               string
	registryPath                 string
	projectionPath               string
	stateDirectory               string
	allowedSigners               string
	retrievalExecutable          string
	retrievalExecutableHash      string
	retrievalStore               string
	retrievalState               string
	retrievalEvidenceStore       string
	retrievalAdmissionPolicy     string
	retrievalAdmissionPolicyHash string
	retrievalCatalog             string
	retrievalCatalogHash         string
	compileManifest              string
	compileOutput                string
	httpBind                     string
	httpTokenFile                string
	repositoryRefreshInterval    time.Duration
	publishPack                  string
	publishRetrieval             string
	publishOutput                string
	publishMaterialize           string
	publishSHA256                string
	publishTarget                string
	publishTrustSource           string
	maxRegistrySize              int64
	showVersion                  bool
	sdkTransport                 bool
	publishStrict                bool
}

func loadConfig(arguments []string, getenv func(string) string) (config, error) {
	values := config{
		repositoryRoot:               getenv("ARCHEION_KNOWLEDGE_ROOT"),
		registryPath:                 getenv("ARCHEION_KNOWLEDGE_REGISTRY"),
		projectionPath:               getenv("ARCHEION_KNOWLEDGE_PROJECTION"),
		stateDirectory:               getenv("ARCHEION_KNOWLEDGE_STATE_DIR"),
		allowedSigners:               getenv("ARCHEION_KNOWLEDGE_ALLOWED_SIGNERS"),
		retrievalExecutable:          getenv("ARCHEION_RETRIEVAL_EXECUTABLE"),
		retrievalExecutableHash:      getenv("ARCHEION_RETRIEVAL_EXECUTABLE_SHA256"),
		retrievalStore:               getenv("ARCHEION_RETRIEVAL_STORE"),
		retrievalState:               getenv("ARCHEION_RETRIEVAL_STATE"),
		retrievalEvidenceStore:       getenv("ARCHEION_RETRIEVAL_EVIDENCE_STORE"),
		retrievalAdmissionPolicy:     getenv("ARCHEION_RETRIEVAL_ADMISSION_POLICY"),
		retrievalAdmissionPolicyHash: getenv("ARCHEION_RETRIEVAL_ADMISSION_POLICY_SHA256"),
		retrievalCatalog:             getenv("ARCHEION_RETRIEVAL_CATALOG"),
		retrievalCatalogHash:         getenv("ARCHEION_RETRIEVAL_CATALOG_SHA256"),
		httpBind:                     getenv("ARCHEION_KNOWLEDGE_HTTP_BIND"),
		httpTokenFile:                getenv("ARCHEION_KNOWLEDGE_HTTP_TOKEN_FILE"),
		repositoryRefreshInterval:    defaultKnowledgeRefreshInterval,
		maxRegistrySize:              defaultMaxRegistryBytes,
	}
	set := flag.NewFlagSet(serverName, flag.ContinueOnError)
	set.SetOutput(os.Stderr)
	set.StringVar(&values.repositoryRoot, "repository-root", values.repositoryRoot, "Git worktree containing local knowledge")
	set.StringVar(&values.registryPath, "registry", values.registryPath, "immutable discovery manifest JSON (candidate mode)")
	set.StringVar(&values.projectionPath, "projection", values.projectionPath, "immutable compact registry projection SQLite file (candidate mode)")
	set.StringVar(&values.stateDirectory, "state-dir", values.stateDirectory, "signed generation-store directory (preferred)")
	set.StringVar(&values.allowedSigners, "allowed-signers", values.allowedSigners, "external read-only operator trust root for --state-dir")
	set.StringVar(&values.retrievalExecutable, "retrieval-executable", values.retrievalExecutable, "exact read-only knowledge-retrieval executable")
	set.StringVar(&values.retrievalExecutableHash, "retrieval-executable-sha256", values.retrievalExecutableHash, "operator-pinned SHA-256 of --retrieval-executable")
	set.StringVar(&values.retrievalStore, "retrieval-store", values.retrievalStore, "evaluated retrieval generation CAS")
	set.StringVar(&values.retrievalState, "retrieval-state", values.retrievalState, "signed retrieval generation pointer state root")
	set.StringVar(&values.retrievalEvidenceStore, "retrieval-evidence-store", values.retrievalEvidenceStore, "immutable normalized evidence CAS")
	set.StringVar(&values.retrievalAdmissionPolicy, "retrieval-admission-policy", values.retrievalAdmissionPolicy, "current public retrieval admission policy")
	set.StringVar(&values.retrievalAdmissionPolicyHash, "retrieval-admission-policy-sha256", values.retrievalAdmissionPolicyHash, "operator-pinned whole-document SHA-256 of the admission policy")
	set.StringVar(&values.retrievalCatalog, "retrieval-catalog", values.retrievalCatalog, "immutable multi-source signed-current retrieval lane catalog")
	set.StringVar(&values.retrievalCatalogHash, "retrieval-catalog-sha256", values.retrievalCatalogHash, "operator-pinned whole-document SHA-256 of --retrieval-catalog")
	set.StringVar(&values.compileManifest, "compile-projection", "", "validate this candidate manifest and compile a compact projection")
	set.StringVar(&values.compileOutput, "projection-output", "", "immutable SQLite output for --compile-projection")
	set.StringVar(&values.publishPack, "publish-pack", "", "verify this signed generation store and pack it into a publication bundle")
	set.StringVar(&values.publishRetrieval, "publish-retrieval", "", "retrieval federation tree to pack alongside --publish-pack")
	set.StringVar(&values.publishOutput, "publish-output", "", "deterministic bundle tar output for --publish-pack")
	set.StringVar(&values.publishMaterialize, "publish-materialize", "", "publication bundle path or http(s) URL to verify and place")
	set.StringVar(&values.publishSHA256, "publish-sha256", "", "operator-pinned SHA-256 of --publish-materialize")
	set.StringVar(&values.publishTarget, "publish-target", "", "directory that receives the verified state/, trust/ and retrieval/ trees")
	set.StringVar(&values.publishTrustSource, "publish-trust-source", "", "allowed-signers file copied into <target>/trust as a plain read-only regular file")
	set.BoolVar(&values.publishStrict, "publish-strict", false, "exit non-zero when materialization fails instead of leaving the broker to report a typed degraded state")
	set.Int64Var(&values.maxRegistrySize, "max-registry-bytes", values.maxRegistrySize, "maximum bytes accepted for one registry object")
	set.BoolVar(&values.showVersion, "version", false, "print version on stderr and exit")
	set.BoolVar(&values.sdkTransport, "mcp-sdk", values.sdkTransport, "serve over the official MCP Go SDK stdio transport instead of the hand-rolled JSON-RPC loop")
	set.StringVar(&values.httpBind, "http-bind", values.httpBind, "serve authenticated Streamable HTTP on this host:port instead of stdio (off when empty)")
	set.StringVar(&values.httpTokenFile, "http-token-file", values.httpTokenFile, "file holding the bearer token for --http-bind (mounted Secret; never the token value itself)")
	set.DurationVar(&values.repositoryRefreshInterval, "repository-refresh-interval", values.repositoryRefreshInterval, "poll interval for atomically refreshing a rotated repository generation")
	if err := set.Parse(arguments); err != nil {
		return config{}, err
	}
	if set.NArg() != 0 {
		return config{}, fmt.Errorf("unexpected positional arguments: %v", set.Args())
	}
	configuredInputs := 0
	for _, value := range []string{values.registryPath, values.projectionPath, values.stateDirectory} {
		if value != "" {
			configuredInputs++
		}
	}
	if configuredInputs > 1 {
		return config{}, errors.New("--registry, --projection and --state-dir are mutually exclusive")
	}
	if values.stateDirectory != "" && values.allowedSigners == "" {
		return config{}, errors.New("--state-dir requires an external --allowed-signers trust root")
	}
	if values.stateDirectory == "" && values.allowedSigners != "" && values.publishPack == "" {
		return config{}, errors.New("--allowed-signers is valid only with --state-dir or --publish-pack")
	}
	if getenv("ARCHEION_RETRIEVAL_CANDIDATE") != "" || getenv("ARCHEION_RETRIEVAL_CANDIDATE_SHA256") != "" {
		return config{}, errors.New("direct retrieval candidate configuration is unsupported; configure the signed current retrieval state")
	}
	// The token value must arrive on disk from a mounted Secret. Accepting it
	// inline would put the credential in the process environment and in every
	// image or manifest that sets it.
	if getenv("ARCHEION_KNOWLEDGE_HTTP_TOKEN") != "" {
		return config{}, errors.New("inline HTTP bearer tokens are unsupported; mount the token as a file and set --http-token-file")
	}
	retrievalValues := []*string{
		&values.retrievalExecutable,
		&values.retrievalExecutableHash,
		&values.retrievalStore,
		&values.retrievalState,
		&values.retrievalEvidenceStore,
		&values.retrievalAdmissionPolicy,
		&values.retrievalAdmissionPolicyHash,
	}
	retrievalConfigured := 0
	for _, value := range retrievalValues {
		if *value != "" {
			retrievalConfigured++
		}
	}
	if retrievalConfigured != 0 && retrievalConfigured != len(retrievalValues) {
		return config{}, errors.New("retrieval requires executable, executable SHA-256, store, signed state root, evidence store, admission policy and admission-policy SHA-256 together")
	}
	if retrievalConfigured != 0 && (!validSHA256Hex(values.retrievalExecutableHash) || !validSHA256Hex(values.retrievalAdmissionPolicyHash)) {
		return config{}, errors.New("retrieval SHA-256 pins must be 64 lowercase hexadecimal characters")
	}
	catalogConfigured := 0
	for _, value := range []string{values.retrievalCatalog, values.retrievalCatalogHash} {
		if value != "" {
			catalogConfigured++
		}
	}
	if catalogConfigured == 1 {
		return config{}, errors.New("retrieval federation requires catalog and catalog SHA-256 together")
	}
	if catalogConfigured != 0 && !validSHA256Hex(values.retrievalCatalogHash) {
		return config{}, errors.New("retrieval catalog SHA-256 pin must be 64 lowercase hexadecimal characters")
	}
	if catalogConfigured != 0 && retrievalConfigured != 0 {
		return config{}, errors.New("retrieval catalog and single-lane retrieval configuration are mutually exclusive")
	}
	anyRetrievalConfigured := retrievalConfigured != 0 || catalogConfigured != 0
	if (values.compileManifest == "") != (values.compileOutput == "") {
		return config{}, errors.New("--compile-projection and --projection-output must be provided together")
	}
	if values.compileManifest != "" && (configuredInputs != 0 || anyRetrievalConfigured) {
		return config{}, errors.New("projection compilation cannot be combined with serving inputs")
	}
	if values.compileManifest != "" && values.sdkTransport {
		return config{}, errors.New("projection compilation cannot be combined with --mcp-sdk serving")
	}
	if values.compileManifest != "" && values.httpBind != "" {
		return config{}, errors.New("projection compilation cannot be combined with --http-bind serving")
	}
	if values.httpBind != "" && values.sdkTransport {
		return config{}, errors.New("--http-bind and --mcp-sdk select different transports; choose one")
	}
	if values.httpBind != "" && values.httpTokenFile == "" {
		return config{}, errors.New("--http-bind requires --http-token-file; the broker will not serve HTTP unauthenticated")
	}
	if values.httpBind == "" && values.httpTokenFile != "" {
		return config{}, errors.New("--http-token-file is valid only with --http-bind")
	}
	if values.httpBind != "" {
		if _, _, splitErr := net.SplitHostPort(values.httpBind); splitErr != nil {
			return config{}, fmt.Errorf("--http-bind must be host:port: %w", splitErr)
		}
		absoluteToken, absErr := filepath.Abs(values.httpTokenFile)
		if absErr != nil {
			return config{}, fmt.Errorf("resolve HTTP token file: %w", absErr)
		}
		values.httpTokenFile = filepath.Clean(absoluteToken)
	}
	publishing, err := validatePublishConfig(&values, configuredInputs)
	if err != nil {
		return config{}, err
	}
	// Publish modes never serve, so they do not need a repository root; the
	// initContainer runs before the broker's Git worktree is guaranteed usable.
	if publishing {
		return values, nil
	}
	if values.maxRegistrySize < 1<<20 || values.maxRegistrySize > 1<<30 {
		return config{}, errors.New("--max-registry-bytes must be between 1 MiB and 1 GiB")
	}
	if values.repositoryRefreshInterval < time.Second || values.repositoryRefreshInterval > time.Hour {
		return config{}, errors.New("--repository-refresh-interval must be between 1s and 1h")
	}
	if values.repositoryRoot == "" {
		discovered, err := discoverRepositoryRoot("")
		if err != nil {
			return config{}, fmt.Errorf("find repository root: %w", err)
		}
		values.repositoryRoot = discovered
	}
	absolute, err := filepath.Abs(values.repositoryRoot)
	if err != nil {
		return config{}, fmt.Errorf("resolve repository root: %w", err)
	}
	values.repositoryRoot = filepath.Clean(absolute)
	if info, err := os.Stat(values.repositoryRoot); err != nil || !info.IsDir() {
		return config{}, fmt.Errorf("repository root is not a readable directory: %s", values.repositoryRoot)
	}
	if values.registryPath != "" {
		values.registryPath, err = filepath.Abs(values.registryPath)
		if err != nil {
			return config{}, fmt.Errorf("resolve registry path: %w", err)
		}
	}
	if values.projectionPath != "" {
		values.projectionPath, err = filepath.Abs(values.projectionPath)
		if err != nil {
			return config{}, fmt.Errorf("resolve projection path: %w", err)
		}
	}
	if values.stateDirectory != "" {
		values.stateDirectory, err = filepath.Abs(values.stateDirectory)
		if err != nil {
			return config{}, fmt.Errorf("resolve state directory: %w", err)
		}
		values.allowedSigners, err = filepath.Abs(values.allowedSigners)
		if err != nil {
			return config{}, fmt.Errorf("resolve allowed-signers trust root: %w", err)
		}
	}
	if retrievalConfigured != 0 {
		for label, target := range map[string]*string{
			"retrieval executable":       &values.retrievalExecutable,
			"retrieval store":            &values.retrievalStore,
			"retrieval state":            &values.retrievalState,
			"retrieval evidence store":   &values.retrievalEvidenceStore,
			"retrieval admission policy": &values.retrievalAdmissionPolicy,
		} {
			*target, err = filepath.Abs(*target)
			if err != nil {
				return config{}, fmt.Errorf("resolve %s: %w", label, err)
			}
			*target = filepath.Clean(*target)
		}
	}
	if catalogConfigured != 0 {
		values.retrievalCatalog, err = filepath.Abs(values.retrievalCatalog)
		if err != nil {
			return config{}, fmt.Errorf("resolve retrieval catalog: %w", err)
		}
		values.retrievalCatalog = filepath.Clean(values.retrievalCatalog)
	}
	if values.compileManifest != "" {
		values.compileManifest, err = filepath.Abs(values.compileManifest)
		if err != nil {
			return config{}, fmt.Errorf("resolve projection input: %w", err)
		}
		values.compileOutput, err = filepath.Abs(values.compileOutput)
		if err != nil {
			return config{}, fmt.Errorf("resolve projection output: %w", err)
		}
	}
	return values, nil
}

func stringTrimSpace(value string) string {
	start, end := 0, len(value)
	for start < end && (value[start] == ' ' || value[start] == '\t' || value[start] == '\r' || value[start] == '\n') {
		start++
	}
	for end > start && (value[end-1] == ' ' || value[end-1] == '\t' || value[end-1] == '\r' || value[end-1] == '\n') {
		end--
	}
	return value[start:end]
}
