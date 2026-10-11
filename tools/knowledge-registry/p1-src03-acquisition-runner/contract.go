package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	apiOrigin            = "https://api.github.com"
	apiVersion           = "2026-03-10"
	workID               = "P1-SRC-03"
	canonicalProfile     = "registry_compact_utf8"
	maxJSONDepth         = 128
	maxJSONNodes         = 10_000_000
	maxObjectJSONBytes   = int64(4 * 1024 * 1024)
	maxResponseBytes     = int64(32 * 1024 * 1024)
	maxBlobBytes         = int64(1024 * 1024)
	maxHTTPRequests      = 128
	expectedHTTPRequests = 36
	maxTokenBytes        = 4096
)

var (
	sha1Pattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
	tagPattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$`)
)

type authorityBoundary struct {
	SourceAdmission    bool `json:"source_admission"`
	RetrievalRelease   bool `json:"retrieval_release"`
	Signing            bool `json:"signing"`
	PointerMutation    bool `json:"pointer_mutation"`
	GitMutation        bool `json:"git_mutation"`
	ProductionMutation bool `json:"production_mutation"`
}

type publisher struct {
	PublisherID string `json:"publisher_id"`
	Name        string `json:"name"`
	URI         string `json:"uri"`
}

type sourceDenominator struct {
	FreezeID             string `json:"freeze_id"`
	FreezeDocumentSHA256 string `json:"freeze_document_sha256"`
	ComparisonOnly       bool   `json:"comparison_only"`
}

type acquisitionCapability struct {
	CapabilityID   string `json:"capability_id"`
	Transport      string `json:"transport"`
	APIOrigin      string `json:"api_origin"`
	APIVersion     string `json:"api_version"`
	ObjectFormat   string `json:"object_format"`
	SelectionMode  string `json:"selection_mode"`
	RedirectPolicy string `json:"redirect_policy"`
}

type contractBounds struct {
	Targets           int   `json:"targets"`
	Files             int   `json:"files"`
	LogicalBytes      int64 `json:"logical_bytes"`
	AnnotatedTagDepth int   `json:"annotated_tag_depth"`
	PathDepth         int   `json:"path_depth"`
	TreeEntries       int   `json:"tree_entries"`
	BlobBytes         int64 `json:"blob_bytes"`
	HTTPRequests      int   `json:"http_requests"`
	HTTPResponseBytes int64 `json:"http_response_bytes"`
	ObjectJSONBytes   int64 `json:"object_json_bytes"`
}

type expectedTagObject struct {
	SHA1       string `json:"sha1"`
	Name       string `json:"name"`
	TargetType string `json:"target_type"`
	TargetSHA1 string `json:"target_sha1"`
}

type pathBinding struct {
	ParentTreeSHA1 string `json:"parent_tree_sha1"`
	Segment        string `json:"segment"`
	ObjectType     string `json:"object_type"`
	Mode           string `json:"mode"`
	ObjectSHA1     string `json:"object_sha1"`
	Bytes          *int64 `json:"bytes,omitempty"`
}

type contractFile struct {
	SourceKey              string        `json:"source_key"`
	Path                   string        `json:"path"`
	Mode                   string        `json:"mode"`
	GitBlobSHA1            string        `json:"git_blob_sha1"`
	RawSHA256              string        `json:"raw_sha256"`
	Bytes                  int64         `json:"bytes"`
	ExpectedPathResolution []pathBinding `json:"expected_path_resolution"`
}

type contractTargetCore struct {
	AuthorityID          string              `json:"authority_id"`
	SourceSetID          string              `json:"source_set_id"`
	ComponentID          string              `json:"component_id"`
	ComponentVersion     string              `json:"component_version"`
	Repository           string              `json:"repository"`
	Publisher            publisher           `json:"publisher"`
	LicenseExpression    string              `json:"license_expression"`
	RequestedTag         string              `json:"requested_tag"`
	ExpectedRefType      string              `json:"expected_ref_object_type"`
	ExpectedRefSHA1      string              `json:"expected_ref_object_sha1"`
	ExpectedTagObjects   []expectedTagObject `json:"expected_annotated_tag_objects"`
	ExpectedCommitSHA1   string              `json:"expected_commit_sha1"`
	ExpectedRootTreeSHA1 string              `json:"expected_root_tree_sha1"`
	Files                []contractFile      `json:"files"`
}

type contractTarget struct {
	TargetID string `json:"target_id"`
	contractTargetCore
}

type contractCore struct {
	Schema                string                `json:"$schema"`
	SchemaVersion         string                `json:"schema_version"`
	Canonicalization      string                `json:"canonicalization"`
	ContractKind          string                `json:"contract_kind"`
	WorkID                string                `json:"work_id"`
	AuthorityState        string                `json:"authority_state"`
	ReviewState           string                `json:"review_state"`
	CompileEligible       bool                  `json:"compile_eligible"`
	PromoteEligible       bool                  `json:"promote_eligible"`
	AuthorityBoundary     authorityBoundary     `json:"authority_boundary"`
	SourceDenominator     sourceDenominator     `json:"source_denominator"`
	AcquisitionCapability acquisitionCapability `json:"acquisition_capability"`
	ExecutionGate         executionGate         `json:"execution_gate"`
	Bounds                contractBounds        `json:"bounds"`
	Targets               []contractTarget      `json:"targets"`
}

type acquisitionContract struct {
	ContractID            string `json:"contract_id"`
	ContractPayloadSHA256 string `json:"contract_payload_sha256"`
	contractCore
}

func treePathBinding(parent, segment, object string) pathBinding {
	return pathBinding{ParentTreeSHA1: parent, Segment: segment, ObjectType: "tree", Mode: "040000", ObjectSHA1: object}
}

func blobPathBinding(parent, segment, object string, size int64) pathBinding {
	return pathBinding{ParentTreeSHA1: parent, Segment: segment, ObjectType: "blob", Mode: "100644", ObjectSHA1: object, Bytes: &size}
}

func exactPathResolutions() map[string][]pathBinding {
	return map[string][]pathBinding{
		"cilium-cluster-pool": {
			treePathBinding("c1eb66441175c3a427cbdaf130cc7a56805fec3b", "Documentation", "765085a029cc25534240ac175a2778b5bb7466c9"),
			treePathBinding("765085a029cc25534240ac175a2778b5bb7466c9", "network", "51207960d523a50a7eb33fdf94add15ab8e8a6f9"),
			treePathBinding("51207960d523a50a7eb33fdf94add15ab8e8a6f9", "concepts", "4acc5c218be2b85fbeff4b5a40ab9286d4019890"),
			treePathBinding("4acc5c218be2b85fbeff4b5a40ab9286d4019890", "ipam", "5dcbd48784a4c1d1c05bb34a364e994f6535cedc"),
			blobPathBinding("5dcbd48784a4c1d1c05bb34a364e994f6535cedc", "cluster-pool.rst", "78dbb979308fd434f6f8a1e4282b3ac2f75d5d57", 2940),
		},
		"cilium-kubeproxy-free": {
			treePathBinding("c1eb66441175c3a427cbdaf130cc7a56805fec3b", "Documentation", "765085a029cc25534240ac175a2778b5bb7466c9"),
			treePathBinding("765085a029cc25534240ac175a2778b5bb7466c9", "network", "51207960d523a50a7eb33fdf94add15ab8e8a6f9"),
			treePathBinding("51207960d523a50a7eb33fdf94add15ab8e8a6f9", "kubernetes", "1df9c970c98871454fa4d10951a5fcf2bd5f99cd"),
			blobPathBinding("1df9c970c98871454fa4d10951a5fcf2bd5f99cd", "kubeproxy-free.rst", "98fbccde3c8a318245e9f86d3c7eb80d5700094c", 83126),
		},
		"go-context": {
			treePathBinding("0bb2fb1cc06c334c36a2a92d2f0b07fea7236d74", "src", "5b5be418172013f981e03ea346adef4e2f264f31"),
			treePathBinding("5b5be418172013f981e03ea346adef4e2f264f31", "context", "1ed5875a31d9dde0466d2c83e4d62910b7e3b3d5"),
			blobPathBinding("1ed5875a31d9dde0466d2c83e4d62910b7e3b3d5", "context.go", "d00ac67e38296573d20520dbd7aceb2fd1a52906", 25036),
		},
		"go-sync-once": {
			treePathBinding("0bb2fb1cc06c334c36a2a92d2f0b07fea7236d74", "src", "5b5be418172013f981e03ea346adef4e2f264f31"),
			treePathBinding("5b5be418172013f981e03ea346adef4e2f264f31", "sync", "4f1af64e6e62fccbeba1923ef332816ce84c4ae3"),
			blobPathBinding("4f1af64e6e62fccbeba1923ef332816ce84c4ae3", "once.go", "7c9ad8dd1aa10d095cb4273b5bd4c4c6dc342316", 2525),
		},
		"kubernetes-core-types": {
			treePathBinding("40e7f58817b42fdaecc67f4148bca38396b7abb7", "pkg", "58d23f5ecbaa257bbe7ae54d731a5ee6e8e8ef37"),
			treePathBinding("58d23f5ecbaa257bbe7ae54d731a5ee6e8e8ef37", "apis", "0252ec8fdeec1b8be9938b7c52a6c874ba8bf7e5"),
			treePathBinding("0252ec8fdeec1b8be9938b7c52a6c874ba8bf7e5", "core", "6321889f8ddccf068c3858b7830fdb2d12960088"),
			blobPathBinding("6321889f8ddccf068c3858b7830fdb2d12960088", "types.go", "ed0bb0ea8782b4f33c364c7e10adc1903982bee5", 312618),
		},
		"kubernetes-meta-types": {
			treePathBinding("40e7f58817b42fdaecc67f4148bca38396b7abb7", "staging", "1ad50228a031eea5cac662b8eaf416f5b65cc33d"),
			treePathBinding("1ad50228a031eea5cac662b8eaf416f5b65cc33d", "src", "83f375ac1ae88acf58f4f6f169ad014402dfe8b4"),
			treePathBinding("83f375ac1ae88acf58f4f6f169ad014402dfe8b4", "k8s.io", "0787c67a92dd6e9a699df141a25664df4fd19175"),
			treePathBinding("0787c67a92dd6e9a699df141a25664df4fd19175", "apimachinery", "64183f9fb9e929fd62a4f604959494f43700e020"),
			treePathBinding("64183f9fb9e929fd62a4f604959494f43700e020", "pkg", "6b602e88026131bea810bce1c946b6d4661e572e"),
			treePathBinding("6b602e88026131bea810bce1c946b6d4661e572e", "apis", "e1ae2301a10bee773bd127ad4dfafc783d03a396"),
			treePathBinding("e1ae2301a10bee773bd127ad4dfafc783d03a396", "meta", "265257352ab6c7caf842e021a46e9fd690b832a8"),
			treePathBinding("265257352ab6c7caf842e021a46e9fd690b832a8", "v1", "29dd53e244c7dfde00905b9c40e627428a4624e0"),
			blobPathBinding("29dd53e244c7dfde00905b9c40e627428a4624e0", "types.go", "c8b87f20c8e1869a1163b711c32180412f63ed7d", 85969),
		},
	}
}

func exactContractCore() (contractCore, error) {
	execution, err := exactExecutionGateBinding()
	if err != nil {
		return contractCore{}, err
	}
	cores := []contractTargetCore{
		{
			AuthorityID: "retrieval-source-authority:cilium:v1.19.5", SourceSetID: "source-acquisition-set:p1-src-03:cilium:v1.19.5", ComponentID: "cilium", ComponentVersion: "v1.19.5", Repository: "cilium/cilium",
			Publisher: publisher{PublisherID: "publisher:github:cilium", Name: "Cilium", URI: "https://github.com/cilium"}, LicenseExpression: "Apache-2.0", RequestedTag: "v1.19.5", ExpectedRefType: "tag", ExpectedRefSHA1: "3ca3059f6aaed3f5901aa7732c4a1c8c9f9551db",
			ExpectedTagObjects: []expectedTagObject{{SHA1: "3ca3059f6aaed3f5901aa7732c4a1c8c9f9551db", Name: "v1.19.5", TargetType: "commit", TargetSHA1: "20eaccfef029cb046d70219717fb6dbbdf27a59f"}},
			ExpectedCommitSHA1: "20eaccfef029cb046d70219717fb6dbbdf27a59f", ExpectedRootTreeSHA1: "c1eb66441175c3a427cbdaf130cc7a56805fec3b",
			Files: []contractFile{
				{SourceKey: "cilium-cluster-pool", Path: "Documentation/network/concepts/ipam/cluster-pool.rst", Mode: "100644", GitBlobSHA1: "78dbb979308fd434f6f8a1e4282b3ac2f75d5d57", RawSHA256: "sha256:f5f3bd8f0a0b9c64d59a44cd73f8e494a7366f2661c5d81bba5dc38e71864e1e", Bytes: 2940},
				{SourceKey: "cilium-kubeproxy-free", Path: "Documentation/network/kubernetes/kubeproxy-free.rst", Mode: "100644", GitBlobSHA1: "98fbccde3c8a318245e9f86d3c7eb80d5700094c", RawSHA256: "sha256:478fe8d36a774f4e3d4e73789168f94b6469a473fe10b17cd7f3752ec42eb30e", Bytes: 83126},
			},
		},
		{
			AuthorityID: "retrieval-source-authority:go:go1.26.5", SourceSetID: "source-acquisition-set:p1-src-03:go:go1.26.5", ComponentID: "go", ComponentVersion: "go1.26.5", Repository: "golang/go",
			Publisher: publisher{PublisherID: "publisher:github:golang", Name: "The Go Authors", URI: "https://github.com/golang"}, LicenseExpression: "BSD-3-Clause", RequestedTag: "go1.26.5", ExpectedRefType: "commit", ExpectedRefSHA1: "c19862e5f8415b4f24b189d065ed739517c548ba", ExpectedTagObjects: []expectedTagObject{},
			ExpectedCommitSHA1: "c19862e5f8415b4f24b189d065ed739517c548ba", ExpectedRootTreeSHA1: "0bb2fb1cc06c334c36a2a92d2f0b07fea7236d74",
			Files: []contractFile{
				{SourceKey: "go-context", Path: "src/context/context.go", Mode: "100644", GitBlobSHA1: "d00ac67e38296573d20520dbd7aceb2fd1a52906", RawSHA256: "sha256:765f99f7cc0710b0117ffa183e432524f429c21496fcbad9b63fb9886fdbaac7", Bytes: 25036},
				{SourceKey: "go-sync-once", Path: "src/sync/once.go", Mode: "100644", GitBlobSHA1: "7c9ad8dd1aa10d095cb4273b5bd4c4c6dc342316", RawSHA256: "sha256:3bc00bab32acd134ddf50c87fdbd1dd70502f224b7684a801a077dfe0a05eb3f", Bytes: 2525},
			},
		},
		{
			AuthorityID: "retrieval-source-authority:kubernetes:v1.36.2", SourceSetID: "source-acquisition-set:p1-src-03:kubernetes:v1.36.2", ComponentID: "kubernetes", ComponentVersion: "v1.36.2", Repository: "kubernetes/kubernetes",
			Publisher: publisher{PublisherID: "publisher:github:kubernetes", Name: "Kubernetes", URI: "https://github.com/kubernetes"}, LicenseExpression: "Apache-2.0", RequestedTag: "v1.36.2", ExpectedRefType: "tag", ExpectedRefSHA1: "5ecab45c278646c9134b656fee70e891da51d0cb",
			ExpectedTagObjects: []expectedTagObject{{SHA1: "5ecab45c278646c9134b656fee70e891da51d0cb", Name: "v1.36.2", TargetType: "commit", TargetSHA1: "24e2b02af5543d7910c2bb074c7264df5a8f0467"}},
			ExpectedCommitSHA1: "24e2b02af5543d7910c2bb074c7264df5a8f0467", ExpectedRootTreeSHA1: "40e7f58817b42fdaecc67f4148bca38396b7abb7",
			Files: []contractFile{
				{SourceKey: "kubernetes-core-types", Path: "pkg/apis/core/types.go", Mode: "100644", GitBlobSHA1: "ed0bb0ea8782b4f33c364c7e10adc1903982bee5", RawSHA256: "sha256:598aae11c7c8bea62e52d4d7d9270a6252d3d436d1176e898ac43b0215daa69b", Bytes: 312618},
				{SourceKey: "kubernetes-meta-types", Path: "staging/src/k8s.io/apimachinery/pkg/apis/meta/v1/types.go", Mode: "100644", GitBlobSHA1: "c8b87f20c8e1869a1163b711c32180412f63ed7d", RawSHA256: "sha256:8941618dff976f6c56746095b8ab5d01ea60f91043455bf6f18d4939e5d505aa", Bytes: 85969},
			},
		},
	}
	pathResolutions := exactPathResolutions()
	for targetIndex := range cores {
		for fileIndex := range cores[targetIndex].Files {
			resolution, ok := pathResolutions[cores[targetIndex].Files[fileIndex].SourceKey]
			if !ok {
				return contractCore{}, errors.New("exact source path resolution is missing")
			}
			cores[targetIndex].Files[fileIndex].ExpectedPathResolution = resolution
		}
	}
	targets := make([]contractTarget, 0, len(cores))
	for _, core := range cores {
		raw, err := canonicalJSON(core)
		if err != nil {
			panic(err)
		}
		digest := sha256.Sum256(raw)
		targets = append(targets, contractTarget{TargetID: "source-acquisition-target:sha256:" + hex.EncodeToString(digest[:]), contractTargetCore: core})
	}
	return contractCore{
		Schema: "https://github.com/cordanaLLM/knowledge/schemas/registry/source-acquisition-contract-v2.schema.json", SchemaVersion: "2.0.0", Canonicalization: canonicalProfile, ContractKind: "p1_src03_exact_github_file_set_acquisition", WorkID: workID,
		AuthorityState: "non_authoritative", ReviewState: "implementation_frozen", CompileEligible: false, PromoteEligible: false, AuthorityBoundary: authorityBoundary{},
		SourceDenominator:     sourceDenominator{FreezeID: "retrieval-evaluation-freeze:sha256:a0fd2cb1067e0b92122e3478632831e8822b5b34f63fa841d3bf60aa65d2de1b", FreezeDocumentSHA256: "sha256:376761716b7b0fb4fec98e36dc8fe4b83838e40bcf4a156e1c8fcb482165bfa4", ComparisonOnly: true},
		AcquisitionCapability: acquisitionCapability{CapabilityID: "github-git-objects-rest-exact-file-v2", Transport: "https-json", APIOrigin: apiOrigin, APIVersion: apiVersion, ObjectFormat: "sha1", SelectionMode: "exact_paths_only", RedirectPolicy: "forbid"},
		ExecutionGate:         execution,
		Bounds:                contractBounds{Targets: 3, Files: 6, LogicalBytes: 512214, AnnotatedTagDepth: 2, PathDepth: 16, TreeEntries: 8192, BlobBytes: maxBlobBytes, HTTPRequests: maxHTTPRequests, HTTPResponseBytes: maxResponseBytes, ObjectJSONBytes: maxObjectJSONBytes}, Targets: targets,
	}, nil
}

func materializeContract(core contractCore) (acquisitionContract, []byte, error) {
	if err := validateContract(core); err != nil {
		return acquisitionContract{}, nil, err
	}
	payload, err := canonicalJSON(core)
	if err != nil {
		return acquisitionContract{}, nil, err
	}
	digest := sha256.Sum256(payload)
	payloadSHA := "sha256:" + hex.EncodeToString(digest[:])
	value := acquisitionContract{ContractID: "source-acquisition-contract:" + payloadSHA, ContractPayloadSHA256: payloadSHA, contractCore: core}
	document, err := documentJSON(value)
	if err != nil {
		return acquisitionContract{}, nil, err
	}
	return value, document, nil
}

func exactContract() (acquisitionContract, []byte, error) {
	core, err := exactContractCore()
	if err != nil {
		return acquisitionContract{}, nil, err
	}
	return materializeContract(core)
}

func validateContract(value contractCore) error {
	if value.Schema != "https://github.com/cordanaLLM/knowledge/schemas/registry/source-acquisition-contract-v2.schema.json" || value.SchemaVersion != "2.0.0" || value.Canonicalization != canonicalProfile || value.ContractKind != "p1_src03_exact_github_file_set_acquisition" || value.WorkID != workID {
		return errors.New("contract schema or work identity differs from P1-SRC-03")
	}
	if value.AuthorityState != "non_authoritative" || value.ReviewState != "implementation_frozen" || value.CompileEligible || value.PromoteEligible || value.AuthorityBoundary != (authorityBoundary{}) {
		return errors.New("contract authority state widened")
	}
	if value.SourceDenominator != (sourceDenominator{FreezeID: "retrieval-evaluation-freeze:sha256:a0fd2cb1067e0b92122e3478632831e8822b5b34f63fa841d3bf60aa65d2de1b", FreezeDocumentSHA256: "sha256:376761716b7b0fb4fec98e36dc8fe4b83838e40bcf4a156e1c8fcb482165bfa4", ComparisonOnly: true}) {
		return errors.New("contract source denominator changed or became authority")
	}
	wantCapability := acquisitionCapability{CapabilityID: "github-git-objects-rest-exact-file-v2", Transport: "https-json", APIOrigin: apiOrigin, APIVersion: apiVersion, ObjectFormat: "sha1", SelectionMode: "exact_paths_only", RedirectPolicy: "forbid"}
	if value.AcquisitionCapability != wantCapability {
		return errors.New("contract transport capability changed")
	}
	execution, err := exactExecutionGateBinding()
	if err != nil {
		return err
	}
	if value.ExecutionGate != execution {
		return errors.New("contract execution verifier gate changed or widened")
	}
	wantBounds := contractBounds{Targets: 3, Files: 6, LogicalBytes: 512214, AnnotatedTagDepth: 2, PathDepth: 16, TreeEntries: 8192, BlobBytes: maxBlobBytes, HTTPRequests: maxHTTPRequests, HTTPResponseBytes: maxResponseBytes, ObjectJSONBytes: maxObjectJSONBytes}
	if value.Bounds != wantBounds || len(value.Targets) != 3 {
		return errors.New("contract bounds or target cardinality changed")
	}
	seenAuthorities := map[string]struct{}{}
	seenSets := map[string]struct{}{}
	seenPublishers := map[string]struct{}{}
	seenFiles := map[string]struct{}{}
	var bytesTotal int64
	for _, target := range value.Targets {
		if _, ok := seenAuthorities[target.AuthorityID]; ok {
			return errors.New("contract aliases source authorities")
		}
		if _, ok := seenSets[target.SourceSetID]; ok {
			return errors.New("contract aliases source sets")
		}
		if _, ok := seenPublishers[target.Publisher.PublisherID]; ok {
			return errors.New("contract aliases publishers")
		}
		seenAuthorities[target.AuthorityID] = struct{}{}
		seenSets[target.SourceSetID] = struct{}{}
		seenPublishers[target.Publisher.PublisherID] = struct{}{}
		if len(target.Files) != 2 || !tagPattern.MatchString(target.RequestedTag) || !sha1Pattern.MatchString(target.ExpectedRefSHA1) || !sha1Pattern.MatchString(target.ExpectedCommitSHA1) || !sha1Pattern.MatchString(target.ExpectedRootTreeSHA1) {
			return errors.New("contract target identity or two-file scope is invalid")
		}
		for _, file := range target.Files {
			if err := validatePath(file.Path); err != nil {
				return err
			}
			if err := validateExpectedPathResolution(file, target.ExpectedRootTreeSHA1); err != nil {
				return err
			}
			key := target.Repository + ":" + file.Path
			if _, ok := seenFiles[key]; ok {
				return errors.New("contract duplicates a source path")
			}
			seenFiles[key] = struct{}{}
			if file.Mode != "100644" || !sha1Pattern.MatchString(file.GitBlobSHA1) || !validSHA256(file.RawSHA256) || file.Bytes < 0 || file.Bytes > maxBlobBytes {
				return errors.New("contract file identity is malformed")
			}
			bytesTotal += file.Bytes
		}
	}
	if len(seenFiles) != 6 || bytesTotal != 512214 {
		return errors.New("contract file count or byte denominator changed")
	}
	exact, err := exactContractCore()
	if err != nil {
		return err
	}
	expected := exact.Targets
	if !equalTargets(value.Targets, expected) {
		return errors.New("contract target denominator differs from the exact three authorities and six files")
	}
	return nil
}

func equalTargets(left, right []contractTarget) bool {
	leftRaw, leftErr := canonicalJSON(left)
	rightRaw, rightErr := canonicalJSON(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftRaw, rightRaw)
}

func validateExpectedPathResolution(file contractFile, rootTree string) error {
	segments := strings.Split(file.Path, "/")
	if len(file.ExpectedPathResolution) != len(segments) {
		return errors.New("contract path resolution cardinality differs from exact path")
	}
	current := rootTree
	seenTrees := map[string]struct{}{rootTree: {}}
	for index, binding := range file.ExpectedPathResolution {
		if binding.ParentTreeSHA1 != current || binding.Segment != segments[index] || !sha1Pattern.MatchString(binding.ObjectSHA1) {
			return errors.New("contract path resolution is disconnected or malformed")
		}
		last := index == len(segments)-1
		if !last {
			if binding.ObjectType != "tree" || binding.Mode != "040000" || binding.Bytes != nil {
				return errors.New("contract intermediate path binding is not an exact tree")
			}
			if _, exists := seenTrees[binding.ObjectSHA1]; exists {
				return errors.New("contract path resolution contains a tree cycle")
			}
			seenTrees[binding.ObjectSHA1] = struct{}{}
			current = binding.ObjectSHA1
			continue
		}
		if binding.ObjectType != "blob" || binding.Mode != file.Mode || binding.ObjectSHA1 != file.GitBlobSHA1 || binding.Bytes == nil || *binding.Bytes != file.Bytes {
			return errors.New("contract terminal path binding differs from exact blob")
		}
	}
	return nil
}

type runnerContract struct {
	APIOrigin              string   `json:"api_origin"`
	APIVersion             string   `json:"api_version"`
	CASCommit              string   `json:"cas_commit"`
	ContractValidation     string   `json:"contract_validation"`
	ExactContractID        string   `json:"exact_contract_id"`
	ExecutionManifestID    string   `json:"execution_manifest_id"`
	GitBlobIdentity        string   `json:"git_blob_identity"`
	HTTPResponseValidation string   `json:"http_response_validation"`
	OutputSchemas          []string `json:"output_schemas"`
	PathResolution         string   `json:"path_resolution"`
	RedirectPolicy         string   `json:"redirect_policy"`
	TagResolution          string   `json:"tag_resolution"`
}

func runnerContractDigest(contract acquisitionContract) (string, error) {
	core := runnerContract{APIOrigin: apiOrigin, APIVersion: apiVersion, CASCommit: "dirfd-anchored-private-single-link-fsync-direct-o-excl-no-delete-v3", ContractValidation: "strict-content-address-plus-exact-bytes-v2", ExactContractID: contract.ContractID, ExecutionManifestID: contract.ExecutionGate.ManifestID, GitBlobIdentity: "git-sha1-header-body-plus-raw-sha256-v1", HTTPResponseValidation: "strict-json-shared-vectors-single-content-type-identity-no-link-v2", OutputSchemas: []string{"source-acquisition-receipt-v2", "source-inventory-proposal-v2"}, PathResolution: "non-recursive-exact-segment-and-tree-chain-v2", RedirectPolicy: "forbid-before-send-v1", TagResolution: "exact-ref-object-and-annotated-chain-v1"}
	raw, err := canonicalJSON(core)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func validatePath(value string) error {
	if value == "" || len(value) > 4096 || strings.HasPrefix(value, "/") || strings.HasSuffix(value, "/") || !utf8.ValidString(value) {
		return errors.New("source path is empty, over-bound, or noncanonical")
	}
	segments := strings.Split(value, "/")
	if len(segments) > 16 {
		return errors.New("source path exceeds depth bound")
	}
	for _, segment := range segments {
		if segment == "" || segment == "." || segment == ".." || strings.ContainsAny(segment, "\x00\r\n") {
			return errors.New("source path has a noncanonical segment")
		}
	}
	return nil
}

func validSHA256(value string) bool {
	if len(value) != 71 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil && value == strings.ToLower(value)
}

func canonicalJSON(value any) ([]byte, error) {
	if err := validateCanonicalInput(reflect.ValueOf(value), 0, new(int), make(map[canonicalVisit]struct{})); err != nil {
		return nil, err
	}
	if normalized, generic, err := normalizeCanonicalInput(value); err != nil {
		return nil, err
	} else if generic {
		value = normalized
	}
	initial, err := marshalCanonicalJSON(value)
	if err != nil {
		return nil, err
	}
	normalized, err := parseStrictJSON(initial)
	if err != nil {
		return nil, err
	}
	return marshalCanonicalJSON(normalized)
}

type canonicalVisit struct {
	typeName string
	pointer  uintptr
}

func validateCanonicalInput(value reflect.Value, depth int, nodes *int, active map[canonicalVisit]struct{}) error {
	if !value.IsValid() {
		return nil
	}
	if depth > maxJSONDepth {
		return errors.New("canonical JSON input exceeds maximum depth")
	}
	*nodes++
	if *nodes > maxJSONNodes {
		return errors.New("canonical JSON input exceeds maximum node count")
	}
	if value.Kind() == reflect.Interface {
		if value.IsNil() {
			return nil
		}
		return validateCanonicalInput(value.Elem(), depth, nodes, active)
	}
	var visit canonicalVisit
	switch value.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Slice:
		if value.IsNil() {
			return nil
		}
		visit = canonicalVisit{typeName: value.Type().String(), pointer: value.Pointer()}
		if _, exists := active[visit]; exists {
			return errors.New("canonical JSON input contains a reference cycle")
		}
		active[visit] = struct{}{}
		defer delete(active, visit)
	}
	switch value.Kind() {
	case reflect.Bool:
		return nil
	case reflect.String:
		if !utf8.ValidString(value.String()) {
			return errors.New("canonical JSON input contains invalid UTF-8")
		}
		return nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		if value.Uint() > math.MaxInt64 {
			return errors.New("canonical JSON input contains an integer outside signed 64-bit range")
		}
		return nil
	case reflect.Float32, reflect.Float64:
		floating := value.Float()
		if math.IsInf(floating, 0) || math.IsNaN(floating) {
			return errors.New("canonical JSON input contains a non-finite number")
		}
		return nil
	case reflect.Pointer:
		return validateCanonicalInput(value.Elem(), depth+1, nodes, active)
	case reflect.Slice, reflect.Array:
		for index := 0; index < value.Len(); index++ {
			if err := validateCanonicalInput(value.Index(index), depth+1, nodes, active); err != nil {
				return err
			}
		}
		return nil
	case reflect.Map:
		if value.Type().Key().Kind() != reflect.String {
			return errors.New("canonical JSON input map keys are not strings")
		}
		iterator := value.MapRange()
		for iterator.Next() {
			if !utf8.ValidString(iterator.Key().String()) {
				return errors.New("canonical JSON input contains an invalid UTF-8 map key")
			}
			if err := validateCanonicalInput(iterator.Value(), depth+1, nodes, active); err != nil {
				return err
			}
		}
		return nil
	case reflect.Struct:
		for index := 0; index < value.NumField(); index++ {
			field := value.Type().Field(index)
			if (field.PkgPath != "" && !field.Anonymous) || field.Tag.Get("json") == "-" {
				continue
			}
			if err := validateCanonicalInput(value.Field(index), depth+1, nodes, active); err != nil {
				return err
			}
		}
		return nil
	default:
		return fmt.Errorf("canonical JSON input contains unsupported Go kind %s", value.Kind())
	}
}

func marshalCanonicalJSON(value any) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	raw := bytes.TrimSuffix(buffer.Bytes(), []byte{'\n'})
	return unescapeJSONLineSeparators(raw), nil
}

func unescapeJSONLineSeparators(raw []byte) []byte {
	result := make([]byte, 0, len(raw))
	for index := 0; index < len(raw); {
		if raw[index] != '\\' || index+1 >= len(raw) {
			result = append(result, raw[index])
			index++
			continue
		}
		if raw[index+1] == '\\' {
			result = append(result, raw[index], raw[index+1])
			index += 2
			continue
		}
		if index+5 < len(raw) && raw[index+1] == 'u' {
			switch string(raw[index+2 : index+6]) {
			case "2028":
				result = append(result, []byte("\u2028")...)
				index += 6
				continue
			case "2029":
				result = append(result, []byte("\u2029")...)
				index += 6
				continue
			}
		}
		result = append(result, raw[index], raw[index+1])
		index += 2
	}
	return result
}

func normalizeCanonicalInput(value any) (any, bool, error) {
	switch typed := value.(type) {
	case nil, bool, string:
		return typed, true, nil
	case json.Number:
		number, err := normalizeJSONNumber(typed)
		return number, true, err
	case float64:
		number, err := canonicalBinary64(typed)
		return number, true, err
	case float32:
		number, err := canonicalBinary64(float64(typed))
		return number, true, err
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return typed, true, nil
	case []any:
		result := make([]any, len(typed))
		for index, item := range typed {
			normalized, generic, err := normalizeCanonicalInput(item)
			if err != nil || !generic {
				return nil, generic, err
			}
			result[index] = normalized
		}
		return result, true, nil
	case map[string]any:
		result := make(map[string]any, len(typed))
		for key, item := range typed {
			normalized, generic, err := normalizeCanonicalInput(item)
			if err != nil || !generic {
				return nil, generic, err
			}
			result[key] = normalized
		}
		return result, true, nil
	default:
		return value, false, nil
	}
}

func documentJSON(value any) ([]byte, error) {
	raw, err := canonicalJSON(value)
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

func parseStrictJSON(raw []byte) (any, error) {
	if !utf8.Valid(raw) {
		return nil, errors.New("JSON is not valid UTF-8")
	}
	if err := validateEscapedUnicode(raw); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	nodes := 0
	value, err := parseJSONValue(decoder, 0, &nodes)
	if err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("JSON has trailing content")
		}
		return nil, fmt.Errorf("JSON trailing content: %w", err)
	}
	return value, nil
}

func parseJSONValue(decoder *json.Decoder, depth int, nodes *int) (any, error) {
	if depth > maxJSONDepth {
		return nil, errors.New("JSON exceeds maximum depth")
	}
	*nodes++
	if *nodes > maxJSONNodes {
		return nil, errors.New("JSON exceeds maximum node count")
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		switch value := token.(type) {
		case json.Number:
			normalized, err := normalizeJSONNumber(value)
			if err != nil {
				return nil, err
			}
			return normalized, nil
		case string:
			if !utf8.ValidString(value) {
				return nil, errors.New("JSON string is not valid UTF-8")
			}
		}
		return token, nil
	}
	switch delimiter {
	case '{':
		result := make(map[string]any)
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return nil, err
			}
			key, ok := keyToken.(string)
			if !ok {
				return nil, errors.New("JSON object key is not a string")
			}
			if _, exists := result[key]; exists {
				return nil, fmt.Errorf("JSON duplicate key: %s", key)
			}
			item, err := parseJSONValue(decoder, depth+1, nodes)
			if err != nil {
				return nil, err
			}
			result[key] = item
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return nil, errors.New("JSON object is not terminated")
		}
		return result, nil
	case '[':
		result := make([]any, 0)
		for decoder.More() {
			item, err := parseJSONValue(decoder, depth+1, nodes)
			if err != nil {
				return nil, err
			}
			result = append(result, item)
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return nil, errors.New("JSON array is not terminated")
		}
		return result, nil
	default:
		return nil, errors.New("unexpected JSON delimiter")
	}
}

func normalizeJSONNumber(value json.Number) (json.Number, error) {
	raw := value.String()
	if !strings.ContainsAny(raw, ".eE") {
		parsed, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			return "", errors.New("JSON integer is outside the signed 64-bit range")
		}
		if parsed == 0 {
			return json.Number("0"), nil
		}
		return value, nil
	}
	parsed, err := strconv.ParseFloat(raw, 64)
	if err != nil || math.IsInf(parsed, 0) || math.IsNaN(parsed) {
		return "", errors.New("JSON number is not finite binary64")
	}
	return canonicalBinary64(parsed)
}

func canonicalBinary64(value float64) (json.Number, error) {
	if math.IsInf(value, 0) || math.IsNaN(value) {
		return "", errors.New("JSON number is not finite binary64")
	}
	scientific := strconv.FormatFloat(value, 'e', -1, 64)
	exponentIndex := strings.LastIndexByte(scientific, 'e')
	exponent, err := strconv.Atoi(scientific[exponentIndex+1:])
	if err != nil {
		return "", errors.New("JSON binary64 exponent is invalid")
	}
	raw := scientific
	if exponent >= -4 && exponent < 16 {
		raw = strconv.FormatFloat(value, 'f', -1, 64)
	}
	if !strings.ContainsAny(raw, ".eE") {
		raw += ".0"
	}
	return json.Number(raw), nil
}

func validateEscapedUnicode(raw []byte) error {
	inside := false
	for index := 0; index < len(raw); index++ {
		switch raw[index] {
		case '"':
			inside = !inside
		case '\\':
			if !inside || index+1 >= len(raw) {
				continue
			}
			index++
			if raw[index] != 'u' || index+4 >= len(raw) {
				continue
			}
			value, ok := parseHexQuad(raw[index+1 : index+5])
			if !ok {
				continue
			}
			index += 4
			if value >= 0xdc00 && value <= 0xdfff {
				return errors.New("JSON string contains an unpaired low surrogate")
			}
			if value < 0xd800 || value > 0xdbff {
				continue
			}
			if index+6 >= len(raw) || raw[index+1] != '\\' || raw[index+2] != 'u' {
				return errors.New("JSON string contains an unpaired high surrogate")
			}
			low, ok := parseHexQuad(raw[index+3 : index+7])
			if !ok || low < 0xdc00 || low > 0xdfff {
				return errors.New("JSON string contains an unpaired high surrogate")
			}
			index += 6
		}
	}
	return nil
}

func parseHexQuad(raw []byte) (uint16, bool) {
	if len(raw) != 4 {
		return 0, false
	}
	var result uint16
	for _, character := range raw {
		result <<= 4
		switch {
		case character >= '0' && character <= '9':
			result |= uint16(character - '0')
		case character >= 'a' && character <= 'f':
			result |= uint16(character-'a') + 10
		case character >= 'A' && character <= 'F':
			result |= uint16(character-'A') + 10
		default:
			return 0, false
		}
	}
	return result, true
}

func sortedKeys(values map[string]struct{}) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
