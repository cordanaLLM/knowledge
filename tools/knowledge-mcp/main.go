package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	configuration, err := loadConfig(os.Args[1:], os.Getenv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: configuration error: %v\n", serverName, err)
		os.Exit(2)
	}
	if configuration.showVersion {
		fmt.Fprintf(os.Stderr, "%s %s\n", serverName, serverVersion)
		return
	}
	if configuration.compileManifest != "" {
		receipt, compileErr := compileRegistryProjection(configuration.compileManifest, configuration.compileOutput, configuration.maxRegistrySize)
		if compileErr != nil {
			fmt.Fprintf(os.Stderr, "%s: projection compilation failed: %v\n", serverName, compileErr)
			os.Exit(1)
		}
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetEscapeHTML(false)
		if err := encoder.Encode(receipt); err != nil {
			fmt.Fprintf(os.Stderr, "%s: encode projection receipt: %v\n", serverName, err)
			os.Exit(1)
		}
		return
	}

	if configuration.publishPack != "" {
		receipt, packErr := packPublishBundle(configuration)
		if packErr != nil {
			fmt.Fprintf(os.Stderr, "%s: bundle packing failed: %v\n", serverName, packErr)
			os.Exit(1)
		}
		emitPublishRecord(receipt)
		return
	}
	if configuration.publishMaterialize != "" {
		status, publishErr := materializePublishBundle(configuration)
		if publishErr != nil {
			// Fail closed without taking the broker down: the store is removed,
			// so registry_status keeps reporting a typed backend_unavailable
			// while knowledge_search stays available.
			fmt.Fprintf(os.Stderr, "%s: publication failed, generation store left unpublished: %v\n", serverName, publishErr)
			if configuration.publishStrict {
				os.Exit(1)
			}
			return
		}
		emitPublishRecord(status)
		return
	}

	// Protocol stdout must contain JSON-RPC frames only.  All diagnostics go to
	// stderr, including startup degradation of an optional registry backend.
	logger := log.New(os.Stderr, serverName+": ", log.LstdFlags|log.LUTC)
	knowledge := buildKnowledgeIndex(configuration.repositoryRoot)
	registry := newRegistryProvider(configuration)
	retrieval := newRetrievalProvider(configuration)
	service := newToolService(knowledge, registry, retrieval)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go service.watchKnowledge(ctx, configuration.repositoryRoot, configuration.repositoryRefreshInterval, logger)
	if configuration.httpBind != "" {
		// Bounded to SIGINT/SIGTERM so in-flight sessions drain on Pod
		// termination instead of being cut mid-response.
		if err := serveHTTPTransport(ctx, service, configuration, slog.New(slog.NewTextHandler(os.Stderr, nil))); err != nil {
			logger.Printf("http transport stopped: %v", err)
			os.Exit(1)
		}
		return
	}
	if configuration.sdkTransport {
		if err := serveSDK(ctx, service); err != nil {
			logger.Printf("protocol stopped: %v", err)
			os.Exit(1)
		}
		return
	}
	if err := newProtocolServer(service, logger).serve(os.Stdin, os.Stdout); err != nil {
		logger.Printf("protocol stopped: %v", err)
		os.Exit(1)
	}
}
