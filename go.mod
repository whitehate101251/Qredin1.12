// Qredin identity and authorization platform.
//
// NOTE: dependency versions below are pinned starting points. Run `go mod tidy`
// once before the first build; see docs/BUILD.md. Every dependency added here
// must be justified in docs/adr/ and pass the supply-chain gates in §15.4 of
// the production plan (SBOM, vulnerability scan, provenance).
module github.com/qredin/qredin

go 1.25.0

require (
	github.com/aws/aws-sdk-go-v2/service/kms v1.35.3
	github.com/jackc/pgx/v5 v5.11.0
	google.golang.org/grpc v1.85.0-dev
	google.golang.org/protobuf v1.36.12
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/aws/aws-sdk-go-v2 v1.30.3 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.3.15 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.6.15 // indirect
	github.com/aws/smithy-go v1.20.3 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/rogpeppe/go-internal v1.16.0 // indirect
	golang.org/x/net v0.57.0 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.40.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260706201446-f0a921348800 // indirect
)
