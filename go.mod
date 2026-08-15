module github.com/grokify/threat-model-spec

go 1.26.1

require (
	github.com/ProductBuildersHQ/specification-workflow-spec v0.0.0-00010101000000-000000000000
	github.com/gorilla/websocket v1.5.3
	github.com/invopop/jsonschema v0.14.0
	github.com/plexusone/structured-evaluation v0.13.0
	github.com/plexusone/w3pilot v0.9.0
	github.com/spf13/cobra v1.10.2
)

require gopkg.in/yaml.v3 v3.0.1

require (
	github.com/ProductBuildersHQ/pdlc v0.0.0-00010101000000-000000000000
	github.com/ProductBuildersHQ/productbuildershq-frameworks v0.0.0-00010101000000-000000000000 // indirect
	github.com/bahlo/generic-list-go v0.2.0 // indirect
	github.com/buger/jsonparser v1.6.1 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/pb33f/ordered-map/v2 v2.3.1 // indirect
	github.com/spf13/pflag v1.0.10 // indirect
	go.yaml.in/yaml/v4 v4.0.0-rc.6 // indirect
)

replace github.com/ProductBuildersHQ/pdlc => ../../ProductBuildersHQ/pdlc

replace github.com/ProductBuildersHQ/specification-workflow-spec => ../../ProductBuildersHQ/specification-workflow-spec

replace github.com/ProductBuildersHQ/productbuildershq-frameworks => ../../ProductBuildersHQ/productbuildershq-frameworks
