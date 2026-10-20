// Example service module.
module github.com/acme/service

go 1.22.3

toolchain go1.22.5

godebug default=go1.21

require github.com/google/uuid v1.6.0

require (
	github.com/gin-gonic/gin v1.10.0
	github.com/BurntSushi/toml v1.4.0 // pinned: config format
	golang.org/x/net v0.0.0-20240416194518-5c4b8b1b7bcd // indirect
	github.com/docker/docker v26.1.3+incompatible
	"gopkg.in/yaml.v3" v3.0.1
	github.com/bytedance/sonic v1.11.6 // indirect; via gin
	`github.com/pelletier/go-toml/v2` v2.2.2 //indirect
)

// A second require block (go mod tidy writes direct and indirect apart).
require (
	github.com/stretchr/testify v1.9.0
	golang.org/x/sys v0.20.0 // indirect
)

exclude github.com/gin-gonic/gin v1.9.0

retract (
	v1.0.1 // published by mistake
	[v1.1.0, v1.1.5]
)

tool golang.org/x/tools/cmd/stringer
