package loader

import (
	"testing"

	"github.com/Overclock-Validator/mithril/pkg/sbpf"
	"github.com/stretchr/testify/assert"
)

func TestSymbolHash_Entrypoint(t *testing.T) {
	assert.Equal(t, sbpf.EntrypointHash, sbpf.SymbolHash("entrypoint"))
}
