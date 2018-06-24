package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cheekybits/is"
)

func TestExtractVersion(t *testing.T) {
	data := map[string]interface{}{
		"app": map[string]interface{}{
			"metadata": map[string]interface{}{
				"go_version": "go1.10.3",
				"foo":        []string{"a", "b", "c"},
			},
		},
	}

	t.Run("normal case", func(t *testing.T) {
		is := is.New(t)
		version, err := extractPageVersion(data, "app.metadata.go_version")
		is.NoErr(err)
		is.Equal(version, "go1.10.3")
	})

	t.Run("key not found", func(t *testing.T) {
		is := is.New(t)
		_, err := extractPageVersion(data, "app.metadata.bar")
		is.Err(err)
		is.Equal(err, errNotFound)
	})

	t.Run("key not a string", func(t *testing.T) {
		is := is.New(t)
		_, err := extractPageVersion(data, "app.metadata.foo")
		is.Err(err)
		is.Equal(err, errNotString)
	})
}

func TestFetchGoVersion(t *testing.T) {
	is := is.New(t)
	hler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("go1.10.3"))
	})

	s := httptest.NewServer(hler)
	defer s.Close()

	version, err := fetchGoVersion(s.URL)
	is.NoErr(err)
	is.Equal(version, "go1.10.3")
}
