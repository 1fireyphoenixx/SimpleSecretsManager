// Package version provides the single version shared by both binaries and the UI.
package version

// Version is replaced by the release build using -ldflags. Keep the fallback
// useful for developers who run go build directly instead of using the Makefile.
var Version = "0.0.4"
