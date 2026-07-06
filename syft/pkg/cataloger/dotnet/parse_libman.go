package dotnet

import (
    "bytes"
    "context"
    "fmt"
    "io"

    "github.com/anchore/syft/syft/artifact"
    "github.com/anchore/syft/syft/file"
    "github.com/anchore/syft/syft/pkg"
    "github.com/anchore/syft/syft/pkg/cataloger/generic"
    "github.com/tailscale/hujson"
)

var _ generic.Parser = parseLibmanJSON

// parseLibmanJSON is a standalone parser for libman.json files used by the dotnet-libman-cataloger.
// It reuses the shared libmanJSON model and produces npm packages for the declared client-side libraries.
// libman.json files may contain // comments (Visual Studio generates them with commented-out example
// entries), so the content is standardized via hujson before being decoded as strict JSON.
func parseLibmanJSON(_ context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
    data, err := io.ReadAll(reader)
    if err != nil {
        return nil, nil, fmt.Errorf("failed to read libman.json file: %w", err)
    }

    // libman.json may contain comments and trailing commas (JSONC), so standardize to strict JSON.
    data, err = hujson.Standardize(data)
    if err != nil {
        return nil, nil, fmt.Errorf("failed to standardize libman.json file: %w", err)
    }

    doc, err := newLibmanJSON(file.NewLocationReadCloser(reader.Location, io.NopCloser(bytes.NewReader(data))))
    if err != nil {
        return nil, nil, fmt.Errorf("failed to parse libman.json file: %w", err)
    }

    pkgs := doc.packages()
    return pkgs, nil, nil
}