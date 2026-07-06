package dotnet

import (
	"testing"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestParseLibmanJSON(t *testing.T) {
	fixture := "testdata/libman.json"
	fixtureLocationSet := file.NewLocationSet(file.NewLocation(fixture))

	jqueryPkg := pkg.Package{
		Name:      "jquery",
		Version:   "3.3.1",
		PURL:      "pkg:npm/jquery@3.3.1",
		Locations: fixtureLocationSet,
		Language:  pkg.JavaScript,
		Type:      pkg.NpmPkg,
	}

	bootstrapPkg := pkg.Package{
		Name:      "twitter-bootstrap",
		Version:   "4.1.1",
		PURL:      "pkg:npm/twitter-bootstrap@4.1.1",
		Locations: fixtureLocationSet,
		Language:  pkg.JavaScript,
		Type:      pkg.NpmPkg,
	}

	expectedPkgs := []pkg.Package{
		jqueryPkg,
		bootstrapPkg,
	}

	pkgtest.TestFileParser(t, fixture, parseLibmanJSON, expectedPkgs, nil)
}
