package main

import (
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"strings"

	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// pathsFS is the embedded filesystem containing all vendor path YAML files.
// The entire paths/ directory tree is bundled into the binary at compile time,
// so no external file access is needed at runtime.
//
//go:embed paths
var pathsFS embed.FS

// VendorPathConfig holds the TR-069 parameter path definitions for a single
// vendor (or the "default" baseline). Each instance is loaded from one YAML
// file in the embedded paths/ directory tree.
//
// YAML layout (see paths/default.yaml for the authoritative schema):
//
//	vendor: zte                       # unique lowercase identifier
//	description: "ZTE ONT family"    # human-readable, optional
//	oui:                              # ManufacturerOUI values (IEEE 6-hex)
//	  - "001141"
//	product_class:                    # ProductClass strings (case-insensitive)
//	  - "F670L"
//	features:                         # map of feature → (param → path template)
//	  pppoe:
//	    username: "IGD.WANDevice.{wan}...."
//
// Path templates use {key} placeholders. Callers pass a vars map to
// FormatPath to substitute instance numbers before use.
type VendorPathConfig struct {
	Vendor       string                       `yaml:"vendor"`
	Description  string                       `yaml:"description,omitempty"`
	OUI          []string                     `yaml:"oui,omitempty"`
	ProductClass []string                     `yaml:"product_class,omitempty"`
	Features     map[string]map[string]string `yaml:"features"`
}

// PathRegistry is the loaded and indexed set of vendor path configs.
// Obtain via newPathRegistry or use globalPathRegistry.
// The zero value is not usable.
type PathRegistry struct {
	defaultCfg VendorPathConfig
	vendors    map[string]*VendorPathConfig // keyed by vendor ID
	ouiIndex   map[string]*VendorPathConfig // keyed by uppercase OUI
	pcIndex    map[string]*VendorPathConfig // keyed by lowercase product class
}

// globalPathRegistry is the package-level registry loaded once at init()
// time from the embedded paths/ directory tree. All handler path lookups
// go through this instance.
var globalPathRegistry *PathRegistry

func init() {
	mustInitPathRegistry(pathsFS)
}

// mustInitPathRegistry loads the path registry from the given filesystem
// and assigns it to globalPathRegistry. Panics on any error — a failure here
// means the embedded YAML files are corrupt or missing, which is a
// programming error that must never reach production.
//
// Extracted from init() so tests can exercise the panic path with a
// synthetic broken filesystem without corrupting the package-level state.
func mustInitPathRegistry(fsys fs.FS) {
	reg, err := newPathRegistry(fsys)
	if err != nil {
		panic("vendor_paths: failed to load path registry: " + err.Error())
	}
	globalPathRegistry = reg
}

// newPathRegistry loads and indexes all YAML path files from the given
// filesystem. The FS must contain:
//   - paths/default.yaml   — the mandatory baseline path config
//   - paths/vendors/*.yaml — optional per-vendor overrides (may be absent)
//
// Accepts any fs.FS, so tests can pass a fstest.MapFS without touching the
// embedded FS.
func newPathRegistry(fsys fs.FS) (*PathRegistry, error) {
	reg := &PathRegistry{
		vendors:  make(map[string]*VendorPathConfig),
		ouiIndex: make(map[string]*VendorPathConfig),
		pcIndex:  make(map[string]*VendorPathConfig),
	}

	// Load the mandatory default config.
	data, err := fs.ReadFile(fsys, "paths/default.yaml")
	if err != nil {
		return nil, fmt.Errorf("load default paths: %w", err)
	}
	if err := yaml.Unmarshal(data, &reg.defaultCfg); err != nil {
		return nil, fmt.Errorf("parse default.yaml: %w", err)
	}
	if reg.defaultCfg.Vendor == "" {
		reg.defaultCfg.Vendor = "default"
	}

	// Load vendor-specific overrides from paths/vendors/.
	// A missing or empty vendors directory is valid (minimal deployment).
	entries, err := fs.ReadDir(fsys, "paths/vendors")
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return reg, nil
		}
		return nil, fmt.Errorf("read vendors dir: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}
		filePath := "paths/vendors/" + entry.Name()
		data, err := fs.ReadFile(fsys, filePath)
		if err != nil {
			return nil, fmt.Errorf("load %s: %w", entry.Name(), err)
		}
		var cfg VendorPathConfig
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return nil, fmt.Errorf("parse %s: %w", entry.Name(), err)
		}
		if cfg.Vendor == "" {
			continue // skip entries without a vendor identifier
		}
		ptr := new(VendorPathConfig)
		*ptr = cfg
		reg.vendors[cfg.Vendor] = ptr
		for _, oui := range cfg.OUI {
			reg.ouiIndex[strings.ToUpper(oui)] = ptr
		}
		for _, pc := range cfg.ProductClass {
			reg.pcIndex[strings.ToLower(pc)] = ptr
		}
	}

	return reg, nil
}

// DetectVendor returns the vendor ID that best matches the given
// ManufacturerOUI and ProductClass strings (as reported by the CPE in its
// TR-069 Inform message). Returns "default" when no match is found.
//
// Match priority:
//  1. OUI exact match (IEEE-assigned 6-hex, uppercase-normalised).
//  2. ProductClass exact match (case-insensitive).
//  3. Fallback to "default".
//
// OUI is preferred over ProductClass because it is a guaranteed-unique IEEE
// identifier, while ProductClass strings can collide across vendors.
func (r *PathRegistry) DetectVendor(oui, productClass string) string {
	if r == nil {
		return "default"
	}
	if cfg, ok := r.ouiIndex[strings.ToUpper(oui)]; ok {
		return cfg.Vendor
	}
	if cfg, ok := r.pcIndex[strings.ToLower(productClass)]; ok {
		return cfg.Vendor
	}
	return "default"
}

// Lookup returns the path template for (vendor, feature, param).
// Falls back to the default config when the vendor has no entry for the
// requested feature+param combination. Returns ("", false) when neither
// the vendor nor the default defines the path.
//
// Example:
//
//	tmpl, ok := globalPathRegistry.Lookup("zte", "pppoe", "username")
//	if !ok { /* handle unsupported path */ }
//	path := FormatPath(tmpl, map[string]string{"wan": "1"})
func (r *PathRegistry) Lookup(vendor, feature, param string) (string, bool) {
	if r == nil {
		return "", false
	}
	// Vendor-specific path takes priority over the default.
	if vendor != "default" {
		if cfg, ok := r.vendors[vendor]; ok {
			if feat, ok := cfg.Features[feature]; ok {
				if tmpl, ok := feat[param]; ok {
					return tmpl, true
				}
			}
		}
	}
	// Fall back to the default config.
	if feat, ok := r.defaultCfg.Features[feature]; ok {
		if tmpl, ok := feat[param]; ok {
			return tmpl, true
		}
	}
	return "", false
}

// MustLookup is like Lookup but logs a warning and returns an empty string
// when the path is not found. Intended for callers that expect the path to
// always be present in default.yaml — a missing path is a programming error.
func (r *PathRegistry) MustLookup(vendor, feature, param string) string {
	tmpl, ok := r.Lookup(vendor, feature, param)
	if !ok {
		logger.Warn("vendor path not found in registry",
			zap.String("vendor", vendor),
			zap.String("feature", feature),
			zap.String("param", param),
		)
		return ""
	}
	return tmpl
}

// FormatPath substitutes {key} placeholders in a path template with values
// from vars. Substitution is case-sensitive. Unmatched placeholders are
// left as-is.
//
//	FormatPath(
//	  "InternetGatewayDevice.WANDevice.{wan}.WANConnectionDevice.1",
//	  map[string]string{"wan": "2"},
//	)
//	// → "InternetGatewayDevice.WANDevice.2.WANConnectionDevice.1"
func FormatPath(template string, vars map[string]string) string {
	if len(vars) == 0 {
		return template
	}
	pairs := make([]string, 0, len(vars)*2)
	for k, v := range vars {
		pairs = append(pairs, "{"+k+"}", v)
	}
	return strings.NewReplacer(pairs...).Replace(template)
}
