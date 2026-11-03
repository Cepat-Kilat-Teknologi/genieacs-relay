package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSetBuildInfoAndAccessors(t *testing.T) {
	origV, origC, origD := buildVersion, buildCommit, buildDate
	defer func() { buildVersion, buildCommit, buildDate = origV, origC, origD }()

	setBuildInfo("9.9.9", "deadbeef", "2026-04-12T10:00:00Z")
	assert.Equal(t, "9.9.9", BuildVersion())
	assert.Equal(t, "deadbeef", BuildCommit())
	assert.Equal(t, "2026-04-12T10:00:00Z", BuildDate())
	assert.NotEmpty(t, Uptime())
}

func TestSetBuildInfoSkipsEmpty(t *testing.T) {
	origV, origC, origD := buildVersion, buildCommit, buildDate
	defer func() { buildVersion, buildCommit, buildDate = origV, origC, origD }()

	setBuildInfo("preserved", "preserved", "preserved")
	setBuildInfo("", "", "")
	// Empty args must not clobber existing values.
	assert.Equal(t, "preserved", BuildVersion())
	assert.Equal(t, "preserved", BuildCommit())
	assert.Equal(t, "preserved", BuildDate())
}
