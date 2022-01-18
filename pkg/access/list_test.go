/*
Copyright 2022 Adolfo García Veytia
SPDX-License-Identifier: Apache-2.0
*/

package access

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func getACLSUT() string {
	return `acl:
  mock:
    - user1
    - user2
    - user5
  nomock:
    - user1
    - user3
`
}

func TestUserCanAccess(t *testing.T) {
	acl, err := parseACL([]byte(getACLSUT()))
	require.NoError(t, err)

	// Nil lists should not b0rk, but error
	var nilACL *List
	_, err = nilACL.UserCanAccess("user", "env")
	require.Error(t, err)

	// Non defined envs should error
	_, err = acl.UserCanAccess("user", "nonexistent")
	require.Error(t, err)

	// List should allow access to these users to mock
	for _, u := range []string{"user1", "user2", "user5"} {
		grant, err := acl.UserCanAccess(u, "mock")
		require.NoError(t, err)
		require.True(t, grant)
	}

	// List should allow access to these users to mock
	for _, u := range []string{"user1", "user3"} {
		grant, err := acl.UserCanAccess(u, "nomock")
		require.NoError(t, err)
		require.True(t, grant)
	}

	// Not listed users should not access
	for u, e := range map[string]string{
		"user5": "nomock", "user3": "mock",
	} {
		grant, err := acl.UserCanAccess(u, e)
		require.NoError(t, err)
		require.False(t, grant)
	}

	// Non existent users should not get access
	grant, err := acl.UserCanAccess("nonexistent", "mock")
	require.NoError(t, err)
	require.False(t, grant)
}

func createTestListFile(t *testing.T) string {
	sut := getACLSUT()
	tmp, err := os.CreateTemp("", "acl-")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(tmp.Name(), []byte(sut), os.FileMode(0o644)))
	return tmp.Name()
}

func TestNewListFromFile(t *testing.T) {
	lfile := createTestListFile(t)
	defer os.Remove(lfile)
	_, err := NewListFromFile(lfile)
	require.NoError(t, err)
}

func TestReadACLFromFile(t *testing.T) {
	// Read a nonexistent file
	_, err := readACLFromFile("dslkjflskjdflksjdfl/lkasdjlakjsldkajsldkjlaskd")
	require.Error(t, err)
	// Read a real list
	sut := getACLSUT()
	tmp, err := os.CreateTemp("", "acl-")
	require.NoError(t, err)
	defer os.Remove(tmp.Name())
	require.NoError(t, os.WriteFile(tmp.Name(), []byte(sut), os.FileMode(0o644)))

	// Read the ACL from the file
	list, err := readACLFromFile(tmp.Name())
	require.NoError(t, err)
	require.NotNil(t, list)
	testSUTACL(t, *list)
}

func testSUTACL(t *testing.T, acl List) {
	require.Len(t, acl, 2)
	require.Len(t, acl["mock"], 3)
	require.Len(t, acl["nomock"], 2)
}

func TestParseACL(t *testing.T) {
	// Parse invalid yaml
	_, err := parseACL([]byte("\t\t"))
	require.Error(t, err)

	sut := getACLSUT()
	acl, err := parseACL([]byte(sut))
	require.NoError(t, err)
	require.NotNil(t, acl)

	testSUTACL(t, *acl)
}
