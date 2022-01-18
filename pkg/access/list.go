/*
Copyright 2022 Adolfo García Veytia
SPDX-License-Identifier: Apache-2.0
*/

package access

import (
	"os"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	yaml "gopkg.in/yaml.v2"
)

// List abstracts an ACL list keyed by environment and
// the users that can access it
type List map[string][]string

type aclFile struct {
	List `yaml:"acl"`
}

// NewListFromFile returns a new List instance from a file
func NewListFromFile(path string) (*List, error) {
	return readACLFromFile(path)
}

// Check returns a bool indicating if the list grants acces to the current env
func (l *List) UserCanAccess(user, env string) (grant bool, err error) {
	if l == nil {
		return grant, errors.New("unable to check access, list is nil")
	}

	// Check if env is listed in the file
	if _, ok := (*l)[env]; !ok {
		return grant, errors.Errorf("unable to check access, environment %s is not defined", env)
	}

	// Now, finally check if the user is listed
	for _, u := range (*l)[env] {
		if u == user {
			logrus.Debugf("ACL allows access to environment %s to user %s", env, user)
			return true, nil
		}
	}
	logrus.Debugf("ACL denies access to environment %s to user %s", env, user)
	return false, nil
}

// readACLFromFile reads a yaml file, looking for the acl: tag and
// builds an ACL list from the data under that node.
func readACLFromFile(path string) (*List, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.Wrap(err, "reading ACL file")
	}
	return parseACL(data)
}

// parseACL parses yaml describing lists matching environments and
// users that can access it
func parseACL(listData []byte) (*List, error) {
	acl := &aclFile{}
	if err := yaml.Unmarshal(listData, acl); err != nil {
		return &acl.List, errors.Wrap(err, "unmarshalling list")
	}
	return &acl.List, nil
}
