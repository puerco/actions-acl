/*
Copyright 2022 Adolfo García Veytia
SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"os"

	"github.com/pkg/errors"
	"github.com/puerco/actions-acl/pkg/access"
	"github.com/sirupsen/logrus"
)

const (
	defaultACLFile = ".buildconf.yaml"
	aclActorVar    = "ACL_ACTOR"
	aclEnvVar      = "ACL_ENV"
)

func main() {
	listPath := defaultACLFile
	if len(os.Args) > 1 {
		listPath = os.Args[1]
	}

	// Read ACL from build point
	list, err := access.NewListFromFile(listPath)
	if err != nil {
		logrus.Fatal(errors.Wrap(err, "opening ACL file"))
	}

	// Call list to ensure user can perform build
	granted, err := list.UserCanAccess(
		os.Getenv(aclActorVar),
		os.Getenv(aclEnvVar),
	)
	if err != nil {
		logrus.Fatal(errors.Wrap(err, "checking auth list"))
	}

	if granted {
		logrus.Infof(
			"ACL: User %s is authorized to run build in %s",
			os.Getenv(aclActorVar), os.Getenv(aclEnvVar),
		)
		os.Exit(0)
	}

	logrus.Warnf(
		"ACL: Access not granted to user %s to run environment %s",
		os.Getenv(aclActorVar), os.Getenv(aclEnvVar),
	)
	os.Exit(1)
}
