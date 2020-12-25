package ldapcluster

import (
	"testing"
	"github.com/dexidp/dex/connector"
	"context"
	"github.com/stretchr/testify/assert"
	"errors"
	log "github.com/sirupsen/logrus"
)

type MockConn struct {
	status bool
}

func (c MockConn) Login(ctx context.Context, s connector.Scopes, username, password string) (ident connector.Identity, validPass bool, err error) {
	if c.status {
		return connector.Identity{}, false, nil
	} else {
		return connector.Identity{}, false, errors.New("failed")
	}
}

func (c MockConn) Refresh(ctx context.Context, s connector.Scopes, ident connector.Identity) (connector.Identity, error) {
	if c.status {
		return connector.Identity{}, nil
	} else {
		return connector.Identity{}, errors.New("failed")
	}
}

func (c MockConn) Prompt() string {
	return "name:"
}

func TestLoginSingle(t *testing.T) {
	var ctx context.Context
	var s connector.Scopes

	var c1 MockConn
	c1.status = true

	var lcc ldapClusterConnector
	lcc.MemberConnectors = append(lcc.MemberConnectors, c1)
	lcc.activeMemberIdx = 0

	var logger *log.Logger
	logger = log.New()
	lcc.logger = logger
	_, _, e := lcc.Login(ctx, s, "testuser", "password")
	assert.Equal(t, e, nil)
}

func TestLoginMultiple(t *testing.T) {
	var ctx context.Context
	var s connector.Scopes

	var c1 MockConn
	c1.status = false

	var c2 MockConn
	c2.status = true

	var lcc ldapClusterConnector
	lcc.MemberConnectors = append(lcc.MemberConnectors, c1)
	lcc.activeMemberIdx = 0
	lcc.MemberConnectors = append(lcc.MemberConnectors, c2)

	var logger *log.Logger
	logger = log.New()
	lcc.logger = logger
	_, _, e := lcc.Login(ctx, s, "testuser", "password")
	assert.Equal(t, e, nil)
	assert.Equal(t, lcc.activeMemberIdx, 1)
}


func TestLoginMultiple2(t *testing.T) {
	var ctx context.Context
	var s connector.Scopes

	var c1 MockConn
	c1.status = false

	var c2 MockConn
	c2.status = false

	var c3 MockConn
	c3.status = true

	var lcc ldapClusterConnector
	lcc.MemberConnectors = append(lcc.MemberConnectors, c1)
	lcc.activeMemberIdx = 0
	lcc.MemberConnectors = append(lcc.MemberConnectors, c2)
	lcc.MemberConnectors = append(lcc.MemberConnectors, c3)

	var logger *log.Logger
	logger = log.New()
	lcc.logger = logger
	_, _, e := lcc.Login(ctx, s, "testuser", "password")
	assert.Equal(t, e, nil)
	assert.Equal(t, lcc.activeMemberIdx, 2)
}
