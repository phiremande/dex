// Package ldapcluster implements strategies for authenticating using the LDAP protocol.
package ldapcluster

import (
	"context"
	"github.com/dexidp/dex/connector"
	"github.com/dexidp/dex/pkg/log"
	conn_ldap "github.com/dexidp/dex/connector/ldap"
)

// Config holds the configuration parameters for the LDAP connector. The LDAP
// connectors require executing two queries, the first to find the user based on
// the username and password given to the connector. The second to use the user
// entry to search for groups.
//
// An example config:
//
//     type: ldap
//     config:
//       host: ldap.example.com:636
//       # The following field is required if using port 389.
//       # insecureNoSSL: true
//       rootCA: /etc/dex/ldap.ca
//       bindDN: uid=seviceaccount,cn=users,dc=example,dc=com
//       bindPW: password
//       userSearch:
//         # Would translate to the query "(&(objectClass=person)(uid=<username>))"
//         baseDN: cn=users,dc=example,dc=com
//         filter: "(objectClass=person)"
//         username: uid
//         idAttr: uid
//         emailAttr: mail
//         nameAttr: name
//         preferredUsernameAttr: uid
//       groupSearch:
//         # Would translate to the separate query per user matcher pair and aggregate results into a single group list:
//         #  "(&(|(objectClass=posixGroup)(objectClass=groupOfNames))(memberUid=<user uid>))"
//         #  "(&(|(objectClass=posixGroup)(objectClass=groupOfNames))(member=<user DN>))"
//         baseDN: cn=groups,dc=example,dc=com
//         filter: "(|(objectClass=posixGroup)(objectClass=groupOfNames))"
//         userMatchers:
//         - userAttr: uid
//           groupAttr: memberUid
//           # Use if full DN is needed and not available as any other attribute
//           # Will only work if "DN" attribute does not exist in the record:
//         - userAttr: DN
//           groupAttr: member
//         nameAttr: name
//

type Config struct {
	ClusterMembers []conn_ldap.Config
}

// Open returns an authentication strategy using LDAP.
func (c *Config) Open(id string, logger log.Logger) (connector.Connector, error) {
	conn, err := c.OpenConnector(logger)
	if err != nil {
		return nil, err
	}
	return connector.Connector(conn), nil
}

// OpenConnector is the same as Open but returns a type with all implemented connector interfaces.
func (c *Config) OpenConnector(logger log.Logger) (interface {
	connector.Connector
	connector.PasswordConnector
	connector.RefreshConnector
}, error) {
	return c.openConnector(logger)
}

func (c *Config) openConnector(logger log.Logger) (*ldapClusterConnector, error) {
	var lcc ldapClusterConnector
	//Initialize each of the connector members.
	for _, v := range c.ClusterMembers {
		lc, e := v.OpenConnector(logger)
		if e != nil {
			return  nil, e
		}
		lcc.MemberConnectors = append(lcc.MemberConnectors, lc)
	}

	lcc.activeMemberIdx = 0
	lcc.logger = logger

	return &lcc, nil
}

type ConnectorIf interface {
	connector.Connector
	connector.PasswordConnector
	connector.RefreshConnector
}

type ldapClusterConnector struct {
	MemberConnectors [](ConnectorIf)
	activeMemberIdx int
	logger log.Logger
}

func (c *ldapClusterConnector) Login(ctx context.Context, s connector.Scopes, username, password string) (ident connector.Identity, validPass bool, err error) {
	// make this check to avoid unauthenticated bind to the LDAP server.
	if password == "" {
		return connector.Identity{}, false, nil
	}

	//Check the active connector first.
	//If the active connector index is -1, we will start
	//with first connector.
	if c.activeMemberIdx == -1 {
		c.activeMemberIdx = 0
	}
	lc := c.MemberConnectors[c.activeMemberIdx]
	i, b, e := lc.Login(ctx, s, username, password)
	if e != nil {
		c.logger.Infof("Failed to connect to server idx: %d", c.activeMemberIdx)
		//current active server has returned error.
		//Try the other servers in round robin manner.
		//If the error returned by a server is nil, 
		//then make that server as 
		//the current active server.
		for k, v := range c.MemberConnectors {
			if k == c.activeMemberIdx {
				//we just tried it.
				//hence skip.
				continue
			}
			i, b , e = v.Login(ctx, s, username, password)
			if e == nil {
				c.logger.Infof("setting active index as: %d", k)
				c.activeMemberIdx = k
				return i, b, e
			}
		}
	}
	return i, b, e
}

func (c *ldapClusterConnector) Refresh(ctx context.Context, s connector.Scopes, ident connector.Identity) (connector.Identity, error) {
	lc := c.MemberConnectors[c.activeMemberIdx]
	i, e := lc.(connector.RefreshConnector).Refresh(ctx, s, ident)
	if e != nil {
		c.logger.Infof("Failed to connect to active index: %d", c.activeMemberIdx)
		//current active server has returned error.
		//Try the other servers in round robin manner.
		//If the error returned by a server is nil, 
		//then make that server as 
		//the current active server.
		for k, v := range c.MemberConnectors {
			if k == c.activeMemberIdx {
				//we just tried it.
				//hence skip.
				continue
			}
			c.logger.Infof("Trying index: %d", k)
			i, e = v.Refresh(ctx, s, ident)
			if e == nil {
				c.logger.Infof("setting active index as: %d", k)
				c.activeMemberIdx = k
				return i, nil
			} else {
				c.logger.Errorf("Failed to connect to index: %d", k)
			}
		}
	}

	return i, e
}

func (c *ldapClusterConnector) Prompt() string {
	lc := c.MemberConnectors[c.activeMemberIdx]
	return lc.Prompt()
}
