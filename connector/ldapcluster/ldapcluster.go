// Package ldapcluster implements strategies for authenticating with a cluster
// of LDAP servers, using the LDAP protocol.
package ldapcluster

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"

	"gopkg.in/ldap.v2"

	"github.com/dexidp/dex/connector"
	conn_ldap "github.com/dexidp/dex/connector/ldap"
	"github.com/dexidp/dex/pkg/log"
)

// Config holds the configuration parameters for the LDAP cluster connector.
// The LDAP cluster configuration holds an arrary of LDAP configuration parameters.
// LDAP cluster connectors require executing two queries,
// the first to find the user based on the username and password given to the connector.
// The second to use the user entry to search for groups.
//
// An example config:
//
//     type: ldap_cluster
//     config:
//       host: ldap1.example.com:636
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
//       groupSearch:
//         # Would translate to the query "(&(objectClass=group)(member=<user uid>))"
//         baseDN: cn=groups,dc=example,dc=com
//         filter: "(objectClass=group)"
//         userAttr: uid
//         # Use if full DN is needed and not available as any other attribute
//         # Will only work if "DN" attribute does not exist in the record
//         # userAttr: DN
//         groupAttr: member
//         nameAttr: name
//
//     config:
//       host: ldap2.example.com:636
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
//       groupSearch:
//         # Would translate to the query "(&(objectClass=group)(member=<user uid>))"
//         baseDN: cn=groups,dc=example,dc=com
//         filter: "(objectClass=group)"
//         userAttr: uid
//         # Use if full DN is needed and not available as any other attribute
//         # Will only work if "DN" attribute does not exist in the record
//         # userAttr: DN
//         groupAttr: member
//         nameAttr: name
//

const InvalidServerIndex = -1

type Config struct {
	//Using an array of LDAP connector's configuration
	//ClusterMembers []conn_ldap.Config `json:"clustermember"`
	ClusterMembers []conn_ldap.Config
}

func scopeString(i int) string {
	switch i {
	case ldap.ScopeBaseObject:
		return "base"
	case ldap.ScopeSingleLevel:
		return "one"
	case ldap.ScopeWholeSubtree:
		return "sub"
	default:
		return ""
	}
}

func parseScope(s string) (int, bool) {
	// NOTE(ericchiang): ScopeBaseObject doesn't really make sense for us because we
	// never know the user's or group's DN.
	switch s {
	case "", "sub":
		return ldap.ScopeWholeSubtree, true
	case "one":
		return ldap.ScopeSingleLevel, true
	}
	return 0, false
}

// Open returns an authentication strategy using LDAP.
func (c *Config) Open(id string, logger log.Logger) (connector.Connector, error) {
	conn, err := c.OpenConnector(logger)
	if err != nil {
		return nil, err
	}
	return connector.Connector(conn), nil
}

type refreshData struct {
	Username string     `json:"username"`
	Entry    ldap.Entry `json:"entry"`
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
	var (
		host string
		err  error
	)

	var ldapClusterConn ldapClusterConnector

	ldapClusterConn.activeIdx = InvalidServerIndex

	//Check all of the LDAP configuration.
	//It is required that all configuration in the cluster is proper.
	//We will not proceed even if one of the LDAP server's configuration has issue.
	//TODO: should this be the case?
	for _, lc := range c.ClusterMembers {
		requiredFields := []struct {
			name string
			val  string
		}{
			{"host", lc.Host},
			{"userSearch.baseDN", lc.UserSearch.BaseDN},
			{"userSearch.username", lc.UserSearch.Username},
		}

		for _, field := range requiredFields {
			if field.val == "" {
				return nil, fmt.Errorf("ldap: missing required field %q", field.name)
			}
		}

		if host, _, err = net.SplitHostPort(lc.Host); err != nil {
			host = lc.Host
			if lc.InsecureNoSSL {
				lc.Host = lc.Host + ":389"
			} else {
				lc.Host = lc.Host + ":636"
			}
		}

		tlsConfig := &tls.Config{ServerName: host, InsecureSkipVerify: lc.InsecureSkipVerify}
		if lc.RootCA != "" || len(lc.RootCAData) != 0 {
			data := lc.RootCAData
			if len(data) == 0 {
				var err error
				if data, err = ioutil.ReadFile(lc.RootCA); err != nil {
					return nil, fmt.Errorf("ldap: read ca file: %v", err)
				}
			}
			rootCAs := x509.NewCertPool()
			if !rootCAs.AppendCertsFromPEM(data) {
				return nil, fmt.Errorf("ldap: no certs found in ca file")
			}
			tlsConfig.RootCAs = rootCAs
		}

		if lc.ClientKey != "" && lc.ClientCert != "" {
			cert, err := tls.LoadX509KeyPair(lc.ClientCert, lc.ClientKey)
			if err != nil {
				return nil, fmt.Errorf("ldap: load client cert failed: %v", err)
			}
			tlsConfig.Certificates = append(tlsConfig.Certificates, cert)
		}
		userSearchScope, ok := parseScope(lc.UserSearch.Scope)
		if !ok {
			return nil, fmt.Errorf("userSearch.Scope unknown value %q", lc.UserSearch.Scope)
		}
		groupSearchScope, ok := parseScope(lc.GroupSearch.Scope)
		if !ok {
			return nil, fmt.Errorf("groupSearch.Scope unknown value %q", lc.GroupSearch.Scope)
		}

		//configuration for this LDAP server is proper; let's append.
		ldapClusterConn.Config.ClusterMembers = append(ldapClusterConn.Config.ClusterMembers, lc)
		ldapClusterConn.userSearchScope = append(ldapClusterConn.userSearchScope, userSearchScope)
		ldapClusterConn.groupSearchScope = append(ldapClusterConn.groupSearchScope, groupSearchScope)
		ldapClusterConn.tlsConfig = append(ldapClusterConn.tlsConfig, tlsConfig)
	}

	ldapClusterConn.logger = logger

	return &ldapClusterConn, nil
}

type ldapClusterConnector struct {
	Config Config

	userSearchScope  []int
	groupSearchScope []int

	tlsConfig []*tls.Config

	logger    log.Logger
	activeIdx int
}

var (
	_ connector.PasswordConnector = (*ldapClusterConnector)(nil)
	_ connector.RefreshConnector  = (*ldapClusterConnector)(nil)
)

func (cc *ldapClusterConnector) tryOne(ctx context.Context, idx int) (*ldap.Conn, error) {
	var (
		conn *ldap.Conn
		err  error
	)
	var c conn_ldap.Config

	c = cc.Config.ClusterMembers[idx]

	cc.logger.Infof("Connecting to server: %s", c.Host)
	switch {
	case c.InsecureNoSSL:
		conn, err = ldap.Dial("tcp", c.Host)
	case c.StartTLS:
		conn, err = ldap.Dial("tcp", c.Host)
		if err != nil {
			return nil, fmt.Errorf("failed to connect: %v", err)
		}
		if err := conn.StartTLS(cc.tlsConfig[idx]); err != nil {
			return nil, fmt.Errorf("start TLS failed: %v", err)
		}
	default:
		conn, err = ldap.DialTLS("tcp", c.Host, cc.tlsConfig[idx])
	}
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %v", c.Host, err)
	}

	// If bindDN and bindPW are empty this will default to an anonymous bind.
	if err := conn.Bind(c.BindDN, c.BindPW); err != nil {
		if c.BindDN == "" && c.BindPW == "" {
			conn.Close()
			return nil, fmt.Errorf("ldap: initial anonymous bind failed: %v", err)
		}
		conn.Close()
		return nil, fmt.Errorf("ldap: initial bind for user %q failed: %v", c.BindDN, err)
	}

	//connection succeeded.
	return conn, err
}

func (cc *ldapClusterConnector) tryAll(ctx context.Context) (*ldap.Conn, int, error) {
	var (
		conn *ldap.Conn
		err  error
	)

	//Let's try all the servers in the cluster.
	//TODO: this will retry the already tried one. we can optimize.
	for i, c := range cc.Config.ClusterMembers {
		conn, err = cc.tryOne(ctx, i)
		if err != nil {
			cc.logger.Infof("failed to connect to %s: %v", c.Host, err)
			//try next server.
			continue
		}

		//connection succeeded.
		return conn, i, nil
	}

	//we have exhausted all the servers.
	return nil, InvalidServerIndex, err
}

// do initializes a connection to the LDAP directory and passes it to the
// provided function. It then performs appropriate teardown or reuse before
// returning. When there are multiple server it iterates over all servers
// till a connection succeeds or till all servers are exhausted.
func (cc *ldapClusterConnector) do(ctx context.Context, anySrvr bool, f func(idx int, c *ldap.Conn) (int, error)) (int, error) {
	// TODO(ericchiang): support context here
	var (
		conn *ldap.Conn
		err  error
		idx  int
	)

	if cc.activeIdx != InvalidServerIndex {
		//Let's try to contact the currently active server first.
		cc.logger.Infof("Connecting to current active server[%d]: %s", cc.activeIdx, cc.Config.ClusterMembers[cc.activeIdx].Host)
		conn, err = cc.tryOne(ctx, cc.activeIdx)
	}

	if err != nil {
		if anySrvr {
			//invalidate the active index.
			cc.logger.Infof("Connection to current active server[%d]: %s failed", cc.activeIdx, cc.Config.ClusterMembers[cc.activeIdx].Host)
			cc.activeIdx = InvalidServerIndex
		} else {
			return InvalidServerIndex, errors.New("Failed to connect to active server")
		}
	}

	if cc.activeIdx == InvalidServerIndex {
		//There are no active servers, let's try all.
		conn, idx, err = cc.tryAll(ctx)
		if err != nil {
			return InvalidServerIndex, errors.New("All servers in the cluster are down")
		}

		//connection to one of the servers succeeded. Update the active index.
		cc.activeIdx = idx
	}

	defer conn.Close()

	//bind success.
	return f(cc.activeIdx, conn)
}

func getAttrs(e ldap.Entry, name string) []string {
	for _, a := range e.Attributes {
		if a.Name != name {
			continue
		}
		return a.Values
	}
	if name == "DN" {
		return []string{e.DN}
	}
	return nil
}

func getAttr(e ldap.Entry, name string) string {
	if a := getAttrs(e, name); len(a) > 0 {
		return a[0]
	}
	return ""
}

func (c *ldapClusterConnector) identityFromEntry(user ldap.Entry, idx int) (ident connector.Identity, err error) {
	// If we're missing any attributes, such as email or ID, we want to report
	// an error rather than continuing.
	missing := []string{}

	// Fill the identity struct using the attributes from the user entry.
	if ident.UserID = getAttr(user, c.Config.ClusterMembers[idx].UserSearch.IDAttr); ident.UserID == "" {
		missing = append(missing, c.Config.ClusterMembers[idx].UserSearch.IDAttr)
	}

	if c.Config.ClusterMembers[idx].UserSearch.NameAttr != "" {
		if ident.Username = getAttr(user, c.Config.ClusterMembers[idx].UserSearch.NameAttr); ident.Username == "" {
			missing = append(missing, c.Config.ClusterMembers[idx].UserSearch.NameAttr)
		}
	}

	if c.Config.ClusterMembers[idx].UserSearch.EmailSuffix != "" {
		ident.Email = ident.Username + "@" + c.Config.ClusterMembers[idx].UserSearch.EmailSuffix
	} else if ident.Email = getAttr(user, c.Config.ClusterMembers[idx].UserSearch.EmailAttr); ident.Email == "" {
		missing = append(missing, c.Config.ClusterMembers[idx].UserSearch.EmailAttr)
	}
	// TODO(ericchiang): Let this value be set from an attribute.
	ident.EmailVerified = true

	if len(missing) != 0 {
		err := fmt.Errorf("ldap: entry %q missing following required attribute(s): %q", user.DN, missing)
		return connector.Identity{}, err
	}
	return ident, nil
}

func (c *ldapClusterConnector) userEntry(idx int, conn *ldap.Conn, username string) (user ldap.Entry, found bool, err error) {

	filter := fmt.Sprintf("(%s=%s)", c.Config.ClusterMembers[idx].UserSearch.Username, ldap.EscapeFilter(username))
	if c.Config.ClusterMembers[idx].UserSearch.Filter != "" {
		filter = fmt.Sprintf("(&%s%s)", c.Config.ClusterMembers[idx].UserSearch.Filter, filter)
	}

	// Initial search.
	req := &ldap.SearchRequest{
		BaseDN: c.Config.ClusterMembers[idx].UserSearch.BaseDN,
		Filter: filter,
		Scope:  c.userSearchScope[idx],
		// We only need to search for these specific requests.
		Attributes: []string{
			c.Config.ClusterMembers[idx].UserSearch.IDAttr,
			c.Config.ClusterMembers[idx].UserSearch.EmailAttr,
			c.Config.ClusterMembers[idx].GroupSearch.UserAttr,
			// TODO(ericchiang): what if this contains duplicate values?
		},
	}

	if c.Config.ClusterMembers[idx].UserSearch.NameAttr != "" {
		req.Attributes = append(req.Attributes, c.Config.ClusterMembers[idx].UserSearch.NameAttr)
	}

	c.logger.Infof("performing ldap search %s %s %s",
		req.BaseDN, scopeString(req.Scope), req.Filter)
	resp, err := conn.Search(req)
	if err != nil {
		return ldap.Entry{}, false, fmt.Errorf("ldap: search with filter %q failed: %v", req.Filter, err)
	}

	switch n := len(resp.Entries); n {
	case 0:
		c.logger.Errorf("ldap: no results returned for filter: %q", filter)
		return ldap.Entry{}, false, nil
	case 1:
		user = *resp.Entries[0]
		c.logger.Infof("username %q mapped to entry %s", username, user.DN)
		return user, true, nil
	default:
		return ldap.Entry{}, false, fmt.Errorf("ldap: filter returned multiple (%d) results: %q", n, filter)
	}
}

func (c *ldapClusterConnector) Login(ctx context.Context, s connector.Scopes, username, password string) (ident connector.Identity, validPass bool, err error) {
	// make this check to avoid unauthenticated bind to the LDAP server.
	if password == "" {
		return connector.Identity{}, false, nil
	}

	var (
		// We want to return a different error if the user's password is incorrect vs
		// if there was an error.
		incorrectPass = false
		user          ldap.Entry
		idx           int
	)

	idx, err = c.do(ctx, true, func(idx int, conn *ldap.Conn) (int, error) {
		entry, found, err := c.userEntry(idx, conn, username)
		if err != nil {
			return idx, err
		}
		if !found {
			incorrectPass = true
			return idx, nil
		}
		user = entry

		// Try to authenticate as the distinguished name.
		if err := conn.Bind(user.DN, password); err != nil {
			// Detect a bad password through the LDAP error code.
			if ldapErr, ok := err.(*ldap.Error); ok {
				switch ldapErr.ResultCode {
				case ldap.LDAPResultInvalidCredentials:
					c.logger.Errorf("ldap: invalid password for user %q", user.DN)
					incorrectPass = true
					return idx, nil
				case ldap.LDAPResultConstraintViolation:
					c.logger.Errorf("ldap: constraint violation for user %q: %s", user.DN, ldapErr.Error())
					incorrectPass = true
					return idx, nil
				}
			} // will also catch all ldap.Error without a case statement above
			return idx, fmt.Errorf("ldap: failed to bind as dn %q: %v", user.DN, err)
		}
		return idx, nil
	})
	if err != nil {
		return connector.Identity{}, false, err
	}
	if incorrectPass {
		return connector.Identity{}, false, nil
	}

	if ident, err = c.identityFromEntry(user, idx); err != nil {
		return connector.Identity{}, false, err
	}

	if s.Groups {
		groups, err := c.groups(ctx, user, idx)
		if err != nil {
			return connector.Identity{}, false, fmt.Errorf("ldap: failed to query groups: %v", err)
		}
		ident.Groups = groups
	}

	if s.OfflineAccess {
		refresh := refreshData{
			Username: username,
			Entry:    user,
		}
		// Encode entry for follow up requests such as the groups query and
		// refresh attempts.
		if ident.ConnectorData, err = json.Marshal(refresh); err != nil {
			return connector.Identity{}, false, fmt.Errorf("ldap: marshal entry: %v", err)
		}
	}

	c.activeIdx = idx

	return ident, true, nil
}

func (c *ldapClusterConnector) Refresh(ctx context.Context, s connector.Scopes, ident connector.Identity) (connector.Identity, error) {
	var data refreshData
	if err := json.Unmarshal(ident.ConnectorData, &data); err != nil {
		return ident, fmt.Errorf("ldap: failed to unmarshal internal data: %v", err)
	}

	var user ldap.Entry
	idx, err := c.do(ctx, true, func(idx int, conn *ldap.Conn) (int, error) {
		entry, found, err := c.userEntry(idx, conn, data.Username)
		if err != nil {
			return idx, err
		}
		if !found {
			return idx, fmt.Errorf("ldap: user not found %q", data.Username)
		}
		user = entry
		return idx, nil
	})
	if err != nil {
		return ident, err
	}
	if user.DN != data.Entry.DN {
		return ident, fmt.Errorf("ldap: refresh for username %q expected DN %q got %q", data.Username, data.Entry.DN, user.DN)
	}

	newIdent, err := c.identityFromEntry(user, idx)
	if err != nil {
		return ident, err
	}
	newIdent.ConnectorData = ident.ConnectorData

	if s.Groups {
		groups, err := c.groups(ctx, user, idx)
		if err != nil {
			return connector.Identity{}, fmt.Errorf("ldap: failed to query groups: %v", err)
		}
		newIdent.Groups = groups
	}

	c.activeIdx = idx

	return newIdent, nil
}

func (c *ldapClusterConnector) groups(ctx context.Context, user ldap.Entry, idx int) ([]string, error) {
	if c.Config.ClusterMembers[idx].GroupSearch.BaseDN == "" {
		c.logger.Debugf("No groups returned for %q because no groups baseDN has been configured.", getAttr(user, c.Config.ClusterMembers[idx].UserSearch.NameAttr))
		return nil, nil
	}

	var groups []*ldap.Entry
	for _, attr := range getAttrs(user, c.Config.ClusterMembers[idx].GroupSearch.UserAttr) {
		filter := fmt.Sprintf("(%s=%s)", c.Config.ClusterMembers[idx].GroupSearch.GroupAttr, ldap.EscapeFilter(attr))
		if c.Config.ClusterMembers[idx].GroupSearch.Filter != "" {
			filter = fmt.Sprintf("(&%s%s)", c.Config.ClusterMembers[idx].GroupSearch.Filter, filter)
		}

		req := &ldap.SearchRequest{
			BaseDN:     c.Config.ClusterMembers[idx].GroupSearch.BaseDN,
			Filter:     filter,
			Scope:      c.groupSearchScope[idx],
			Attributes: []string{c.Config.ClusterMembers[idx].GroupSearch.NameAttr},
		}

		gotGroups := false
		if _, err := c.do(ctx, false, func(idx int, conn *ldap.Conn) (int, error) {
			c.logger.Infof("performing ldap search %s %s %s",
				req.BaseDN, scopeString(req.Scope), req.Filter)
			resp, err := conn.Search(req)
			if err != nil {
				return idx, fmt.Errorf("ldap: search failed: %v", err)
			}
			gotGroups = len(resp.Entries) != 0
			groups = append(groups, resp.Entries...)
			return idx, nil
		}); err != nil {
			return nil, err
		}
		if !gotGroups {
			// TODO(ericchiang): Is this going to spam the logs?
			c.logger.Errorf("ldap: groups search with filter %q returned no groups", filter)
		}
	}

	var groupNames []string
	for _, group := range groups {
		name := getAttr(*group, c.Config.ClusterMembers[idx].GroupSearch.NameAttr)
		if name == "" {
			// Be obnoxious about missing missing attributes. If the group entry is
			// missing its name attribute, that indicates a misconfiguration.
			//
			// In the future we can add configuration options to just log these errors.
			return nil, fmt.Errorf("ldap: group entity %q missing required attribute %q",
				group.DN, c.Config.ClusterMembers[idx].GroupSearch.NameAttr)
		}

		groupNames = append(groupNames, name)
	}
	return groupNames, nil
}

func (c *ldapClusterConnector) Prompt() string {
	//TODO: During Open, verify all UsernamePrompt overrides are same for all servers.
	//fmt.Printf("%+v\n", c)
	return c.Config.ClusterMembers[0].UsernamePrompt
}
