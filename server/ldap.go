package server

import (
	"os"
	"os/user"
	"bufio"
	"regexp"
	"strings"
	"gopkg.in/ldap.v2"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"sort"
	"strconv"
	"time"
	"io/ioutil"
	"path/filepath"
	"errors"
	"sargon/diag"
	"sargon/access"
)

var (
	commentRe = regexp.MustCompile(`^\s*#`)
	settingRe = regexp.MustCompile(`^\s*(\S+)\s+(.+)$`)
	ldapURIRe = regexp.MustCompile(`^(ldap[is]?)://((.+?)(?::(.+))?)$`)
)

type LdapConfig map[string]string

func (lcf LdapConfig) Read(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	diag.Debug("reading file %s\n", filename)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		s := scanner.Text()
		if commentRe.FindStringSubmatch(s) != nil {
			continue
		}
		if res := settingRe.FindStringSubmatch(s); res != nil {
			lcf[strings.ToLower(res[1])] = res[2]
		}
	}
	return nil
}

func (lcf LdapConfig) ReadPath(path string) (err error) {
	for _, file := range strings.Split(path, `:`) {
		err = lcf.Read(file);
		if err == nil || !os.IsNotExist(err) {
			break
		}
	}
	return
}

func uriToNetAddr(uri string) (net, address string, ssl bool) {
	if (uri == "") {
		net = "tcp"
		address = "127.0.0.1:389"
	} else if res := ldapURIRe.FindStringSubmatch(uri); res != nil {
		if (res[1] == `ldap`) {
			var port string
			if res[4] != "" {
				port = res[4]
			} else {
				port = "389"
			}
			net = "tcp"
			address = res[3] + ":" + port
		} else if (res[1] == `ldaps`) {
			var port string
			if res[4] != "" {
				port = res[4]
			} else {
				port = "639"
			}
			net = "tcp"
			address = res[3] + ":" + port
			ssl = true
		} else if (res[1] == `ldapi`) {
			net = "unix"
			address = res[2]
		}
	}
	return
}

func FilterGroupCond(username string) string {
	group_cond := ""
	usr, err := user.Lookup(username)
	if err == nil {
		groups, err := usr.GroupIds()
		if err == nil {
			s := make([]string, len(groups))
			for i, gid := range groups {
				if grp, err := user.LookupGroupId(gid);
				    err == nil {
					s[i] = fmt.Sprintf("(sargonUser=%%%s)",
							   grp.Name)
				} else {
					s[i] = fmt.Sprintf("(sargonUser=%%#%s)",
							   gid)
				}
			}
			group_cond = strings.Join(s, "")
		}
	}
	return group_cond
}

func LdapEntryToACE(entry *ldap.Entry) access.ACE {
	var ace access.ACE
	ace.Id = entry.DN
	for _, attr := range entry.Attributes {
		switch attr.Name {
		case `sargonUser`:
			ace.User = attr.Values
		case `sargonHost`:
			ace.Host = attr.Values
		case `sargonAllow`:
			ace.Allow = attr.Values
		case `sargonDeny`:
			ace.Deny = attr.Values
		case `sargonOrder`:
			n, err := strconv.Atoi(attr.Values[0])
			if err == nil {
				ace.Order = n
			}
		case `sargonMount`:
			ace.Mount = attr.Values
		case `sargonAllowPrivileged`:
			ace.AllowPriv = new(bool)
			*ace.AllowPriv = attr.Values[0] == "TRUE"
		case `sargonMaxMemory`:
			n, err := access.ConvSize(attr.Values[0])
			if err == nil {
				ace.MaxMemory = &n
			}
		case `sargonMaxKernelMemory`:
			n, err := access.ConvSize(attr.Values[0])
			if err == nil {
				ace.MaxKernelMemory = &n
			}
		case `sargonAllowCapability`:
			ace.AllowCapability = attr.Values
		}
	}
	return ace
}

func matchStr(r bool) string {
	if r {
		return "MATCH!"
	} else {
		return "no match"
	}
}

func MatchHost(hostname, username string) (result bool) {
	diag.Debug("checking %s %s\n", hostname, username)
	if hostname == `ALL` {
		result = true
	} else if myhostname, err := os.Hostname(); err == nil {
		if (string(hostname[0]) == `+`) {
			ar := strings.Split(myhostname, ".")
			myhost := ar[0]
			mydomain := strings.Join(ar[1:], ".")
			diag.Debug("myhost=%s, mydomain=%s\n",myhost,mydomain)
			result = InNetgroup(string(hostname[1:]), myhost,
					           username, mydomain)
		} else {
			result = strings.ToLower(hostname) == strings.ToLower(myhostname)
		}
	}
	diag.Debug("checking %s %s - %s\n", hostname, username, matchStr(result))
	return 
}

func ExpandUser(ace *access.ACE, usr *user.User) {
	re := regexp.MustCompile(`\$(((\w+)\b)|\{\w+\})`)
	for i, mp := range ace.Mount {
		ace.Mount[i] = re.ReplaceAllStringFunc(mp,
			func (kw string) string {
				switch kw {
				case `$uid`,`${uid}`:
					return usr.Uid
				case `$gid`,`${gid}`:
					return usr.Gid
				case `$name`,`${name}`:
					return usr.Username
				case `$home`,`${home}`,`$dir`,`${dir}`:
					return usr.HomeDir
				}
				return `$` + kw
			})
		if mp != ace.Mount[i] {
			diag.Debug("expand %s => %s\n", mp, ace.Mount[i]);
		}
	}
}

func FilterLdapEntriesToACL(entries []*ldap.Entry, username string) access.ACL {
	acl := access.NewSargonACL(len(entries))
	i := 0
	usr, err := user.Lookup(username)
	if err != nil {
		if _, ok := err.(user.UnknownUserError); ok {
			diag.Debug("no such system user: %s\n", username);
		} else {
			diag.Error("can't get user record for %s\n", username);
		}
	}
	for _, ent := range entries {
		t := LdapEntryToACE(ent)
		var match bool
		if len(t.Host) == 0 {
			match = true
		} else {
			match = false
			for _, hostname := range t.Host {
				if match = MatchHost(hostname, username); match {
					break
				}
			}
		}
		if match {
			if err == nil {
				ExpandUser(&t, usr)
			}
			acl[i] = t
			i += 1
		}
	}
	acl = acl[0:i]
	sort.Stable(acl)
	return acl
}

func NewTlsConfig(cf LdapConfig) (tlsconf *tls.Config, ok bool) {
	tlsconf = &tls.Config{}
	ok = true

	switch cf["tls_reqcert"] {
	case `never`,`allow`:
		tlsconf.InsecureSkipVerify = true
	case `demand`,`try`: // FIXME: `try` should be handled separately
		tlsconf.InsecureSkipVerify = false
	}

	// Set random source
	if randfile, prs := cf["tls_randfile"]; prs {
		file, err := os.Open(randfile)
		if err == nil {
			defer file.Close()
			tlsconf.Rand = file
		} else {
			diag.Error("can't open tls_randfile %s: %s\n",
				    randfile,
				    err.Error())
			diag.Error("using default instead\n")
		}
	}

	// Set the client certificate
	crtfile, crtprs := cf["tls_cert"]
	keyfile, keyprs := cf["tls_key"]
	if crtprs && keyprs {
		crt, err := tls.LoadX509KeyPair(crtfile, keyfile)
		if err == nil {
			tlsconf.Certificates = []tls.Certificate{crt}
		} else {
			diag.Error("can't set client certificate: %s\n",
				    err.Error())
		}
	}

	cacert, cacertprs := cf["tls_cacert"]
	cacertdir, cacertdirprs := cf["tls_cacertdir"]
	if cacertprs || cacertdirprs {
		tlsconf.RootCAs = x509.NewCertPool()
	}
	if cacertprs {
		file, err := ioutil.ReadFile(cacert)
		if err == nil {
			if !tlsconf.RootCAs.AppendCertsFromPEM(file) {
				diag.Error("failed to load any certificates from %s\n",
					cacert)
			}
		} else {
			diag.Error("can't read tls_cacert %s: %s",
				    cacert,
				    err.Error())
			ok = false
		}
	}

	if cacertdirprs {
		files, err := ioutil.ReadDir(cacertdir)
		if err != nil {
			diag.Error("failed to read directory %s: %s",
				    cacertdir,
				    err.Error())
			ok = false
		}
		for _, file := range files {
			if file.Mode().IsRegular() {
				filename := filepath.Join(cacertdir, file.Name())
				file, err := ioutil.ReadFile(filename)
				if err == nil {
					if !tlsconf.RootCAs.AppendCertsFromPEM(file) {
						diag.Error("failed to load any certificates from %s\n",
							filename)
					}
				} else {
					diag.Error("can't read certificate file %s: %s",
						    filename,
						    err.Error())
				}
			}
		}
	}

	/* FIXME:
	if ciphers, prs := cf["tls_cipher_suite"]; prs {
		tlsconf.CipherSuites = ...
	}
	*/

	return
}

func (srg *Sargon) FindUser (username string) (access.ACL, error) {
	diag.Debug("Looking up user %s\n", username)
	cf := LdapConfig{}
	err := cf.ReadPath(srg.LdapConf)
	if err != nil {
		return nil, err
	}

	net, addr, ssl := uriToNetAddr(cf[`uri`])
	if net == "" {
		diag.Error("can't parse URI\n")
		return nil, errors.New("invalid LDAP URI")
	}

	var l *ldap.Conn

	diag.Debug("Connecting to LDAP at %s://%s", net, addr)
	if ssl {
		tlsconf, _ := NewTlsConfig(cf)
		l, err = ldap.DialTLS(net, addr, tlsconf)
	} else {
		l, err = ldap.Dial(net, addr)
	}

	if err != nil {
		diag.Error("can't connect to LDAP: %s\n", err.Error())
		return nil, err
	}
	defer l.Close()

	if srg.LdapTLS {
		tlsconf, _ := NewTlsConfig(cf)

		err := l.StartTLS(tlsconf)
		if err != nil {
			diag.Error("can't start TLS session: %s\n", err.Error())
			return nil, err
		}
	}

	user := srg.LdapUser
	if user == "" {
		user = cf["binddn"]
	}
	passwd := srg.LdapPass
	if passwd == "" {
		if pwfile := cf["bindpwfile"]; pwfile != "" {
			pw, err := ioutil.ReadFile(pwfile)
			if err == nil {
				passwd = string(pw)
			} else {
				diag.Error("can't read password file %s: %s\n",
					pwfile,
					err.Error())
				return nil, err
			}
		}
	}

	err = l.Bind(user, passwd)
	if err != nil {
		diag.Error("can't bind as %s: %s\n", srg.LdapUser, err.Error())
		return nil, err
	}

	group_cond := FilterGroupCond(username)
	// The following schizophrenic notation means just "%Y%m%d%H%M%S.0Z".
	t := time.Now().UTC().Format("20060102150405") + ".0Z"
	filter := fmt.Sprintf(
		"(&(objectClass=sargonACL)" +
		"(|(sargonUser=%s)(sargonUser=ALL)%s)" +
		"(|(!(sargonNotAfter=*))(sargonNotAfter>=%s))" +
		"(|(!(sargonNotBefore=*))(sargonNotBefore<=%s)))",
		username,
		group_cond,
		t,
		t)

	scope := ldap.ScopeWholeSubtree
	if kw, prs := cf[`scope`]; prs {
		switch strings.ToLower(kw) {
		case `sub`:
			scope = ldap.ScopeWholeSubtree
		case `one`:
			scope = ldap.ScopeSingleLevel
		case `base`:
			scope = ldap.ScopeBaseObject
		}
	}

	deref := ldap.NeverDerefAliases
	if kw, prs := cf[`deref`]; prs {
		switch strings.ToLower(kw) {
		case `never`:
			deref = ldap.NeverDerefAliases
		case `searching`:
			deref = ldap.DerefInSearching
		case `finding`:
			deref = ldap.DerefFindingBaseObj
		case `always`:
			deref = ldap.DerefAlways
		}
	}

	diag.Debug("using filter %s\n", filter)
	req := ldap.NewSearchRequest(
		cf[`base`],
		scope,
		deref,
		0,
		0,
		false,
		filter,
		[]string{
			"dn",
			"sargonUser",
			"sargonHost",
			"sargonAllow",
			"sargonDeny",
			"sargonOrder",
			"sargonMount",
			"sargonAllowPrivileged",
			"sargonMaxMemory",
			"sargonMaxKernelMemory",
			"sargonAllowCapability",
		},
		nil)
	sr, err := l.Search(req)
	if err != nil {
		diag.Error("search request failed: %s\n", err.Error())
		return nil, err
	}

	return FilterLdapEntriesToACL(sr.Entries, username), nil
}
