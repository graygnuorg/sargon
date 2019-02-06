package main

import (
	"os"
	"os/user"
	"bufio"
	"regexp"
	"strings"
	"gopkg.in/ldap.v2"
	"crypto/tls"
	"crypto/x509"
	"log"
	"fmt"
	"sort"
	"strconv"
	"io/ioutil"
	"path/filepath"
	"errors"
)

var (
	commentRe = regexp.MustCompile(`^\s*#`)
	settingRe = regexp.MustCompile(`^\s*(\S+)\s+(.+)$`)
	ldapURIRe = regexp.MustCompile(`^(ldap[is]?)://((.+)(?::(.+))?)$`)
)

func ReadLDAPConf(filename string) (map[string]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	debug("reading file %s\n", filename)
	scanner := bufio.NewScanner(file)
	conf := make(map[string]string)
	for scanner.Scan() {
		s := scanner.Text()
		if commentRe.FindStringSubmatch(s) != nil {
			continue
		}
		if res := settingRe.FindStringSubmatch(s); res != nil {
			conf[strings.ToLower(res[1])] = res[2]
		}
	}
	return conf, nil
}

func ReadLDAPConfPath() (map[string]string, error) {
	for _, file := range strings.Split(config.LdapConf, `:`) {
		ldapcf, err := ReadLDAPConf(file)
		if ldapcf != nil {
			return ldapcf, nil
		} else if os.IsNotExist(err) {
			continue
		} else {
			return nil, err
		}
	}
	return make(map[string]string), nil
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

func LdapEntryToACE(entry *ldap.Entry) SargonACE {
	var ace SargonACE
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
			n, err := ConvSize(attr.Values[0])
			if err == nil {
				ace.MaxMemory = &n
			}
		case `sargonMaxKernelMemory`:
			n, err := ConvSize(attr.Values[0])
			if err == nil {
				ace.MaxKernelMemory = &n
			}
		case `sargonAllowCapability`:
			ace.AllowCapability = attr.Values
		}
	}
	return ace
}

func MatchHost(hostname, username string) bool {
	debug("checking %s %s\n", hostname, username)
	if myhostname, err := os.Hostname(); err == nil {
		if (string(hostname[0]) == `+`) {
			ar := strings.Split(myhostname, ".")
			myhost := ar[0]
			mydomain := strings.Join(ar[1:], ".")
			debug("myhost=%s, mydomain=%s\n",myhost,mydomain)
			return InNetgroup(string(hostname[1:]), myhost,
				username, mydomain)
		}
		if strings.ToLower(hostname) == strings.ToLower(myhostname) {
			return true
		}
	}
	return false
}

func FilterLdapEntriesToACL(entries []*ldap.Entry, username string) SargonACL {
	acl := NewSargonACL(len(entries))
	i := 0
	for _, ent := range entries {
		t := LdapEntryToACE(ent)
		m := false
		for _, hostname := range t.Host {
			if m = MatchHost(hostname, username); m {
				break
			}
		}
		if m {
			acl[i] = t
			i += 1
		}
	}
	acl = acl[0:i]
	sort.Stable(acl)
	return acl
}

func NewTlsConfig(cf map[string]string) (tlsconf *tls.Config, ok bool) {
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
			log.Println("can't open tls_randfile " +
				    randfile +
				    ": " +
				    err.Error())
			log.Println("using default instead")
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
			log.Println("can't set client certificate: " +
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
				log.Println("failed to load any certificates from " + cacert)
			}
		} else {
			log.Println("can't read tls_cacert " +
				    cacert +
				    ": " +
				    err.Error())
			ok = false
		}
	}

	if cacertdirprs {
		files, err := ioutil.ReadDir(cacertdir)
		if err != nil {
			log.Println("failed to read directory " +
				    cacertdir +
				    ": " +
				    err.Error())
			ok = false
		}
		for _, file := range files {
			if file.Mode().IsRegular() {
				filename := filepath.Join(cacertdir, file.Name())
				file, err := ioutil.ReadFile(filename)
				if err == nil {
					debug("LOADINGB")
					if !tlsconf.RootCAs.AppendCertsFromPEM(file) {
						log.Println("failed to load any certificates from " + filename)
					}
				} else {
					log.Println("can't read certificate file " +
						    filename +
						    ": " +
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

func FindUser (username string) (SargonACL, error) {
	debug("Looking up user %s\n", username)
	cf, err := ReadLDAPConfPath()
	if err != nil {
		return nil, err
	}

	net, addr, ssl := uriToNetAddr(cf[`uri`])
	if net == "" {
		log.Println("can't parse URI")
		return nil, errors.New("invalid LDAP URI")
	}

	var l *ldap.Conn

	if ssl {
		tlsconf, _ := NewTlsConfig(cf)
		l, err = ldap.DialTLS(net, addr, tlsconf)
	} else {
		l, err = ldap.Dial(net, addr)
	}

	if err != nil {
		log.Println("can't connect to LDAP: " + err.Error())
		return nil, err
	}
	defer l.Close()

	if config.LdapTLS {
		tlsconf, _ := NewTlsConfig(cf)

		err := l.StartTLS(tlsconf)
		if err != nil {
			log.Println("can't start TLS session: " + err.Error())
			return nil, err
		}
	}

	user := config.LdapUser
	if user == "" {
		user = cf["binddn"]
	}
	passwd := config.LdapPass
	if passwd == "" {
		if pwfile := cf["bindpwfile"]; pwfile != "" {
			pw, err := ioutil.ReadFile(pwfile)
			if err == nil {
				passwd = string(pw)
			} else {
				log.Fatal("can't read password file " + pwfile + ": " + err.Error())
				return nil, err
			}
		}
	}

	err = l.Bind(user, passwd)
	if err != nil {
		log.Println("can't bind as " + config.LdapUser +
			    ": " + err.Error())
		return nil, err
	}

	group_cond := FilterGroupCond(username)
	filter := fmt.Sprintf("(&(objectClass=sargonACL)(|(sargonUser=%s)(sargonUser=ALL)%s))",
			      username,
			      group_cond)
	debug("using filter %s\n", filter)
	req := ldap.NewSearchRequest(
		cf[`base`],
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
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
		log.Println("search request failed: " + err.Error())
		return nil, err
	}

	return FilterLdapEntriesToACL(sr.Entries, username), nil
}
