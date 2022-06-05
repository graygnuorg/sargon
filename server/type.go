package server

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"sargon/access"
)

type Sargon struct {
	PidFile string
	LdapConf string
	LdapUser string
	LdapPass string
	LdapTLS bool
	AnonymousUser string
	ACL access.ACL
}

func (srg *Sargon) ReadConfig(f string) {
	raw, err := ioutil.ReadFile(f)
	if err != nil {
		log.Fatal(err.Error())
	}
	json.Unmarshal(raw, srg)
}

