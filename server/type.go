package server

import (
	"encoding/json"
	"io/ioutil"
	"log"
)

type Sargon struct {
	Pidfile   string `json:"pidfile"`
	LdapConf string `json:"ldapconf"`
	LdapUser string `json:"ldapuser"`
	LdapPass string `json:"ldappassword"`
	LdapTLS bool `json:"ldaptls"`
	AnonymousUser string `json:anonymoususer"`
}

func (srg *Sargon) ReadConfig(f string) {
	raw, err := ioutil.ReadFile(f)
	if err != nil {
		log.Fatal(err.Error())
	}
	json.Unmarshal(raw, srg)
}

