package server

import (
	"encoding/json"
	"io/ioutil"
	"log"
)

type Sargon struct {
	PidFile   string `json:"PidFile"`
	LdapConf string `json:"LdapConf"`
	LdapUser string `json:"LdapUser"`
	LdapPass string `json:"LdapPassword"`
	LdapTLS bool `json:"LdapTLS"`
	AnonymousUser string `json:AnonymousUser"`
}

func (srg *Sargon) ReadConfig(f string) {
	raw, err := ioutil.ReadFile(f)
	if err != nil {
		log.Fatal(err.Error())
	}
	json.Unmarshal(raw, srg)
}

