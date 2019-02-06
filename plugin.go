package main

import (
	"os"
	"fmt"
	"bytes"
	"encoding/json"
	"io/ioutil"
	"strings"
	"net/url"
	"github.com/docker/go-plugins-helpers/authorization"
	"github.com/docker/engine-api/types/container"
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
		fmt.Println(err.Error())
		os.Exit(1)
	}
	json.Unmarshal(raw, srg)
}

type createRequest struct {
	*container.Config
	HostConfig       *container.HostConfig
}

func (srg *Sargon) AuthZReq(req authorization.Request) authorization.Response {

	uri, err := url.QueryUnescape(req.RequestURI)
	if err != nil {
		return authorization.Response{Err: err.Error()}
	}

	// Remove query parameters
	uri = (strings.SplitN(uri,"?",2))[0];

	if req.User == "" {
		req.User = srg.AnonymousUser
	}
	
	debug("checking %s request to %s from user %s\n",
              req.RequestMethod, uri, req.User)

	action := GetAction(req.RequestMethod, uri)
	acl, err := srg.FindUser(req.User)
	if err != nil {
		return authorization.Response{Msg: "Autorization denied",
			                      Err: err.Error()}
	}

	debug("checking if action %s is allowed\n", action)
	ok, id := acl.ActionIsAllowed(action)
	trace("%s: action %s is %s by %s\n",
	      req.User, action, Resolution(ok), id)
	if !ok {
		return authorization.Response{Msg: "Action not allowed"}
	}

	if (action == "ContainerCreate") {
		debug("checking container parameters\n")
		body := &createRequest{}
		if err := json.NewDecoder(bytes.NewReader(req.RequestBody)).Decode(body); err != nil {
			return authorization.Response{Err: err.Error()}
		}
		
		if res, msg := acl.AllowCreate(body, req.User);
		   res == false {
			debug("DENY: %s\n", msg)
			return authorization.Response{Msg: msg}
	 	}
	}

	return authorization.Response{Allow: true}
}

func (srg *Sargon) AuthZRes(req authorization.Request) authorization.Response {
	return authorization.Response{Allow: true}
}

