package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"net/url"
	"github.com/docker/go-plugins-helpers/authorization"
	"github.com/docker/engine-api/types/container"
)	

type sargon struct {
}

func newPlugin() (*sargon, error) {
	return &sargon{}, nil
}

type createRequest struct {
	*container.Config
	HostConfig       *container.HostConfig
}

func (p *sargon) AuthZReq(req authorization.Request) authorization.Response {

	uri, err := url.QueryUnescape(req.RequestURI)
	if err != nil {
		return authorization.Response{Err: err.Error()}
	}

	// Remove query parameters
	uri = (strings.SplitN(uri,"?",2))[0];

	if req.User == "" {
		req.User = config.AnonymousUser
	}
	
	debug("checking %s request to %s from user %s\n",
              req.RequestMethod, uri, req.User)

	action := GetAction(req.RequestMethod, uri)
	acl, err := FindUser(req.User)
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
		
		if res, msg := acl.AllowCreate(body, &config, req.User);
		   res == false {
			debug("DENY: %s\n", msg)
			return authorization.Response{Msg: msg}
	 	}
	}

	return authorization.Response{Allow: true}
}

func (p *sargon) AuthZRes(req authorization.Request) authorization.Response {
	return authorization.Response{Allow: true}
}

