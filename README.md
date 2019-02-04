# Sargon

Sargon is a docker authorization plugin that controls container creation.
It enables the administrator to excercise control over the containers that
users are allowed to create and decide whether to permit creation of
privileged containers, what parts of the host file system can be visible
to containers via bind or volume mechanism, what memory limits to apply,
etc.

## Building

After cloning, change to the source directory and run

```text
  dep init
  dep ensure
  go build
```

## Usage

When started, the program reads its configuration file, disconnects iself
from the controlling terminal and continues running in the background. Error
reporting goes to the syslog facility `daemon`. The following options are
recognized:

* `-foreground`

  Run in the foreground. Send diagnostic output to the stderr.
  
* `-config=`*FILE*

  Read configuration from *FILE* instead of the default
  `/etc/docker/sargon.json`

* `-debug`

  Enable verbose debugging output

In order to configure docker to consult sargon when creating new containers,
add the following option to its command line:

```text
  --authorization-plugin=sargon
```

## Configuration  

Sargon configuration is kept in JSON format in file `/etc/docker/sargon`.
The following keywords are recognized:

* `pidfile`

  Name of the PID file. Defaults to `/var/run/sargon.pid`.

* `LdapConf`

  Colon-separated list of LDAP configuration files to look for. The first of
  them that exists will be read. Default is
  `/etc/ldap.conf:/etc/ldap/ldap.conf:/etc/openldap/ldap.conf`

* `LdapUser`

  Bind to LDAP using this DN. Defaults to empty string.

* `LdapPass`

  Bind to LDAP with this password. Defaults to empty string.

* `AnonymousUser`

  If docker connection is not authenticated, use this string as the user name.

## LDAP object

FIXME
  
