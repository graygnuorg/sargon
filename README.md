# Sargon

Sargon authorizes requests to a `dockerd` daemon using access control
lists defined in a LDAP database or in its configuration file.

Used with due proficiency, Sargon mitigates security risks that appear when
running `dockerd` in a multi-user environment.

## Installation

### Building

After cloning the repository, change to the source directory and run

```sh
 make
```

To install the created binary, run (as root):

```sh
 make install
```

By default, the *sargon* binary is installed to `/usr/local/bin`.  To
select another installation directory, use the `BINDIR` or `PREFIX`
variable.  The `BINDIR` variable specifies the directory to install
*sargon* to.  E.g. to install it to `/usr/bin`, do

```sh
 make install BINDIR=/usr/bin
```

Alternatively, you may use the `PREFIX` variable, which specifies the
directory where `bin` is located, e.g.:

```sh
 make install PREFIX=/usr
``` 

### Create the configuration file

Sargon provides sufficiently sane defaults that allow it to be run
without explicit configuration file.  These defaults are:

1. Upon startup, the PID of the running process is stored in file `/var/run/sargon.pid`.

2. ACLs are stored in an LDAP database.

3. The LDAP configuration file is looked up in the following locations:

  * `/etc/ldap.conf`
  * `/etc/ldap/ldap.conf`
  * `/etc/openldap/ldap.conf`

4. Anonymous user name is `ANONYMOUS`.

If these don't suit your needs, create the file `/etc/docker/sargon.json`.
Using the [configuration file description](#user-content-configuration),
edit the Sargon settings to your liking.

The above defaults correspond to the following `sargon.json` file:

```json
{
    "PidFile":"/var/run/sargon.pid",
    "LdapConf":"/etc/ldap.conf:/etc/ldap/ldap.conf:/etc/openldap/ldap.conf",
    "AnonymousUser":"ANONYMOUS"
}
```

In the discussion below we assume you will be using the LDAP database to
store Sargon ACLs.  If it's not the case and your intent is to keep all ACLs
in the configuration file and disable LDAP altogether, use the following
configuration file:

```json
{
    "LdapConf":""
}
```

(setting `LdapConf` to an empty string disables LDAP).

In this case you can skip the section that follows.

### Configure the LDAP database

Include the Sargon schema into your `slapd` configuration.  

Most `slapd` installations nowadays use [dynamic configuration
system](https://www.openldap.org/doc/admin24/slapdconf2.html).  In
that case, import the `sargon.ldif` file into your configuration:

```sh
 ldapadd -f sargon.ldif
```

Depending on your setup, you may need additional options to `ldapadd`

If using the [legacy configuration](https://www.openldap.org/doc/admin24/slapdconfig.html), 
copy the file `sargon.schema` to the schema subdirectory of your `slapd`
configuration directory.  Depending on the installation, it is
`/etc/openldap/schema` or `/etc/ldap/schema`.  Include it in your
`slapd` configuration, by adding the following statement to your
`slapd.conf`:

```conf
 include         /etc/openldap/schema/sargon.schema
```

Restart `slapd`.

Create the root object for Sargon ACL hierarchy:

```sh
ldapadd <<EOF
dn: ou=sargon,dc=example,dc=com
objectClass: organizationalUnit
ou: sargon
description: root for Sargon (Docker ACL) objects.
EOF
```

<a name="default-policy"></a>
Create the default policy entry.  It's an ACL entry that will be used
when no other object matches the request.  The built-in Sargon
defaults are very (perhaps even overly) strict, that's why such an
entry is needed so that you can continue using docker while building
and tuning your ACLs:

```sh
ldapadd <<EOF
dn: cn=default-policy,ou=sargon,dc=example,dc=com
cn: default-policy
objectClass: sargonACL
sargonUser: ANONYMOUS
sargonAllow: ALL
sargonOrder: 100
EOF
```

(don't forget to replace `dc=example,dc=org` with your actual base dn.)

This entry allows anonymous users to issue any docker requests.  The
`sargonOrder` attribute ensures it will be placed at 
the end of the [constructed access control list](#user-content-request-processing).

Of course it is only a minimal example.  You can modify this entry as
needed or even remove it altogether.

An alternative to keeping the default in the LDAP database is storing it
in the configuration file.

### Storing ACLs in the configuration file

If you prefer to keep the default policy entry, or even entire ACL, in
the configuration file, use the `ACL` attribute.  The value of this
attribute is a list of access control entries stored as JSON object.
For example, the default policy discussed above is stored in the
configuration file as:

```json
{
    "ACL":[
      {
          "Id":"default policy",
	  "User":["ANONYMOUS"],
	  "Allow":["ALL"],
	  "Order":100
      }
    ]
}
```

The rules for converting ACL objects from LDAP to JSON are:

1. Replace `cn` attribute with `Id`.
2. Replace each `sargon*` attribute with its name without the `sargon`
   prefix.  E.g. `sargonUser` becomes `User`, etc.  Notice that LDAP
   attribute names are case-insensitive, whereas JSON attribute names
   aren't.  Use the [canonical attribute names](#user-content-acls)
   when performing conversion.
3. Use scalar value if attribute is marked as _(single)_ in the
   [attribute list](#user-content-acls), otherwise use array.
4. Upper-case `TRUE` and `FALSE` become lower-case (e.g. for
   the [`sargonAllowPrivileged`](#user-content-sargonAllowPrivileged)
   attribute).
5. Ensure proper ordering of objects in the `ACL` array, either by
   using `Order` attributes or by explicitly ordering the entries.
   Remember that Sargon will use the first entry that matches the
   request.
   
### Configure Docker to use Sargon

Add the following option to your `dockerd` command line:

```sh
  --authorization-plugin=sargon
```

The exact place for it depends on how `dockerd` is started on your
system.  If your system uses `systemd` (which is the case for most
modern GNU/Linux distributions, such as Ubuntu, Debian, etc), first
extract the actual `dockerd` command line:

```sh
systemctl show --property=ExecStart --value docker | sed -e 's/.*argv\[\]=//' -e 's/;.*//'
```

Then run

```sh
systemctl edit docker
```

In the text editor it starts, type the following:

```text
[Service]
ExecStart=
ExecStart=COMMAND --authorization-plugin=sargon
```

where _COMMAND_ is the command line you obtained in the previous step.
Notice the empty `ExecStart=` at the start of the section.  It is
mandatory.

Save your changes and exit the editor.

### Adding your first ACL entry

To illustrate the effect of Sargon ACLs on docker, let's add to the
LDAP database an object that will control what directories anonymous
users are allowed to mount in containers.  Using your editor, create
the following `ldif` file:

```ldif
dn: cn=anon,ou=sargon,dc=example,dc=com
cn: anon
objectClass: sargonACL
sargonUser: ANONYMOUS
sargonMount: /var/lib/mounts/*
```

The `sargonUser` attribute declares that this entry applies to
anonymous users only.  The `sargonMount` attribute says that only
subdirectories of `/var/lib/mounts` on host machine are allowed to be
mounted in containers.

Add your changes to the database:

```sh
 ldapadd -f file.ldif
```

Now, if you try to run

```sh
 docker run -v /etc:/usr/local/etc debian:10
```

you will get the following error:

```text
docker: Error response from daemon: authorization denied by plugin sargon: mounting /etc is not allowed.
```

If `sargon` is running in trace mode (`--trace` option), you will see
the following in its logs:

```text
[TRACE] ANONYMOUS: binding to /etc is rejected by default policy
```

On the other hand, running

```sh
 docker run -v /var/lib/mounts/src:/usr/src debian:10
```

will succeed.  Sargon trace in this case will contain:

```text
[TRACE] ANONYMOUS: binding to /var/lib/mounts/src is accepted by cn=anon,ou=sargon,dc=example,dc=com
```

## Usage

When started, the program reads its configuration file, disconnects itself
from the controlling terminal and continues running in the background. Error
reporting goes to the syslog facility `daemon`. Both short
(single-dash) and GNU-style long (double-dash) options are supported.
The following options are recognized:

* `-f`, `--foreground`

  Run in the foreground. Send diagnostic output to the stderr.
  
* `-c`, `-config=`*FILE*

  Read configuration from *FILE* instead of the default
  `/etc/docker/sargon.json`

* `-t`, `--trace`

  Trace ACL entries and their effect.

* `-d`, `--debug`

  Enable verbose debugging output.

* `-h`, `--help`

  Produce a short command line usage summary and exit.

* `-v`, `--version`

  Print program version, short copying information, and exit.

## Configuration  

Sargon configuration is kept in JSON format in file `/etc/docker/sargon.json`.
The following keywords are recognized:

* `PidFile`

  Name of the PID file. Defaults to `/var/run/sargon.pid`.

* `LdapConf`

  Colon-separated list of LDAP configuration files to look for. The first of
  them that exists will be read. The default is
  `/etc/ldap.conf:/etc/ldap/ldap.conf:/etc/openldap/ldap.conf`

  To disable LDAP, set this attribute to an empty string.

* `LdapUser`

  Bind to LDAP using this DN. Defaults to empty string.
  This value overrides the `binddn` setting in `ldap.conf` file, which
  is the preferred way of configuring bind DN.

* `LdapPass`

  Bind to LDAP with this password. Defaults to empty string.
  This value overrides the password obtained from the `bindpwfile`
  setting in `ldap.conf` file.

* `LdapTLS`

  If `true`, start LDAP TLS session.

* `AnonymousUser`

  If docker connection is not authenticated, use this string as the user name.

* `ACL`

  A list of ACL entries stored in [JSON format](#user-content-storing-acls-in-the-configuration-file).  This list will be appended to the list [obtained from LDAP](#user-content-acls)
  before final sorting of entries, or used alone if LDAP database is
  disabled or is unreachable. This makes it useful for storing [default policies](#user-content-default-policy).
  
## The `ldap.conf` file

After reading its main configuration file, *sargon* scans the LDAP
configuration path (see the `LdapConf` variable above). The first file that
exists and is readable is read. The format of the file is described in
detail in [ldap.conf(5)](https://www.openldap.org/software/man.cgi?query=ldap.conf).
The following keywords are recognized:

* `URI` ldap[si]://[name[:port]]

  URI of an LDAP server to which *sargon* should connect.
  
* `BASE` _base_

  Specifies the default base DN to use when performing ldap queries.
  
* `BINDDN` _dn_

  Specifies the default bind DN to use when performing ldap operations.

* `BINDPWFILE` _filename_

  Use the content of _filename_ as the password for simple
  authentication.  Note, that the file is read verbatim and is not parsed
  in any way.  In particular, beware of trailing newlines.

* `TLS_CACERT` _filename_

  Specifies the file that contains certificates for all of the Certificate
  Authorities the client will recognize.
  
* `TLS_CACERTDIR` _dirname_

  Specifies  the path of a directory that contains Certificate Authority
  certificates in separate individual files.
  The `TLS_CACERT` is always used before `TLS_CACERTDIR`.
  
* `TLS_CERT` _filename_

  Specifies the file that contains client certificate.

* `TLS_KEY` _filename_

  Specifies the file that contains the private key for the
  certificate stored in the TLS_CERT file.
  
* `TLS_RANDFILE` _filename_

  Specifies the file to obtain random bits from, instead of the default
  `/dev/urandom` or `/dev/random`.
  
* `TLS_REQCERT` _level_

  Specifies  what  checks to perform on server certificates in a TLS session,
  if any. The _level_ is one of: `never`, `allow`, `try`, `demand`, or
  `try`.
  
## ACLs

Privileges for docker users are defined in the LDAP database in form of
`sargonACL` objects. Each such object defines privileges for a set of
users performing certain docker action on a set of servers. Each `sargonACL`
object must have the `cn` attribute, uniquely identifying the object.
It may also have one or more of the following attributes. Except as marked
with _(single)_, multiple attribute instances are allowed.

* `sargonUser`

  User to whom this entry applies. If the value begins with a percent
  sign, the rest of characters is treated as the name of a
  user group and the entry applies to all users in this group.

<a name="sargonHost"></a>
* `sargonHost`

  Host on which this entry takes effect. If the value starts with a plus
  sign, it is treated as the name of the NIS netgroup.

<a name="sargonAllow"></a>
* `sargonAllow`

  Allowed action. The value must be one of the docker [action keywords](#user-content-actions), or the word `ALL` (uppercase) matching all actions.
  
<a name="sargonDeny"></a>
* `sargonDeny`

  Denied action. The value must be one of the docker [action keywords](#user-content-actions), or the word `ALL` (uppercase) matching all actions. See [below](#user-content-request-processing) for a detailed discussion on how `sargonAllow` and `sargonDeny` policies operate.

<a name="sargonOrder"></a>
* `sargonOrder` _(single)_

  An integer used to order multiple `sargonACL` entries. If not present, 0
  is assumed.

<a name="sargonMount"></a>
* `sargonMount`

  Name of the directory on the host filesystem that is allowed for
  mounting inside a container.  The value of this attribute is treated
  as a _globbing pattern_.  Before use, it undergoes _variable expansion_: any
  variable references in form `$`_V_ or `${`_V_`}` are replaced with the
  actual value of variable _V_. The following variables are defined:

  | Variable   | Expands to |
  | ---------- | ---------- |
  | `uid`      | User ID    |
  | `gid`      | Group ID   |
  | `name`     | User name  |
  | `home` or `dir` | Home directory |

  Undefined variables are left unexpanded.

  For example:

  * `sargonMount:/var/lib/mounts`

    Allow to mount only `/var/lib/mounts`

  * `sargonMount:/var/lib/mounts/*`

    Allow to mount any directories under `/var/lib/mounts`

  The value can end with a list of _flags_ in parentheses.  The
  following flags are recognized:

  * `ro`

    Allow read-only mounting.  Attempts to mount the directory for
    writing will be rejected.

  * `globlex`
  
    Use _lexical globbing_: the `*` wildcard matches any sequence of
    characters, including directory separators (slashes) and the `?`
    wildcard matches any character, including slash.  This is the
    default.

  * `globpath`

    Use _pathname globbing_: `*` and `?` don't match slash.

  * `globstar`

    Use _star globbing_.  As with `globpath` neither `*` nor `?` will
    match a slash character.  The `**` wildcard is provided, which
    matches zero or more arbitrary characters, including slashes.

  Some more examples:

  * `sargonMount:/var/lib/mounts/*(ro,globpath)`

    Allow to mount only subdirectories of `/var/lib/mounts` and only
    for reading.

  * `sargonMount:/var/*/mounts/**(globstar)`

    Allow to mount directories located at any depth under the `mounts`
    directory in any subdirectory of `/var`.  Thus, mounting
    `/var/lib/mounts/foo/bar` will be allowed, whereas mounting
    `/var/lib/sub/mounts/foo/bar` will not.
  
<a name="sargonAllowPrivileged"></a>
* `sargonAllowPrivileged` _(single)_

  The word `TRUE` if the object allows creation of privileged containers.
  `FALSE` otherwise.

<a name="sargonMaxMemory"></a>
* `sargonMaxMemory` _(single)_

  Maximum size of the memory the container is allowed to use. The value is
  an integer optionally suffixed with `K`, `M`, or `G` (case-insensitive).
  
<a name="sargonMaxKernelMemory"></a>
* `sargonMaxKernelMemory` _(single)_

  Limit on kernel memory usage. The value is an integer optionally suffixed
  with `K`, `M`, or `G` (case-insensitive).

<a name="sargonAllowCapability"></a>
* `sargonAllowCapability`

  Name of the linux capability that is allowed to use with the `--cap-add`
  docker option. See [capabilities(7)](http://man7.org/linux/man-pages/man7/capabilities.7.html), for a list of capability names.
  Names listed in this attribute are case-insensitive. The `CAP_` prefix is
  optional.

<a name="sargonNotBefore"></a>
* `sargonNotBefore`

  A timestamp in the form `yyyymmddHHMMSSZ` that provides a start date/time
  for when this entry will be valid. Notice, that the timestamp must be in
  UTC.

* `sargonNotAfter`

  A timestamp in the form `yyyymmddHHMMSSZ` that provides an expiration
  date/time after which this entry ceases to be valid. Notice, that the
  timestamp must be in UTC.

## Actions

The following values can be used in `sargonAllow` and `sargonDeny` attributes:

* `BuildPrune`
  Delete builder cache.

* `ConfigCreate`
  Create a config.

* `ConfigDelete`
  Delete a config.

* `ConfigInspect`
  Inspect a config.

* `ConfigList`
  List configs.

* `ConfigUpdate`
  Update a config.

* `ContainerArchive`
  Get an archive of a filesystem resource in a container.

* `ContainerArchiveInfo`
  Get information about files in a container.

* `ContainerAttach`
  Attach to a container.

* `ContainerAttachWebsocket`
  Attach to a container via a websocket.

* `ContainerChanges`
  Get changes on a container’s filesystem.

* `ContainerCreate`
  Create a container.

* `ContainerDelete`
  Remove a container.

* `ContainerExec`
  Create an exec instance.

* `ContainerExport`
  Export a container.

* `ContainerInspect`
  Inspect a container.

* `ContainerKill`
  Kill a container.

* `ContainerList`
  List containers.

* `ContainerLogs`
  Get container logs.

* `ContainerPause`
  Pause a container.

* `ContainerPrune`
  Delete stopped containers.

* `ContainerRename`
  Rename a container.

* `ContainerResize`
  Resize a container TTY.

* `ContainerRestart`
  Restart a container.

* `ContainerStart`
  Start a container.

* `ContainerStats`
  Get container stats based on resource usage.

* `ContainerStop`
  Stop a container.

* `ContainerTop`
  List processes running inside a container.

* `ContainerUnpause`
  Unpause a container.

* `ContainerUpdate`
  Update a container.

* `ContainerWait`
  Wait for a container.

* `DistributionInspect`
  Get image information from the registry.

* `ExecInspect`
  Inspect an exec instance.

* `ExecResize`
  Resize an exec instance.

* `ExecStart`
  Start an exec instance.

* `GetPluginPrivileges`
  Get plugin privileges.

* `ImageBuild`
  Build an image.

* `ImageCommit`
  Create a new image from a container.

* `ImageCreate`
  Create an image.

* `ImageDelete`
  Remove an image.

* `ImageGet`
  Export an image.

* `ImageGetAll`
  Export several images.

* `ImageHistory`
  Get the history of an image.

* `ImageInspect`
  Inspect an image.

* `ImageList`
  List Images.

* `ImageLoad`
  Import images.

* `ImagePrune`
  Delete unused images.

* `ImagePush`
  Push an image.

* `ImageSearch`
  Search images.

* `ImageTag`
  Tag an image.

* `NetworkConnect`
  Connect a container to a network.

* `NetworkCreate`
  Create a network.

* `NetworkDelete`
  Remove a network.

* `NetworkDisconnect`
  Disconnect a container from a network.

* `NetworkInspect`
  Inspect a network.

* `NetworkList`
  List networks.

* `NetworkPrune`
  Delete unused networks.

* `NodeDelete`
  Delete a node.

* `NodeInspect`
  Inspect a node.

* `NodeList`
  List nodes.

* `NodeUpdate`
  Update a node.

* `PluginCreate`
  Create a plugin.

* `PluginDelete`
  Remove a plugin.

* `PluginDisable`
  Disable a plugin.

* `PluginEnable`
  Enable a plugin.

* `PluginInspect`
  Inspect a plugin.

* `PluginList`
  List plugins.

* `PluginPull`
  Install a plugin.

* `PluginPush`
  Push a plugin.

* `PluginSet`
  Configure a plugin.

* `PluginUpgrade`
  Upgrade a plugin.

* `PutContainerArchive`
  Extract an archive of files or folders to a directory in a container.

* `SecretCreate`
  Create a secret.

* `SecretDelete`
  Delete a secret.

* `SecretInspect`
  Inspect a secret.

* `SecretList`
  List secrets.

* `SecretUpdate`
  Update a Secret.

* `ServiceCreate`
  Create a service.

* `ServiceDelete`
  Delete a service.

* `ServiceInspect`
  Inspect a service.

* `ServiceList`
  List services.

* `ServiceLogs`
  Get service logs.

* `ServiceUpdate`
  Update a service.

* `Session`
  Initialize interactive session.

* `SwarmInit`
  Initialize a new swarm.

* `SwarmInspect`
  Inspect swarm.

* `SwarmJoin`
  Join an existing swarm.

* `SwarmLeave`
  Leave a swarm.

* `SwarmUnlock`
  Unlock a locked manager.

* `SwarmUnlockkey`
  Get the unlock key.

* `SwarmUpdate`
  Update a swarm.

* `SystemAuth`
  Check auth configuration.

* `SystemDataUsage`
  Get data usage information.

* `SystemEvents`
  Monitor events.

* `SystemInfo`
  Get system information.

* `SystemPing`
  Ping.

* `SystemVersion`
  Get version.

* `TaskInspect`
  Inspect a task.

* `TaskList`
  List tasks.

* `TaskLogs`
  Get task logs.

* `VolumeCreate`
  Create a volume.

* `VolumeDelete`
  Remove a volume.

* `VolumeInspect`
  Inspect a volume.

* `VolumeList`
  List volumes.

* `VolumePrune`
  Delete unused volumes.

## Request processing

When authorizing incoming requests, *sargon* uses the following
algorithm:

1. Create LDAP filter with the user name and the names of the groups the
   user belongs to.
   For example, if the requesting user name is `smt`, and this user is
   member of the groups `staff`, `docker`, and `wheel`, then the LDAP
   filter will be:

```text
      (&(objectClass=sargonACL)
        (|(sargonUser=smt)
          (sargonUser=ALL)
          (sargonUser=%staff)
          (sargonUser=%docker)
          (sargonUser=%wheel)))
```	  

   Notice, that (1) the filter string is split in multiple indented lines
   for readability, and (2) the filter normally contains conditions that
   control validity of the entry using the [`sargonNotBefore`](#user-content-sargonNotBefore) and
   `sargonNotAfter` attributes. These conditions are omitted for clarity.

2. Execute LDAP query, get the response.

3. Iterate over the returned `sargonACL` objects, selecting only those
   with the value of [`sargonHost`](#user-content-sargonHost)
   attribute matching the server hostname, or (if the value starts
   with `+`) with the netgroup that matches the `(host,user,domain)` triplet.

   To match the netgroup, the libc function [innetgr(3)](http://man7.org/linux/man-pages/man3/setnetgrent.3.html) is used.

4. Sort the remaining entries by the value of their
   [`sargonOrder`](#user-content-sargonOrder) attribute in ascending order.

5. Start with the first returned object.

6. If the requested docker action is explicitly listed in one of its
   [`sargonAllow`](#user-content-sargonAllow) attributes, go to step 9.

7. Otherwise, if the object has one or more
   [`sargonDeny`](#user-content-sargonDeny) attributes and one of
   these contains the requested action or the meta-action `ALL`,
   then deny the request.

8. Advance to the next object, and restart from step 6.

9. Unless the requested action is `ContainerCreate` or `VolumeCreate`,
   authorize the request.

10. For `VolumeCreate` requests, check if the requested mountpoint
    satisfies the [`sargonMount`](#user-content-sargonMount)
    attribute.  Authorize the request is so and reject it otherwise.

The steps below are followed when processing `ContainerCreate` requests
 
11. If creation of a privileged container is requested, consult the 
    [`sargonAllowPrivileged`](#user-content-sargonAllowPrivileged)
    attribute. If its value is `FALSE`, deny the request. Otherwise,
    advance to the next step.

12. If any additional linux capabilities are requested, check if all of
    them are listed in [`sargonAllowCapability`](#user-content-sargonAllowCapability)
    attributes. If not, deny the request.

13. Check the requested binds and mounts. Check each source directory against
    each [`sargonMount`](#user-content-sargonMount) attribute.  If the
    directory matches the attribute exactly, or if the attribute value
    ends with a `/*` and the source directory prefix matches the
    value, then the mount is allowed. Otherwise, the request is denied,

14. If the requested maximum memory is greater than the value of the
    [`sargonMaxMemory`](#user-content-sargonMaxMemory) attribute, the request is denied.

15. If the requested maximum kernel memory is greater than the value of the
    [`sargonMaxKernelMemory`](#user-content-sargonMaxKernelMemory)
    attribute, the request is denied.

16. Otherwise, the request is authorized.


