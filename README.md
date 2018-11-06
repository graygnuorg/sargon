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

* `mount`

  A list of directories on the file system, from which it is allowed
  to bind subdirectories to the containers being created. By default
  it is empty, meaning that binds are not allowed at all.

* `allowpriv`

  Allow the use of privileged containers. Defaults to `false`.

* `MaxMemory`

  Maximum memory limit allowed to use when starting containers. Users
  will have to use --memory=N option with N lower than or equal to this
  value.

* `MaxKernelMemory`

  Ditto for kernel memory limit (see the `--kernel-memory` option to
  `docker run`).

* `AllowCapAdd`

  A list of Linux capabilities that are allowed for use in `--cap-add`
  option. See capabilities(7) for a list of capability names. Names can
  be listed with or without the `CAP_` prefix. Name matching is case-
  insensitive.
  
## Example

The following configuration allows users to bind only subdirectories located
under `/var/lib/mounts` and `/mnt`:

```json
{
    "pidfile":"/var/run/sargon.pid" ,
    "mount":[ "/var/lib/mounts", "/mnt" ]
}
```

  
