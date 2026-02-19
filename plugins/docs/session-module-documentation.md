# inwx.collection.session module

Module for retrieving an INWX API session with two factor authentication

## Requirements

* Python 2.7+
* Python `requests` module
## Examples

### Playbooks

* [Ready to go example playbooks](../../playbooks/examples/)

### Tasks

```yaml
- name: Get a session without two factor authentication
  inwx.collection.session:
    username: test_user
    password: test_password

- name: Get a session with two factor authentication
  inwx.collection.session:
    username: test_user
    password: test_password
    shared_secret: test_shared_secret

- name: Get a session for the OTE API
  inwx.collection.session:
    api_env: 'ote'
    username: test_user
    password: test_password
```

## Options

```yaml
api_env:
    description:
        - Defines which api should be used.
    type: str
    choices: [ live, ote ]
    default: 'live'
    required: false
password:
    description:
        - INWX Account Password
        - Required for API authentication.
    type: str
    required: true
    aliases: [ pass ]
shared_secret:
    description:
        - INWX Account Shared Secret
        - Required for the generation of a TOTP.
    type: str
    required: false
username:
    description:
        - INWX Account Username
        - Required for API authentication.
    type: str
    required: true
    aliases: [ user ]
```

## Return Values

```yaml
session:
    description: The session for this log in.
    returned: success
    type: str
```

License
----

MIT