# inwx.dns module

Module for managing dns records via the api.

## Examples

```yaml
- name: Create an A record
  inwx.collection.dns:
    domain: example.com
    type: A
    record: test
    value: 127.0.0.1
    username: test_user
    password: test_password

- name: Create an A record in the ote environemnt
  inwx.collection.dns:
    domain: example.com
    type: A
    record: test
    value: 127.0.0.1
    api_env: ote
    username: test_user
    password: test_password

- name: Delete the A record
  inwx.collection.dns:
    domain: example.com
    type: A
    record: test
    username: test_user
    password: test_password
    state: absent

- name: Create an example.com A record with value 127.0.0.1
  inwx.collection.dns:
    domain: example.com
    type: A
    value: 127.0.0.1
    username: test_user
    password: test_password

- name: Create another example.com A record with value 127.0.0.2 with custom ttl
  inwx.collection.dns:
    domain: example.com
    type: A
    value: 127.0.0.2
    ttl: 43200
    username: test_user
    password: test_password

- name: Update ttl of example.com A record with value 127.0.0.1
  inwx.collection.dns:
    domain: example.com
    type: A
    value: 127.0.0.1
    ttl: 604800
    username: test_user
    password: test_password

- name: Create an test.example.com AAAA record
  inwx.collection.dns:
    domain: example.com
    type: AAAA
    record: test
    value: ::1
    username: test_user
    password: test_password

- name: Create an test.example.com AFSDB record
  inwx.collection.dns:
    domain: example.com
    type: AFSDB
    record: test
    service: '1'
    value: database1.example.com
    username: test_user
    password: test_password

- name: Create a mail.example.com CNAME record
  inwx.collection.dns:
    domain: example.com
    type: CNAME
    record: mail
    value: example.com
    username: test_user
    password: test_password

- name: Create a test.example.com CAA record
  inwx.collection.dns:
    domain: example.com
    type: CAA
    record: test
    flag: '0'
    tag: issue
    value: ;
    username: test_user
    password: test_password

- name: Create a test.example.com HINFO record
  inwx.collection.dns:
    domain: example.com
    type: HINFO
    record: test
    value: 'INTEL-IPSC UNIX'
    username: test_user
    password: test_password

- name: Create a test.example.com LOC record
  inwx.collection.dns:
    domain: example.com
    type: LOC
    record: test
    value: '51 30 12.748 N 0 7 39.612 W 0.00'
    username: test_user
    password: test_password

- name: Create a mail.example.com MX record
  inwx.collection.dns:
    domain: example.com
    type: MX
    record: mail
    priority: 1
    value: 'mail.example.com'
    username: test_user
    password: test_password

- name: Create a test.example.com NAPTR record
  inwx.collection.dns:
    domain: example.com
    type: NAPTR
    record: test
    weight: 1
    flag: '10'
    service: 'S'
    regex: 'SIP+D2U'
    substitution: '!^.*$!sip:customer-service@example.com!'
    username: test_user
    password: test_password

- name: Create a example.com NS record
  inwx.collection.dns:
    domain: example.com
    type: NS
    value: 'ns1.exampleserver.net'
    ttl: 86400
    username: test_user
    password: test_password

- name: Create a example.com RP record
  inwx.collection.dns:
    domain: example.com
    type: RP
    value: mail@example.com
    username: test_user
    password: test_password

- name: Update example.com's SOA record value and ttl
  inwx.collection.dns:
    domain: '{{ domain }}'
    type: SOA
    value: 'ns.ote.inwx.de hostmaster@inwx.de 2019103186'
    ttl: 86400
    username: '{{ username }}'
    password: '{{ password }}'

- name: Create a example.com SRV record
  inwx.collection.dns:
    domain: example.com
    type: SRV
    record: _foo._tcp.fooservice
    value: example.com
    port: 3500
    priority: 10
    weight: 10
    username: test_user
    password: test_password

- name: Create a test.example.com SSHFP record
  inwx.collection.dns:
    domain: example.com
    type: SSHFP
    record: test
    algorithm: '4'
    hash_type: '2'
    value: 9dc1d6742696d2f51ca1f1a78b3d16a840f7d111eb9454239e70db31363f33e1
    username: test_user
    password: test_password

- name: Create a TLSA record _25._tcp.mail.example.com
  inwx.collection.dns:
    domain: example.com
    type: TLSA
    record: _25._tcp.mail
    cert_usage: 3
    selector: 1
    hash_type: 1
    value: 6b76d034492b493e15a7376fccd08e63befdad0edab8e442562f532338364bf3
    username: test_user
    password: test_password

- name: Create a test.example.com TXT record
  inwx.collection.dns:
    domain: example.com
    type: TXT
    record: test
    value: 'hello world'
    username: test_user
    password: test_password
```

## Options

```yaml
options:
    algorithm:
        description:
            - Algorithm number.
            - Required for C(type=SSHFP) when C(state=present).
        type: int
        required: false
    api_env:
        description:
            - Defines which api should be used.
        type: str
        choices: [ live, ote ]
        default: 'live'
        required: false
    flag:
        description:
            - Flag for C(type=CAA) record defining if record is critical.
            - Flag for C(type=NAPTR) record defining the returned record type.
            - Required for C(type=CAA) and C(type=NAPTR) when C(state=present).
        type: str
        required: false
    tag:
        description:
            - Tag identifier.
            - An ASCII string that defines the identifier of the property represented by the record.
            - Required for C(type=CAA) when C(state=present).
        type: str
        choices: [ issue, issuewild, iodef ]
        required: false
    cert_usage:
        description:
            - Certificate usage number.
            - Required for C(type=TLSA) when C(state=present).
        type: int
        choices: [ 0, 1, 2, 3 ]
        required: false
    domain:
        description:
            - The name of the Domain to work with (e.g. "example.com").
        type: str
        required: true
    hash_type:
        description:
            - Hash type number.
            - Required for C(type=SSHFP) and C(type=TLSA) when C(state=present).
        type: int
        required: false
    regex:
        description:
            - Regex string.
            - Defines what should be replaced with the defined C(substitution).
            - Required for C(type=NAPTR) when C(state=present).
        type: str
        required: false
    password:
        description:
            - INWX Account Password
            - Required for API authentication.
        type: str
        required: true
        aliases: [ pass ]
    priority:
        description:
            - Record priority.
            - Required for C(type=MX) and C(type=SRV)
        type: int
        required: false
        default: 1
    port:
        description:
            - Service port.
            - Required for C(type=SRV).
        type: int
        required: false
    record:
        description:
            - Record to add.
            - Required if C(state=present).
        type: str
        required: false
        default: ''
        aliases: [ name ]
    selector:
        description:
            - Selector number.
            - Required for C(type=TLSA) when C(state=present).
        type: int
        required: false
        choices: [ 0, 1 ]
    service:
        description:
            - Record service.
            - Required for C(type=SRV).
        type: str
        required: false
    state:
        description:
            - Whether the record(s) should exist or not.
        type: str
        required: true
        choices: [ absent, present ]
        default: present
    substitution:
        description:
            - Substitution string.
            - Replaces everything matching in C(regex) with the defined substitution.
            - Required for C(type=NAPTR) when C(state=present).
        type: str
        required: false
    ttl:
        description:
            - The TTL to give the new record.
            - Must be between 3600 and 2,147,483,647 seconds.
        type: int
        required: false
        default: 86400
    type:
        description:
            - The type of DNS record.
        type: str
        required: false
        choices: [ A, AAAA, AFSDB, CAA, CNAME, HINFO, LOC, MX, NAPTR, NS, PTR, RP, SOA, SRV, SSHFP, TLSA, TXT ]
    username:
        description:
            - INWX Account Username
            - Required for API authentication.
        type: str
        required: true
        aliases: [ user ]
    value:
        description:
            - The record value.
            - Required for C(state=present).
        type: str
        required: false
        aliases: [ content ]
    weight:
        description:
            - Service weight.
            - Required for C(type=SRV) and C(type=NAPTR).
        type: int
        required: false
        default: 1
```

## Return Values

```yaml
record:
    description: A dictionary containing the record data.
    returned: success, except on record deletion
    type: complex
    contains:
        id:
            description: The record ID.
            returned: success
            type: int
            sample: 33121
        type:
            description: The record type.
            returned: success
            type: str
            sample: A
        name:
            description: The record name as FQDN.
            returned: success
            type: str
            sample: www.sample.com
        content:
            description: The record content (details depend on record type).
            returned: success
            type: str
            sample: 192.0.2.91
        priority:
            description: Priority of the MX or SRV record.
            returned: success, if type is MX or SRV
            type: int
            sample: 10
        ttl:
            description: The time-to-live for the record.
            returned: success
            type: int
            sample: 3600
api_response:
    description: A dictionary containing the API response when an error occurrence.
    returned: failure
    type: str
```

License
----

MIT