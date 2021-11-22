# inwx.dns module

Module for managing dns records via the api.

## Requirements

* Python 2.7+
* Python `requests` module
* Python `netaddr` module (when dealing with PTR records)
## Examples

### Playbooks

* [Ready to go example playbook](../../playbooks/examples/dns_requests_installation.yml)

### Tasks

```yaml
- name: Create an A record
  inwx.collection.dns:
    domain: example.com
    type: A
    record: test
    value: 127.0.0.1
    username: test_user
    password: test_password

- name: Create an A record in the ote environment
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

- name: Create an example.com ALIAS record
  inwx.collection.dns:
    domain: example.com
    type: ALIAS
    record: ''
    value: example.org
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

- name: Create a example.com CERT record
  inwx.collection.dns:
    domain: example.com
    type: CERT
    record: test
    cert_type: 2
    cert_key_tag: 77
    algorithm: 2
    value: 'TUlJQ1l6Q0NBY3lnQXdJQkFnSUJBREFOQmdrcWh'
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

- name: Create a test.example.com HINFO record
  inwx.collection.dns:
    domain: example.com
    type: HINFO
    record: test
    value: 'INTEL-IPSC UNIX'
    username: test_user
    password: test_password

- name: Create a test.example.com KEY record
  inwx.collection.dns:
    domain: example.com
    type: KEY
    record: test
    key_flags: 256
    key_protocol: 3
    algorithm:  3
    value: |
       BOPdJjdc/ZQWCVA/ONz6LjvugMnB2KKL3F1D2i9Gdrpi
       rcWRKS2DfRn5KiMM2HQXBHv0ZdkFs/tmjg7rYxrN+bzB
       NrlwfU5RMjioi67PthD07EHbZjwoZ5sKC2BZ/M596hyg
       fx5JAvbIWBQVF+ztiuCnWCkbGvVXwsmE+odINCur+o+E
       jA9hF06LqTviUJKqTxisQO5OHM/0ufNenzIbijJPTXbU
       cF3vW+CMlX+AUPLSag7YnhWaEu7BLCKfg3vJVw9mtaN2
       W3oWPRdebGUf/QfyVKXoWD6zDLByCZh4wKvpcwgAsel4
       bO5LVe7s8qstSxqrwzmvaZ5XYOMZFbN7CXtutiswAkb0
       pkehIYime6IRkDwWDG+14H5yriRuCDK3m7GvwxMo+ggV
       0k3Po9LD5wWSIi1N ) ; key id = 22004
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
    record: ''
    value: 'ns1.exampleserver.net'
    ttl: 86400
    username: test_user
    password: test_password

- name: Create a example.com OPENPGPKEY record
  inwx.collection.dns:
    domain: example.com
    type: OPENPGPKEY
    hash: '7f0b629cbb9d794b3daf19fcd686a30a039b47395545394dadc05747'
    value: |
        mQGiBGFW68wRBACRhxAjR9Ar0bKETL0S38Tt1TxBYcl4X2A4hNXoq7AKivrEhg1G
        P0T5Y9e2vevOKkP/PClKKSPpvTfHB4J5vtromHq7e+e5CDsqDxnmeaMG4SCyeXVr
        JzZ41laQCeQEQSVZr/hNxHyBt9+fdBSuUN4WpftD92R6Hs1wDNTHwJwSTwCgxipp
        kIziajC9St7gkOt2O63vtBUD/AghlnpCi2heEw4r7q8zpOHIZrG1ItTjFkoCP0F6
        LwjK1i6fVEuTpyZ828mSjmv+GJhcQUtK2t286NB9X6yhX4UrRTMKvF4K0eLMYRqF
        YA2l+JFxYa0zUBKoV1NYgx7r73+qFER76s96e/1mP4lWzI0Vu2N6sgEFuPkAdQZn
        eKRMA/9G5L7eksnjmZVMFNQZdYALRyUvm4Ugn3rQMqc8fa/ABZIELmvpH2UEIdo4
        lGEQhPGR/f/RZWK4YSLVQ2H8mqUUPlmXCofLNO5Zwhew3oSlr6Q8BuaxCwJtNuJN
        4woOd3EloTE4VYcJh61EiTt73QbhjOXmKIaSoss0RvkFY/kms7Qbbmlja3VmZXIg
        PG5pY2tAZXhhbXBsZS5jb20+iHkEExEKADkWIQRURPeTsAMS+m8TFyFCPDD5kjYX
        BAUCYVbrzAIbAwYLCQgHCgMFFQoJCAsFFgIDAQACHgECF4AACgkQQjww+ZI2FwRW
        QwCgtTb1zj7mO3Riw4cnMkGBPMLZChQAn0tpNWn6/uZ2EFwhtj+ABfc6a2UB
        =i4gG
    ttl: 86400
    username: test_user
    password: test_password

- name: Create a example.com OPENPGPKEY record example2
  inwx.collection.dns:
    domain: example.com
    type: OPENPGPKEY
    hash: 'nick@example.com'
    value: |
        -----BEGIN PGP PUBLIC KEY BLOCK-----
        mQGiBGFW68wRBACRhxAjR9Ar0bKETL0S38Tt1TxBYcl4X2A4hNXoq7AKivrEhg1G
        P0T5Y9e2vevOKkP/PClKKSPpvTfHB4J5vtromHq7e+e5CDsqDxnmeaMG4SCyeXVr
        JzZ41laQCeQEQSVZr/hNxHyBt9+fdBSuUN4WpftD92R6Hs1wDNTHwJwSTwCgxipp
        kIziajC9St7gkOt2O63vtBUD/AghlnpCi2heEw4r7q8zpOHIZrG1ItTjFkoCP0F6
        LwjK1i6fVEuTpyZ828mSjmv+GJhcQUtK2t286NB9X6yhX4UrRTMKvF4K0eLMYRqF
        YA2l+JFxYa0zUBKoV1NYgx7r73+qFER76s96e/1mP4lWzI0Vu2N6sgEFuPkAdQZn
        eKRMA/9G5L7eksnjmZVMFNQZdYALRyUvm4Ugn3rQMqc8fa/ABZIELmvpH2UEIdo4
        lGEQhPGR/f/RZWK4YSLVQ2H8mqUUPlmXCofLNO5Zwhew3oSlr6Q8BuaxCwJtNuJN
        4woOd3EloTE4VYcJh61EiTt73QbhjOXmKIaSoss0RvkFY/kms7Qbbmlja3VmZXIg
        PG5pY2tAZXhhbXBsZS5jb20+iHkEExEKADkWIQRURPeTsAMS+m8TFyFCPDD5kjYX
        BAUCYVbrzAIbAwYLCQgHCgMFFQoJCAsFFgIDAQACHgECF4AACgkQQjww+ZI2FwRW
        QwCgtTb1zj7mO3Riw4cnMkGBPMLZChQAn0tpNWn6/uZ2EFwhtj+ABfc6a2UB
        =i4gG
        -----END PGP PUBLIC KEY BLOCK-----
    ttl: 86400
    username: test_user
    password: test_password

- name: Create a server-1.example.com PTR record. With only host part as record
  inwx.collection.dns:
    domain: '8.b.d.0.1.0.0.2.ip6.arpa'
    record: '1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0'
    type: PTR
    value: 'server-1.example.com'
    ttl: 86400
    username: test_user
    password: test_password

- name: Create a server-1.example.com PTR record
  inwx.collection.dns:
    domain: '8.b.d.0.1.0.0.2.ip6.arpa'
    record: '1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa'
    type: PTR
    value: 'server-1.example.com'
    ttl: 86400
    username: test_user
    password: test_password

- name: Create a server-1.example.com PTR record. Automatically generate reverse dns record from server ip
  inwx.collection.dns:
    domain: '8.b.d.0.1.0.0.2.ip6.arpa'
    record: '2001:db8::1'
    reversedns: yes
    type: PTR
    value: 'server-1.example.com'
    ttl: 86400
    username: test_user
    password: test_password

- name: Create a example.com RP record
  inwx.collection.dns:
    domain: example.com
    type: RP
    record: ''
    value: mail@example.com
    username: test_user
    password: test_password
    
- name: Create a example.com RP record
  inwx.collection.dns:
    domain: example.com
    type: SMIMEA
    hash: '7f0b629cbb9d794b3daf19fcd686a30a039b47395545394dadc05747'
    cert_usage: 0
    selector: 0
    matching_type: 1
    value: |
        MIIBbzCCARSgAwIBAgIUOLyf9DRFyxkfKV0WsdszKhX2AY4wCgYIKoZIzj0EAwIw
        FTETMBEGA1UEAxMKRXhhbXBsZSBDQTAeFw0yMTEwMDExMTEyMDBaFw0yNjA5MzAx
        MTEyMDBaMBUxEzARBgNVBAMTCkV4YW1wbGUgQ0EwWTATBgcqhkjOPQIBBggqhkjO
        PQMBBwNCAARfetQDkndbSLk+U/ns3KvXbF1gR5v3PU4lcEbqoecruRe8sYsKjVn3
        QD9E4t/BEvrDUyrg2TDSpFANQAj7Mcb2o0IwQDAOBgNVHQ8BAf8EBAMCAQYwDwYD
        VR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUnUowQBs6dHHU/qjboPoY+ei0lCIwCgYI
        KoZIzj0EAwIDSQAwRgIhALnkf8yVB24TaUxCLvvSGwtOUrBwOzzffRbfJ5g5Hr6s
        AiEA/qkGwyRr2E/VpuVjzxJTpL1nMaqk8j30/k7K6dtihVU=
    username: test_user
    password: test_password
    
- name: Create a example.com RP record
  inwx.collection.dns:
    domain: example.com
    type: SMIMEA
    hash: nick@example.com
    cert_usage: 0
    selector: 0
    matching_type: 1
    value: |
        -----BEGIN CERTIFICATE-----
        MIIBbzCCARSgAwIBAgIUOLyf9DRFyxkfKV0WsdszKhX2AY4wCgYIKoZIzj0EAwIw
        FTETMBEGA1UEAxMKRXhhbXBsZSBDQTAeFw0yMTEwMDExMTEyMDBaFw0yNjA5MzAx
        MTEyMDBaMBUxEzARBgNVBAMTCkV4YW1wbGUgQ0EwWTATBgcqhkjOPQIBBggqhkjO
        PQMBBwNCAARfetQDkndbSLk+U/ns3KvXbF1gR5v3PU4lcEbqoecruRe8sYsKjVn3
        QD9E4t/BEvrDUyrg2TDSpFANQAj7Mcb2o0IwQDAOBgNVHQ8BAf8EBAMCAQYwDwYD
        VR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUnUowQBs6dHHU/qjboPoY+ei0lCIwCgYI
        KoZIzj0EAwIDSQAwRgIhALnkf8yVB24TaUxCLvvSGwtOUrBwOzzffRbfJ5g5Hr6s
        AiEA/qkGwyRr2E/VpuVjzxJTpL1nMaqk8j30/k7K6dtihVU=
        -----END CERTIFICATE-----
    username: test_user
    password: test_password

- name: Update example.com's SOA record value and ttl
  inwx.collection.dns:
    domain: '{{ domain }}'
    type: SOA
    record: ''
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

- name: Create a test.example.com URI record
  inwx.collection.dns:
    domain: example.com
    type: URI
    record: '_ftp._tcp'
    priority: 10
    weight: 1
    value: 'ftp://ftp.example.com/public'
    username: test_user
    password: test_password

- name: Ensure that there is only one A record for test.example.com
  inwx.collection.dns:
    domain: example.com
    type: A
    record: test
    value: 127.0.0.1
    solo: yes
    username: test_user
    password: test_password
```

## Options

```yaml
options:
    algorithm:
        description:
            - Algorithm number.
            - https://datatracker.ietf.org/doc/html/rfc2535#section-3.2
            - Required for C(type=CERT) when C(state=present).
            - Required for C(type=KEY) when C(state=present).
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
    cert_usage:
        description:
            - Certificate usage number.
            - https://datatracker.ietf.org/doc/html/rfc6698#section-2.1.1
            - Required for C(type=TLSA) when C(state=present).
        type: int
        choices: [ 0, 1, 2, 3 ]
        required: false
    cert_key_tag:
        description:
            - 16 bit value computed for the key embedded in the certificate as specified in the DNSSEC Standard [RFC 2535].
            - https://datatracker.ietf.org/doc/html/rfc2535#section-4.1.6
            - Required for C(type=CERT) when C(state=present).
        type: int
        required: false
    cert_type:
        description:
            - Certificate Type.
            - https://datatracker.ietf.org/doc/html/rfc2538.html#section-2.1
            - Required for C(type=CERT) when C(state=present).
        type: int
        required: false
    domain:
        description:
            - The name of the Domain to work with (e.g. "example.com").
        type: str
        required: true
    flag:
        description:
            - Flag for C(type=CAA) record defining if record is critical.
            - Flag for C(type=NAPTR) record defining the returned record type.
            - Required for C(type=CAA) and C(type=NAPTR) when C(state=present).
        type: str
        required: false
    hash:
        description:
            - A hash (ex. SHA-256) in hex digits.
            - Must be at least 56 digits long.
            - Can be an email name for C(type=SMIMEA)
            - Required for C(type=OPENPGPKEY) when C(state=present)
            - Required for C(type=SMIMEA) when C(state=present)
    hash_type:
        description:
            - Hash type number.
            - Required for C(type=SSHFP) and C(type=TLSA) when C(state=present).
        type: int
        required: false
    key_flags:
        description:
            - Key Flags Field.
            - https://datatracker.ietf.org/doc/html/rfc2535#section-3.1.2
            - Required for C(type=KEY) when C(state=present).
        type: int
        required: false
    key_protocol:
        description:
            - Protocol Octet.
            - https://datatracker.ietf.org/doc/html/rfc2535#section-3.1.3
            - Required for C(type=KEY) when C(state=present).
        type: int
        required: false
    matching_type:
        description:
            - Certificate Matching Type.
            - https://datatracker.ietf.org/doc/html/rfc6698#section-2.1.3
            - Required for C(type=SMIMEA) when C(state=present).
        type: int
        choices: [ 0, 1 ]
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
    regex:
        description:
            - Regex string.
            - Defines what should be replaced with the defined C(substitution).
            - Required for C(type=NAPTR) when C(state=present).
        type: str
        required: false
    reversedns:
        description:
            - Whether the record (an IP) should be converted to a reverse dns value.
            - Only works with C(type=PTR).
        type: bool
        required: false
        default: false
    selector:
        description:
            - Selector number.
            - https://datatracker.ietf.org/doc/html/rfc6698#section-2.1.2
            - Required for C(type=TLSA) when C(state=present).
            - Required for C(type=SMIMEA) when C(state=present).
        type: int
        required: false
        choices: [ 0, 1 ]
    service:
        description:
            - Record service.
            - Required for C(type=SRV).
        type: str
        required: false
    solo:
        description:
            - Wether the record should be the only one for that record name and type.
            - Only works with `state=present`
            - This will delete all other records with the same record name and type.
        type: bool
        required: false
        default: false
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
    tag:
        description:
            - Tag identifier.
            - An ASCII string that defines the identifier of the property represented by the record.
            - Required for C(type=CAA) when C(state=present).
        type: str
        choices: [ issue, issuewild, iodef ]
        required: false
    ttl:
        description:
            - The TTL to give the new record.
            - Must be between 300 and 864000 seconds.
        type: int
        required: false
        default: 86400
    type:
        description:
            - The type of DNS record.
        type: str
        required: false
        choices: [ A, AAAA, AFSDB, ALIAS, CAA, CERT, CNAME, HINFO, KEY, LOC, MX, NAPTR, NS, OPENPGPKEY, PTR, RP, SMIMEA, SOA, SRV, SSHFP, TLSA, TXT, URI ]
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