#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2022, INWX <developer@inwx.de>
# MIT License (see https://opensource.org/licenses/MIT)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = '''
---
module: inwx.collection.dns
author:
    - Nick Ufer (@NickUfer)
requirements:
  - python >= 3.6
version_added: "2.10"
short_description: Manage INWX DNS records
notes:
    - "This module does NOT support two factor authentication."
    - "Use the inwx.collection.session module to get a session for an account with two factor authentication."
description:
    - "Manages DNS records via the INWX API."
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
        choices: [ A, AAAA, AFSDB, ALIAS, CAA, CERT, CNAME, HINFO, HTTPS, KEY, LOC, MX, NAPTR, NS, OPENPGPKEY, PTR, RP, SMIMEA, SOA, SRV, SSHFP, TLSA, TXT, URI ]
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
'''

EXAMPLES = '''
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
'''

RETURN = '''
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
'''

import base64
import hashlib
import hmac
import json
import random
import re
import string
import struct
import sys
import time

# The requests may not be installed.
# We check that further in the run_module function and install it if necessary
try:
    import requests
except ImportError:
    pass

if sys.version_info.major == 3:
    import xmlrpc.client
else:
    import xmlrpclib


class ApiType:
    XML_RPC = '/xmlrpc/'
    JSON_RPC = '/jsonrpc/'

    def __init__(self):
        pass


class ApiClient:
    CLIENT_VERSION = '3.1.1'
    API_LIVE_URL = 'https://api.domrobot.com'
    API_OTE_URL = 'https://api.ote.domrobot.com'

    def __init__(self, api_url=API_OTE_URL, api_type=ApiType.XML_RPC, language='en', client_transaction_id=None,
                 debug_mode=False):
        """
        Args:
            api_url: Url of the api.
            api_type: Type of the api. See ApiType class for all types.
            language: Language for api messages and error codes in responses.
            client_transaction_id: Sent with every request to distinguish your api requests in case you need support.
            debug_mode: Whether requests and responses should be printed out.
        """

        self.api_url = api_url
        self.api_type = api_type
        self.language = language
        self.client_transaction_id = client_transaction_id
        self.debug_mode = debug_mode
        self.customer = None
        self.api_session = requests.Session()

    def login(self, username, password, shared_secret=None):
        """Performs a login at the api and saves the session cookie for following api calls.

        Args:
            username: Your username.
            password: Your password.
            shared_secret: A secret used to generate a secret code to solve 2fa challenges when 2fa is enabled. This is
                the code/string encoded in the QR-Code you scanned with your google authenticator app when you enabled 2fa.
                If you don't have this secret anymore, disable and re-enable 2fa for your account but this time save the
                code/string encoded in the QR-Code.
        Returns:
            The api response body parsed as a dict.
        Raises:
            Exception: Username and password must not be None.
            Exception: Api requests two factor challenge but no shared secret is given. Aborting.
        """

        if username is None or password is None:
            raise Exception('Username and password must not be None.')

        params = {
            'lang': self.language,
            'user': username,
            'pass': password
        }

        login_result = self.call_api('account.login', params)
        if login_result['code'] == 1000 and 'tfa' in login_result['resData'] and login_result['resData']['tfa'] != '0':
            if shared_secret is None:
                raise Exception('Api requests two factor challenge but no shared secret is given. Aborting.')
            secret_code = self.get_secret_code(shared_secret)
            unlock_result = self.call_api('account.unlock', {'tan': secret_code})
            if unlock_result['code'] != 1000:
                return unlock_result

        return login_result

    def logout(self):
        """Logs out the user and destroys the session.

        Returns:
            The api response body parsed as a dict.
        """

        logout_result = self.call_api('account.logout')
        self.api_session.close()
        self.api_session = requests.Session()
        return logout_result

    def call_api(self, api_method, method_params=None):
        """Makes an api call.

        Args:
            api_method: The name of the method called in the api.
            method_params: A dict of parameters added to the request.
        Returns:
            The api response body parsed as a dict.
        Raises:
            Exception: Api method must not be None.
            Exception: Invalid ApiType.
        """

        if api_method is None:
            raise Exception('Api method must not be None.')
        if method_params is None:
            method_params = {}

        if self.customer:
            method_params['subuser'] = self.customer
        if self.client_transaction_id is not None:
            method_params['clTRID'] = self.client_transaction_id

        if self.api_type == ApiType.XML_RPC:
            if sys.version_info.major == 3:
                payload = xmlrpc.client.dumps((method_params,), api_method, encoding='UTF-8').replace('\n', '')
            else:
                payload = xmlrpclib.dumps((method_params,), api_method, encoding='UTF-8').replace('\n', '')
        elif self.api_type == ApiType.JSON_RPC:
            payload = str(json.dumps({'method': api_method, 'params': method_params}))
        else:
            raise Exception('Invalid ApiType.')

        headers = {
            'Content-Type': 'text/xml; charset=UTF-8',
            'User-Agent': 'DomRobot/' + ApiClient.CLIENT_VERSION + ' (Python ' + self.get_python_version() + ')'
        }

        response = self.api_session.post(self.api_url + self.api_type, data=payload.encode('UTF-8'),
                                         headers=headers)
        response.raise_for_status()

        if self.debug_mode:
            print('Request (' + api_method + '): ' + payload)
            print('Response (' + api_method + '): ' + response.text)

        if self.api_type == ApiType.XML_RPC:
            if sys.version_info.major == 3:
                return xmlrpc.client.loads(response.text)[0][0]
            else:
                return xmlrpclib.loads(response.text)[0][0]
        elif self.api_type == ApiType.JSON_RPC:
            return response.json()

    @staticmethod
    def get_secret_code(shared_secret):
        """Generates a secret code for 2fa with a shared secret.

        Args:
            shared_secret: The shared secret used to generate the secret code.
        Returns:
            A secret code used to solve 2fa challenges.
        Raises:
            Exception: Shared secret must not be None.
        """

        if shared_secret is None:
            raise Exception('Shared secret must not be None.')

        key = base64.b32decode(shared_secret, True)
        msg = struct.pack(">Q", int(time.time()) // 30)
        hmac_hash = hmac.new(key, msg, hashlib.sha1).digest()
        if sys.version_info.major == 3:
            o = hmac_hash[19] & 15
        else:
            o = ord(hmac_hash[19]) & 15
        hmac_hash = (struct.unpack(">I", hmac_hash[o:o + 4])[0] & 0x7fffffff) % 1000000
        return hmac_hash

    @staticmethod
    def get_random_string(size=12):
        return ''.join(random.choice(string.ascii_letters + string.digits) for x in range(size))

    @staticmethod
    def get_python_version():
        return '.'.join(tuple(str(x) for x in sys.version_info))


from ansible.module_utils.basic import AnsibleModule


def remove_suffix(input_string, suffix):
    input_string = str(input_string)
    if suffix and input_string.endswith(suffix):
        return input_string[:-len(suffix)]
    return input_string


def build_record_afsdb(module):
    keys = ('service', 'value')
    return ' '.join(map(lambda key: str(module.params[key]), keys))


def build_record_caa(module):
    values = (str(module.params['flag']),
              str(module.params['tag']),
              '"' + str(module.params['value']) + '"')
    return ' '.join(map(str, values))


def build_record_cert(module):
    keys = ('cert_type', 'cert_key_tag', 'algorithm', 'value')
    return ' '.join(map(lambda key: str(module.params[key]), keys))


def build_record_key(module):
    values = (str(module.params['key_flags']),
              str(module.params['key_protocol']),
              str(module.params['algorithm']),
              re.sub(r'(-----[A-Z ]*-----)|(\s)', '', str(module.params['value'])))
    return ' '.join(map(str, values))


def build_record_naptr(module):
    values = (str(module.params['weight']),
              '"' + str(module.params['flag']) + '"',
              '"' + str(module.params['service']) + '"',
              str(module.params['regex']),
              str(module.params['substitution']))
    return ' '.join(map(str, values))


def build_record_openpgpkey(module):
    trimmed = re.sub(r'(-----[A-Z ]*-----)|(\s)', '', str(module.params['value']))
    # Removing checksum from end of key
    if len(trimmed) < 5:
        module.fail_json(msg='Supplied "value" value is too short.')
    if trimmed[-5] == "=":
        trimmed = remove_suffix(trimmed, trimmed[-5:])
    return trimmed


def build_record_smimea(module):
    values = (
        str(module.params['cert_usage']),
        str(module.params['selector']),
        str(module.params['matching_type']),
        re.sub(r'(-----[A-Z ]*-----)|(\s)', '', str(module.params['value'])))
    return ' '.join(map(str, values))


def build_record_srv(module):
    keys = ('weight', 'port', 'value')
    return ' '.join(map(lambda key: str(module.params[key]), keys))


def build_record_sshfp(module):
    keys = ('algorithm', 'hash_type', 'value')
    return ' '.join(map(lambda key: str(module.params[key]), keys))


def build_record_tlsa(module):
    keys = ('cert_usage', 'selector', 'hash_type', 'value')
    return ' '.join(map(lambda key: str(module.params[key]), keys))


def build_record_uri(module):
    return str(module.params['priority']) + ' ' + str(module.params['weight']) + ' "' + str(
        module.params['value']) + '"'


def build_default_record(module):
    return str(module.params['value'])


def build_record_content(module):
    switcher = {
        'A': build_default_record,
        'AAAA': build_default_record,
        'AFSDB': build_record_afsdb,
        'ALIAS': build_default_record,
        'CAA': build_record_caa,
        'CERT': build_record_cert,
        'CNAME': build_default_record,
        'HINFO': build_default_record,
        'HTTPS': build_default_record,
        'KEY': build_record_key,
        'LOC': build_default_record,
        'MX': build_default_record,
        'NAPTR': build_record_naptr,
        'NS': build_default_record,
        'OPENPGPKEY': build_record_openpgpkey,
        'PTR': build_default_record,
        'RP': build_default_record,
        'SMIMEA': build_record_smimea,
        'SOA': build_default_record,
        'SRV': build_record_srv,
        'SSHFP': build_record_sshfp,
        'TLSA': build_record_tlsa,
        'TXT': build_default_record,
        'URI': build_record_uri,
    }

    return switcher.get(str(module.params['type']).upper())(module)


def get_record_fqdn(module):
    if str(module.params['type']) == 'SMIMEA':
        used_hash = str(module.params['hash'])
        if re.match('^[a-fA-F0-9]{56,64}$', used_hash):
            if len(used_hash) > 56:
                used_hash = used_hash[0:56]  # hash should only be 56 chars long.
        else:
            # Convenience Feature:
            # If hash is not a hash try to manually calculate the hash.
            if '@' in used_hash:
                used_hash = used_hash.split('@')[0]
            import hashlib
            m = hashlib.sha256()
            m.update(used_hash)
            used_hash = m.hexdigest()[0:56]  # hash should only be 56 chars long.

        record = used_hash + '._smimecert'
        if module.params['record'] and not str(module.params['record']).isspace() and str(
                module.params['record']) != '@':
            record += '.' + str(module.params['record'])
        return record + '.' + str(module.params['domain'])
    elif str(module.params['type']) == 'OPENPGPKEY':
        used_hash = str(module.params['hash'])
        if re.match('^[a-fA-F0-9]{56,64}$', used_hash):
            if len(used_hash) > 56:
                used_hash = used_hash[0:56]  # hash should only be 56 chars long.
        else:
            # Convenience Feature:
            # If hash is not a hash try to manually calculate the hash.
            if '@' in used_hash:
                used_hash = used_hash.split('@')[0]
            import hashlib
            m = hashlib.sha256()
            m.update(used_hash)
            used_hash = m.hexdigest()[0:56]  # hash should only be 56 chars long.

        record = used_hash + '._openpgpkey'
        if module.params['record'] and not str(module.params['record']).isspace() and str(
                module.params['record']) != '@':
            record += '.' + str(module.params['record'])
        return record + '.' + str(module.params['domain'])
    elif str(module.params['type']) == 'PTR':
        if bool(module.params['reversedns']):
            if sys.version_info.major == 3:
                check_and_install_module(module, 'netaddr', 'python3-netaddr')
            elif sys.version_info.major == 2:
                check_and_install_module(module, 'netaddr', 'python-netaddr')
            import netaddr

            return remove_suffix(netaddr.IPAddress(str(module.params['record'])).reverse_dns,
                                 '.' + remove_suffix(str(module.params['domain']), '.') + '.')
        else:
            return remove_suffix(
                remove_suffix(remove_suffix(module.params['record'], '.'), remove_suffix(module.params['domain'], '.')),
                '.')
    else:
        fqdn = ''
        if module.params['record'] and not str(module.params['record']).isspace() and str(
                module.params['record']) != '@':
            fqdn = str(module.params['record']) + '.'
        fqdn += str(module.params['domain'])
        return fqdn


def check_present_state_required_arguments(module):
    required_params_for_type = {
        'A': ['value'],
        'AAAA': ['value'],
        'AFSDB': ['service', 'value'],
        'ALIAS': ['value'],
        'CAA': ['flag', 'tag', 'value'],
        'CERT': ['cert_type', 'cert_key_tag', 'algorithm', 'value'],
        'CNAME': ['value'],
        'HINFO': ['value'],
        'HTTPS': ['value'],
        'KEY': ['key_flags', 'key_protocol', 'algorithm', 'value'],
        'LOC': ['value'],
        'MX': ['priority', 'value'],
        'NAPTR': ['flag', 'service', 'regex', 'substitution'],
        'NS': ['value'],
        'OPENPGPKEY': ['hash', 'value'],
        'PTR': ['value'],
        'RP': ['value'],
        'SMIMEA': ['cert_usage', 'hash', 'selector', 'matching_type', 'value'],
        'SOA': ['value'],
        'SRV': ['priority', 'port', 'value'],
        'SSHFP': ['algorithm', 'hash_type', 'value'],
        'TLSA': ['cert_usage', 'selector', 'hash_type', 'value'],
        'TXT': ['value'],
        'URI': ['priority', 'weight', 'value']
    }

    unsatisfied_params = required_params_for_type[str(module.params['type'])]

    for required_param in unsatisfied_params:
        if module.params.get(required_param, None) is not None:
            unsatisfied_params.remove(required_param)
        else:
            module.fail_json(msg='arguments missing for type ' + str(module.params['type'])
                                 + ' record: ' + ' '.join(unsatisfied_params))
            return


def build_check_mode_record(module):
    return {
        'id': 0,
        'type': str(module.params['type']),
        'name': get_record_fqdn(module),
        'content': build_record_content(module),
        'priority': int(module.params['priority']),
        'ttl': int(module.params['ttl'])
    }


def build_record_from_response(record_data):
    return {
        'id': record_data['id'],
        'type': record_data['type'],
        'name': record_data['name'],
        'content': record_data['content'],
        'priority': record_data.get('prio', 0),
        'ttl': record_data['ttl']
    }


def remove_dict_none_values(dictionary):
    filtered_dict = {}
    for key, value in dictionary.items():
        if value is not None:
            filtered_dict[key] = value
    return filtered_dict


def call_api_authenticated(module, method, params):
    if str(module.params['api_env']) == 'live':
        api_url = ApiClient.API_LIVE_URL
    else:
        api_url = ApiClient.API_OTE_URL

    client = ApiClient(api_url=api_url, api_type=ApiType.JSON_RPC, debug_mode=True)

    if module.params['session'] is not None and not str(module.params['session']).isspace():
        client.api_session.cookies.set('domrobot', str(module.params['session']))
    else:
        params['user'] = str(module.params['username'])
        params['pass'] = str(module.params['password'])

    params = remove_dict_none_values(params)
    return client.call_api(method, params)


def get_records(module, ignore_content=False):
    if ignore_content:
        content = None
    else:
        content = build_record_content(module)

    if str(module.params['type']) == 'SOA':
        result = call_api_authenticated(module, 'nameserver.info', {
            'domain': str(module.params['domain']),
            'type': str(module.params['type'])
        })
    else:
        result = call_api_authenticated(module, 'nameserver.info', {
            'domain': str(module.params['domain']),
            'type': str(module.params['type']),
            'name': get_record_fqdn(module),
            'content': content
        })

    if result['code'] != 1000:
        module.fail_json(msg='API error.', result={'api_response': result})
        return None

    if result['resData'].get('record', None) is not None:
        # map all response records to internal record dicts
        records = list(map(build_record_from_response, result['resData']['record']))
        return records
    else:
        return None


def update_soa_record(module, record_id):
    result = call_api_authenticated(module, 'nameserver.updateRecord', {
        'id': record_id,
        'name': get_record_fqdn(module),
        'content': build_record_content(module),
        'ttl': int(module.params['ttl'])
    })

    if result['code'] != 1000:
        module.fail_json(msg='API error.', result={'api_response': result})
        return None

    # fetch record again as the updated version should now be present
    return get_records(module)[0]


def update_record_ttl(module, record_id):
    result = call_api_authenticated(module, 'nameserver.updateRecord', {
        'id': record_id,
        'ttl': int(module.params['ttl'])
    })

    if result['code'] != 1000:
        module.fail_json(msg='API error.', result={'api_response': result})

    # fetch record again as the updated version should now be present
    return get_records(module)[0]


def create_record(module):
    record_content = build_record_content(module)
    result = call_api_authenticated(module, 'nameserver.createRecord', {
        'domain': str(module.params['domain']),
        'type': str(module.params['type']),
        'content': record_content,
        'name': get_record_fqdn(module),
        'ttl': int(module.params['ttl']),
        'prio': int(module.params['priority'])
    })

    if result['code'] != 1000:
        module.fail_json(msg='API error.', result={'api_response': result})
        return None

    # fetch record again as the updated version should now be present
    return get_records(module)[0]


def delete_record(module, record_id):
    call_api_authenticated(module, 'nameserver.deleteRecord', {'id': record_id})


def check_and_install_module(module, python_module_name, apt_module_name):
    """
    Installs the module with the name of python_module_name if it is not already installed.
    """
    import_successful = False

    import importlib
    try:
        importlib.import_module(python_module_name)
        import_successful = True
    except ImportError:
        pass

    if not import_successful:
        # don't make changes if we're in check_mode
        if module.check_mode:
            module.fail_json(msg="%s must be installed to use check mode. "
                                 "If run normally this module can auto-install it." % python_module_name)

        module.warn("Updating cache and auto-installing missing dependency: %s" % apt_module_name)
        module.run_command(['apt-get', 'update'], check_rc=True)

        # try to install the apt python package
        module.run_command(['apt-get', 'install', '--no-install-recommends', apt_module_name, '-y', '-q'],
                           check_rc=True)

        import_successful = False
        import importlib
        try:
            globals()[python_module_name] = importlib.import_module(python_module_name)
            import_successful = True
        except ImportError:
            pass

        if not import_successful:
            module.fail_json(
                msg="{0} must be installed and visible from {1}.".format(python_module_name, sys.executable))


def run_module():
    module = AnsibleModule(
        argument_spec=dict(
            algorithm=dict(type='int', required=False),
            api_env=dict(type='str', reduired=False, default='live', choices=['live', 'ote']),
            flag=dict(type='str', required=False),
            tag=dict(type='str', required=False, choices=['issue', 'issuewild', 'iodef']),
            cert_usage=dict(type='int', required=False, choices=[0, 1, 2, 3]),
            cert_key_tag=dict(type='int', required=False),
            cert_type=dict(type='int', required=False),
            domain=dict(type='str', required=True),
            hash=dict(type='str', required=False),
            hash_type=dict(type='int', required=False),
            key_flags=dict(type='int', required=False),
            key_protocol=dict(type='int', required=False),
            matching_type=dict(type='int', required=False, choices=[0, 1]),
            regex=dict(type='str', required=False),
            password=dict(type='str', required=False, aliases=['pass'], no_log=True),
            priority=dict(type='int', required=False, default=1),
            port=dict(type='int', required=False),
            record=dict(type='str', required=False, default='', aliases=['name']),
            reversedns=dict(type='bool', required=False, default=False),
            selector=dict(type='int', required=False, choices=[0, 1]),
            session=dict(type='str', required=False),
            service=dict(type='str', required=False),
            solo=dict(type='bool', required=False, default=False),
            state=dict(type='str', choices=['present', 'absent'], default='present'),
            substitution=dict(type='str', required=False),
            ttl=dict(type='int', required=False, default=86400),
            type=dict(type='str', required=True,
                      choices=['A', 'AAAA', 'AFSDB', 'ALIAS', 'CAA', 'CERT', 'CNAME', 'HINFO', 'HTTPS', 'KEY', 'LOC',
                               'MX', 'NAPTR', 'NS', 'OPENPGPKEY', 'PTR', 'RP', 'SMIMEA', 'SOA', 'SRV', 'SSHFP',
                               'TLSA', 'TXT', 'URI']),
            username=dict(type='str', required=False, aliases=['user']),
            value=dict(type='str', required=False, aliases=['content'], default=''),
            weight=dict(type='int', required=False, default=1),
        ),
        supports_check_mode=True,
        required_if=[
            ('state', 'absent', ['record']),
            ('state', 'present', ['record', 'type'])
        ],
        required_together=[
            ('username', 'password')
        ],
        required_one_of=[
            ('username', 'session')
        ]
    )

    # Required for Domrobot
    if sys.version_info.major == 3:
        check_and_install_module(module, 'requests', 'python3-requests')
    elif sys.version_info.major == 2:
        check_and_install_module(module, 'requests', 'python-requests')

    found_records = get_records(module)

    if str(module.params['state']) == 'absent':
        if found_records:
            if str(module.params['type']) == 'SOA':
                module.fail_json(changed=False, msg="SOA record can only be updated.")
            else:
                # records exist, delete them if multiple match.
                if not module.check_mode:
                    for found_record in found_records:
                        delete_record(module, int(found_record['id']))
                module.exit_json(changed=True)
        else:
            # record doesn't exist, nothing to delete.
            module.exit_json(changed=False)
    elif str(module.params['state']) == 'present':
        check_present_state_required_arguments(module)
        if bool(module.params['solo']):
            solomode_deletions = False
            all_records = get_records(module, ignore_content=True)
            if all_records:
                for record in all_records:
                    if record['content'] != build_record_content(module):
                        if not module.check_mode:
                            delete_record(module, int(record['id']))
                        solomode_deletions = True
        if str(module.params['type']) == 'SOA':
            # can only be one
            soa_record = found_records[0]
            if soa_record['name'] == get_record_fqdn(module) \
                    and str(soa_record['content']) == str(build_record_content(module)) \
                    and int(soa_record['ttl']) == int(module.params['ttl']):
                # record, content and ttl are equal, nothing changed.
                module.exit_json(changed=False, result={'record': soa_record})
            else:
                # record, content or ttl changed, update it.
                if module.check_mode:
                    updated_record = build_check_mode_record(module)
                else:
                    updated_record = update_soa_record(module, soa_record['id'])
                module.exit_json(changed=True, result={'record': updated_record})
        elif found_records:
            # should only contain one record
            found_record = found_records[0]
            if int(found_record['ttl']) != int(module.params['ttl']):
                # record exists but with another ttl. Update it.
                if module.check_mode:
                    updated_record = build_check_mode_record(module)
                else:
                    updated_record = update_record_ttl(module, found_record['id'])
                module.exit_json(changed=True, result={'record': updated_record})
            else:
                # identical record exists.
                module.exit_json(changed=bool(module.params['solo']) and solomode_deletions,
                                 result={'record': found_record})
        else:
            # record doesn't exist, create it.
            if module.check_mode:
                created_record = build_check_mode_record(module)
            else:
                created_record = create_record(module)
            module.exit_json(changed=True, result={'record': created_record})


def main():
    run_module()


if __name__ == '__main__':
    main()
