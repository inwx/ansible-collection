#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Carl Jock <carl.jock@proton.me>
# MIT License (see https://opensource.org/licenses/MIT)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = """
---
module: inwx.collection.nsset
author:
    - INWX Developer (@inwx)
requirements:
  - python >= 3.6
version_added: "2.10"
short_description: Manage INWX nameserver sets
notes:
    - "This module does NOT support two factor authentication."
    - "Use the inwx.collection.session module to get a session for an account with two factor authentication."
description:
    - "Manages nameserver sets (nssets) via the INWX DomRobot API."
    - "Nameserver sets are reusable named collections of nameservers that can be assigned to domains."
options:
    api_env:
        description:
            - Defines which API endpoint to use.
        type: str
        choices: [ live, ote ]
        default: 'live'
        required: false
    hostmaster:
        description:
            - Email address of the hostmaster.
        type: str
        required: false
    mail:
        description:
            - Mail server address.
        type: str
        required: false
    master_ip:
        description:
            - Master IP address.
            - Relevant for C(type=SECONDARY) nameserver sets.
        type: str
        required: false
    name:
        description:
            - The human-readable label for the nameserver set.
            - Used to identify the nsset; the API uses integer IDs internally.
        type: str
        required: true
    ns:
        description:
            - List of nameserver hostnames.
            - Required when C(state=present).
        type: list
        elements: str
        required: false
    password:
        description:
            - INWX Account Password.
            - Required for API authentication when no session is provided.
        type: str
        required: false
        aliases: [ pass ]
        no_log: true
    prio:
        description:
            - Priority value for the nameserver set.
        type: int
        required: false
        default: 0
    session:
        description:
            - Pre-authenticated session cookie from the inwx.collection.session module.
            - Use this for accounts with two-factor authentication.
        type: str
        required: false
    state:
        description:
            - Whether the nameserver set should exist or not.
        type: str
        required: false
        choices: [ absent, present ]
        default: present
    type:
        description:
            - The type of the nameserver set.
            - Required when C(state=present).
        type: str
        required: false
        choices: [ primary, secondary, external ]
    username:
        description:
            - INWX Account Username.
            - Required for API authentication when no session is provided.
        type: str
        required: false
        aliases: [ user ]
    visible:
        description:
            - Whether the nameserver set should be visible.
        type: bool
        required: false
        default: true
    web:
        description:
            - Web server IP or URL.
        type: str
        required: false
"""

EXAMPLES = """
- name: Create a primary nameserver set
  inwx.collection.nsset:
    name: my-nsset
    type: primary
    ns:
      - ns1.example.com
      - ns2.example.com
    hostmaster: admin@example.com
    username: test_user
    password: test_password

- name: Create a primary nameserver set in the OTE environment
  inwx.collection.nsset:
    name: my-nsset
    type: primary
    ns:
      - ns1.example.com
      - ns2.example.com
    api_env: ote
    username: test_user
    password: test_password

- name: Create a secondary nameserver set
  inwx.collection.nsset:
    name: my-secondary-nsset
    type: secondary
    ns:
      - ns1.example.com
    master_ip: 192.0.2.1
    username: test_user
    password: test_password

- name: Delete a nameserver set
  inwx.collection.nsset:
    name: my-nsset
    state: absent
    username: test_user
    password: test_password

- name: Use a pre-authenticated session (for 2FA accounts)
  inwx.collection.nsset:
    name: my-nsset
    type: primary
    ns:
      - ns1.example.com
      - ns2.example.com
    session: "{{ session_result.result.session }}"
"""

RETURN = """
result:
    description: A dictionary containing the nameserver set data.
    returned: success, except on deletion
    type: complex
    contains:
        id:
            description: The nameserver set ID.
            returned: success
            type: int
            sample: 42
        name:
            description: The nameserver set name.
            returned: success
            type: str
            sample: my-nsset
        type:
            description: The nameserver set type.
            returned: success
            type: str
            sample: PRIMARY
        ns:
            description: List of nameserver hostnames.
            returned: success
            type: list
            sample: ['ns1.example.com', 'ns2.example.com']
        hostmaster:
            description: Hostmaster email address.
            returned: success
            type: str
            sample: admin@example.com
        visible:
            description: Whether the nameserver set is visible.
            returned: success
            type: bool
            sample: true
        prio:
            description: Priority value.
            returned: success
            type: int
            sample: 0
        web:
            description: Web server IP or URL.
            returned: success
            type: str
            sample: ''
        mail:
            description: Mail server address.
            returned: success
            type: str
            sample: ''
        master_ip:
            description: Master IP address.
            returned: success
            type: str
            sample: ''
api_response:
    description: A dictionary containing the API response when an error occurs.
    returned: failure
    type: str
"""

import base64
import hashlib
import hmac
import importlib
import json
import random
import string
import struct
import sys
import time

# The requests module may not be installed.
# We check that further in the run_module function and install it if necessary.
try:
    import requests
except ImportError:
    pass

if sys.version_info.major == 3:
    import xmlrpc.client
else:
    import xmlrpclib


class ApiType:
    XML_RPC = "/xmlrpc/"
    JSON_RPC = "/jsonrpc/"

    def __init__(self):
        pass


class ApiClient:
    CLIENT_VERSION = "3.1.1"
    API_LIVE_URL = "https://api.domrobot.com"
    API_OTE_URL = "https://api.ote.domrobot.com"

    def __init__(
        self,
        api_url=API_OTE_URL,
        api_type=ApiType.XML_RPC,
        language="en",
        client_transaction_id=None,
        debug_mode=False,
    ):
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
            raise Exception("Username and password must not be None.")

        params = {"lang": self.language, "user": username, "pass": password}

        login_result = self.call_api("account.login", params)
        if (
            login_result["code"] == 1000
            and "tfa" in login_result["resData"]
            and login_result["resData"]["tfa"] != "0"
        ):
            if shared_secret is None:
                raise Exception(
                    "Api requests two factor challenge but no shared secret is given. Aborting."
                )
            secret_code = self.get_secret_code(shared_secret)
            unlock_result = self.call_api("account.unlock", {"tan": secret_code})
            if unlock_result["code"] != 1000:
                return unlock_result

        return login_result

    def logout(self):
        """Logs out the user and destroys the session.

        Returns:
            The api response body parsed as a dict.
        """

        logout_result = self.call_api("account.logout")
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
            raise Exception("Api method must not be None.")
        if method_params is None:
            method_params = {}

        if self.customer:
            method_params["subuser"] = self.customer
        if self.client_transaction_id is not None:
            method_params["clTRID"] = self.client_transaction_id

        if self.api_type == ApiType.XML_RPC:
            if sys.version_info.major == 3:
                payload = xmlrpc.client.dumps(
                    (method_params,), api_method, encoding="UTF-8"
                ).replace("\n", "")
            else:
                payload = xmlrpclib.dumps(
                    (method_params,), api_method, encoding="UTF-8"
                ).replace("\n", "")
        elif self.api_type == ApiType.JSON_RPC:
            payload = str(json.dumps({"method": api_method, "params": method_params}))
        else:
            raise Exception("Invalid ApiType.")

        headers = {
            "Content-Type": "text/xml; charset=UTF-8",
            "User-Agent": "DomRobot/"
            + ApiClient.CLIENT_VERSION
            + " (Python "
            + self.get_python_version()
            + ")",
        }

        response = self.api_session.post(
            self.api_url + self.api_type, data=payload.encode("UTF-8"), headers=headers
        )
        response.raise_for_status()

        if self.debug_mode:
            print("Request (" + api_method + "): " + payload)
            print("Response (" + api_method + "): " + response.text)

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
            raise Exception("Shared secret must not be None.")

        key = base64.b32decode(shared_secret, True)
        msg = struct.pack(">Q", int(time.time()) // 30)
        hmac_hash = hmac.new(key, msg, hashlib.sha1).digest()
        if sys.version_info.major == 3:
            o = hmac_hash[19] & 15
        else:
            o = ord(hmac_hash[19]) & 15
        hmac_hash = (
            struct.unpack(">I", hmac_hash[o : o + 4])[0] & 0x7FFFFFFF
        ) % 1000000
        return hmac_hash

    @staticmethod
    def get_random_string(size=12):
        return "".join(
            random.choice(string.ascii_letters + string.digits) for x in range(size)
        )

    @staticmethod
    def get_python_version():
        return ".".join(tuple(str(x) for x in sys.version_info))


from ansible.module_utils.basic import AnsibleModule


def check_and_install_module(module, python_module_name, apt_module_name):
    """Installs the module with the name of python_module_name if it is not already installed."""
    import_successful = False

    try:
        importlib.import_module(python_module_name)
        import_successful = True
    except ImportError:
        pass

    if not import_successful:
        if module.check_mode:
            module.fail_json(
                msg="%s must be installed to use check mode. "
                "If run normally this module can auto-install it." % python_module_name
            )

        module.warn(
            "Updating cache and auto-installing missing dependency: %s"
            % apt_module_name
        )
        module.run_command(["apt-get", "update"], check_rc=True)
        module.run_command(
            [
                "apt-get",
                "install",
                "--no-install-recommends",
                apt_module_name,
                "-y",
                "-q",
            ],
            check_rc=True,
        )

        try:
            globals()[python_module_name] = importlib.import_module(python_module_name)
        except ImportError:
            module.fail_json(
                msg="{0} must be installed and visible from {1}.".format(
                    python_module_name, sys.executable
                )
            )


def remove_dict_none_values(dictionary):
    filtered_dict = {}
    for key, value in dictionary.items():
        if value is not None:
            filtered_dict[key] = value
    return filtered_dict


def call_api_authenticated(module, method, params):
    if str(module.params["api_env"]) == "live":
        api_url = ApiClient.API_LIVE_URL
    else:
        api_url = ApiClient.API_OTE_URL

    client = ApiClient(api_url=api_url, api_type=ApiType.JSON_RPC, debug_mode=True)

    if (
        module.params["session"] is not None
        and not str(module.params["session"]).isspace()
    ):
        client.api_session.cookies.set("domrobot", str(module.params["session"]))
    else:
        params["user"] = str(module.params["username"])
        params["pass"] = str(module.params["password"])

    params = remove_dict_none_values(params)
    return client.call_api(method, params)


def get_nsset_by_name(module, name):
    """Look up a nameserver set by name, paginating through results as needed."""
    page = 1
    pagelimit = 100
    while True:
        result = call_api_authenticated(
            module,
            "nameserverset.list",
            {
                "wide": True,
                "page": page,
                "pagelimit": pagelimit,
            },
        )
        if result["code"] != 1000:
            module.fail_json(msg="API error.", result={"api_response": result})
            return None

        res_data = result.get("resData", {})
        nssets = res_data.get("nsset") or []
        count = res_data.get("count", 0)

        for nsset in nssets:
            if nsset.get("name") == name:
                return nsset

        if page * pagelimit >= count:
            break
        page += 1

    return None


def build_desired_nsset(module):
    """Build a dict of all user-supplied fields (excluding None values for optional params)."""
    desired = {
        "type": module.params["type"],
        "ns": module.params["ns"],
        "visible": module.params["visible"],
        "prio": module.params["prio"],
    }
    if module.params["hostmaster"] is not None:
        desired["hostmaster"] = module.params["hostmaster"]
    if module.params["web"] is not None:
        desired["web"] = module.params["web"]
    if module.params["mail"] is not None:
        desired["mail"] = module.params["mail"]
    if module.params["master_ip"] is not None:
        desired["master_ip"] = module.params["master_ip"]
    return desired


def nsset_needs_update(current, desired):
    """Compare current API state against desired state.

    Returns (needs_update: bool, changed_fields: dict).
    changed_fields uses Ansible key names (master_ip, not masterIp).
    """
    changed_fields = {}

    # ns: sorted list comparison
    current_ns = sorted(current.get("ns") or [])
    desired_ns = sorted(desired.get("ns") or [])
    if current_ns != desired_ns:
        changed_fields["ns"] = desired["ns"]

    # type
    if desired.get("type") != current.get("type"):
        changed_fields["type"] = desired["type"]

    # Scalar fields: (ansible_key, api_response_key)
    for ansible_key, api_key in [
        ("hostmaster", "hostmaster"),
        ("visible", "visible"),
        ("prio", "prio"),
        ("web", "web"),
        ("mail", "mail"),
        ("master_ip", "masterIp"),
    ]:
        if ansible_key in desired and desired[ansible_key] != current.get(api_key):
            changed_fields[ansible_key] = desired[ansible_key]

    return len(changed_fields) > 0, changed_fields


def build_nsset_result(nsset_data):
    """Normalize API response keys: masterIp -> master_ip."""
    result = {}
    for key, value in nsset_data.items():
        if key == "masterIp":
            result["master_ip"] = value
        else:
            result[key] = value
    return result


def format_nsset_for_diff(nsset):
    if nsset is None:
        return ""
    lines = []
    lines.append("name: " + str(nsset.get("name", "")))
    lines.append("type: " + str(nsset.get("type", "")))
    ns_list = nsset.get("ns") or []
    lines.append("ns: " + ", ".join(sorted(ns_list)))
    if nsset.get("hostmaster"):
        lines.append("hostmaster: " + str(nsset["hostmaster"]))
    if nsset.get("visible") is not None:
        lines.append("visible: " + str(nsset["visible"]))
    if nsset.get("prio") is not None:
        lines.append("prio: " + str(nsset["prio"]))
    if nsset.get("web"):
        lines.append("web: " + str(nsset["web"]))
    if nsset.get("mail"):
        lines.append("mail: " + str(nsset["mail"]))
    master_ip = nsset.get("master_ip") or nsset.get("masterIp")
    if master_ip:
        lines.append("master_ip: " + str(master_ip))
    return "\n".join(lines)


def create_diff(before_nsset=None, after_nsset=None):
    before_text = format_nsset_for_diff(before_nsset)
    after_text = format_nsset_for_diff(after_nsset)
    return [
        {
            "before": before_text,
            "after": after_text,
            "before_header": "Nameserver set before change",
            "after_header": "Nameserver set after change",
        }
    ]


def create_nsset(module):
    """Call nameserverset.create, then fetch the result via nameserverset.info."""
    params = {
        "type": module.params["type"].upper(),
        "ns": module.params["ns"],
        "name": module.params["name"],
        "visible": module.params["visible"],
        "prio": module.params["prio"],
    }
    if module.params["hostmaster"] is not None:
        params["hostmaster"] = module.params["hostmaster"]
    if module.params["web"] is not None:
        params["web"] = module.params["web"]
    if module.params["mail"] is not None:
        params["mail"] = module.params["mail"]
    if module.params["master_ip"] is not None:
        params["masterIp"] = module.params["master_ip"]

    result = call_api_authenticated(module, "nameserverset.create", params)
    if result["code"] != 1000:
        module.fail_json(msg="API error.", result={"api_response": result})
        return None

    nsset_id = result["resData"]["id"]
    info_result = call_api_authenticated(module, "nameserverset.info", {"id": nsset_id})
    if info_result["code"] != 1000:
        module.fail_json(
            msg="API error fetching created nsset.",
            result={"api_response": info_result},
        )
        return None

    return build_nsset_result(info_result["resData"])


def update_nsset(module, nsset_id, changed_fields):
    """Call nameserverset.update with only the changed fields, then fetch the updated state."""
    params = {"id": nsset_id}
    for key, value in changed_fields.items():
        if key == "master_ip":
            params["masterIp"] = value
        elif key == "type":
            params["type"] = value.upper()
        else:
            params[key] = value

    result = call_api_authenticated(module, "nameserverset.update", params)
    if result["code"] != 1000:
        module.fail_json(msg="API error.", result={"api_response": result})
        return None

    info_result = call_api_authenticated(module, "nameserverset.info", {"id": nsset_id})
    if info_result["code"] != 1000:
        module.fail_json(
            msg="API error fetching updated nsset.",
            result={"api_response": info_result},
        )
        return None

    return build_nsset_result(info_result["resData"])


def delete_nsset(module, nsset_id):
    """Call nameserverset.delete."""
    result = call_api_authenticated(module, "nameserverset.delete", {"id": nsset_id})
    if result["code"] != 1000:
        module.fail_json(msg="API error.", result={"api_response": result})


def run_module():
    module = AnsibleModule(
        argument_spec=dict(
            api_env=dict(
                type="str", required=False, default="live", choices=["live", "ote"]
            ),
            hostmaster=dict(type="str", required=False),
            mail=dict(type="str", required=False),
            master_ip=dict(type="str", required=False),
            name=dict(type="str", required=True),
            ns=dict(type="list", elements="str", required=False),
            password=dict(type="str", required=False, aliases=["pass"], no_log=True),
            prio=dict(type="int", required=False, default=0),
            session=dict(type="str", required=False),
            state=dict(
                type="str",
                required=False,
                choices=["present", "absent"],
                default="present",
            ),
            type=dict(
                type="str", required=False, choices=["primary", "secondary", "external"]
            ),
            username=dict(type="str", required=False, aliases=["user"]),
            visible=dict(type="bool", required=False, default=True),
            web=dict(type="str", required=False),
        ),
        supports_check_mode=True,
        required_if=[
            ("state", "present", ["type", "ns"]),
        ],
        required_together=[
            ("username", "password"),
        ],
        required_one_of=[
            ("username", "session"),
        ],
    )

    if sys.version_info.major == 3:
        check_and_install_module(module, "requests", "python3-requests")
    elif sys.version_info.major == 2:
        check_and_install_module(module, "requests", "python-requests")

    name = module.params["name"]
    state = module.params["state"]

    current_nsset = get_nsset_by_name(module, name)

    if state == "absent":
        if current_nsset is None:
            module.exit_json(changed=False)
        else:
            before_result = build_nsset_result(current_nsset)
            diff = create_diff(before_nsset=before_result, after_nsset=None)
            if not module.check_mode:
                delete_nsset(module, current_nsset["id"])
            module.exit_json(changed=True, diff=diff)

    elif state == "present":
        if module.params["type"].upper() != "PRIMARY":
            for param in ("web", "mail", "hostmaster"):
                if module.params[param] is not None:
                    module.warn(
                        "Parameter '%s' is only used by PRIMARY nameserver sets; "
                        "it will be ignored for type '%s'." % (param, module.params["type"])
                    )

        desired = build_desired_nsset(module)

        if current_nsset is None:
            # Build a representative after-state for check mode / diff
            after_nsset_preview = {
                "id": 0,
                "name": name,
                "type": module.params["type"],
                "ns": module.params["ns"],
                "visible": module.params["visible"],
                "prio": module.params["prio"],
                "hostmaster": module.params.get("hostmaster") or "",
                "web": module.params.get("web") or "",
                "mail": module.params.get("mail") or "",
                "master_ip": module.params.get("master_ip") or "",
            }
            diff = create_diff(before_nsset=None, after_nsset=after_nsset_preview)
            if module.check_mode:
                module.exit_json(changed=True, result=after_nsset_preview, diff=diff)
            after_nsset = create_nsset(module)
            diff = create_diff(before_nsset=None, after_nsset=after_nsset)
            module.exit_json(changed=True, result=after_nsset, diff=diff)
        else:
            current_result = build_nsset_result(current_nsset)
            needs_update, changed_fields = nsset_needs_update(current_nsset, desired)
            if not needs_update:
                module.exit_json(changed=False, result=current_result)
            else:
                if module.check_mode:
                    after_nsset = dict(current_result)
                    after_nsset.update(changed_fields)
                    diff = create_diff(
                        before_nsset=current_result, after_nsset=after_nsset
                    )
                    module.exit_json(changed=True, result=after_nsset, diff=diff)
                after_nsset = update_nsset(module, current_nsset["id"], changed_fields)
                diff = create_diff(before_nsset=current_result, after_nsset=after_nsset)
                module.exit_json(changed=True, result=after_nsset, diff=diff)


def main():
    run_module()


if __name__ == "__main__":
    main()
