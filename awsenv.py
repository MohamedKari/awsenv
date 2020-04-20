import sys
import argparse
import boto3
import json
import os
import base64
from datetime import datetime, timezone
from hashlib import sha384
from pathlib import Path
from typing import List

CONFIG_FILE = "~/.awsenv/config.jsonc"
SESSIONS_FILE = "~/.awsenv/sessions.json"

def load_json_with_comments(json_file):
    output_lines = []

    with open(json_file) as f:
        for rawline in f.readlines():
            line = rawline.strip()
            if not line.startswith("//"):
                output_lines.append(line)

    try:
        output_json = json.loads("\n".join(output_lines))
    except json.decoder.JSONDecodeError as e:
        sys.stderr.write(
            f"{json_file} is invalid:" 
            f"Please also remember that comments are only allowed in lines starting with //")
        raise e
    
    return output_json

def clear_aws_env_vars():
    for k, _ in os.environ.items():
        if k.startswith("AWS_"):
            os.unsetenv(k)
            del os.environ[k]

def derive_session_name(account, role, access_key_id):
    hash_obj = sha384()
    hash_obj.update(access_key_id.encode("utf-8"))
    hash_code = hash_obj.hexdigest()

    return f"{role}_{account}_{hash_code[-6:]}"

def credentials_expired(temporary_credentials):        
    utc_expiration_datetime = datetime.strptime(temporary_credentials["AWS_EXPIRATION"], "%Y-%m-%d %H:%M:%S%z")
    utc_expiration_timestamp = utc_expiration_datetime.timestamp()
    utcnow_timestamp = datetime.now(timezone.utc).timestamp()
    sys.stderr.write(f"Credentials expire in {int((utc_expiration_timestamp - utcnow_timestamp)/60)} minutes. \n")
    return utc_expiration_timestamp < utcnow_timestamp

def get_cached_credentials(session_name, sessions_json):
    if os.path.exists(sessions_json):
        with open(sessions_json, "rt") as f:
            return json.load(f).get(session_name)
    else:
        return None

def cache_credentials(session_name, credentials, sessions_json):
    if os.path.exists(sessions_json):
        with open(sessions_json, "rt") as f:
            pre_json = json.load(f) 
    else:
        pre_json = {
            session_name: credentials
        }

    pre_json.update({
        session_name: credentials
    })
    with open(sessions_json, "wt") as f:
        json.dump(pre_json, f, indent=4, default=str)

def fetch_temporary_credentials(user, role, session_name, sessions_json):

    sys.stderr.write("MFA_token: ")
    mfa_token = input("")

    if user:
        sts = boto3.client(
            "sts",
            aws_access_key_id=user["AWS_ACCESS_KEY_ID"],
            aws_secret_access_key=user["AWS_SECRET_ACCESS_KEY"]
        )
    else: 
        sts = boto3.client("sts") # fallback to .aws credentials

    fetched_credentials = sts.assume_role(
        RoleArn=f"arn:aws:iam::{role['account']}:role/{role['role']}",
        SerialNumber=user["SERIAL_NUMBER"],
        RoleSessionName=session_name,
        TokenCode=mfa_token,
        DurationSeconds=int(role["duration"])
    )["Credentials"]

    temporary_credentials = {}

    temporary_credentials["AWS_ACCESS_KEY_ID"] = fetched_credentials["AccessKeyId"]
    temporary_credentials["AWS_SECRET_ACCESS_KEY"] = fetched_credentials["SecretAccessKey"]
    temporary_credentials["AWS_SESSION_TOKEN"] = fetched_credentials["SessionToken"]
    temporary_credentials["AWS_EXPIRATION"] = fetched_credentials["Expiration"]

    cache_credentials(session_name, temporary_credentials, sessions_json)
    
    return temporary_credentials

def get_temporary_credentials(user=None, role=None, config_file=CONFIG_FILE, sessions_file=SESSIONS_FILE):
    config = load_json_with_comments(config_file)

    if not user:
        user = config["users"][config["defaultUser"]]
    elif isinstance(user, str):
        user = config["users"][user]
    elif isinstance(user, dict):
        pass
    else: 
        raise ValueError("user invalid")

    if not role:
        role = config["roles"][config["defaultRole"]]
    elif isinstance(user, str):
        role = config["roles"][role]
    elif isinstance(role, dict):
        pass
    else: 
        raise ValueError("user invalid")

    session_name = derive_session_name(role["account"], role["role"], user["AWS_ACCESS_KEY_ID"])

    cached_credentials = get_cached_credentials(session_name, sessions_file)

    if cached_credentials and not credentials_expired(cached_credentials):
        return cached_credentials

    return fetch_temporary_credentials(user, role, session_name, sessions_file)

def print_to_stdout(output):
    print("\n".join([f"export {k}=\"{v}\"" for k, v in output.items()]))

def encode_dict_as_base64(dict_to_encode):
    raw_string = json.dumps(dict_to_encode, default=str)
    raw_bytes = raw_string.encode("ascii")
    base64_bytes = base64.b64encode(raw_bytes)
    base64_string = bytes.decode(base64_bytes, "ascii")

    return base64_string

def get_boto_session(
        shortcut=None, 
        role=None, 
        user=None, 
        account=None, 
        duration=None, 
        config_file=CONFIG_FILE, 
        sessions_file=SESSIONS_FILE):

    credentials = get_credentials(
        shortcut=shortcut,
        role=role,
        user=user,
        account=account,
        duration=duration,
        config_file=config_file,
        sessions_file=sessions_file,
        print_credentials=False
    )

    return boto3.session.Session(
        aws_access_key_id=credentials["AWS_ACCESS_KEY_ID"],
        aws_secret_access_key=credentials["AWS_SECRET_ACCESS_KEY"],
        aws_session_token=credentials["AWS_SESSION_TOKEN"],
        region_name=credentials["AWS_DEFAULT_REGION"]
    )

def expand_paths(*paths: List[str]) -> List[str]:
    expanded_paths = []
    
    for path in paths:
        expanded_paths.append(
            str(Path(path).expanduser()) if path else None)
        
    return expanded_paths

def get_credentials(
        shortcut=None, 
        role=None, 
        user=None, 
        account=None, 
        duration=None, 
        config_file=CONFIG_FILE, 
        sessions_file=SESSIONS_FILE, 
        print_credentials=False):
    
    clear_aws_env_vars()

    config_file, sessions_file = expand_paths(config_file, sessions_file) # pylint: disable=unbalanced-tuple-unpacking

    config = load_json_with_comments(config_file)
    output = {}

    output["AWS_DEFAULT_REGION"] = config["AWS_DEFAULT_REGION"]
    output["AWS_DEFAULT_OUTPUT"] = config["AWS_DEFAULT_OUTPUT"]
    output["AWS_PAGER"] = config["AWS_PAGER"]

    final_settings = {}

    config_defaults = {
        "role": config.get("defaultRole"),
        "user": config.get("defaultUser"), 
        "account": config.get("defaultAccount"),
        "duration": config.get("defaultDuration")
    }
    final_settings = config_defaults

    if shortcut:
        predefined = {
            "role": config["predefinedShortcuts"][shortcut].get("role") or final_settings["role"],
            "user": config["predefinedShortcuts"][shortcut].get("user") or final_settings["user"], 
            "account": config["predefinedShortcuts"][shortcut].get("account") or final_settings["account"],
            "duration": config["predefinedShortcuts"][shortcut].get("duration")  or final_settings["duration"]
        }
        final_settings = predefined

    cli = {
        "role": role or final_settings["role"],
        "user": user or final_settings["user"], 
        "account": account or final_settings["account"],
        "duration": duration or final_settings["duration"]
    }

    final_settings.update(cli)
    sys.stderr.write(str(final_settings) + "\n")

    if final_settings["user"]:
        desired_user = config["users"][final_settings["user"]]

    desired_role = {
        "role": final_settings["role"],
        "account": final_settings["account"],
        "duration": final_settings["duration"]
    }

    if not desired_role["role"] or desired_role["role"] == ".":

        output.update(
            desired_user
        )
    
    else:

        output.update(
            get_temporary_credentials(
                user=desired_user,
                role=desired_role, 
                config_file=config_file,
                sessions_file=sessions_file
            )
        )

    if config.get("output") \
       and config["output"].get("variables") \
       and config["output"]["variables"].get("AWS_TEMPORARY_CREDENTIALS_BASE64"):

        dict_to_encode = {}
        dict_to_encode["AWS_ACCESS_KEY_ID"] = output["AWS_ACCESS_KEY_ID"]
        dict_to_encode["SECRET_ACCESS_KEY"] = output["AWS_SECRET_ACCESS_KEY"]

        if "AWS_SESSION_TOKEN" in output:
            dict_to_encode["AWS_SESSION_TOKEN"] = output["AWS_SESSION_TOKEN"]
            dict_to_encode["AWS_EXPIRATION"] = output["AWS_EXPIRATION"]

        output["AWS_TEMPORARY_CREDENTIALS_BASE64"] = encode_dict_as_base64(dict_to_encode)

    if print_credentials:
        print_to_stdout(output)

    return output


if __name__ == "__main__":

    parser = argparse.ArgumentParser()

    # order of prcedence:
    # - config defaults 
    # - config shortcuts
    # - command line arguments

    parser.add_argument("shortcut", nargs="?")
    parser.add_argument("-r", "--role", default=None, help="The role to assume. If no role should be assumed, indicate '.' (a dot).")
    parser.add_argument("-u", "--user", default=None)
    parser.add_argument("-a", "--account", default=None)
    parser.add_argument("-d", "--duration", default=None, type=int)
    parser.add_argument("-c", "--config", default=CONFIG_FILE, dest="config_file")
    parser.add_argument("-s", "--sessions", default=SESSIONS_FILE, dest="sessions_file")
    parser.add_argument("-q", "--quiet", action="store_true", help="Suppresses printing credentials")

    args = parser.parse_args(sys.argv[1:])

    get_credentials(
        shortcut=args.shortcut,
        role=args.role,
        user=args.user,
        account=args.account,
        duration=args.duration,
        config_file=args.config_file,
        sessions_file=args.sessions_file,
        print_credentials=(not args.quiet)
    )



    


