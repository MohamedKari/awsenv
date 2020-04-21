
# Setup

1. Install boto3 to your base env

2. Add the following awsenv function to your shell resource config (e. g. .zshrc or .oh-my-zsh/custom/awsenv.zsh)

```sh
awsenv(){
  path_to_awsenv_py="$HOME/code/awsenv/awsenv.py"
  eval $(python $path_to_awsenv_py $@)
}
```

3. Add a `config.jsonc` (note the c for comment) with the following strutucture under `~/.awsenv/config.json`

```json
{
    "AWS_DEFAULT_REGION": "eu-central-1",
    "AWS_DEFAULT_OUTPUT": "json",
    "AWS_PAGER": "",

    "defaultUser": "<your-name-you-want-to-login-with-by-default,must-match-a-name-below-in-users>",
    "defaultRole": "<some-role-name>",
    "defaultAccount": "<some-account-id>",
    "defaultDuration": 3600,

    "users": {
        "<your-name-1>": {
            "AWS_ACCESS_KEY_ID": "<your-access-key>",
            "AWS_SECRET_ACCESS_KEY": "<your-secret-access-key>",
            "SERIAL_NUMBER": "<your-mfa-serial>"
        }
    },

    "predefinedShortcuts": {
        "<some-shortcut-1>": {
            "user": "<your-name>",
            "role": "<some-role-name>",
            "account": "617095144398",
            "duration": 43200
        },
        "<some-shortcut-2>": {
            "user": "<your-name>",
            "role": "<some-role-name>",
            "account": "<some-account-id>",
            "duration": 3600
        }
    }
}
```