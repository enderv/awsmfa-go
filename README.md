# awsmfa-go
[![Build Status](https://travis-ci.org/enderv/awsmfa-go.svg?branch=master)](https://travis-ci.org/enderv/awsmfa-go)

This is a project to handle having to use a MFA token to access AWS Resources. Assuming you have your credential file setup with profiles you can use it to generate temporary credentials with your MFA token. This is based on [this](https://github.com/dcoker/awsmfa/) great tool in python and has been reimplemented in golang so you don't have to worry about setting about virtualenvs.


### Installation
Download a release and put the binary on your path.

### To Use
Once the binary is on your systems path you can just call 
```
> awsmfa
Enter MFA Token:
```

#### Command line Arguments
Currently supported
```
  -c string
        Full path to credentials file (default "~\.aws\credentials")
  -config-profile string
        Config Profile To use for assuming role
  -d int
        Token Duration (default 28800)
  -env
        Flag to print commands to set environment variables
  -format string
        Env OS Printout format, possible values are cmd, bash, pwshell (default "bash")
  -i string
        Source Profile (default "identity")
  -n string
        Full path to config file (default "~\.aws\config")
  -o    Boolean flag to overwrite profile if this is not set you can not have same source and target profile
  -role-to-assume string
        Full ARN of Role To Assume
  -rotate-identity-keys
        Boolean flag to rotate keys of the source profile when fetching new credentials
  -sessionName string
        Name for session when assuming role (default "awsmfa<date>")
  -t string
        Destination Profile (default "default")
  -use-role-config
        Use config profile for assuming a role
```

#### Assuming Role Using Config File
Setup your config file
```
[profile test]
role_arn = bleh
source_profile = test-mfa

```
And then run
```
awsmfa -use-role-config -config-profile test -t destination-profile

```

#### Environment Variables
```
AWSMFA_ALWAYS_ROTATE
      If set to "true" (or any case variant of), awsmfa-go will always rotate access keys after every run.
```

### Development

#### Tests

### Docker


License
----

MIT
