# awsmfa-go

This is a project to handle having to use a MFA token to access AWS Resources. Assuming you have your credential file setup with profiles you can use it to generate temporary credentials with your MFA token. This is based on [this](https://github.com/dcoker/awsmfa/) great tool in python and has been reimplemented in golang so you don't have to worry about setting about virtualenvs.


### Installation

### To Use
Once the binary is on your systems path you can just call 
```
> awsmfa
Enter MFA Token:
```

#### Command line Arguments
Currently supported
```
  c string
        Full path to credentials file (default "<Users Home>\.aws\credentials")
  -d int
        Token Duration (default 28800)
  -env
        Boolean flag to print commands to set environment variables
  -format string
        Env Printout format if not specified default is bash, possible values are cmd, bash, pwshell (default "bash")
  -i string
        Source Profile (default "default")
  -o    Boolean flag to overwrite profile if this is not set you can not have same source and target profile
  -rotate-identity-keys
        Boolean flag to rotate keys of the source profile when fetching new credentials
  -t string
        Destination Profile (default "default")
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
