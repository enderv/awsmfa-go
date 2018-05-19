package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"github.com/alyu/configparser"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/sts"
)

type credentialResult struct {
	AccessKeyId     string
	SecretAccessKey string
	Expiration      string
	SessionToken    string
}

func main() {
	sourceProfile := flag.String("i", "identity", "Source Profile")
	targetProfile := flag.String("t", "default", "Destination Profile")
	rotateKeys := flag.Bool("rotate-identity-keys", false, "Boolean flag to rotate keys of the source profile when fetching new credentials")
	overwrite := flag.Bool("o", false, "Boolean flag to overwrite profile if this is not set you can not have same source and target profile")
	printOut := flag.Bool("env", false, "Flag to print commands to set environment variables")
	printFormat := flag.String("format", "bash", "Env OS Printout format, possible values are cmd, bash, pwshell")
	roleToAssume := flag.String("role-to-assume", "", "Full ARN of Role To Assume")
	useRoleConfig := flag.Bool("use-role-config", false, "Use config profile for assuming a role")
	configProfile := flag.String("config-profile", "", "Config Profile To use for assuming role")
	sessionName := flag.String("sessionName", "awsmfa"+time.Now().Format("2006-01-02"), "Name for session when assuming role")
	credFile := flag.String("c", filepath.Join(getCredentialPath(), ".aws", "credentials"), "Full path to credentials file")
	configFile := flag.String("n", filepath.Join(getCredentialPath(), ".aws", "config"), "Full path to config file")
	duration := flag.Int64("d", 28800, "Token Duration")
	flag.Parse()

	// If AWSMFA_ALWAYS_ROTATE is set to true, always rotate the key.
	forceRotate := strings.EqualFold(os.Getenv("AWSMFA_ALWAYS_ROTATE"), "true")

	if sourceProfile == targetProfile && !*overwrite {
		fmt.Println("Source equals target and will overwrite it you probably don't want to do this")
		return
	}

	if *useRoleConfig {
		var err error
		sourceProfile, roleToAssume, err = getConfigProfileValues(configFile, configProfile)
		if err != nil {
			fmt.Println(err.Error())
			return
		}
	}

	//Get Current Credentials
	exists, err := checkProfileExists(credFile, sourceProfile)
	if err != nil || !exists {
		fmt.Println(err.Error())
		return
	}
	sess := CreateSession(sourceProfile)
	userSerial, err := getUserMFA(sess)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	//Get MFA Code
	mfa, err := getMFACode()
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	var tempCreds *credentialResult
	if *roleToAssume != "" {
		tempCreds = getRoleCredentials(sess, mfa, duration, userSerial, roleToAssume, sessionName)
	} else {
		tempCreds = getSTSCredentials(sess, mfa, duration, userSerial)
	}

	if tempCreds != nil {
		writeNewProfile(credFile, targetProfile, sourceProfile, *tempCreds)
	}

	if forceRotate || *rotateKeys {
		fmt.Print("Rotating Keys...\n")
		newKeys, err := rotateCredentialKeys(sess)
		if err != nil {
			fmt.Println(err.Error())
			return
		}
		writeNewKeys(credFile, sourceProfile, newKeys)
	}

	if *printOut {
		if tempCreds != nil {
			printNewProfile(*tempCreds, strings.ToLower(*printFormat))
		}
	}

	if tempCreds != nil {
		fmt.Printf("Credentials expire at %s", tempCreds.Expiration)
	}
}

// getMFACode prompts for MFA Token input
// It returns the value as a string and any error
func getMFACode() (string, error) {
	var mfa string
	fmt.Print("Enter MFA Token: ")
	reader := bufio.NewReader(os.Stdin)
	mfa, err := reader.ReadString('\n')
	if err != nil {
		return mfa, errors.New("failed to get token")
	}
	return strings.TrimSpace(mfa), nil
}

// CreateSession Creates AWS Session with specified profile
func CreateSession(profileName *string) *session.Session {
	profileNameValue := *profileName
	sess := session.Must(session.NewSessionWithOptions(session.Options{
		Profile: profileNameValue,
	}))
	return sess
}

// getUserMFA takes a session
// It returns the users MFA Serial and any errors
func getUserMFA(sess *session.Session) (*string, error) {
	var newToken *string

	svc := iam.New(sess)

	params := &iam.GetUserInput{}
	resp, err := svc.GetUser(params)

	if err != nil {
		// Print the error, cast err to awserr.Error to get the Code and
		// Message from an error.
		fmt.Println(err.Error())
		return newToken, errors.New("failed to Fetch User")
	}
	userName := *resp.User.UserName
	mfaparams := &iam.ListMFADevicesInput{
		MaxItems: aws.Int64(1),
		UserName: aws.String(userName),
	}
	mfaresp, err := svc.ListMFADevices(mfaparams)

	if err != nil {
		// Print the error, cast err to awserr.Error to get the Code and
		// Message from an error.
		fmt.Println(err.Error())
		return newToken, errors.New("failed to Fetch User")
	}

	if len(mfaresp.MFADevices) == 0 {
		return nil, errors.New("unable to find a MFA device for this identity")
	}

	return mfaresp.MFADevices[0].SerialNumber, nil
}

// getCredentialPath returns the users home directory path as a string
func getCredentialPath() string {
	usr, err := user.Current()
	if err != nil {
		log.Fatal(err)
	}
	return usr.HomeDir
}

// writeNewProfile writes out the new profile keys in the credential file
// Returns nothing
func writeNewProfile(credFile *string, profileName *string, sourceProfile *string, sessionDetails credentialResult) {
	config, err := configparser.Read(*credFile)
	sourceSection, err := config.Section(*sourceProfile)
	region := sourceSection.ValueOf("region")
	section, err := config.Section(*profileName)
	if err != nil {
		section = config.NewSection(*profileName)
	}

	if region != "" {
		section.Add("region", region)
	}

	section.Add("aws_access_key_id", sessionDetails.AccessKeyId)
	section.Add("aws_secret_access_key", sessionDetails.SecretAccessKey)
	section.Add("aws_session_token", sessionDetails.SessionToken)
	section.Add("awsmfa_expiration", sessionDetails.Expiration)
	err = configparser.Save(config, *credFile)
	if err != nil {
		log.Fatal(err)
	}
}

// printNewProfile prints out the commands to set the credentials as env variables
// Returns nothing
func printNewProfile(sessionDetails credentialResult, format string) {
	switch format {
	case "bash":
		fmt.Printf("AWS_ACCESS_KEY_ID=%s; export AWS_ACCESS_KEY_ID;", sessionDetails.AccessKeyId)
		fmt.Printf("AWS_SECRET_ACCESS_KEY=%s; export AWS_SECRET_ACCESS_KEY;", sessionDetails.SecretAccessKey)
		fmt.Printf("AWS_SESSION_TOKEN=%s; export AWS_SESSION_TOKEN;", sessionDetails.SessionToken)
		fmt.Printf("AWS_SECURITY_TOKEN=%s; export AWS_SECURITY_TOKEN;", sessionDetails.SessionToken)
	case "cmd":
		fmt.Printf("setx AWS_ACCESS_KEY_ID=\"%s\";", sessionDetails.AccessKeyId)
		fmt.Printf("setx AWS_SECRET_ACCESS_KEY=\"%s\";", sessionDetails.SecretAccessKey)
		fmt.Printf("setx AWS_SESSION_TOKEN=\"%s\";", sessionDetails.SessionToken)
		fmt.Printf("setx AWS_SECURITY_TOKEN=\"%s\";", sessionDetails.SessionToken)
	case "pwshell":
		fmt.Printf("[Environment]::SetEnvironmentVariable(\"AWS_ACCESS_KEY_ID\", \"%s\", \"User\");", sessionDetails.AccessKeyId)
		fmt.Printf("[Environment]::SetEnvironmentVariable(\"AWS_SECRET_ACCESS_KEY\", \"%s\", \"User\");", sessionDetails.SecretAccessKey)
		fmt.Printf("[Environment]::SetEnvironmentVariable(\"AWS_SESSION_TOKEN\", \"%s\", \"User\");", sessionDetails.SessionToken)
		fmt.Printf("[Environment]::SetEnvironmentVariable(\"AWS_SECURITY_TOKEN\", \"%s\", \"User\");", sessionDetails.SessionToken)
	default:
		fmt.Printf("%s is an unrecognized option", format)
	}
}

// writeNewKeys replaces old aws keys in the credentials file
// Returns nothing
func writeNewKeys(credFile *string, profileName *string, newKeys *iam.CreateAccessKeyOutput) {
	config, err := configparser.Read(*credFile)
	sourceSection, err := config.Section(*profileName)
	region := sourceSection.ValueOf("region")
	section, err := config.Section(*profileName)
	if err != nil {
		section = config.NewSection(*profileName)
	}
	section.Add("region", region)
	section.Add("aws_access_key_id", *newKeys.AccessKey.AccessKeyId)
	section.Add("aws_secret_access_key", *newKeys.AccessKey.SecretAccessKey)
	err = configparser.Save(config, *credFile)
	if err != nil {
		log.Fatal(err)
	}
}

// checkProfileExists takes path to the credentials file and profile name to search for
// Returns bool and any errors
func checkProfileExists(credFile *string, profileName *string) (bool, error) {
	config, err := configparser.Read(*credFile)
	if err != nil {
		fmt.Println("Could not find credentials file")
		fmt.Println(err.Error())
		return false, err
	}
	section, err := config.Section(*profileName)
	if err != nil {
		fmt.Println("Could not find profile in credentials file")
		return false, nil
	}
	if !section.Exists("aws_access_key_id") {
		fmt.Println("Could not find access key in profile")
		return false, nil
	}

	return true, nil
}

// getConfigProfileValues takes path to the config file and profile name to search for
// Returns bool and any errors
func getConfigProfileValues(configFile *string, profileName *string) (*string, *string, error) {
	var err error
	config, err := configparser.Read(*configFile)
	if err != nil {
		fmt.Println("Could not find config file")
		fmt.Println(err.Error())
		return nil, nil, err
	}
	section, err := config.Section("profile " + *profileName)
	if err != nil {
		fmt.Println("Could not find profile in config file")
		return nil, nil, err
	}
	if !section.Exists("role_arn") {
		fmt.Println("Config File Not Configured Correctly")
		err = errors.New("Misconfigured config missing role_arn")
		return nil, nil, err
	}
	if !section.Exists("source_profile") {
		fmt.Println("Config File Not Configured Correctly")
		err = errors.New("Misconfigured config missing source_profile")
		return nil, nil, err
	}
	sourceProfile := section.ValueOf("source_profile")
	roleToAssume := section.ValueOf("role_arn")

	return &sourceProfile, &roleToAssume, nil
}

// getSTSCredentials takes session, users inputted MFA token, duration, and device serial
// Returns GetSessionTokenOutput
func getSTSCredentials(sess *session.Session, tokenCode string, duration *int64, device *string) *credentialResult {
	svc := sts.New(sess)
	params := &sts.GetSessionTokenInput{
		DurationSeconds: aws.Int64(*duration),
		SerialNumber:    aws.String(*device),
		TokenCode:       aws.String(tokenCode),
	}
	resp, err := svc.GetSessionToken(params)

	if err != nil {
		fmt.Println(err.Error())
		return nil
	}
	newDetails := credentialResult{
		AccessKeyId:     *resp.Credentials.AccessKeyId,
		SecretAccessKey: *resp.Credentials.SecretAccessKey,
		Expiration:      (*resp.Credentials.Expiration).String(),
		SessionToken:    *resp.Credentials.SessionToken,
	}
	return &newDetails
}

// getRoleCredentials takes session, users inputted MFA token, duration, and device serial, and Role To Assume
// Returns GetSessionTokenOutput
func getRoleCredentials(sess *session.Session, tokenCode string, duration *int64, device *string, role *string, sessionName *string) *credentialResult {
	svc := sts.New(sess)
	if *duration > 3600 {
		*duration = 3600
	}
	params := &sts.AssumeRoleInput{
		DurationSeconds: aws.Int64(*duration),
		RoleArn:         aws.String(*role),
		SerialNumber:    aws.String(*device),
		TokenCode:       aws.String(tokenCode),
		RoleSessionName: aws.String(*sessionName),
	}
	resp, err := svc.AssumeRole(params)

	if err != nil {
		fmt.Println(err.Error())
		return nil
	}
	newDetails := credentialResult{
		AccessKeyId:     *resp.Credentials.AccessKeyId,
		SecretAccessKey: *resp.Credentials.SecretAccessKey,
		Expiration:      (*resp.Credentials.Expiration).String(),
		SessionToken:    *resp.Credentials.SessionToken,
	}
	return &newDetails
}

// rotateCredentialKeys takes session and will delete users existing key and create a new one
// Returns the new credentials
func rotateCredentialKeys(sess *session.Session) (*iam.CreateAccessKeyOutput, error) {
	svc := iam.New(sess)
	input := &iam.ListAccessKeysInput{}
	var currentAccessKey *iam.AccessKeyMetadata
	var createResult *iam.CreateAccessKeyOutput
	result, err := svc.ListAccessKeys(input)
	if err != nil {
		fmt.Println(err.Error())
		return nil, err
	}
	currentCreds, err := sess.Config.Credentials.Get()
	for _, accessKey := range result.AccessKeyMetadata {
		if *accessKey.AccessKeyId == currentCreds.AccessKeyID {
			currentAccessKey = accessKey
		}
	}
	if currentAccessKey != nil {
		deleteKeyInput := &iam.DeleteAccessKeyInput{
			AccessKeyId: currentAccessKey.AccessKeyId,
		}
		_, err := svc.DeleteAccessKey(deleteKeyInput)
		if err != nil {
			fmt.Println(err.Error())
			return nil, err
		}
		createKeyInput := &iam.CreateAccessKeyInput{}
		createResult, err = svc.CreateAccessKey(createKeyInput)
		if err != nil {
			fmt.Println(err.Error())
			return nil, err
		}
		fmt.Printf("Replacing %s with %s", currentCreds.AccessKeyID, *createResult.AccessKey.AccessKeyId)
		return createResult, nil
	}
	return nil, errors.New("unable to find a current access key for this Identity")
}
