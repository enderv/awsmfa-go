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

	"github.com/alyu/configparser"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/sts"
)

func main() {
	sourceProfile := flag.String("i", "default", "Source Profile")
	targetProfile := flag.String("t", "default", "Destination Profile")
	rotateKeys := flag.Bool("rotate-identity-keys", false, "Boolean flag to rotate keys of the source profile when fetching new credentials")
	overwrite := flag.Bool("o", false, "Boolean flag to overwrite profile if this is not set you can not have same source and target profile")
	printOut := flag.Bool("env", false, "Flag to print commands to set environment variables")
	printFormat := flag.String("format", "bash", "Env OS Printout format, possible values are cmd, bash, pwshell")
	credFile := flag.String("c", filepath.Join(getCredentialPath(), ".aws", "credentials"), "Full path to credentials file")
	duration := flag.Int64("d", 28800, "Token Duration")
	flag.Parse()

	// If AWSMFA_ALWAYS_ROTATE is set to true, always rotate the key.
	forceRotate := strings.EqualFold(os.Getenv("AWSMFA_ALWAYS_ROTATE"), "true")

	if sourceProfile == targetProfile && !*overwrite {
		fmt.Println("Source equals target and will overwrite it you probably don't want to do this")
		return
	}

	//Get Current Credentials
	exists, err := checkProfileExists(credFile, sourceProfile)
	if err != nil || !exists {
		fmt.Println(err.Error())
		return
	}
	sess := CreateSession(sourceProfile)
	user, err := getUserMFA(sess)
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

	tempCreds := getSTSCredentials(sess, mfa, duration, user)
	if tempCreds != nil {
		writeNewProfile(credFile, targetProfile, sourceProfile, tempCreds)
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
			printNewProfile(tempCreds, strings.ToLower(*printFormat))
		}
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
func writeNewProfile(credFile *string, profileName *string, sourceProfile *string, sessionDetails *sts.GetSessionTokenOutput) {
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

	section.Add("aws_access_key_id", *sessionDetails.Credentials.AccessKeyId)
	section.Add("aws_secret_access_key", *sessionDetails.Credentials.SecretAccessKey)
	section.Add("aws_session_token", *sessionDetails.Credentials.SessionToken)
	section.Add("awsmfa_expiration", (*sessionDetails.Credentials.Expiration).String())
	err = configparser.Save(config, *credFile)
	if err != nil {
		log.Fatal(err)
	}
}

// printNewProfile prints out the commands to set the credentials as env variables
// Returns nothing
func printNewProfile(sessionDetails *sts.GetSessionTokenOutput, format string) {
	switch format {
	case "bash":
		fmt.Printf("AWS_ACCESS_KEY_ID=%s; export AWS_ACCESS_KEY_ID;", *sessionDetails.Credentials.AccessKeyId)
		fmt.Printf("AWS_SECRET_ACCESS_KEY=%s; export AWS_SECRET_ACCESS_KEY;", *sessionDetails.Credentials.SecretAccessKey)
		fmt.Printf("AWS_SESSION_TOKEN=%s; export AWS_SESSION_TOKEN;", *sessionDetails.Credentials.SessionToken)
		fmt.Printf("AWS_SECURITY_TOKEN=%s; export AWS_SECURITY_TOKEN;", *sessionDetails.Credentials.SessionToken)
	case "cmd":
		fmt.Printf("setx AWS_ACCESS_KEY_ID=\"%s\";", *sessionDetails.Credentials.AccessKeyId)
		fmt.Printf("setx AWS_SECRET_ACCESS_KEY=\"%s\";", *sessionDetails.Credentials.SecretAccessKey)
		fmt.Printf("setx AWS_SESSION_TOKEN=\"%s\";", *sessionDetails.Credentials.SessionToken)
		fmt.Printf("setx AWS_SECURITY_TOKEN=\"%s\";", *sessionDetails.Credentials.SessionToken)
	case "pwshell":
		fmt.Printf("[Environment]::SetEnvironmentVariable(\"AWS_ACCESS_KEY_ID\", \"%s\", \"User\");", *sessionDetails.Credentials.AccessKeyId)
		fmt.Printf("[Environment]::SetEnvironmentVariable(\"AWS_SECRET_ACCESS_KEY\", \"%s\", \"User\");", *sessionDetails.Credentials.SecretAccessKey)
		fmt.Printf("[Environment]::SetEnvironmentVariable(\"AWS_SESSION_TOKEN\", \"%s\", \"User\");", *sessionDetails.Credentials.SessionToken)
		fmt.Printf("[Environment]::SetEnvironmentVariable(\"AWS_SECURITY_TOKEN\", \"%s\", \"User\");", *sessionDetails.Credentials.SessionToken)
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

// getSTSCredentials takes session, users inputted MFA token, duration, and device serial
// Returns GetSessionTokenOutput
func getSTSCredentials(sess *session.Session, tokenCode string, duration *int64, device *string) *sts.GetSessionTokenOutput {
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
	return resp
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
