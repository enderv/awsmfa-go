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
	credFile := flag.String("c", filepath.Join(getCredentialPath(), ".aws", "credentials"), "Full path to credentials file")
	duration := flag.Int64("d", 28800, "Token Duration")
	flag.Parse()

	if sourceProfile == targetProfile {
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
	//Get MFA Code
	mfa, err := getMFACode()
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	tempCreds := getSTSCredentials(sess, mfa, duration, user)
	writeNewProfile(credFile, targetProfile, sourceProfile, tempCreds)
}

func getMFACode() (string, error) {
	var mfa string
	fmt.Print("Enter MFA Token: ")
	reader := bufio.NewReader(os.Stdin)
	mfa, err := reader.ReadString('\n')
	if err != nil {
		return mfa, errors.New("failed to get token")
	}
	fmt.Println(mfa)
	return strings.TrimSpace(mfa), nil
}

//CreateSession Creates AWS Session with specified profile
func CreateSession(profileName *string) *session.Session {
	profileNameValue := *profileName
	sess := session.Must(session.NewSessionWithOptions(session.Options{
		Profile: profileNameValue,
	}))
	return sess
}

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
	return mfaresp.MFADevices[0].SerialNumber, nil
}

func getCredentialPath() string {
	usr, err := user.Current()
	if err != nil {
		log.Fatal(err)
	}
	return usr.HomeDir
}

func writeNewProfile(credFile *string, profileName *string, sourceProfile *string, sessionDetails *sts.GetSessionTokenOutput) {
	config, err := configparser.Read(*credFile)
	sourceSection, err := config.Section(*sourceProfile)
	region := sourceSection.ValueOf("region")
	section, err := config.Section(*profileName)
	if err != nil {
		section = config.NewSection(*profileName)
	}
	section.Add("region", region)
	section.Add("aws_access_key_id", *sessionDetails.Credentials.AccessKeyId)
	section.Add("aws_secret_access_key", *sessionDetails.Credentials.SecretAccessKey)
	section.Add("aws_session_token", *sessionDetails.Credentials.SessionToken)
	section.Add("awsmfa_expiration", (*sessionDetails.Credentials.Expiration).String())
	err = configparser.Save(config, *credFile)
	if err != nil {
		log.Fatal(err)
	}
}

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

func getSTSCredentials(sess *session.Session, tokenCode string, duration *int64, device *string) *sts.GetSessionTokenOutput {
	svc := sts.New(sess)
	params := &sts.GetSessionTokenInput{
		DurationSeconds: aws.Int64(*duration),
		SerialNumber:    aws.String(*device),
		TokenCode:       aws.String(tokenCode),
	}
	resp, err := svc.GetSessionToken(params)

	if err != nil {
		// Print the error, cast err to awserr.Error to get the Code and
		// Message from an error.
		fmt.Println(err.Error())
		return nil
	}
	return resp
}
