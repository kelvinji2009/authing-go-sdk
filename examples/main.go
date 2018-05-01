package main

import (
	"encoding/json"
	"log"
	"os"
	"regexp"

	authing "github.com/Authing/authing-go-sdk"
	"github.com/kelvinji2009/graphql"
)

const (
	clientID  = "5adb75e03055230001023b26"
	appSecret = "e683d18f9d597317d43d7a6522615b9d"
)

func main() {
	client := authing.NewClient(clientID, appSecret, false)
	// Enable debug info for graphql client, just comment it if you want to disable the debug info
	client.Client.Log = func(s string) { log.Println(s) }

	// >>>>Graphql Mutation: register
	// input := authing.UserRegisterInput{
	// 	Email:            graphql.String("kelvinji2009@gmail.com"),
	// 	Password:         graphql.String("password"),
	// 	RegisterInClient: graphql.String(clientID),
	// }

	// m, err := client.Register(&input)
	// if err != nil {
	// 	log.Println(">>>>Register failed: " + err.Error())
	// } else {
	// 	printJSON(m)
	// }

	//------------------------------------------------------------------------------------

	// >>>>Graphql Mutation: login
	// loginInput := authing.UserLoginInput{
	// 	Email:            graphql.String("kelvinji2009@gmail.com"),
	// 	Password:         graphql.String("password!"),
	// 	RegisterInClient: graphql.String(clientID),
	// }

	// m, err := client.Login(&loginInput)
	// if err != nil {
	// 	log.Println(">>>>Login failed: " + err.Error())
	// } else {
	// 	printJSON(m)
	// }

	// userID := string(m.Login.ID) //5ae3d830f0db4b000117a95e

	//------------------------------------------------------------------------------------

	// >>>>Graphql Query: checkLoginStatus
	// q, err := client.CheckLoginStatus()
	// if err != nil {
	// 	log.Println(">>>>Check login status failed: " + err.Error())
	// } else {
	// 	printJSON(q)
	// }

	//------------------------------------------------------------------------------------

	// >>>>Graphql Query: user
	// p := authing.UserQueryParameter{
	// 	ID:               graphql.String("5ae3d830f0db4b000117a95e"),
	// 	RegisterInClient: graphql.String(clientID),
	// }

	// q, err := client.User(&p)
	// if err != nil {
	// 	log.Println(">>>>Query user failed: " + err.Error())
	// } else {
	// 	printJSON(q)
	// }

	//------------------------------------------------------------------------------------

	// >>>>Graphql Query: users
	// p := authing.UsersQueryParameter{
	// 	RegisterInClient: graphql.String(clientID),
	// 	Page:             graphql.Int(1),
	// 	Count:            graphql.Int(10),
	// }

	// q, err := client.Users(&p)
	// if err != nil {
	// 	log.Println(">>>>Query users failed: " + err.Error())
	// } else {
	// 	printJSON(q)
	// }

	//------------------------------------------------------------------------------------

	// >>>>Graphql Mutation: removeUsers
	removeUsersInput := authing.RemoveUsersInput{
		IDs:              []graphql.String{"5ae3d830f0db4b000117a95f"}, // NOTE: Please use your real user IDs
		RegisterInClient: graphql.String(clientID),
		// Operator should be your `Authing.cn` account ID
		// Operator:         graphql.String("5adb75be3055230001023b20"), // no more needed
	}

	// UserID Validation
	for i, id := range removeUsersInput.IDs {
		re := regexp.MustCompile("^[0-9a-fA-F]{24}$")

		if !re.MatchString(string(id)) {
			log.Fatalf(">>>> user ID is invalid ,index: %d, id: %s", i, id)
		}
	}

	m, err := client.RemoveUsers(&removeUsersInput)
	if err != nil {
		log.Println(">>>>Remove users failed: " + err.Error())
	} else {
		printJSON(m)
	}

	//------------------------------------------------------------------------------------

	// >>>>Graphql Mutation: updateUser
	// userUpdateInput := authing.UserUpdateInput{
	// 	ID:               graphql.String("5ae3d830f0db4b000117a95e"), // Mandotory in struct
	// 	Username:         graphql.String("kelvinji2009x"),
	// 	Nickname:         graphql.String("Sicario13th"),
	// 	Phone:            graphql.String("18665308994"),
	// 	RegisterInClient: graphql.String(clientID),
	// }

	// m, err := client.UpdateUser(&userUpdateInput)
	// if err != nil {
	// 	log.Println(">>>>Update user failed: " + err.Error())
	// } else {
	// 	printJSON(m)
	// }

	//------------------------------------------------------------------------------------

	// >>>>Graphql Muation: sendVerifyEmail
	// sendVerifyEmailInput := authing.SendVerifyEmailInput{
	// 	Email:  graphql.String("kelvinji2009@gmail.com"),
	// 	Client: graphql.String(clientID),
	// }

	// err := client.SendVerifyEmail(&sendVerifyEmailInput)
	// if err != nil {
	// 	log.Println(">>>>Send verify email failed: " + err.Error())
	// }

	//------------------------------------------------------------------------------------

	// >>>>Graphql Mutation: sendResetPasswordEmail
	// sendResetPasswordEmailInput := authing.SendResetPasswordEmailInput{
	// 	Client: graphql.String(clientID),
	// 	Email:  graphql.String("kelvinji2009@gmail.com"),
	// }

	// err := client.SendResetPasswordEmail(&sendResetPasswordEmailInput)
	// if err != nil {
	// 	log.Println(">>>>Send reset password email failed: " + err.Error())
	// }

	//------------------------------------------------------------------------------------

	// >>>>Graphql Mutation: verifyResetPasswordVerifyCode
	// verifyResetPasswordVerifyCodeInput := authing.VerifyResetPasswordVerifyCodeInput{
	// 	Client:     graphql.String(clientID),
	// 	Email:      graphql.String("kelvinji2009@gmail.com"),
	// 	VerifyCode: graphql.String("7670"),
	// }

	// err := client.VerifyResetPasswordVerifyCode(&verifyResetPasswordVerifyCodeInput)
	// if err != nil {
	// 	log.Println(">>>>Verify reset passwod verify code failed: " + err.Error())
	// }

	//------------------------------------------------------------------------------------

	// >>>>Graphql Mutation: changePassword
	// changePasswordInput := authing.ChangePasswordInput{
	// 	Client:     graphql.String(clientID),
	// 	Email:      graphql.String("kelvinji2009@gmail.com"),
	// 	VerifyCode: graphql.String("7670"),
	// 	Password:   graphql.String("password!"),
	// }

	// err := client.ChangePassword(&changePasswordInput)
	// if err != nil {
	// 	log.Println(">>>>Change password failed: " + err.Error())
	// }

	//------------------------------------------------------------------------------------

	// oauthClient := authing.NewOauthClient(clientID, appSecret, false)
	// // Enable debug info for graphql client, just comment it if you want to disable the debug info
	// oauthClient.Client.Log = func(s string) { log.Println(s) }

	// // >>>>Graphql Query: Read OAuth List
	// readOauthListQueryParameter := authing.ReadOauthListQueryParameter{
	// 	ClientID:   graphql.String(clientID),
	// 	DontGetURL: graphql.Boolean(false),
	// }

	// q, err := oauthClient.ReadOauthList(&readOauthListQueryParameter)
	// if err != nil {
	// 	log.Println(">>>>Read OAuth List failed: " + err.Error())
	// } else {
	// 	printJSON(q)
	// }

}

// printJSON prints v as JSON encoded with indent to stdout. It panics on any error.
func printJSON(v interface{}) {
	w := json.NewEncoder(os.Stdout)
	w.SetIndent("", "\t")
	err := w.Encode(v)
	if err != nil {
		panic(err)
	}
}
