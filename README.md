# authing-go-sdk

### What is Authing

[Authing](https://authing.cn/) is an IDaaS which is created by Ivy.

### Qucik Guide

```go
package main

import (
	"encoding/json"
	"log"
	"os"

	"github.com/kelvinji2009/authing-go-sdk"
	"github.com/kelvinji2009/graphql"
)

const (
	clientID  = "5adb75e03055230001023b26"
	appSecret = "e683d18f9d597317d43d7a6522615b9d"
)

func main() {
	client := authing.NewClient(clientID, appSecret, false)

	// >>>Graphql Mutation: register
	input := authing.UserRegisterInput{
		Email:            graphql.String("kelvinji2009@gmail.com"),
		Password:         graphql.String("password"),
		RegisterInClient: graphql.String(clientID),
	}

	m, err := client.Register(&input)
	if err != nil {
		log.Println(">>>>Register failed: " + err.Error())
	} else {
		printJSON(m)
	}

	// oauthClient := authing.NewOauthClient(clientID, appSecret, false)

	// >>>>Graphql Query: Read OAuth List
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
```

### TODO

- [ ] More detailed API usages and documents
- [ ] Travis CI support


### Thanks
[Go GraphQL Client](https://github.com/shurcooL/graphql)

[Simple low-level GraphQL HTTP client for Go](https://github.com/machinebox/graphql)

