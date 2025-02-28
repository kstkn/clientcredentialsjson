# ClientCredentialsJSON for Go OAuth2

clientcredentialsjson package provides an adjusted implementation of golang.org/x/oauth2/clientcredentials
for the case when auth server wants client credentials in JSON format.

# Usage

```go
package main

import (
    "context"
	"fmt"

    "github.com/kstkn/clientcredentialsjson"
)

func main() {
	cfg := &clientcredentialsjson.Config{
		ClientID:       clientID,
		ClientSecret:   clientSecret,
		TokenURL:       tokenURL,
		EndpointParams: make(url.Values),
	}
	cfg.EndpointParams.Set("username", username)
	cfg.EndpointParams.Set("password", password)

	token, err := cfg.Token(context.Background())
	fmt.Println(token, err)
}
```
