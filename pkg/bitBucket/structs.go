package bitBucket

type Response struct {
	Scopes       string `bson:"scopes" json:"scopes"`
	AccessToken  string `bson:"access_token" json:"access_token"`
	ExpiresIn    int    `bson:"expires_in" json:"expires_in"`
	TokenType    string `bson:"token_type" json:"token_type"`
	RefreshToken string `bson:"refresh_token" json:"refresh_token"`
}
