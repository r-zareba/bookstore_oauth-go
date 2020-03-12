package oauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/mercadolibre/golang-restclient/rest"
	"github.com/r-zareba/bookstore_utils-go/rest_errors"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	headerXPublic   = "X-Public"
	headerXClientId = "X-Client-Id"
	headerXCallerId   = "X-Caller-Id"

	paramAccessToken = "access_token"
)

var (
	oAuthRestClient = rest.RequestBuilder{
		BaseURL: "http://localhost:8080",
		Timeout: 200 * time.Millisecond,
	}
)

type accessToken struct {
	Token     string `json:"token"`
	UserId    int64  `json:"user_id"`
	ClientId  int64  `json:"client_id"`
	ExpiresIn int64  `json:"expires_in"`
}

func IsPublic(request *http.Request) bool {
	if request == nil {
		return true
	}
	return request.Header.Get(headerXPublic) == "true"
}

func GetCallerId(request *http.Request) int64 {
	if request == nil {
		return 0
	}
	callerId, err := strconv.ParseInt(request.Header.Get(headerXCallerId), 10, 64)
	if err != nil {
		return 0
	}
	return callerId
}

func GetClientId(request *http.Request) int64 {
	if request == nil {
		return 0
	}
	callerId, err := strconv.ParseInt(request.Header.Get(headerXClientId), 10, 64)
	if err != nil {
		return 0
	}
	return callerId
}

func AuthenticateRequest(request *http.Request) *rest_errors.RestError {
	if request == nil {
		return nil
	}

	cleanRequest(request)
	accessTokenId := strings.TrimSpace(request.URL.Query().Get(paramAccessToken))
	if accessTokenId == "" {
		return nil
	}

	at, err := getAccessToken(accessTokenId)
	if err != nil {
		if err.Status == http.StatusNotFound {
			return nil
		}
		return err
	}
	request.Header.Add(headerXClientId, strconv.FormatInt(at.ClientId, 10))
	request.Header.Add(headerXCallerId, strconv.FormatInt(at.UserId, 10))
	return nil
}

func cleanRequest(request *http.Request) {
	if request == nil {
		return
	}
	request.Header.Del(headerXClientId)
	request.Header.Del(headerXCallerId)
}

func getAccessToken(accessTokenId string) (*accessToken, *rest_errors.RestError) {

	response := oAuthRestClient.Get(fmt.Sprintf("/oauth/access_token/%s", accessTokenId))
	if response == nil || response.Response == nil {
		return nil, rest_errors.InternalServerError("Invalid Rest client response when trying to login user",
			errors.New("invalid response err"))
	}

	if response.StatusCode > 299 {
		var restErr rest_errors.RestError
		err := json.Unmarshal(response.Bytes(), &restErr)
		if err != nil {
			return nil, rest_errors.InternalServerError("Invalid error interface when trying to login user",
				errors.New("invalid response err"))
		}
		return nil, &restErr
	}

	fmt.Println("RESPONSE ", response)
	var at accessToken
	err := json.Unmarshal(response.Bytes(), &at)
	if err != nil {
		return nil, rest_errors.InternalServerError("Error when trying to unmarshal users response",
			errors.New("invalid response err"))
	}
	return &at, nil
}



type aAuthClient struct {
}

type oAuthInterface interface {
}

