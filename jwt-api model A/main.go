package main

import (
  "encoding/json"
  "fmt"
  "log"
  "net/http"
  "os"
  "strconv"
  "strings"

  "github.com/dgrijalva/jwt-go"
  "github.com/gorilla/mux"
  "golang.org/x/crypto/bcrypt"
)

// Client struct with added ID
type Client struct {
  ID      int    `json:"id"`
  Username string `json:"username"`
  Password string `json:"password"`
  Token    string `json:"token"`
}

var clients []Client

func main() {
  if os.Getenv("JWT_SECRET") == "" {
    log.Fatalf("JWT_SECRET environment variable not set")
  }

  r := mux.NewRouter()
  r.HandleFunc("/api/register", RegisterClient).Methods("POST")
  r.HandleFunc("/api/profile", Auth(http.HandlerFunc(getProfile))).Methods("GET")

  log.Fatal(http.ListenAndServe(":8080", r))
}

// RegisterClient middleware
func RegisterClient(w http.ResponseWriter, r *http.Request) {
  if r.Method != "POST" {
    http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
    return
  }

  var newClient Client
  err := json.NewDecoder(r.Body).Decode(&newClient)
  if err != nil {
    http.Error(w, err.Error(), http.StatusBadRequest)
    return
  }

  // Generate strong random password hash
  hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newClient.Password), bcrypt.DefaultCost)
  if err != nil {
    http.Error(w, err.Error(), http.StatusInternalServerError)
    return
  }
  newClient.Password = string(hashedPassword)

  // Generate a JWT token
  token := generateJWT(newClient)

  // Store the client with the new token
  newClient.ID = len(clients) + 1 // Assigned ID automatically
  newClient.Token = token
  clients = append(clients, newClient)

  json.NewEncoder(w).Encode(newClient)
}

func getProfile(w http.ResponseWriter, r *http.Request) {
  username := r.Header.Get("X-Auth-Username")
  for _, client := range clients {
    if client.Username == username {
      json.NewEncoder(w).Encode(client)
      return
    }
  }
  http.Error(w, "Client not found", http.StatusForbidden)
}

// Auth middleware
func Auth(next http.Handler) http.Handler {
  return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    tokenString := r.Header.Get("Authorization")
    if strings.HasPrefix(tokenString, "Bearer ") {
      tokenString = tokenString[7:]
    }

    token, err := jwt.ParseWithClaims(tokenString, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
      return []byte(os.Getenv("JWT_SECRET")), nil
    })

    if err != nil {
      http.Error(w, err.Error(), http.StatusUnauthorized)
      return
    }

    if !token.Valid {
      http.Error(w, "Token invalid", http.StatusUnauthorized)
      return
    }

    // Authenticate client based on user id from JWT
    claims, ok := token.Claims.(*jwt.StandardClaims)
    if !ok || claims.Subject == "" {
      http.Error(w, "Invalid token claims", http.StatusUnauthorized)
      return
    }

    var loggedClient Client
    for _, client := range clients {
      if strconv.Itoa(client.ID) == claims.Subject {
        loggedClient = client
        break
      }
    }
    if loggedClient.ID == 0 {
      http.Error(w, "Client not found", http.StatusForbidden)
      return
    }

    // Generate a fresh token
    newToken := generateJWT(loggedClient)
    loggedClient.Token = newToken

    r.Header.Set("X-Auth-Username", loggedClient.Username)
    next.ServeHTTP(w, r)
  })
}

func generateJWT(client Client) string {
  token := jwt.New(jwt.SigningMethodHS256)
  token.Claims = &jwt.StandardClaims{
    Subject: strconv.Itoa(client.ID),
    ExpiresAt: time.Now().Add(time.Hour * 24).Unix(),
  }
  tokenString, err := token.SignedString([]byte(os.Getenv("JWT_SECRET")))
  if err != nil {
    log.Fatalf("Error generating JWT: %v", err)
  }
  return tokenString
}