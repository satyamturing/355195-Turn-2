package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
)

type client struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
	Token    string `json:"token"`
}

var clients []client

func main() {
	// Initialize database (in memory for this example)
	clients = []client{}

	// Set JWT secret
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		jwtSecret = "my-secret-key" // Replace this with a strong, secure secret key in production
		os.Setenv("JWT_SECRET", jwtSecret)
	}

	// Initialize router
	r := mux.NewRouter()

	r.HandleFunc("/api/register", RegisterClient).Methods("POST")
	r.HandleFunc("/api/login", Login).Methods("POST")
	r.PathPrefix("/api/protected").Handler(Auth(http.StripPrefix("/api/protected", http.HandlerFunc(protectedHandler))))

	fmt.Println("Server is running on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", r))
}

// RegisterClient middleware
func RegisterClient(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var newClient client
	err := json.NewDecoder(r.Body).Decode(&newClient)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newClient.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	newClient.Password = string(hashedPassword)

	// Generate a JWT token
	token := generateJWT(newClient)

	// Store the client with the new token
	newClient.Token = token
	clients = append(clients, newClient)

	json.NewEncoder(w).Encode(newClient)
}

// Login middleware
func Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var loginClient client
	err := json.NewDecoder(r.Body).Decode(&loginClient)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	for _, client := range clients {
		if client.Username == loginClient.Username {
			err := bcrypt.CompareHashAndPassword([]byte(client.Password), []byte(loginClient.Password))
			if err == nil {
				// Generate a JWT token
				token := generateJWT(client)
				client.Token = token
				json.NewEncoder(w).Encode(client)
				return
			}
		}
	}

	http.Error(w, "Invalid username or password", http.StatusUnauthorized)
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

		var loggedClient client
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

func protectedHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello, %s! You are protected.", r.Header.Get("X-Auth-Username"))
}

func generateJWT(client client) string {
	token := jwt.New(jwt.SigningMethodHS256)
	token.Claims = &jwt.StandardClaims{
		ExpiresAt: time.Now().Add(time.Hour * 24).Unix(),
		Subject:   strconv.Itoa(client.ID),
	}

	secret := []byte(os.Getenv("JWT_SECRET"))
	signedToken, err := token.SignedString(secret)
	if err != nil {
		log.Fatalf("Error generating token: %v", err)
	}

	return signedToken
}
