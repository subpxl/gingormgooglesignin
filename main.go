package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// User struct with GORM fields
type User struct {
	gorm.Model
	Email         string `json:"email" gorm:"unique"`
	Password      string `json:"password,omitempty"`
	VerifiedEmail bool   `json:"verified_email"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
	GoogleID      string `json:"google_id"`
}

// Create a separate struct for Google's response
type GoogleUser struct {
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
	ID            string `json:"id"` // Google returns ID as string
}

// RegisterInput struct for registration
type RegisterInput struct {
	Email    string `json:"email" binding:"required"`
	Password string `json:"password" binding:"required"`
	Name     string `json:"name" binding:"required"`
}

// LoginInput struct for login
type LoginInput struct {
	Email    string `json:"email" binding:"required"`
	Password string `json:"password" binding:"required"`
}

var (
	config *oauth2.Config
	db     *gorm.DB
)

// AuthMiddleware checks if user is authenticated
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		userID := session.Get("userID")
		if userID == nil {
			c.Redirect(http.StatusSeeOther, "/")
			c.Abort()
			return
		}
		c.Next()
	}
}

func init() {
	// Load .env file
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Error loading .env file: %v", err)
	}

	// Initialize database
	db, err = gorm.Open(sqlite.Open("users.db"), &gorm.Config{})
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	// Auto migrate the schema
	db.AutoMigrate(&User{})

	config = &oauth2.Config{
		ClientID:     os.Getenv("CLIENTID"),
		ClientSecret: os.Getenv("CLIENTSECRET"),
		RedirectURL:  "http://localhost:8000/callback",
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
		},
		Endpoint: google.Endpoint,
	}
}

func main() {
	router := gin.Default()
	router.LoadHTMLGlob("templates/*")
	// Setup session middleware
	store := cookie.NewStore([]byte("secret"))
	router.Use(sessions.Sessions("mysession", store))

	// Public routes
	router.GET("/", handleHome)
	router.GET("/login", handleLogin)
	router.GET("/callback", handleCallback)
	router.POST("/register", handleRegister)
	router.POST("/login-traditional", handleTraditionalLogin)
	router.GET("/logout", handleLogout)

	// Protected routes
	protected := router.Group("/protected")
	protected.Use(AuthMiddleware())
	{
		protected.GET("/dashboard", handleDashboard)
	}

	router.Run("127.0.0.1:8000")
}

func handleHome(c *gin.Context) {
	c.HTML(http.StatusOK, "index.html", gin.H{
		"title": "Main website",
	})
}

func handleLogin(c *gin.Context) {
	url := config.AuthCodeURL("state")
	c.Redirect(http.StatusTemporaryRedirect, url)
}

func handleRegister(c *gin.Context) {
	var input RegisterInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}

	user := User{
		Email:    input.Email,
		Password: string(hashedPassword),
		Name:     input.Name,
	}

	result := db.Create(&user)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
		return
	}

	user.Password = "" // Remove password from response
	c.JSON(http.StatusOK, user)
}

func handleTraditionalLogin(c *gin.Context) {
	var input LoginInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var user User
	result := db.Where("email = ?", input.Email).First(&user)
	if result.Error != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(input.Password))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	session := sessions.Default(c)
	session.Set("userID", user.ID)
	session.Save()

	c.JSON(http.StatusOK, gin.H{"success": true})
}

// Modify the handleCallback function
func handleCallback(c *gin.Context) {
	code := c.Query("code")

	token, err := config.Exchange(c, code)
	if err != nil {
		c.String(http.StatusInternalServerError, "Failed to exchange token: "+err.Error())
		return
	}

	client := config.Client(c, token)
	userInfo, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		c.String(http.StatusInternalServerError, "Failed to get user info: "+err.Error())
		return
	}
	defer userInfo.Body.Close()

	// Use GoogleUser struct instead of User
	var googleUser GoogleUser
	if err := json.NewDecoder(userInfo.Body).Decode(&googleUser); err != nil {
		c.String(http.StatusInternalServerError, "Failed to decode user info: "+err.Error())
		return
	}

	// Check if user exists
	var user User
	result := db.Where("email = ?", googleUser.Email).First(&user)
	if result.Error != nil {
		// Create new user from Google data
		user = User{
			Email:         googleUser.Email,
			VerifiedEmail: googleUser.VerifiedEmail,
			Name:          googleUser.Name,
			Picture:       googleUser.Picture,
			GoogleID:      googleUser.ID,
		}
		result = db.Create(&user)
		if result.Error != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
			return
		}
	} else {
		// Update existing user with Google info
		user.Picture = googleUser.Picture
		user.VerifiedEmail = true
		user.GoogleID = googleUser.ID
		db.Save(&user)
	}

	session := sessions.Default(c)
	session.Set("userID", user.ID)
	session.Save()

	c.Redirect(http.StatusSeeOther, "/protected/dashboard")
}

func handleDashboard(c *gin.Context) {
	session := sessions.Default(c)
	userID := session.Get("userID")

	var user User
	db.First(&user, userID)

	c.HTML(http.StatusOK, "dashboard.html", gin.H{
		"user": user,
	})
}

func handleLogout(c *gin.Context) {
	session := sessions.Default(c)
	session.Clear()
	session.Save()
	c.Redirect(http.StatusSeeOther, "/")
}
