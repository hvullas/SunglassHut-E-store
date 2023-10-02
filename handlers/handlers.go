package handlers

import (
	"backend/authorise"
	"backend/db"
	"backend/token"
	"crypto/internal/edwards25519/field"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"path"
	"regexp"
	"strconv"
	"time"

	"github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

type NewUserReg struct {
	UserName    string  `json:"user_name"`
	Email       string  `json:"email"`
	PhoneNumber string  `json:"phone_number"`
	Password    string  `json:"password"`
	Role        []int64 `json:"role"`
}

type UserId struct {
	UserId int64  `json:"user_id,omitempty"`
	Token  string `json:"token,omitempty"`
}

// user registration handler
func NewUser(w http.ResponseWriter, r *http.Request) {
	log.Println(r.URL)
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		w.WriteHeader(405) //method not allowed
		return
	}

	var userdata NewUserReg
	err := json.NewDecoder(r.Body).Decode(&userdata)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if len(userdata.UserName) > 20 {
		http.Error(w, "Username must should be 6 to 20 characters", http.StatusBadRequest)
		return
	}

	err = ValidatePassword(userdata.Password)
	if err != nil {
		http.Error(w, "Choose correct password", http.StatusBadRequest)
		return
	}
	err = ValidateEmail(userdata.Email)
	if err != nil {
		http.Error(w, "Choose correct password", http.StatusBadRequest)
		return
	}
	err = ValidatePhone(userdata.PhoneNumber)
	if err != nil {
		http.Error(w, "Choose correct password", http.StatusBadRequest)
		return
	}
	pass := []byte(userdata.Password)

	//Hashing the password
	hash, err := bcrypt.GenerateFromPassword(pass, 7)
	if err != nil {
		panic(err)
	}
	var exists bool
	err = db.DB.QueryRow("SELECT EXISTS (SELECT 1 FROM users WHERE email=$1 AND phone_number=$2)", userdata.Email, userdata.PhoneNumber).Scan(&exists)
	if err != nil {
		panic(err)
	}

	if exists {
		http.Error(w, "User exists with this mail id or phone number", http.StatusBadRequest)
		return
	}

	if len(userdata.Role) == 0 {
		http.Error(w, "Role not mentioned", http.StatusBadRequest)
	}
	var userId UserId
	err = db.DB.QueryRow("INSERT INTO users(name,email,phone_number,role,password) VALUES($1,$2,$3,$4,$5) RETURNING user_id", userdata.UserName, userdata.Email, userdata.PhoneNumber, pq.Array(userdata.Role), string(hash)).Scan(&userId.UserId)
	if err != nil {
		fmt.Println(err)
		http.Error(w, "Error creating user", http.StatusInternalServerError)
		return
	}

	for _, val := range userdata.Role {

		_, err = db.DB.Exec("INSERT INTO user_role(user_id,role_id) VALUES($1,$2)", userId.UserId, val)
		if err != nil {
			http.Error(w, "Error assigning role to user", http.StatusInternalServerError)
			return
		}

	}

	claims := &token.JwtClaims{
		Username: userdata.UserName,
		Roles:    userdata.Role,
	}

	userId.Token, err = token.GenrateToken(claims, time.Now().Add(time.Hour*300))
	if err != nil {
		http.Error(w, "error generating token", http.StatusInternalServerError)
		return
	}

	err = json.NewEncoder(w).Encode(userId)
	if err != nil {
		http.Error(w, "Error encoding response", http.StatusInternalServerError)
		return
	}
	return

}

type Credentials struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type Session struct {
	UserId int64   `json:"user_id"`
	Name   string  `json:"user_name"`
	Role   []int64 `json:"role"`
	Token  string  `json:"token"`
}

// login handler
func Login(w http.ResponseWriter, r *http.Request) {
	log.Println(r.URL)
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var credentials Credentials
	err := json.NewDecoder(r.Body).Decode(&credentials)
	if err != nil {
		http.Error(w, "Error decoding the body", http.StatusBadRequest)
		return
	}
	var session Session
	var passwordHash, name string
	var role pq.Int64Array
	err = db.DB.QueryRow("SELECT user_id,name,password,role FROM users WHERE email=$1", credentials.Email).Scan(&session.UserId, &session.Name, &passwordHash, &role)
	if err != nil {
		if err == sql.ErrNoRows {
			fmt.Fprintln(w, "Invalid email")
			return
		}
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}
	err = bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(credentials.Password))
	if err != nil {
		fmt.Fprintln(w, "Invalid password")
		return
	}
	claims := &token.JwtClaims{
		Username: name,
		Roles:    role,
	}

	expirationTime := time.Now().Add(time.Hour * 300)

	session.Token, err = token.GenrateToken(claims, expirationTime)
	if err != nil {
		http.Error(w, "error generating token", http.StatusInternalServerError)
		return
	}

	session.Role = role

	err = json.NewEncoder(w).Encode(session)
	if err != nil {
		http.Error(w, "Error encoding token", http.StatusInternalServerError)
		return
	}

	fmt.Fprintln(w, "Logged in successfully")

}

type Token struct {
	Token string `json:"token"`
}

type Brand struct {
	BrandId    int64    `json:"brand_id,omitempty"`
	BrandName  string   `json:"brand_name,omitempty"`
	BrandLogo  string   `json:"brand_logo,omitempty"`
	BrandInfo  string   `json:"brand_info,omitempty"`
	BrandImage []string `json:"images,omitempty"`
	Token      string   `json:"token,omitempty"`
}

type ProductPic struct {
	Front string `json:"front_view,omitempty"`
	Back  string `json:"back_view,omitempty"`
	Side  string `json:"side_view,omitempty"`
	Top   string `json:"top_view,omitempty"`
}

type Product struct {
	ProductId         int64    `json:"product_id,omitempty"`
	ProductName       string   `json:"product_name,omitempty"`
	ProductCategory   string   `json:"product_category,omitempty"` //M or F or U
	GlassType         string   `json:"glass_type,omitempty"`       //polarized or clear&photochromatic lenses
	ProductPrice      float64  `json:"product_price,omitempty"`
	ProductURL        []string `json:"product_pictures,omitempty"`
	ProductDimensions []int64  `json:"dimensions,omitempty"`
	FrameSize         string   `json:"frame_size,omitempty"`
	FrameColor        []string `json:"frame_color,omitempty"`
	FrameType         string   `json:"frame_type,omitempty"`
	FrameShape        string   `json:"frame_shape,omitempty"`
	FrameMaterial     string   `json:"rame_material,omitempty"`
	Fit               string   `json:"fit,omitempty"`
	LensFeature       string   `json:"lens_feature,omitempty"`
	LensHeight        int64    `json:"lens_height,omitempty"`
	LensColor         string   `json:"lens_color,omitempty"`
	LensMaterial      string   `json:"lens_material,omitempty"`
	SuitableFaces     []string `json:"suitable_faces,omitempty"`
	ProductInfo       string   `json:"product_info,omitempty"`
	AvailableQuantity int64    `json:"available_quantity,omitempty"`
	DiscountedPrice   *float64 `json:"discounted_price,omitempty"`
	Brand             Brand    `json:"brand,omitempty"`
	BrandId           int64    `json:"brand_id,omitempty"`

	Token string `json:"token,omitempty"`
}

// homepage handler
func AllBrands(w http.ResponseWriter, r *http.Request) {
	log.Println(r.URL)
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var jwttoken Token
	err := json.NewDecoder(r.Body).Decode(&jwttoken)
	if err != nil {
		http.Error(w, "Error decoding request body", http.StatusBadRequest)
		return
	}
	//specify the permission id
	valid, _ := authorise.CheckPerm(jwttoken.Token, 7)
	if !valid {
		http.Error(w, "User unauthorised", http.StatusUnauthorized)
		return
	}

	var brand []Brand
	row, err := db.DB.Query("SELECT brand_id,brand_name,brand_logo,brand_images FROM brands")
	if err != nil {
		http.Error(w, "Query error on brands", http.StatusInternalServerError)
		return
	}
	for row.Next() {
		var brand_info Brand
		err = row.Scan(&brand_info.BrandId, &brand_info.BrandName, &brand_info.BrandLogo, pq.Array(&brand_info.BrandImage))
		if err != nil {
			http.Error(w, "Scan error on brands", http.StatusInternalServerError)
			return
		}
		brand_info.BrandLogo = "http://localhost:3000/brandlogo/" + brand_info.BrandLogo
		for i, val := range brand_info.BrandImage {
			brand_info.BrandImage[i] = "http://localhost:3000/brandimage/" + val
		}
		brand = append(brand, brand_info)
	}

	err = json.NewEncoder(w).Encode(brand)
	if err != nil {
		http.Error(w, "Error encoding response", http.StatusInternalServerError)
		return
	}

}

// collections/women handler
func ProductsByCategory(w http.ResponseWriter, r *http.Request) {
	log.Println(r.URL)
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	category := path.Base(r.URL.Path)
	if category == "men" {
		category = "M"
	}

	if category == "women" {
		category = "F"
	}

	var jwttoken Token
	err := json.NewDecoder(r.Body).Decode(&jwttoken)
	if err != nil {
		http.Error(w, "Error decoding request body", http.StatusBadRequest)
		return
	}
	//specify the permission id
	valid, _ := authorise.CheckPerm(jwttoken.Token, 10)
	if !valid {
		http.Error(w, "User unauthorised", http.StatusUnauthorized)
		return
	}

	var products []Product
	row, err := db.DB.Query("SELECT product_id,product_name,category,product_image,product_price FROM products WHERE category=$1", category)
	if err != nil {
		fmt.Println(err)
		http.Error(w, "Query error on products", http.StatusInternalServerError)
		return
	}

	for row.Next() {
		var prod Product
		err = row.Scan(&prod.ProductId, &prod.ProductName, &prod.ProductCategory, pq.Array(&prod.ProductURL), &prod.ProductPrice)
		if err != nil {
			http.Error(w, "Scan error on products", http.StatusInternalServerError)
			return
		}

		for i, val := range prod.ProductURL {
			prod.ProductURL[i] = "http://localhost:3000/product_images/" + val
		}
		products = append(products, prod)
	}

	json.NewEncoder(w).Encode(products)
}

// collection/brand -> get products by brand name
func ProductsByBrand(w http.ResponseWriter, r *http.Request) {
	log.Println(r.URL)
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	brandIdstr := path.Base(r.URL.Path)
	brandId, err := strconv.Atoi(brandIdstr)
	if err != nil {
		http.Error(w, "Invalid brand id", http.StatusBadRequest)
		return
	}

	var jwttoken Token
	err = json.NewDecoder(r.Body).Decode(&jwttoken)
	if err != nil {
		http.Error(w, "Error decoding request body", http.StatusBadRequest)
		return
	}
	//specify the permission id
	valid, _ := authorise.CheckPerm(jwttoken.Token, 10)
	if !valid {
		http.Error(w, "User unauthorised", http.StatusUnauthorized)
		return
	}

	var products []Product
	row, err := db.DB.Query("SELECT product_id,product_name,product_image,product_price,discounted_price,glass_type FROM products WHERE brand_id=$1", brandId)
	if err != nil {
		fmt.Println(err)
		http.Error(w, "Query error on products", http.StatusInternalServerError)
		return
	}

	for row.Next() {
		var prod Product
		err = row.Scan(&prod.ProductId, &prod.ProductName, pq.Array(&prod.ProductURL), &prod.ProductPrice, &prod.DiscountedPrice, &prod.GlassType)
		if err != nil {
			http.Error(w, "Scan error on products", http.StatusInternalServerError)
			return
		}
		for i, val := range prod.ProductURL {
			prod.ProductURL[i] = "http://localhost:3000/product_images/" + val
		}
		products = append(products, prod)
	}

	json.NewEncoder(w).Encode(products)
}

// new arrival --queried based on recently added products
func NewArrival(w http.ResponseWriter, r *http.Request) {
	log.Println(r.URL)
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var jwttoken Token
	err := json.NewDecoder(r.Body).Decode(&jwttoken)
	if err != nil {
		http.Error(w, "Error decoding request body", http.StatusBadRequest)
		return
	}
	//specify the permission id
	valid, _ := authorise.CheckPerm(jwttoken.Token, 10)
	if !valid {
		http.Error(w, "User unauthorised", http.StatusUnauthorized)
		return
	}

	var products []Product
	row, err := db.DB.Query("SELECT product_id,product_name,product_image,product_price,glass_type FROM products WHERE created_at > now()-INTERVAL '15' day")
	if err != nil {
		fmt.Println(err)
		http.Error(w, "Query error on products", http.StatusInternalServerError)
		return
	}

	for row.Next() {
		var prod Product
		err = row.Scan(&prod.ProductId, &prod.ProductName, pq.Array(&prod.ProductURL), &prod.ProductPrice, &prod.GlassType)
		if err != nil {
			http.Error(w, "Scan error on products", http.StatusInternalServerError)
			return
		}
		for i, val := range prod.ProductURL {
			prod.ProductURL[i] = "http://localhost:3000/product_images/" + val
		}
		products = append(products, prod)
	}

	json.NewEncoder(w).Encode(products)
}

// sales handler gives product in which the products.discounted_price field is set in db
func Sales(w http.ResponseWriter, r *http.Request) {
	log.Println(r.URL)
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var jwttoken Token
	err := json.NewDecoder(r.Body).Decode(&jwttoken)
	if err != nil {
		http.Error(w, "Error decoding request body", http.StatusBadRequest)
		return
	}
	//specify the permission id
	valid, _ := authorise.CheckPerm(jwttoken.Token, 10)
	if !valid {
		http.Error(w, "User unauthorised", http.StatusUnauthorized)
		return
	}

	var products []Product
	row, err := db.DB.Query("SELECT product_id,product_name,product_image,product_price,glass_type,discounted_price FROM products WHERE discounted_price IS NOT NULL")
	if err != nil {
		fmt.Println(err)
		http.Error(w, "Query error on products", http.StatusInternalServerError)
		return
	}

	for row.Next() {
		var prod Product
		err = row.Scan(&prod.ProductId, &prod.ProductName, pq.Array(&prod.ProductURL), &prod.ProductPrice, &prod.GlassType, &prod.DiscountedPrice)
		if err != nil {
			http.Error(w, "Scan error on products", http.StatusInternalServerError)
			return
		}
		for i, val := range prod.ProductURL {
			prod.ProductURL[i] = "http://localhost:3000/product_images/" + val
		}
		products = append(products, prod)
	}

	json.NewEncoder(w).Encode(products)
}

// request body to get products by gender(men/women)
type ProductByCategory struct {
	Token    string `json:"token"`
	Brand_id int64  `json:"brand_id"`
	Category string `json:"category"`
}

// get products for men and women by brands
func ProductsForGender(w http.ResponseWriter, r *http.Request) {
	log.Println(r.URL)
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var info ProductByCategory
	err := json.NewDecoder(r.Body).Decode(&info)
	if err != nil {
		http.Error(w, "Error decoding request body", http.StatusBadRequest)
		return
	}
	//specify the permission id
	valid, _ := authorise.CheckPerm(info.Token, 10)
	if !valid {
		http.Error(w, "User unauthorised", http.StatusUnauthorized)
		return
	}

	var products []Product
	row, err := db.DB.Query("SELECT product_id,product_name,product_image,product_price,glass_type,discounted_price,category FROM products WHERE brand_id=$1 AND category=$2", info.Brand_id, info.Category)
	if err != nil {
		fmt.Println(err)
		http.Error(w, "Query error on products", http.StatusInternalServerError)
		return
	}

	for row.Next() {
		var prod Product
		err = row.Scan(&prod.ProductId, &prod.ProductName, pq.Array(&prod.ProductURL), &prod.ProductPrice, &prod.GlassType, &prod.DiscountedPrice, &prod.ProductCategory)
		if err != nil {
			http.Error(w, "Scan error on products", http.StatusInternalServerError)
			return
		}
		for i, val := range prod.ProductURL {
			prod.ProductURL[i] = "http://localhost:3000/product_images/" + val
		}
		products = append(products, prod)
	}

	json.NewEncoder(w).Encode(products)
}

// get product by product_id
func ProductById(w http.ResponseWriter, r *http.Request) {
	log.Println(r.URL)
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	idStr := path.Base(r.URL.Path)
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Invalid product id", http.StatusBadRequest)
		return
	}

	var token Token
	err = json.NewDecoder(r.Body).Decode(&token)
	if err != nil {
		http.Error(w, "Error decoding request body", http.StatusBadRequest)
		return
	}
	//specify the permission id
	valid, _ := authorise.CheckPerm(token.Token, 10)
	if !valid {
		http.Error(w, "User unauthorised", http.StatusUnauthorized)
		return
	}

	var prod Product
	err = db.DB.QueryRow("SELECT product_id,product_name,dimensions,frame_size,frame_color,frame_type,frame_shape,frame_material,fit,lens_feature,lens_height,lens_color,lens_material,suitable_faces,product_information,glass_type,product_image,product_price,discounted_price,brand_name,brand_logo,brand_info FROM products inner join brands ON products.brand_id=brands.brand_id WHERE product_id=$1", id).Scan(&prod.ProductId, &prod.ProductName, pq.Array(&prod.ProductDimensions), &prod.FrameSize, pq.Array(&prod.FrameColor), &prod.FrameType, &prod.FrameShape, &prod.FrameMaterial, &prod.Fit, &prod.LensFeature, &prod.LensHeight, &prod.LensColor, &prod.LensMaterial, pq.Array(&prod.SuitableFaces), &prod.ProductInfo, &prod.GlassType, pq.Array(&prod.ProductURL), &prod.ProductPrice, &prod.DiscountedPrice, &prod.Brand.BrandName, &prod.Brand.BrandLogo, &prod.Brand.BrandInfo)
	if err != nil {
		// fmt.Println(err)
		http.Error(w, "Query error on products", http.StatusInternalServerError)
		return
	}

	for i, val := range prod.ProductURL {
		prod.ProductURL[i] = "http://localhost:3000/product_images/" + val
	}

	json.NewEncoder(w).Encode(prod)
}

// product by tag
func ProductByTag(w http.ResponseWriter, r *http.Request) {
	log.Println(r.URL)
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	tagidStr := path.Base(r.URL.Path)
	tagid, err := strconv.Atoi(tagidStr)
	if err != nil {
		http.Error(w, "Invalid product id", http.StatusBadRequest)
		return
	}

	var info ProductByCategory
	err = json.NewDecoder(r.Body).Decode(&info)
	if err != nil {
		http.Error(w, "Error decoding request body", http.StatusBadRequest)
		return
	}
	//specify the permission id
	valid, _ := authorise.CheckPerm(info.Token, 10)
	if !valid {
		http.Error(w, "User unauthorised", http.StatusUnauthorized)
		return
	}
	var products []Product
	row, err := db.DB.Query("SELECT product_id,product_name,product_image,product_price,glass_type,discounted_price,category FROM products WHERE $1=ANY(tags)", tagid)
	if err != nil {
		fmt.Println(err)
		http.Error(w, "Query error on products", http.StatusInternalServerError)
		return
	}

	for row.Next() {
		var prod Product
		err = row.Scan(&prod.ProductId, &prod.ProductName, pq.Array(&prod.ProductURL), &prod.ProductPrice, &prod.GlassType, &prod.DiscountedPrice, &prod.ProductCategory)
		if err != nil {
			http.Error(w, "Scan error on products", http.StatusInternalServerError)
			return
		}
		for i, val := range prod.ProductURL {
			prod.ProductURL[i] = "http://localhost:3000/product_images/" + val
		}
		products = append(products, prod)
	}

	json.NewEncoder(w).Encode(products)

}

// insert brands
func CreateBrands(w http.ResponseWriter, r *http.Request) {
	log.Println(r.URL)
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var brandData Brand
	err := json.NewDecoder(r.Body).Decode(&brandData)
	if err != nil {
		http.Error(w, "Error decoding request body", http.StatusBadRequest)
		return
	}

	//specify the permission id
	valid, _ := authorise.CheckPerm(brandData.Token, 13) //permission id for deleting brands
	if !valid {
		http.Error(w, "User unauthorised", http.StatusUnauthorized)
		return
	}

	if len(brandData.BrandName) < 1 && len(brandData.BrandName) > 40 {
		http.Error(w, "Len of Brand name should be atleast between 1 and 40 ", http.StatusBadRequest)
		return
	}

	if len(brandData.BrandInfo) > 250 {
		http.Error(w, "Brand info can contain upto 250 charactes only", http.StatusBadRequest)
		return
	}

	err = db.DB.QueryRow("INSERT INTO brands(brand_name,brand_info) VALUES($1,$2) RETURNING brand_id", brandData.BrandName, brandData.BrandInfo).Scan(&brandData.BrandId)
	if err != nil {
		fmt.Println(err)
		http.Error(w, "Error inserting brand", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(brandData.BrandId)
}

// update brands
func UpdateBrands(w http.ResponseWriter, r *http.Request) {
	log.Println(r.URL)
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var brandData Brand
	err := json.NewDecoder(r.Body).Decode(&brandData)
	if err != nil {
		http.Error(w, "Error decoding request body", http.StatusBadRequest)
		return
	}

	//specify the permission id
	valid, _ := authorise.CheckPerm(brandData.Token, 15) //permission id for deleting brands
	if !valid {
		http.Error(w, "User unauthorised", http.StatusUnauthorized)
		return
	}

	_, err = db.DB.Exec("UPDATE brands SET brand_name=$1,brand_info=$2,updated_at=$3 WHERE brand_id=$4", brandData.BrandName, brandData.BrandInfo, time.Now(), brandData.BrandId)
	if err != nil {
		http.Error(w, "Error updateing brand", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(brandData.BrandId)
}

// update brand logo and images
func UpdateBrandImages(w http.ResponseWriter, r *http.Request) {
	log.Println(r.URL)
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var brandData Brand
	err := json.NewDecoder(r.Body).Decode(&brandData)
	if err != nil {
		http.Error(w, "Error decoding request body", http.StatusBadRequest)
		return
	}

	//specify the permission id
	valid, _ := authorise.CheckPerm(brandData.Token, 15) //permission id for deleting brands
	if !valid {
		http.Error(w, "User unauthorised", http.StatusUnauthorized)
		return
	}
	match, _ := regexp.MatchString(".png$", brandData.BrandLogo)
	if !match {
		http.Error(w, "Only .png files are allowed", http.StatusBadRequest)
		return
	}

	if len(brandData.BrandImage) == 0 {
		http.Error(w, "No images", http.StatusBadRequest)
		return
	}

	for _, val := range brandData.BrandImage {
		match, _ := regexp.MatchString(".png$", val)
		if !match {
			http.Error(w, "Only .png files are allowed", http.StatusBadRequest)
			return
		}
	}

	_, err = db.DB.Query("UPDATE brands SET brand_logo=$1,brand_images=$2,updated_at=$3 WHERE brand_id=$4 ", brandData.BrandLogo, pq.Array(brandData.BrandImage), time.Now(), brandData.BrandId)
	if err != nil {
		fmt.Println(err)
		http.Error(w, "Error updating brand", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode("Updated successfully")
}

// delete brands
func DeleteBrands(w http.ResponseWriter, r *http.Request) {
	log.Println(r.URL)
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var brandData Brand
	err := json.NewDecoder(r.Body).Decode(&brandData)
	if err != nil {
		http.Error(w, "Error decoding request body", http.StatusBadRequest)
		return
	}

	//specify the permission id
	valid, _ := authorise.CheckPerm(brandData.Token, 16) //permission id for deleting brands
	if !valid {
		http.Error(w, "User unauthorised", http.StatusUnauthorized)
		return
	}

	_, err = db.DB.Exec("DELETE FROM brands WHERE brand_id=$1", brandData.BrandId)
	if err != nil {
		http.Error(w, "Error updating brand", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode("Successfully deleted brand")
}

// insert products
func CreateProduct(w http.ResponseWriter, r *http.Request) {
	log.Println(r.URL)
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var productData Product
	err := json.NewDecoder(r.Body).Decode(&productData)
	if err != nil {
		http.Error(w, "Error decoding request body", http.StatusBadRequest)
		return
	}

	//specify the permission id
	valid, _ := authorise.CheckPerm(productData.Token, 7) //create product perm id
	if !valid {
		http.Error(w, "User unauthorised", http.StatusUnauthorized)
		return
	}

	if len(productData.ProductName) > 100 {
		http.Error(w, "User name should contain atmost 100 characters", http.StatusBadRequest)
		return
	}

	if productData.ProductCategory != "M" && productData.ProductCategory != "F" && productData.ProductCategory != "U" {
		http.Error(w, "Use M,F or U for category", http.StatusBadRequest)
		return
	}

	if productData.FrameSize != "S" && productData.FrameSize != "M" && productData.FrameSize != "L" && productData.FrameSize != "XL" && productData.FrameSize != "XXL" {
		http.Error(w, "Choose proper size S,M,L,XL,XXL", http.StatusBadRequest)
		return
	}

	if productData.FrameType != "FULL RIM" && productData.FrameType != "RIMLESS" {
		http.Error(w, "Enter valid RIM type(FULL RIM or RIMLESS)", http.StatusBadRequest)
		return
	}

	frameShape := []string{"SQAURE", "RECTANGLE", "PILOT", "IRREGULAR", "ROUND", "PHANTOS", "OVAL", "CAT EYE"}
	var found bool
	for i := range frameShape {
		if frameShape[i] == productData.FrameShape {
			found = true
			break
		}
	}
	if !found {
		http.Error(w, "Invalid Frame shape", http.StatusBadRequest)
		return
	}

	frameMaterial := []string{"METAL", "ACETATE", "NYLON", "STEEL", "INJECTED", "PROTIONATE", "PEEK", "CARBON FIBER", "TITANIUM"}
	for i := range frameMaterial {
		if frameMaterial[i] == productData.FrameMaterial {
			found = true
			break
		}
	}
	if !found {
		http.Error(w, "Invalid Frame Material", http.StatusBadRequest)
		return
	}

	fit := []string{"Regular fit-Adjustable nosepads", "Regular fit-High bridge fit", "Narrow fit-Adjustable nosepads", "Narrow fit-High bridge fit", "Wide fit-Adjustable nosepads", "Wide fit-High bridge fit"}
	for i := range fit {
		if fit[i] == productData.Fit {
			found = true
			break
		}
	}
	if !found {
		http.Error(w, "Invalid Frame Material", http.StatusBadRequest)
		return
	}

	if productData.LensFeature != "GRADIENT" && productData.LensFeature != "CLASSIC" && productData.LensFeature != "NA" {
		http.Error(w, "Invalid lens feature", http.StatusBadRequest)
		return
	}

	if productData.LensHeight < 45 && productData.LensHeight > 65 {
		http.Error(w, "Invalid lens height", http.StatusBadRequest)
		return
	}

	//todo frame color
	//todo lens color

	lensMaterial := []string{"GLASS", "PLASTIC", "POLYAMIDE", "POLYCARBONATE", "NOT GLASS", "AMIDE"}
	for i := range lensMaterial {
		if lensMaterial[i] == productData.LensMaterial {
			found = true
			break
		}
	}
	if !found {
		http.Error(w, "Lens Material Not found", http.StatusBadRequest)
		return
	}

	suitableFaces := []string{"ROUND", "OVAL", "HEART", "SQUARE"}
	for i := range suitableFaces {
		for j := range productData.SuitableFaces {
			if suitableFaces[i] == productData.SuitableFaces[j] {
				found = true
				break
			}
		}
	}
	if !found {
		http.Error(w, "Invalid suitable-face literal", http.StatusBadRequest)
		return
	}

	if len(productData.ProductInfo) > 250 {
		http.Error(w, "Enter product info within 250 charaters", http.StatusBadRequest)
		return
	}

	if productData.ProductPrice <= 0 {
		http.Error(w, "Invalid price ", http.StatusBadRequest)
		return
	}

	if productData.AvailableQuantity <= 0 || productData.AvailableQuantity > 250 {
		http.Error(w, "Enter proper available quantity filed", http.StatusBadRequest)
		return
	}

	//todo authenticate brand_id

	insertQuery := `INSERT INTO products(product_name,category,frame_size,frame_color,frame_type,frame_shape,frame_material,fit,lens_feature,lens_height,lens_color,lens_material,suitable_faces,product_information,product_price,available_quantity,brand_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17) RETURNING product_id`
	err = db.DB.QueryRow(insertQuery, productData.ProductName, productData.ProductCategory, productData.FrameSize, pq.Array(productData.FrameColor), productData.FrameType, productData.FrameShape, productData.FrameMaterial, productData.Fit, productData.LensFeature, productData.LensHeight, productData.LensColor, productData.LensMaterial, pq.Array(&productData.SuitableFaces), productData.ProductInfo, productData.ProductPrice, productData.AvailableQuantity, productData.BrandId).Scan(&productData.ProductId)
	if err != nil {
		fmt.Println(err)
		http.Error(w, "Error creating product", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(productData.ProductId)
}

// update images of products
func UpdateProductImages(w http.ResponseWriter, r *http.Request) {
	log.Println(r.URL)
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var productData Product
	err := json.NewDecoder(r.Body).Decode(&productData)
	if err != nil {
		http.Error(w, "Error decoding request body", http.StatusBadRequest)
		return
	}

	//specify the permission id
	valid, _ := authorise.CheckPerm(productData.Token, 11) //update-product_id=11
	if !valid {
		http.Error(w, "User unauthorised", http.StatusUnauthorized)
		return
	}

	if len(productData.ProductURL) > 4 {
		http.Error(w, "Only four picture allowed", http.StatusBadRequest)
		return
	}

	for _, val := range productData.ProductURL {
		if len(productData.ProductURL) > 4 {
			http.Error(w, "Only four images are allowed", http.StatusBadRequest)
			return
		}
		match, _ := regexp.MatchString(".png$", val)
		if len(val) > 250 {
			http.Error(w, "Length of URL out of range", http.StatusBadRequest)
			return
		}
		if !match {
			http.Error(w, "Only .png files are allowed", http.StatusBadRequest)
		}
	}

	updateQuery := `UPDATE products set product_image=$1 WHERE product_id=$2`
	_, err = db.DB.Exec(updateQuery, pq.Array(productData.ProductURL), productData.ProductId)
	if err != nil {
		http.Error(w, "Error updating product images", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(productData.ProductId)
	fmt.Sprintln(w, "Updated Successfully")
}

// todo generic update
// update product information
func UpdateProduct(w http.ResponseWriter, r *http.Request) {
	log.Println(r.URL)
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var productData Product
	err := json.NewDecoder(r.Body).Decode(&productData)
	if err != nil {
		http.Error(w, "Error decoding request body", http.StatusBadRequest)
		return
	}

	//specify the permission id
	valid, _ := authorise.CheckPerm(productData.Token, 11)
	if !valid {
		http.Error(w, "User unauthorised", http.StatusUnauthorized)
		return
	}

	insertQuery := `UPDATE products set product_name=$1,dimensions=$2,frame_size=$3,frame_color=$4,frame_type=$5,frame_shape=$6,frame_material=$7,fit=$8,lens_feature=$9,lens_height=$10,lens_color=$11,lens_material=$12,suitable_faces=$13,product_information=$14,product_price=$15,discounted_price=$16,available_quantity=$17,brand_id=$18`
	err = db.DB.QueryRow(insertQuery, productData.ProductName, pq.Array(productData.ProductDimensions), productData.FrameSize, productData.FrameColor, productData.FrameType, productData.FrameShape, productData.FrameMaterial, productData.Fit, productData.LensFeature, productData.LensHeight, productData.LensColor, productData.LensMaterial, pq.Array(&productData.SuitableFaces), productData.ProductInfo, productData.ProductPrice, productData.DiscountedPrice, productData.Brand.BrandId).Scan(&productData.ProductId)
	if err != nil {
		fmt.Fprintln(w, err)
		http.Error(w, "Error updating product", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(productData.ProductId)
}

// delete product
func DeleteProduct(w http.ResponseWriter, r *http.Request) {
	log.Println(r.URL)
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var product_id Product
	err := json.NewDecoder(r.Body).Decode(&product_id)
	if err != nil {
		http.Error(w, "Error decoding request body", http.StatusBadRequest)
		return
	}

	//specify the permission id
	valid, _ := authorise.CheckPerm(product_id.Token, 12)
	if !valid {
		http.Error(w, "User unauthorised", http.StatusUnauthorized)
		return
	}

	_, err = db.DB.Exec("DELETE FROM products WHERE product_id=$1", product_id.ProductId)
	if err != nil {
		http.Error(w, "Error deleting role", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode("Deleted role successfully")
}

type Role struct {
	RoleID   int64  `json:"role_id,omitempty"`
	RoleName string `json:"role_name,omitempty"`
	Token    string `json:"token,omitempty"`
}

// create roles
func CreateRole(w http.ResponseWriter, r *http.Request) {
	log.Println(r.URL)
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var role Role
	err := json.NewDecoder(r.Body).Decode(&role)
	if err != nil {
		http.Error(w, "Error decoding request body", http.StatusBadRequest)
		return
	}

	//specify the permission id
	valid, _ := authorise.CheckPerm(role.Token, 1)
	if !valid {
		http.Error(w, "User unauthorised", http.StatusUnauthorized)
		return
	}

	err = db.DB.QueryRow("INSERT INTO roles(role_name) VALUES($1) RETURNING role_id", role.RoleName).Scan(&role.RoleID)
	if err != nil {
		http.Error(w, "Error creating role", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(role)
}

// update role
func UpdateRole(w http.ResponseWriter, r *http.Request) {
	log.Println(r.URL)
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPut {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var role Role
	err := json.NewDecoder(r.Body).Decode(&role)
	if err != nil {
		http.Error(w, "Error decoding request body", http.StatusBadRequest)
		return
	}

	//specify the permission id
	valid, _ := authorise.CheckPerm(role.Token, 1)
	if !valid {
		http.Error(w, "User unauthorised", http.StatusUnauthorized)
		return
	}

	_, err = db.DB.Exec("UPDATE roles set role_name=$1 WHERE role_id=$2", role.RoleName, role.RoleID)
	if err != nil {
		http.Error(w, "Error updating role", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode("Updated role successfully")
}

// delete role
func DeleteRole(w http.ResponseWriter, r *http.Request) {
	log.Println(r.URL)
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var role Role
	err := json.NewDecoder(r.Body).Decode(&role)
	if err != nil {
		http.Error(w, "Error decoding request body", http.StatusBadRequest)
		return
	}

	//specify the permission id
	valid, _ := authorise.CheckPerm(role.Token, 2)
	if !valid {
		http.Error(w, "User unauthorised", http.StatusUnauthorized)
		return
	}

	_, err = db.DB.Exec("DELETE FROM roles WHERE role_id=$1", role.RoleID)
	if err != nil {
		http.Error(w, "Error deleting role", http.StatusInternalServerError)
		return
	}
	fmt.Fprintln(w, "Deleted role successfully")
}

// get all roles
func GetAllRoles(w http.ResponseWriter, r *http.Request) {
	log.Println(r.URL)
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var token Token
	var roles []Role
	err := json.NewDecoder(r.Body).Decode(&token)
	if err != nil {
		http.Error(w, "Error decoding request body", http.StatusBadRequest)
		return
	}

	//specify the permission id
	valid, _ := authorise.CheckPerm(token.Token, 3)
	if !valid {
		http.Error(w, "User unauthorised", http.StatusUnauthorized)
		return
	}

	row, err := db.DB.Query("SELECT role_id,role_name FROM roles")
	if err != nil {
		http.Error(w, "Error getting roles", http.StatusInternalServerError)
		return
	}
	for row.Next() {
		var r Role
		err = row.Scan(&r.RoleID, &r.RoleName)
		if err != nil {
			http.Error(w, "Scan error on roles", http.StatusInternalServerError)
			return
		}
		roles = append(roles, r)
	}
	json.NewEncoder(w).Encode(roles)
}

type Permissions struct {
	PermissionId   int64  `json:"permission_id,omitempty"`
	PermissionName string `json:"permission_name,omitempty"`
	Token          string `json:"token,omitempty"`
}

// create permissions
func CreatePermission(w http.ResponseWriter, r *http.Request) {
	log.Println(r.URL)
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var permission Permissions
	err := json.NewDecoder(r.Body).Decode(&permission)
	if err != nil {
		http.Error(w, "Error decoding request body", http.StatusBadRequest)
		return
	}

	//specify the permission id
	valid, _ := authorise.CheckPerm(permission.Token, 4)
	if !valid {
		http.Error(w, "User unauthorised", http.StatusUnauthorized)
		return
	}

	err = db.DB.QueryRow("INSERT INTO permissions(permission_name) VALUES($1) RETURNING permission_id", permission.PermissionName).Scan(&permission.PermissionId)
	if err != nil {
		http.Error(w, "Error creating permission", http.StatusInternalServerError)
		return
	}
	permission.Token = ""
	json.NewEncoder(w).Encode(permission)
}

// update permission name
func UpdatePermission(w http.ResponseWriter, r *http.Request) {
	log.Println(r.URL)
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPut {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var perm Permissions
	err := json.NewDecoder(r.Body).Decode(&perm)
	if err != nil {
		http.Error(w, "Error decoding request body", http.StatusBadRequest)
		return
	}

	//specify the permission id
	valid, _ := authorise.CheckPerm(perm.Token, 4)
	if !valid {
		http.Error(w, "User unauthorised", http.StatusUnauthorized)
		return
	}

	if len(perm.PermissionName) > 100 {
		http.Error(w, "Permission name too long (max 100 chars)", http.StatusBadRequest)
		return
	}

	_, err = db.DB.Query("UPDATE permissions SET permission_name=$1,updated_at=$2 WHERE permission_id=$3", perm.PermissionName, time.Now(), perm.PermissionId)
	if err != nil {
		fmt.Println(err)
		http.Error(w, "Error updating permission", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode("Updated successfully")
}

// get all permissions
func GetAllPermissions(w http.ResponseWriter, r *http.Request) {
	log.Println(r.URL)
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var token Token
	var perms []Permissions
	err := json.NewDecoder(r.Body).Decode(&token)
	if err != nil {
		http.Error(w, "Error decoding request body", http.StatusBadRequest)
		return
	}

	//specify the permission id
	valid, _ := authorise.CheckPerm(token.Token, 6)
	if !valid {
		http.Error(w, "User unauthorised", http.StatusUnauthorized)
		return
	}

	row, err := db.DB.Query("SELECT permission_id,permission_name FROM permissions")
	if err != nil {
		http.Error(w, "Error retriving permissions", http.StatusInternalServerError)
		return
	}
	for row.Next() {
		var p Permissions
		err = row.Scan(&p.PermissionId, &p.PermissionName)
		if err != nil {
			http.Error(w, "Scan error on permissionss", http.StatusInternalServerError)
			return
		}
		perms = append(perms, p)
	}
	json.NewEncoder(w).Encode(perms)

}

// delete permission
func DeletePermission(w http.ResponseWriter, r *http.Request) {
	log.Println(r.URL)
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var perm Permissions
	err := json.NewDecoder(r.Body).Decode(&perm)
	if err != nil {
		http.Error(w, "Error decoding request body", http.StatusBadRequest)
		return
	}

	//specify the permission id
	valid, _ := authorise.CheckPerm(perm.Token, 5)
	if !valid {
		http.Error(w, "User unauthorised", http.StatusUnauthorized)
		return
	}

	_, err = db.DB.Exec("DELETE FROM permissions WHERE permission_id=$1", perm.PermissionId)
	if err != nil {
		http.Error(w, "Error deleting permissions", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode("Deleted permission successfully")
}

// create tags
type Tags struct {
	TagId     int64    `json:"tag_id,omitempty"`
	TagName   string   `json:"tag_name,omitempty"`
	TagImages []string `json:"tag_images,omitempty"`
	Token     string   `json:"token,omitempty"`
}

// get all tags
func GetAllTags(w http.ResponseWriter, r *http.Request) {
	log.Println(r.URL)
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var info ProductByCategory
	err := json.NewDecoder(r.Body).Decode(&info)
	if err != nil {
		http.Error(w, "Error decoding request body", http.StatusBadRequest)
		return
	}
	//specify the permission id
	valid, _ := authorise.CheckPerm(info.Token, 18)
	if !valid {
		http.Error(w, "User unauthorised", http.StatusUnauthorized)
		return
	}
	var tags []Tags

	row, err := db.DB.Query("SELECT tag_id,tag_name,tag_image_url FROM tags")
	if err != nil {
		http.Error(w, "Error querying tags", http.StatusInternalServerError)
		return
	}

	for row.Next() {
		var t Tags
		err = row.Scan(&t.TagId, &t.TagName, pq.Array(&t.TagImages))
		if err != nil {
			http.Error(w, "Error scanning tags", http.StatusInternalServerError)
			return
		}
		for i, val := range t.TagImages {
			t.TagImages[i] = "http://localhost:3000/tag_image/" + val
		}
		tags = append(tags, t)
	}

	json.NewEncoder(w).Encode(tags)

}

// create tag
func CreateTag(w http.ResponseWriter, r *http.Request) {
	log.Println(r.URL)
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var tag Tags
	err := json.NewDecoder(r.Body).Decode(&tag)
	if err != nil {
		http.Error(w, "Error decoding request body", http.StatusBadRequest)
		return
	}

	//specify the permission id
	valid, _ := authorise.CheckPerm(tag.Token, 17)
	if !valid {
		http.Error(w, "User unauthorised", http.StatusUnauthorized)
		return
	}

	if len(tag.TagName) > 100 {
		http.Error(w, "Tag name can have upto 100 characters only", http.StatusBadRequest)
		return
	}

	err = db.DB.QueryRow("INSERT INTO tags(tag_name) VALUES($1) RETURNING tag_id", tag.TagName).Scan(&tag.TagId)
	if err != nil {
		http.Error(w, "Error creating tags", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(tag.TagId)
}

// update tags
func UpdateTagImage(w http.ResponseWriter, r *http.Request) {
	log.Println(r.URL)
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPut {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var tagImage Tags
	err := json.NewDecoder(r.Body).Decode(&tagImage)
	if err != nil {
		http.Error(w, "Error decoding request body", http.StatusBadRequest)
		return
	}

	//specify the permission id
	valid, _ := authorise.CheckPerm(tagImage.Token, 19)
	if !valid {
		http.Error(w, "User unauthorised", http.StatusUnauthorized)
		return
	}

	if len(tagImage.TagImages) > 4 {
		http.Error(w, "Only four images are allowed", http.StatusBadRequest)
		return
	}
	for i := range tagImage.TagImages {
		if len(tagImage.TagImages[i]) > 250 {
			http.Error(w, "URL very long to accomadate(max 250 char)", http.StatusBadRequest)
			return
		}
		match, _ := regexp.MatchString(".png$", tagImage.TagImages[i])
		if !match {
			http.Error(w, "Only .png files are allowed", http.StatusBadRequest)
			return
		}

	}

	err = db.DB.QueryRow("UPDATE tags SET tag_image_url=$1 WHERE tag_id=$2 RETURNING tag_id", pq.Array(tagImage.TagImages), tagImage.TagId).Scan(&tagImage.TagId)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "Invalid tag_id", http.StatusBadRequest)
			return
		}
		http.Error(w, "Error updating tag image", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode("Tag updated successfully")
}

// update tagbinages
func UpdateTag(w http.ResponseWriter, r *http.Request) {
	log.Println(r.URL)
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPut {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var tag Tags
	err := json.NewDecoder(r.Body).Decode(&tag)
	if err != nil {
		http.Error(w, "Error decoding request body", http.StatusBadRequest)
		return
	}

	//specify the permission id
	valid, _ := authorise.CheckPerm(tag.Token, 19)
	if !valid {
		http.Error(w, "User unauthorised", http.StatusUnauthorized)
		return
	}

	_, err = db.DB.Exec("UPDATE tags SET tag_name=$1 WHERE tag_id=$2", tag.TagName, tag.TagId)
	if err != nil {
		http.Error(w, "Error updating tag", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode("Tag updated successfully")
}

// delete tag
func DeleteTag(w http.ResponseWriter, r *http.Request) {
	log.Println(r.URL)
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var tag Tags
	err := json.NewDecoder(r.Body).Decode(&tag)
	if err != nil {
		http.Error(w, "Error decoding request body", http.StatusBadRequest)
		return
	}

	//specify the permission id
	valid, _ := authorise.CheckPerm(tag.Token, 20)
	if !valid {
		http.Error(w, "User unauthorised", http.StatusUnauthorized)
		return
	}

	_, err = db.DB.Exec("DELETE FROM tags WHERE tag_id=$1", tag.TagId)
	if err != nil {
		http.Error(w, "Error deleting tag", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode("Tag Deleted successfully")
}

//create handler for updating only the price and dicounted_price columns of products

type UserRole struct {
	UserId int64  `json:"user_id"`
	RoleId int64  `json:"role_id,omitempty"`
	Token  string `json:"token"`
}

// create user-role
func CreateUserRole(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var userRole UserRole
	err := json.NewDecoder(r.Body).Decode(&userRole)
	if err != nil {
		http.Error(w, "Error decoding request body", http.StatusBadRequest)
		return
	}

	//specify the permission id
	valid, _ := authorise.CheckPerm(userRole.Token, 20)
	if !valid {
		http.Error(w, "User unauthorised", http.StatusUnauthorized)
		return
	}
	var id int64
	err = db.DB.QueryRow("INSERT INTO user_role(user_id,role_id) VALUES($1,$2) RETURNING user_id ", userRole.UserId, userRole.RoleId).Scan(&id)
	if err != nil {
		http.Error(w, "Error creating user-role", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode("Created role for user successfully")

}

// delete user-role
func DeleteUserRole(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var userRole UserRole
	err := json.NewDecoder(r.Body).Decode(&userRole)
	if err != nil {
		http.Error(w, "Error decoding request body", http.StatusBadRequest)
		return
	}

	//specify the permission id
	valid, _ := authorise.CheckPerm(userRole.Token, 20)
	if !valid {
		http.Error(w, "User unauthorised", http.StatusUnauthorized)
		return
	}

	_, err = db.DB.Exec("DELETE FROM user_role WHERE user_id=$1 AND role_id=$2", userRole.UserId, userRole.RoleId)
	if err != nil {
		http.Error(w, "Error deleting user-role", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode("Deleted role for the user successfully")

}

type AssignedRolesOfUser struct {
	UserId  int64   `json:"user_id"`
	RolesId []int64 `json:"roles"`
}

// get all roles of a user querying user-role table
func GetUserRole(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var userRole UserRole
	err := json.NewDecoder(r.Body).Decode(&userRole)
	if err != nil {
		http.Error(w, "Error decoding request body", http.StatusBadRequest)
		return
	}

	//specify the permission id
	valid, _ := authorise.CheckPerm(userRole.Token, 20)
	if !valid {
		http.Error(w, "User unauthorised", http.StatusUnauthorized)
		return
	}

	row, err := db.DB.Query("SELECT role_id FROM user_role WHERE user_id=$1", userRole.UserId)
	if err != nil {
		http.Error(w, "Error creating user-role", http.StatusInternalServerError)
		return
	}
	var assignedRoles AssignedRolesOfUser
	assignedRoles.UserId = userRole.UserId
	for row.Next() {
		var assignedRole int64
		err = row.Scan(&assignedRole)
		if err != nil {
			http.Error(w, "Error scan on user_role", http.StatusInternalServerError)
			return
		}
		assignedRoles.RolesId = append(assignedRoles.RolesId, assignedRole)
	}

	json.NewEncoder(w).Encode(assignedRoles)

}

type RolePerm struct {
	RoleId int64  `json:"role_id"`
	PermId int64  `json:"perm_id,omitempty"`
	Token  string `json:"token"`
}

func CreateRolePerm(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var rolePerm RolePerm
	err := json.NewDecoder(r.Body).Decode(&rolePerm)
	if err != nil {
		http.Error(w, "Error decoding request body", http.StatusBadRequest)
		return
	}

	//specify the permission id
	valid, _ := authorise.CheckPerm(rolePerm.Token, 20)
	if !valid {
		http.Error(w, "User unauthorised", http.StatusUnauthorized)
		return
	}
	id := 0
	err = db.DB.QueryRow("INSERT INTO role_perm(role_id,perm_id) VALUES($1,$2) RETURNING role_id ", rolePerm.RoleId, rolePerm.PermId).Scan(&id)
	if err != nil {
		fmt.Println(err)
		http.Error(w, "Error creating role-perm", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode("Created role-perm successfully")

}

// delete user-role
func DeleteRolePerm(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var rolePerm RolePerm
	err := json.NewDecoder(r.Body).Decode(&rolePerm)
	if err != nil {
		http.Error(w, "Error decoding request body", http.StatusBadRequest)
		return
	}

	//specify the permission id
	valid, _ := authorise.CheckPerm(rolePerm.Token, 20)
	if !valid {
		http.Error(w, "User unauthorised", http.StatusUnauthorized)
		return
	}

	_, err = db.DB.Exec("DELETE FROM role_perm WHERE role_id=$1 AND perm_id=$2", rolePerm.RoleId, rolePerm.PermId)
	if err != nil {
		http.Error(w, "Error deleting role-perm", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode("deleted perm for the role successfully")

}

type AssignedPermForRole struct {
	RoleId int64   `json:"role_id"`
	PermId []int64 `json:"permission_ids"`
}

// get all roles of a user querying user-role table
func GetrolePerm(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var rolePerm RolePerm
	err := json.NewDecoder(r.Body).Decode(&rolePerm)
	if err != nil {
		http.Error(w, "Error decoding request body", http.StatusBadRequest)
		return
	}

	//specify the permission id
	valid, _ := authorise.CheckPerm(rolePerm.Token, 20)
	if !valid {
		http.Error(w, "User unauthorised", http.StatusUnauthorized)
		return
	}

	row, err := db.DB.Query("SELECT perm_id FROM role_perm WHERE role_id=$1", rolePerm.RoleId)
	if err != nil {
		http.Error(w, "Query error on user-role perm", http.StatusInternalServerError)
		return
	}
	var assignedPerms AssignedPermForRole
	for row.Next() {
		var assignedPerm int64
		err = row.Scan(&assignedPerm)
		if err != nil {
			http.Error(w, "Error scan on perm-role", http.StatusInternalServerError)
			return
		}
		assignedPerms.PermId = append(assignedPerms.PermId, assignedPerm)
	}

	assignedPerms.RoleId = rolePerm.RoleId
	json.NewEncoder(w).Encode(assignedPerms)
}

// get all roles and their permissions
func GetAllrolePerm(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var rolePerm RolePerm
	err := json.NewDecoder(r.Body).Decode(&rolePerm)
	if err != nil {
		http.Error(w, "Error decoding request body", http.StatusBadRequest)
		return
	}

	//specify the permission id
	valid, _ := authorise.CheckPerm(rolePerm.Token, 20)
	if !valid {
		http.Error(w, "User unauthorised", http.StatusUnauthorized)
		return
	}

	row, err := db.DB.Query("SELECT perm_id FROM role_perm", rolePerm.RoleId)
	if err != nil {
		http.Error(w, "Query error on user-role perm", http.StatusInternalServerError)
		return
	}
	var assignedPerms AssignedPermForRole
	for row.Next() {
		var assignedPerm int64
		err = row.Scan(&assignedPerm)
		if err != nil {
			http.Error(w, "Error scan on perm-role", http.StatusInternalServerError)
			return
		}
		assignedPerms.PermId = append(assignedPerms.PermId, assignedPerm)
	}

	assignedPerms.RoleId = rolePerm.RoleId
	json.NewEncoder(w).Encode(assignedPerms)
}

// to read input
type Item struct {
	Quantity int64   `json:"quantity"`
	Price    float64 `json:"price"`
	Total    float64 `json:"total"`
}

type ItemMap map[string]Item

type RequestBody struct {
	Token     string  `json:"token"`
	UserId    int64   `json:"user_id"`
	Items     ItemMap `json:"items"`
	ProductId string  `json:"product_id"`
}

// cart is created at user creation time
func AddItemstoCart(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var body RequestBody
	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		http.Error(w, "Error decoding request body", http.StatusBadRequest)
		return
	}

	//specify the permission id
	valid, _ := authorise.CheckPerm(body.Token, 20)
	if !valid {
		http.Error(w, "User unauthorised", http.StatusUnauthorized)
		return
	}

	query := "SELECT items FROM cart WHERE cart_id=$1"

	var jsonData []byte
	if err := db.DB.QueryRow(query, body.UserId).Scan(&jsonData); err != nil {
		log.Fatal(err)
	}
	var data ItemMap
	if err := json.Unmarshal(jsonData, &data); err != nil {
		log.Fatal(err)
	}

	for k, v := range body.Items {
		data[k] = v
	}

	jsonItems, err := json.Marshal(data)
	if err != nil {
		panic(err)
	}

	err = db.DB.QueryRow("UPDATE cart SET items=$1,updated_at=now() WHERE cart_id=$2 RETURNING cart_id", string(jsonItems), body.UserId).Scan(&body.UserId)
	if err != nil {
		panic(err)
	}

	json.NewEncoder(w).Encode(body.UserId)

}

type UpdateCart struct {
	Token     string `json:"token"`
	UserId    int64  `json:"user_id"`
	ProductId int64  `json:"product_id"`
	Item      Item   `json:"item"`
}

// update cart items
func UpdateItemsInCart(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var body UpdateCart
	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		http.Error(w, "Error decoding request body", http.StatusBadRequest)
		return
	}

	//specify the permission id
	valid, _ := authorise.CheckPerm(body.Token, 20)
	if !valid {
		http.Error(w, "User unauthorised", http.StatusUnauthorized)
		return
	}

	jsonItems, err := json.Marshal(body.Item)
	if err != nil {
		panic(err)
	}

	_, err = db.DB.Query("UPDATE cart SET items =jsonb_set(items,'{$1}',$1) WHERE items ? $2", fmt.Sprint(body.ProductId), string(jsonItems), body.ProductId)
	if err != nil {
		panic(err)

	}

	json.NewEncoder(w).Encode("Updated successfully")

}

// delete item from cart
func DeleteItemsInCart(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var body UpdateCart
	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		http.Error(w, "Error decoding request body", http.StatusBadRequest)
		return
	}

	//specify the permission id
	valid, _ := authorise.CheckPerm(body.Token, 20)
	if !valid {
		http.Error(w, "User unauthorised", http.StatusUnauthorized)
		return
	}

	_, err = db.DB.Query("UPDATE cart SET items =items-$1 WHERE cart_id=$2 ", body.ProductId, body)
	if err != nil {
		panic(err)

	}

	json.NewEncoder(w).Encode("Updated successfully")

}

type Cart struct {
	Items    ItemMap `json:"item"`
	CheckOut bool    `json:"checked_out"`
}

// getall items in cart
func ItemsInCart(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var body RequestBody
	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		http.Error(w, "Error decoding request body", http.StatusBadRequest)
		return
	}

	//specify the permission id
	valid, _ := authorise.CheckPerm(body.Token, 20)
	if !valid {
		http.Error(w, "User unauthorised", http.StatusUnauthorized)
		return
	}

	var data []byte
	var response Cart

	err = db.DB.QueryRow("SELECT items,checked_out FROM cart WHERE cart_id=$1", body.UserId).Scan(&data, &response.CheckOut)
	if err != nil {
		panic(err)

	}

	if err := json.Unmarshal(data, &response.Items); err != nil {
		log.Fatal(err)
	}

	json.NewEncoder(w).Encode(response)

}

type Address struct {
	AddressId   int64  `json:"address_id"`
	UserId      int64  `json:"user_id"`
	AddressName string `json:"address_name"`
	AddressInfo string `json:"address_info"`
	City        string `json:"city"`
	PostalCode  string `json:"postal_code"`
	Country     string `json:"country"`
	Token       string `json:"token"`
}

// add adress
func AddAdress(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var body Address
	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		http.Error(w, "Error decoding request body", http.StatusBadRequest)
		return
	}

	//specify the permission id
	valid, _ := authorise.CheckPerm(body.Token, 20)
	if !valid {
		http.Error(w, "User unauthorised", http.StatusUnauthorized)
		return
	}
	err = db.DB.QueryRow("INSERT INTO address(user_id,adress_name,address_info,city,postal_code,country) VALUES($1,$2,$3,$4,$5,$6) RETURNING address_id", body.UserId, body.AddressName, body.AddressInfo, body.City, body.City, body.PostalCode, body.Country).Scan(&body.AddressId)
	if err != nil {
		http.Error(w, "Error inserting address", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(body.AddressId)
}

func DeleteAdress(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var body Address
	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		http.Error(w, "Error decoding request body", http.StatusBadRequest)
		return
	}

	//specify the permission id
	valid, _ := authorise.CheckPerm(body.Token, 20)
	if !valid {
		http.Error(w, "User unauthorised", http.StatusUnauthorized)
		return
	}
	_, err = db.DB.Query("DELETE FROM address WHERE address_id=$1", body.AddressId)
	if err != nil {
		http.Error(w, "Error deleting address", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode("Address deleted successfully")
}

// update address
func UpdateAdress(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var body Address
	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		http.Error(w, "Error decoding request body", http.StatusBadRequest)
		return
	}

	//specify the permission id
	valid, _ := authorise.CheckPerm(body.Token, 20)
	if !valid {
		http.Error(w, "User unauthorised", http.StatusUnauthorized)
		return
	}
	_, err = db.DB.Query("UPDATE address SET adress_name=$1,address_info=$2,city=$3,postal_code=$4,country=&5 WHERE address_id=$6", body.AddressName, body.AddressInfo, body.City, body.PostalCode, body.Country, body.AddressId)
	if err != nil {
		http.Error(w, "Error deleting address", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode("Address updated successfully")
}

type Order struct {
	OrderId      int64   `json:"order"`
	User_id      int64   `json:"user_id"`
	PaymentRefId string  `json:"payment_ref_id"`
	ShipAddress  int64   `json:"shipment_address"`
	ItemDetails  ItemMap `json:"item_details"`
	Token        string  `json:"token"`
}

// create order
func CreateOrder(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var body Order
	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		http.Error(w, "Error decoding request body", http.StatusBadRequest)
		return
	}

	//specify the permission id
	valid, _ := authorise.CheckPerm(body.Token, 20)
	if !valid {
		http.Error(w, "User unauthorised", http.StatusUnauthorized)
		return
	}

	err = db.DB.QueryRow("INSERT INTO orders(user_id,item_details,order_status) VALUES($1,$2,$3) RETURNING order_id").Scan(&body.OrderId)
	if err!=nil{
		http.Error(w,"Error creating order",http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(body.OrderId)

}


//update order
func UpdateOrder(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var body Order
	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		http.Error(w, "Error decoding request body", http.StatusBadRequest)
		return
	}

	//specify the permission id
	valid, _ := authorise.CheckPerm(body.Token, 20)
	if !valid {
		http.Error(w, "User unauthorised", http.StatusUnauthorized)
		return
	}
	var query string

	if body.PaymentRefId!=""{
		query="UPDATE orders SET "
	}
	if body.ShipAddress!=0{
		query="UPDATE orders SET shipment_address_id=$1"
	}
	err = db.DB.QueryRow(query).Scan(&body.OrderId)
	if err!=nil{
		http.Error(w,"Error creating order",http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(body.OrderId)

}