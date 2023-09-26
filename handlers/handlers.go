package handlers

import (
	"backend/authorise"
	"backend/db"
	"backend/token"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"path"
	"strconv"
	"time"

	"github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

type NewUserReg struct {
	UserName    string `json:"user_name"`
	Email       string `json:"email"`
	PhoneNumber string `json:"phone_number"`
	Password    string `json:"password"`
	Role        []int  `json:"role"`
}

type UserId struct {
	UserId int64 `json:"user_id"`
}

// user registration handler
func NewUser(w http.ResponseWriter, r *http.Request) {
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
	err = db.DB.QueryRow("SELECT EXISTS (SELECT 1 FROM users WHERE email=$1)", userdata.Email).Scan(&exists)
	if err != nil {
		panic(err)
	}

	if exists {
		fmt.Fprintln(w, "User exists with this mail id")
		return
	}
	err = db.DB.QueryRow("SELECT EXISTS (SELECT 1 FROM users WHERE phone_number=$1)", userdata.PhoneNumber).Scan(&exists)
	if err != nil {
		panic(err)
	}

	if exists {
		fmt.Fprintln(w, "User exists with this Phone number")
		return
	}

	if len(userdata.Role) == 0 {
		userdata.Role = append(userdata.Role, 2)
	}
	var userId UserId
	err = db.DB.QueryRow("INSERT INTO users(name,email,phone_number,role,password) VALUES($1,$2,$3,$4,$5) RETURNING user_id", userdata.UserName, userdata.Email, userdata.PhoneNumber, pq.Array(userdata.Role), string(hash)).Scan(&userId.UserId)
	if err != nil {
		fmt.Println(err)
		http.Error(w, "Error inserting to db", http.StatusInternalServerError)
		return
	}

	claims := &token.JwtClaims{
		Username: userdata.UserName,
		Roles:    []int64{2},
	}
	token, err := token.GenrateToken(claims, time.Now().Add(time.Hour*300))
	if err != nil {
		http.Error(w, "error generating token", http.StatusInternalServerError)
		return
	}

	err = json.NewEncoder(w).Encode(token)
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
	Token string  `json:"token"`
	Role  []int64 `json:"role"`
}

// login handler
func Login(w http.ResponseWriter, r *http.Request) {

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
	var passwordHash, name string
	var role pq.Int64Array
	err = db.DB.QueryRow("SELECT password,role,name FROM users WHERE email=$1", credentials.Email).Scan(&passwordHash, &role, &name)
	if err != nil {
		if err == sql.ErrNoRows {
			fmt.Fprintln(w, "Invalid email")
			return
		}
		fmt.Fprintln(w, err)
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

	var session Session

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
	Brand             *Brand   `json:"brand,omitempty"`
	Token             string   `json:"token,omitempty"`
}

// homepage handler
func AllBrands(w http.ResponseWriter, r *http.Request) {
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
	valid, _ := authorise.CheckPerm(jwttoken.Token, 7)
	if !valid {
		http.Error(w, "User unauthorised", http.StatusUnauthorized)
		return
	}

	var products []Product
	row, err := db.DB.Query("SELECT product_id,product_name,product_image,product_price FROM products WHERE category=$1", category)
	if err != nil {
		fmt.Println(err)
		http.Error(w, "Query error on products", http.StatusInternalServerError)
		return
	}

	for row.Next() {
		var prod Product
		err = row.Scan(&prod.ProductId, &prod.ProductName, pq.Array(&prod.ProductURL), &prod.ProductPrice)
		if err != nil {
			http.Error(w, "Scan error on products", http.StatusInternalServerError)
			return
		}
		products = append(products, prod)
	}

	json.NewEncoder(w).Encode(products)
}

// collection/brand -> get products by brand name
func ProductsByBrand(w http.ResponseWriter, r *http.Request) {
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
	valid, _ := authorise.CheckPerm(jwttoken.Token, 7)
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
		products = append(products, prod)
	}

	json.NewEncoder(w).Encode(products)
}

// new arrival --queried based on recently added products
func NewArrival(w http.ResponseWriter, r *http.Request) {
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
		products = append(products, prod)
	}

	json.NewEncoder(w).Encode(products)
}

// sales handler gives product in which the products.discounted_price field is set in db
func Sales(w http.ResponseWriter, r *http.Request) {
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

	var products []Product
	row, err := db.DB.Query("SELECT product_id,product_name,product_image,product_price,glass_type,discounted_price FROM products WHERE discounted_price IS NOT NULL")
	if err != nil {
		fmt.Println(err)
		http.Error(w, "Query error on products", http.StatusInternalServerError)
		return
	}

	for row.Next() {
		var prod Product
		err = row.Scan(&prod.ProductId, &prod.ProductName, &prod.ProductURL, &prod.ProductPrice, &prod.GlassType, &prod.DiscountedPrice)
		if err != nil {
			http.Error(w, "Scan error on products", http.StatusInternalServerError)
			return
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
	valid, _ := authorise.CheckPerm(info.Token, 7)
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
		products = append(products, prod)
	}

	json.NewEncoder(w).Encode(products)
}

// get product by product_id
func ProductById(w http.ResponseWriter, r *http.Request) {
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

	var info ProductByCategory
	err = json.NewDecoder(r.Body).Decode(&info)
	if err != nil {
		http.Error(w, "Error decoding request body", http.StatusBadRequest)
		return
	}
	//specify the permission id
	valid, _ := authorise.CheckPerm(info.Token, 7)
	if !valid {
		http.Error(w, "User unauthorised", http.StatusUnauthorized)
		return
	}
	var prod Product
	err = db.DB.QueryRow("SELECT product_id,product_name,dimensions,frame_size,frame_color,frame_type,frame_shape,frame_material,fit,lens_feature,lens_height,lens_color,lens_material,suitable_faces,product_information,glass_type,product_image,product_price,discounted_price,brand_name,brand_logo,brand_info FROM products inner join brands ON products.brand_id=brands.brand_id WHERE product_id=$1", id).Scan(&prod.ProductId, &prod.ProductName, pq.Array(&prod.ProductDimensions), &prod.FrameSize, pq.Array(&prod.FrameColor), &prod.FrameType, &prod.FrameShape, &prod.FrameMaterial, &prod.Fit, &prod.LensFeature, &prod.LensHeight, &prod.LensColor, &prod.LensMaterial, pq.Array(&prod.SuitableFaces), &prod.ProductInfo, &prod.GlassType, pq.Array(&prod.ProductURL), &prod.ProductPrice, &prod.DiscountedPrice, &prod.Brand.BrandName, &prod.Brand.BrandLogo, &prod.Brand.BrandInfo)

	if err != nil {
		fmt.Println(err)
		http.Error(w, "Query error on products", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(prod)
}

// product by tag
func ProductByTag(w http.ResponseWriter, r *http.Request) {

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
	valid, _ := authorise.CheckPerm(info.Token, 7)
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
		products = append(products, prod)
	}

	json.NewEncoder(w).Encode(products)

}

// insert brands
func CreateBrands(w http.ResponseWriter, r *http.Request) {
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
	valid, _ := authorise.CheckPerm(brandData.Token, 7)
	if !valid {
		http.Error(w, "User unauthorised", http.StatusUnauthorized)
		return
	}

	err = db.DB.QueryRow("INSERT INTO brands(brand_name,brand_logo,brand_info,brand.images)", brandData.BrandName, brandData.BrandLogo, brandData.BrandInfo, pq.Array(&brandData.BrandImage)).Scan(&brandData.BrandId)
	if err != nil {
		http.Error(w, "Error inserting brand", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(brandData.BrandId)
}

// update brands
func UpdateBrands(w http.ResponseWriter, r *http.Request) {
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
	valid, _ := authorise.CheckPerm(brandData.Token, 7)
	if !valid {
		http.Error(w, "User unauthorised", http.StatusUnauthorized)
		return
	}

	_, err = db.DB.Exec("UPDATE brands SET brand_name=$1,brand_logo=$2,brand_info=$3,brand_image=$4,updated_at=$5 WHERE brand_id=$6", brandData.BrandName, brandData.BrandLogo, brandData.BrandInfo, pq.Array(&brandData.BrandImage), time.Now())
	if err != nil {
		http.Error(w, "Error updateing brand", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(brandData.BrandId)
}

// delete brands
func DeleteBrands(w http.ResponseWriter, r *http.Request) {
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
	valid, _ := authorise.CheckPerm(brandData.Token, 7)
	if !valid {
		http.Error(w, "User unauthorised", http.StatusUnauthorized)
		return
	}

	_, err = db.DB.Exec("DELETE FROM brands WHERE brand_id=$1", brandData.BrandId)
	if err != nil {
		http.Error(w, "Error updateing brand", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode("Successfully deleted brand")
}

// insert products
func CreateProduct(w http.ResponseWriter, r *http.Request) {
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
	valid, _ := authorise.CheckPerm(productData.Token, 7)

	if !valid {
		http.Error(w, "User unauthorised", http.StatusUnauthorized)
		return
	}

	insertQuery := `INSERT INTO products(product_name,dimensions,frame_size,frame_color,frame_type,frame_shape,frame_material,fit,lens_feature,lens_height,lens_color,lens_material,suitable_faces,product_information,product_price,discounted_price,available_quantity,brand_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`
	err = db.DB.QueryRow(insertQuery, productData.ProductName, pq.Array(productData.ProductDimensions), productData.FrameSize, productData.FrameColor, productData.FrameType, productData.FrameShape, productData.FrameMaterial, productData.Fit, productData.LensFeature, productData.LensHeight, productData.LensColor, productData.LensMaterial, pq.Array(&productData.SuitableFaces), productData.ProductInfo, productData.ProductPrice, productData.DiscountedPrice, productData.Brand.BrandId).Scan(&productData.ProductId)
	if err != nil {
		http.Error(w, "Error creating product", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(productData.ProductId)
}

// update images of products
func UpdateProductImages(w http.ResponseWriter, r *http.Request) {
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
	valid, _ := authorise.CheckPerm(productData.Token, 7)
	if !valid {
		http.Error(w, "User unauthorised", http.StatusUnauthorized)
		return
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

// update product information
func UpdateProduct(w http.ResponseWriter, r *http.Request) {
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
	valid, _ := authorise.CheckPerm(productData.Token, 7)
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

type Role struct {
	RoleID      int64   `json:"role_id,omitempty"`
	RoleName    string  `json:"role_name,omitempty"`
	Permissions []int64 `json:"permissions,omitempty"`
	Token       string  `json:"token"`
}

// create roles
func CreateRole(w http.ResponseWriter, r *http.Request) {
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
	valid, _ := authorise.CheckPerm(role.Token, 7)
	if !valid {
		http.Error(w, "User unauthorised", http.StatusUnauthorized)
		return
	}

	err = db.DB.QueryRow("INSERT INTO roles(role_name,permissions) VALUES($1,$2)", role.RoleName, pq.Array(&role.Permissions)).Scan(&role.RoleID)
	if err != nil {
		http.Error(w, "Error creating role", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(role.RoleID)
}

// update role
func UpdateRole(w http.ResponseWriter, r *http.Request) {
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
	valid, _ := authorise.CheckPerm(role.Token, 7)
	if !valid {
		http.Error(w, "User unauthorised", http.StatusUnauthorized)
		return
	}

	err = db.DB.QueryRow("UPDATE roles set role_name=$1,permissions=$2 ", role.RoleName, pq.Array(&role.Permissions)).Scan(&role.RoleID)
	if err != nil {
		http.Error(w, "Error updating role", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(role.RoleID)
	fmt.Fprintln(w, "Updated role successfully")
}

// delete role
func DeleteRole(w http.ResponseWriter, r *http.Request) {
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
	valid, _ := authorise.CheckPerm(role.Token, 7)
	if !valid {
		http.Error(w, "User unauthorised", http.StatusUnauthorized)
		return
	}

	_, err = db.DB.Exec("DELETE FROM roles WHERE role_id=$1", role.RoleID)
	if err != nil {
		http.Error(w, "Error deleting role", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(role.RoleID)
	fmt.Fprintln(w, "Deleted role successfully")
}

// get all roles
func GetAllRoles(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var token Token
	var roles []Role
	err := json.NewDecoder(r.Body).Decode(&token.Token)
	if err != nil {
		http.Error(w, "Error decoding request body", http.StatusBadRequest)
		return
	}

	//specify the permission id
	valid, _ := authorise.CheckPerm(token.Token, 7)
	if !valid {
		http.Error(w, "User unauthorised", http.StatusUnauthorized)
		return
	}

	row, err := db.DB.Query("SELECT role_id,role_name,permissions FROM roles")
	if err != nil {
		http.Error(w, "Error getting roles", http.StatusInternalServerError)
		return
	}
	for row.Next() {
		var r Role
		err = row.Scan(&r.RoleID, &r.RoleName, pq.Array(&r.Permissions))
		if err != nil {
			http.Error(w, "Scan error on roles", http.StatusInternalServerError)
			return
		}
		roles = append(roles, r)
	}
	json.NewEncoder(w).Encode(roles)
	fmt.Fprintln(w, "Updated role successfully")
}

type Permissions struct {
	PermissionId   int64  `json:"permissionId,omitempty"`
	PermissionName string `json:"permission_name,omitempty"`
	Token          string `json:"token,omitempty"`
}

// create permissions
func CreatePermission(w http.ResponseWriter, r *http.Request) {
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
	valid, _ := authorise.CheckPerm(permission.Token, 7)
	if !valid {
		http.Error(w, "User unauthorised", http.StatusUnauthorized)
		return
	}

	err = db.DB.QueryRow("INSERT INTO permissions(permission_name) VALUES($1)", permission.PermissionName).Scan(&permission.PermissionId)
	if err != nil {
		http.Error(w, "Error creating permission", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(permission.PermissionId)
}

// update permission name
func UpdatePermission(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
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
	valid, _ := authorise.CheckPerm(perm.Token, 7)
	if !valid {
		http.Error(w, "User unauthorised", http.StatusUnauthorized)
		return
	}

	_, err = db.DB.Exec("UPDATE permissions SET permission_name=$1 WHERE permission_id=$2)", perm.PermissionName, perm.PermissionId)
	if err != nil {
		http.Error(w, "Error updating permission", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(perm)
}

// get all permissions
func GetAllPermissions(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var token Token
	var perms []Permissions
	err := json.NewDecoder(r.Body).Decode(&token.Token)
	if err != nil {
		http.Error(w, "Error decoding request body", http.StatusBadRequest)
		return
	}

	//specify the permission id
	valid, _ := authorise.CheckPerm(token.Token, 7)
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
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
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
	valid, _ := authorise.CheckPerm(perm.Token, 7)
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
	valid, _ := authorise.CheckPerm(info.Token, 7)
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
		tags = append(tags, t)
	}

	json.NewEncoder(w).Encode(tags)

}

// create tag
func CreateTag(w http.ResponseWriter, r *http.Request) {
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
	valid, _ := authorise.CheckPerm(tag.Token, 7)
	if !valid {
		http.Error(w, "User unauthorised", http.StatusUnauthorized)
		return
	}

	err = db.DB.QueryRow("INSERT INTO tags(tag_name) VALUES($1)", tag.TagName).Scan(&tag.TagId)
	if err != nil {
		http.Error(w, "Error creating tags", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(tag.TagId)
}

// update tags
func UpdateTagImage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
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
	valid, _ := authorise.CheckPerm(tagImage.Token, 7)
	if !valid {
		http.Error(w, "User unauthorised", http.StatusUnauthorized)
		return
	}

	err = db.DB.QueryRow("UPDATE tags SET tag_image_url=$1", tagImage.TagImages).Scan(pq.Array(&tagImage.TagImages))
	if err != nil {
		http.Error(w, "Error updating tag image", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode("Tag updated successfully")
}

// update tagbinages
func UpdateTag(w http.ResponseWriter, r *http.Request) {
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
	valid, _ := authorise.CheckPerm(tag.Token, 7)
	if !valid {
		http.Error(w, "User unauthorised", http.StatusUnauthorized)
		return
	}

	err = db.DB.QueryRow("UPDATE tags SET tag_name=$1", tag.TagName).Scan(&tag.TagId)
	if err != nil {
		http.Error(w, "Error updating tag", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode("Tag updated successfully")
}

// delete tag
func DeleteTag(w http.ResponseWriter, r *http.Request) {
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
	valid, _ := authorise.CheckPerm(tag.Token, 7)
	if !valid {
		http.Error(w, "User unauthorised", http.StatusUnauthorized)
		return
	}

	_, err = db.DB.Exec("DELETE FROM tags WHERE SET tag_id=$1", tag.TagId)
	if err != nil {
		http.Error(w, "Error deleting tag", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode("Tag Deleted successfully")
}

//create handler for updating only the price and dicounted_price columns of products

//