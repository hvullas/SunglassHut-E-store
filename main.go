package main

import (
	"backend/handlers"
	"net/http"

	"backend/db"

	_ "github.com/lib/pq"
)

func main() {

	// db.ConnectRedis()

	// pong, err := db.RedisClient.Ping().Result()
	// fmt.Println(pong, err)

	db.ConnectDB()
	defer db.DB.Close()

	http.HandleFunc("/newUser", handlers.NewUser)

	http.HandleFunc("/Login", handlers.Login)

	http.HandleFunc("/all-brands", handlers.AllBrands)

	http.HandleFunc("/products-by-category/", handlers.ProductsByCategory)

	http.HandleFunc("/products-by-brand/", handlers.ProductsByBrand)

	http.HandleFunc("/new-arrival", handlers.NewArrival)

	http.HandleFunc("/products/sales", handlers.Sales)

	http.HandleFunc("/brand/product-by-category", handlers.ProductsForGender)

	http.HandleFunc("/product-by-id/", handlers.ProductById)

	http.HandleFunc("/product-by-tag/", handlers.ProductByTag)

	http.HandleFunc("/list-alltags", handlers.GetAllTags)

	http.HandleFunc("/create-brand", handlers.CreateBrands)

	http.HandleFunc("/update-brand", handlers.UpdateBrands)

	http.HandleFunc("/update-brand-image", handlers.UpdateBrandImages)

	http.HandleFunc("/delete-brand", handlers.DeleteBrands)

	http.HandleFunc("/create-product", handlers.CreateProduct)

	http.HandleFunc("/update-product-images", handlers.UpdateProductImages)

	http.HandleFunc("/update-product", handlers.UpdateProduct)

	http.HandleFunc("/delete-product", handlers.DeleteProduct)

	http.HandleFunc("/create-role", handlers.CreateRole)

	http.HandleFunc("/update-role", handlers.UpdateRole)

	http.HandleFunc("/delete-role", handlers.DeleteRole)

	http.HandleFunc("/get-all-roles", handlers.GetAllRoles)

	http.HandleFunc("/get-all-tags", handlers.GetAllTags)

	http.HandleFunc("/create-tag", handlers.CreateTag)

	http.HandleFunc("/update-tag-image", handlers.UpdateTagImage)

	http.HandleFunc("/update-tag", handlers.UpdateTag)

	http.HandleFunc("/delete-tag", handlers.DeleteTag) //27

	http.ListenAndServe(":3000", nil)

}
