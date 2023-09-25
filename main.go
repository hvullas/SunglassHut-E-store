package main

import (
	"backend/db"
	"backend/handlers"
	"net/http"

	_ "github.com/lib/pq"
)

func main() {

	db.ConnectDB()
	defer db.DB.Close()

	http.HandleFunc("/newUser", handlers.NewUser)
	http.HandleFunc("/Login", handlers.Login)
	http.HandleFunc("/homepage", handlers.Homepage)
	http.HandleFunc("/collections/women", handlers.CollectionWomen)
	http.HandleFunc("/collections/polarized/", handlers.PolarizedGlassFor)
	http.HandleFunc("/collections/clear-and-photochromatic-lenses", handlers.ClearPhotochramatic)
	http.HandleFunc("/collections/brand-id/", handlers.Brands)
	http.HandleFunc("/collections/new-arrival", handlers.NewArrival)
	http.HandleFunc("/collections/sale", handlers.Sales)
	http.HandleFunc("/brand/product-by-category", handlers.ProductsForGender)
	http.HandleFunc("/product/", handlers.ProductById)
	http.HandleFunc("/tags/", handlers.ProductByTag)
	http.HandleFunc("/tags", handlers.GetAllTags)

	http.ListenAndServe(":3000", nil)

}
