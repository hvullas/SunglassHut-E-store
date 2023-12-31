package main

import (
	"net/http"

	"backend/db"
	"backend/handlers"

	_ "github.com/lib/pq"
)

func main() {

	db.ConnectRedis()
	defer db.RedisClient.Close()

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

	http.HandleFunc("/products/sort/", handlers.SortOnPrice)

	http.HandleFunc("/create-brand", handlers.CreateBrands)

	http.HandleFunc("/update-brand", handlers.UpdateBrands)

	http.HandleFunc("/update-brand-image", handlers.UpdateBrandImages)

	http.HandleFunc("/delete-brand", handlers.DeleteBrands)

	http.HandleFunc("/create-product", handlers.CreateProduct)

	http.HandleFunc("/update-product-images", handlers.UpdateProductImages)

	http.HandleFunc("/update-product", handlers.UpdateProduct) //todo

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

	http.HandleFunc("/create-permission", handlers.CreatePermission) //creates new permission in permissions table

	http.HandleFunc("/update-permission", handlers.UpdatePermission) //updates permission in permissions table

	http.HandleFunc("/delete-permission", handlers.DeletePermission) //deletes permission in permissions table

	http.HandleFunc("/get-all-perms", handlers.GetAllPermissions) //gives all permissions and name from permissions table

	http.HandleFunc("/get-user-roles", handlers.GetUserRole) //get all roles assigned to the user

	http.HandleFunc("/create-user-role", handlers.CreateUserRole) //create a new role for a user in user_role table

	http.HandleFunc("/delete-user-role", handlers.DeleteUserRole) //delete role assigned to the user in user_role table

	http.HandleFunc("/create-role-perm", handlers.CreateRolePerm) //create/assign permission for a role in role_perm table

	http.HandleFunc("/delete-role-perm", handlers.DeleteRolePerm) //delete perm Assigned to the role in role_perm table

	http.HandleFunc("/get-role-perms", handlers.GetrolePerm) //get all the perms assigned to the role in role_perm table

	//building orders api
	http.HandleFunc("/cart/add-items", handlers.AddItemstoCart)

	http.HandleFunc("/cart/update-item", handlers.UpdateItemsInCart)

	http.HandleFunc("/cart/delete-item", handlers.DeleteItemsInCart)

	http.HandleFunc("/cart/items", handlers.ItemsInCart)

	http.HandleFunc("/create-order", handlers.CreateOrder)

	http.HandleFunc("/order/update-address-id", handlers.UpdateShipmentAddress)

	http.HandleFunc("/order/update-payment-ref-id", handlers.UpdatePaymentRefId)

	http.HandleFunc("/order/myorders", handlers.Myorders)

	//http.HandleFunc("/order/delete",handlers.DeleteOrder)

	http.HandleFunc("/delete-address", handlers.DeleteAddress)

	http.HandleFunc("/add_address", handlers.AddAdress)

	http.HandleFunc("/addresses", handlers.GetAllAddress)

	http.ListenAndServe(":3000", nil)

}
