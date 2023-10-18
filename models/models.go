package models

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

// request body to get products by gender(men/women)
type ProductByCategory struct {
	Token    string `json:"token"`
	Brand_id int64  `json:"brand_id"`
	Category string `json:"category"`
}

type Permissions struct {
	PermissionId   int64  `json:"permission_id,omitempty"`
	PermissionName string `json:"permission_name,omitempty"`
	Token          string `json:"token,omitempty"`
}

// create tags
type Tags struct {
	TagId     int64    `json:"tag_id,omitempty"`
	TagName   string   `json:"tag_name,omitempty"`
	TagImages []string `json:"tag_images,omitempty"`
	Token     string   `json:"token,omitempty"`
}

//create handler for updating only the price and dicounted_price columns of products

type UserRole struct {
	UserId int64  `json:"user_id"`
	RoleId int64  `json:"role_id,omitempty"`
	Token  string `json:"token"`
}

type AssignedRolesOfUser struct {
	UserId  int64   `json:"user_id"`
	RolesId []int64 `json:"roles"`
}

type RolePerm struct {
	RoleId int64  `json:"role_id"`
	PermId int64  `json:"perm_id,omitempty"`
	Token  string `json:"token"`
}

type AssignedPermForRole struct {
	RoleId int64   `json:"role_id"`
	PermId []int64 `json:"permission_ids"`
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

type UpdateCart struct {
	Token     string `json:"token"`
	UserId    int64  `json:"user_id"`
	ProductId int64  `json:"product_id"`
	Item      Item   `json:"item"`
}

type Cart struct {
	ProductId    int      `json:"product_id"`
	Product_name string   `json:"name"`
	ProductImage []string `json:"images"`
	Price        float64  `json:"price"`
	Size         string   `json:"size"`
	CheckOut     bool     `json:"checked_out"`
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

type Order struct {
	OrderId      int64   `json:"order_id"`
	User_id      int64   `json:"user_id,omitempty"`
	PaymentRefId *string `json:"payment_ref_id"`
	ShipAddress  *int64  `json:"shipment_address"`
	ItemDetails  ItemMap `json:"item_details"`
	Updated_on   string  `json:"updated_on,omitempty"`
	Token        string  `json:"token,omitempty"`
}
