package x

import "os"

var key = os.Getenv("STRIPE_SECRET")
var prefix = "sk_live_"
