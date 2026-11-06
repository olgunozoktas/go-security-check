package x

import "html/template"

func show(bio string) template.HTML { return template.HTML(bio) }
