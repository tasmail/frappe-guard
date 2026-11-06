app_name = "frappe_guard"
app_title = "Frappe Guard"
app_publisher = "FOSS-On-Line"
app_description = (
	"CAPTCHA and rate limit for the public forms and the sign-up/login endpoints of Frappe sites"
)
app_email = "foss@foss.ua"
app_license = "mit"

after_install = ["frappe_guard.install.after_install"]
required_apps = ["frappe"]
