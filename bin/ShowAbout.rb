
######################################################################
#  This is a modal window used to display information about Firefox OS
#	Vulnerability Scanner
#######################################################################

class ShowAbout 

	include GladeGUI

	def show(parent)
		load_glade(__FILE__)
	
		show_window()
	end	
	def button1__clicked(button)
		Launchy.open("https://www.owasp.org/index.php/DOM_Based_XSS")
	end
	
	def button2__clicked(button)
		Launchy.open("https://github.com/chrisallenlane/watchtower")
	end

end
