
###########################################################################
#  This is a modal window allows user to open and view the report generated
#	by the scanner
###########################################################################
require 'rbconfig'

class ShowReports 

	include GladeGUI
include RbConfig
	
	def show(parent)
		load_glade(__FILE__)
		show_window()
	end	
	
	def showReport__clicked(button)
		case $output_format
			when 'csv'
				Launchy.open("./reports/#{$sanitizedProject_name}Report.txt")
			else 
				Launchy.open("./reports/#{$sanitizedProject_name}Report.html")
			end
	end	
end
