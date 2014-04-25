#################################################################################
#assigning GUI controls to variable
#################################################################################
class VulnScan

	def initialize(username, scan, project_name, output_format, 
		fButton1, fButton2, fButton3, fButton4, config_file, before_context, 
		after_context, context)
		@username = username    
		@scan = scan
    	@project_name =  project_name
		$output_format = output_format
		@output_format1 = fButton1
		@output_format2 = fButton2
		@output_format3 = fButton3
		@output_format4 = fButton4
		@config_file = config_file
		@before_context = before_context
		@after_context = after_context
		@context = context
	end

end
