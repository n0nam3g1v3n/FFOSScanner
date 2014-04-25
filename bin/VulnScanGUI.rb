######################################################################################
# Load scanner's graphical user interface
#####################################################################################
class VulnScanGUI < VulnScan

	include GladeGUI

	def show()
		load_glade(__FILE__)  #loads file, glade/VulnScanGUI.glade into @builder


		set_glade_all() #populates glade controls with insance variables 
		show_window() 
	end	

	def quitButton__clicked(button)
		GTK.main.quit
	end

	def buttonAbout__clicked(button)
		y = ShowAbout.new() #self = parent
		y.show(self)
	end
	
	def buttonScan__clicked(button)
		get_glade_all() #retrieve instance variables from values input by user  
			#		sanitizing user inputs against XSS		
		if @username == ""
			VR::Dialog.message_box( "You must enter a username.", title="Firefox OS Vulnerability Scanner")
			Gtk.main.quit
		else
			@sanitizedUsername = Sanitize.clean(@username)
		end 

		if @project_name == "" #check if the project name is left blank
			VR::Dialog.message_box( "You must enter a project name.", title="Firefox OS Vulnerability Scanner")
			Gtk.main.quit
		else

			$sanitizedProject_name = Sanitize.clean(@project_name, Sanitize::Config::RESTRICTED)
		end
		@scan = @builder['VulnScanGUI.scan'].current_folder #save web app's location to a variable

		if @scan == nil
			VR::Dialog.message_box( "You must select a directory to scan.", title="Firefox OS Vulnerability Scanner" )
			Gtk.main.quit
		end



	#######################################################################
# Configs, Signatures, and Option Validation
#######################################################################
# Load the configuration file
		unless File.exists? @config_file
    	VR::Dialog.message_box( 'The specified config file does not exist.')
			@config_file = './config.rb'
			Gtk.main.quit
			
    end
     require @config_file

		unless File.directory? @scan
    	begin    
    		# simply verify that the specified URL is valid so we can fail
    		# gracefully if not
    		res = open(@scan).read
    		# kludge: I don't know if it's bad form to output a notice to 
    		# stderr when there isn't actually a problem
    		VR::Dialog.message_box( "Downloading the page source for '#{@scan}. This may take some time.")
        
    		# parse the domain out of the URL, because that's the name wget
    		# is going to choose for its output directory
    		$configs[:domain] = URI::split(@scan)[2]
        
    		# don't accidentally nuke any existing files
    		if File.exists? "/tmp/#{$configs[:domain]}"
    		   VR::Dialog.message_box( "The directory '#{@scan}' already exists. Please " +
    		     "rename that directory to avoid a naming collision.", title="Firefox OS Vulnerability Scanner")
    		end
    		   `cd /tmp/; wget -mq '#{@scan}'`
        
        # when the download is complete, specify the downloaded 
        # directory for scanning
        @scan = "/tmp/#{$configs[:domain]}"
        
        # make a note to clean up after wget when the scan is complete
        $configs[:clean_up_after_wget] = true
    		rescue
    			VR::Dialog.message_box( "The path or URL specified for scanning appears to be invalid.", title="Firefox OS Vulnerability Scanner")
					Gtk.main.quit
    		end
			end


# Verify that -A and -B are >= 1
			if Integer(@before_context) < 1 or Integer(@after_context) < 1
				VR::Dialog.message_box( "Options --before-context and --after-context may not be less than 1.", title="Firefox OS Vulnerability Scanner")
				Gtk.main.quit
        
# Verify that -C is >= 3
  		elsif Integer(@context) < 3
				VR::Dialog.message_box( "Option --context may not be less than 3.", title="Firefox OS Vulnerability Scanner")
				Gtk.main.quit         
			else
				case #determine user's output format
					when @output_format1 then $output_format = "html"
					when @output_format2 then $output_format = "csv"
					when @output_format3 then $output_format = "xml"
					when @output_format4 then $output_format = "markdown"
				end
				
				VR::Dialog.message_box("You have entered:\n\ Username: #{@sanitizedUsername}\n\ Project name: #{$sanitizedProject_name}\n\ Location of web app: #{@scan}\n\ Output format: #{$output_format}\n\ Config file: #{@config_file}\n", title="Firefox OS Vulnerability Scanner")			
				s = TowerInit.new(@sanitizedUsername, @scan, $sanitizedProject_name, $output_format, @config_file, @before_context, @after_context, @context)
				s.show
			end
			x = ShowReports.new() #self = parent
			x.show(self)
	end

end

