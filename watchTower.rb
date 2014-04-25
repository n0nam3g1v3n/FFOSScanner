include ERB::Util
#######################################################################################################
# Modified Watchtower script to scan web app 
#####################################################################################################
class TowerInit

attr_accessor :scan, :config_file, :output_format, :sanitizedProject_name, :before_context, :after_context, :context

	
	def initialize (username, scan, project_name, output_format, config_file, before_context, after_context, context)
  		@sanitizedUsername = username
		@scan = scan
  		$sanitizedProject_name = project_name
  		@output_format = output_format
  		@config_file = config_file
  		@before_context = before_context
  		@after_context = after_context
  		@context = context
	end

  def show #perform scan
		vulnscanner = VulnScanner.new({
			:signatures		=> $signatures,
			:scan_dir		=> @scan,
			:before_context	=> Integer(@before_context),
			:after_context	=> Integer(@after_context),
			:context    	=> Integer(@context),
		})
		vulnscanner.scan

		if vulnscanner.points_of_interest.count.zero? #prompt user if no signature matched 
	    	VR::Dialog.message_box( "No signature matches were found within the project. Terminating.", title="Firefox OS Vulnerability Scanner")
			Gtk.main.quit
		end

		# clean up after wget if necessary
		`rm -rf '/tmp/#{$configs[:domain]}'` if $configs[:clean_up_after_wget].eql? true
		case @output_format
			when 'csv'
		# print a header row
				vulnscanner.points_of_interest.each do |point|
				File.open("./reports/#{$sanitizedProject_name}Report.txt", 'w') {|f| f.write('"file_type","file","line_number","match","name","snippet","group"')}
		 	 	File.open("./reports/#{$sanitizedProject_name}Report.txt", 'a') {|f| f.write("\n")}
        		File.open("./reports/#{$sanitizedProject_name}Report.txt", 'a') {|f| f.write(CSV.generate_line(point.to_a, { :force_quotes => true }).gsub("\r", '').gsub("\n", ''))}
			
			end
			when 'html'
				# sort the points of interest for HTML output
				vulnscanner.sort
				# parse and display the HTML output
		 		erb = ERB.new(File.read($configs[:report_file][:html]), 0, '<>', 'buffer')
				# create html report
				File.open("./reports/#{$sanitizedProject_name}Report.html", 'w') {|f| f.write(erb.result(binding))}
			
			when 'markdown'
				# require erb for templating
				vulnscanner.sort
		# parse and display the HTML output
				erb = ERB.new(File.read($configs[:report_file][:markdown]), 0, '<>', 'buffer')
				File.open("./reports/#{$sanitizedProject_name}Report.html", 'w') {|f| f.write(erb.result(binding))}
			
			when 'xml'
				File.open("./reports/#{$sanitizedProject_name}Report.xml", 'w') {|f| f.write('<points_of_interest>')}
				File.open("./reports/#{$sanitizedProject_name}Report.xml", 'a') {|f| f.write("\n")}
				File.open("./reports/#{$sanitizedProject_name}Report.xml", 'a') {|f| f.write(vulnscanner.points_of_interest.each {|point| puts point.to_xml})}
				File.open("./reports/#{$sanitizedProject_name}Report.xml", 'a') {|f| f.write("\n")}					
				File.open("./reports/#{$sanitizedProject_name}Report.xml", 'a') {|f| f.write('</points_of_interest>')}
			end
  		end
	
end
