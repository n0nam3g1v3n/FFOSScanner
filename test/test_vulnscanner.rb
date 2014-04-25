require 'rubygems'
require 'backports'
require_relative './test_helper.rb'
require_relative '../lib/models/signature.rb'
require_relative '../lib/models/vulnscanner.rb'

# @todo: I should probably beef up the testing on this class in the
# future. It's a bit weak right now.
class TestVulnscanner < ::Test::Unit::TestCase  
  def setup
	# mock the config file
	$configs                    = {}
	$configs[:exclude_files]    = []
	$configs[:exclude_dirs]     = []
    $configs[:ftype_ext]        = {}
    $configs[:ftype_ext][:php]  = %w[php phpt php3 php4 php5 phtml]
    
	# specify the signatures
	signatures = {}
	signatures[:php] = {}
	signatures[:php][:dangerous_functions] = [
		Signature.new({:literal => 'eval('}),
		Signature.new({:literal => 'base64_decode('}),
	]
	
	# specify the directory to scan
	scandir = File.dirname(__FILE__)
	@vulnscanner = VulnScanner.new({
		:signatures 	=> signatures,
		:scan_dir 		=> scandir,
		:before_context => 1,
		:after_context	=> 1,
		:context	    => 3
	})
  end
  
  must "scan" do
	@vulnscanner.scan
	assert_equal @vulnscanner.points_of_interest.count, 2	
  end
  
  must "sort" do
	@vulnscanner.scan
	@vulnscanner.sort
	assert_equal @vulnscanner.points_of_interest.count, 2
	assert_equal @vulnscanner.points_of_interest_sorted.count, 1
  end
  
end
