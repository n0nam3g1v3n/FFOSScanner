Gem::Specification.new do |s|
  s.name = "firefoxproject"  # i.e. visualruby.  This name will show up in the gem list.
  s.version = "0.0.1"  # i.e. (major,non-backwards compatable).(backwards compatable).(bugfix)
	s.add_dependency "vrlib", ">= 0.0.1"
	s.add_dependency "gtk2", ">= 0.0.1"
	s.add_dependency "require_all", ">= 0.0.1"
	s.has_rdoc = false
  s.authors = ["Stanley Wong"] 
  s.email = "you@yoursite.com" # optional
  s.summary = "Firefox OS Web App Vulnerability Scanner is a BCIT's graduation project"
  s.homepage = "http://www.yoursite.org/"  # optional
  s.description = "Full description here" # optional
	s.executables = ['FFscanner']  # i.e. 'vr' (optional, blank if library project)
	s.default_executable = ['FFscanner']  # i.e. 'vr' (optional, blank if library project)
	s.bindir = ['.']    # optional, default = bin
	s.require_paths = ['.']  # optional, default = lib 
	s.files = Dir.glob(File.join("**", "*.{rb,glade}"))
	s.rubyforge_project = "nowarning" # supress warning message 
end
