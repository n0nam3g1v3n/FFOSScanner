class UrlSinkDescription #Provides description, vulnerabilities, and solutions for each signature within URL Sinks signature group

attr_accessor :sig_name, :message

	
	def initialize (sig_name, message)
		@sig_name = sig_name
		@message = message
	end

	def displayUrlSink #Provides description and vulnerabilities for each signature for each URL Sinks signature
			
		if sig_name == '\.src'
			message = "src is an attribute which specifies the URI of the content such as external script file to 
						appear in the element .  Assigning input to src attribute can be a risk because attacker can modify the URI with Javacript code to excute DOM based XSS..<br><br>Example:<br><br><ul><li>&lt;script&gt;maliciousScript&lt;&#8260;script&gt;;</li><br><li>&lt;img src=nonexistent onerror=maliciousCode&gt;</li></ul>"

		elsif sig_name == '\.data'
			message = ".data is an attribute which can be used to specify the URI of the content such as external script file to 
						appear in the element .  Assigning input to data attribute can be a risk because attacker can modify the URI with Javacript code to excute DOM based XSS."
		elsif sig_name == '\.href'
			message = "The href attribute <i>&quot;...specifies the location of a Web 
						resource, thus defining a link between the current element (the source anchor)
						 and the destination anchor defined by this attribute.&quot;</i> 
			 			(<a href='http://www.w3.org/TR/1998/REC-html40-19980424/struct/links.html#adef-href'>
						 W3C</a>, 2000)  Assigning input to href attribute can be a risk because attacker can modify the URI with Javacript code to excute DOM based XSS."
		
		elsif sig_name == '\.action'
	 		message = "<i>&quot;The action attribute specifies a form processing agent. User agent
	 		 			behavior for a value other than an HTTP URI is undefined.&quot;</i> 
	 					 (<a href='http://www.w3.org/TR/1999/REC-html401-19991224/interact/forms.html#adef-action'>
	 		 			W3C</a>)  Assigning input to action attribute can be a risk because attacker can modify the URI with Javacript code to execute DOM based XSS."
	 	
	 	elsif sig_name == 'document.URL'
	 		message = "document.URL returns a URL string of the HTML document.  The URL parameter from document.URL can be subjected to DOM based XSS if it is not sanitized."
	 	
	 	elsif sig_name =='document.referrer'
		    message = "If the document referrer string contains  malicious Javascript code and did not sanitized properly, attacker can use Javascript redirects or user interaction by sending a link of a page which can cause the execution of the malicious code in the context of the page to the victim."
	 	
	 	elsif sig_name == 'document.URLUnencoded'
	 		message = "document.URLUnencoded is used to get the URL for the document and stripped of any character encoding. It should be inspected since the document object can be infuenced by the user or attacker in DOM."
	
	 	elsif sig_name == 'document.location'
	 		message = "document.location and many of its properties should be inspected since the document object can be infuenced by the user or attacker in DOM."
	 	
	 	elsif sig_name == 'window.location'
	 		message = "window.location and many of its properties should be inspected since the Window object can be infuenced by the user or attacker in DOM."
	
		else
			message = "No info available"
		end
 	
	end

	def displayUrlSinkSolutions #Provides solutions for each signature for each URL Sinks signature
			if sig_name == '\.src'
			message = "<ul><li><i>&quot;Check for Javascript which assigns input to src attribute on supported elements</li>
						<li>Check for Javascript which settings window.location, document.location, and etc.&quot;</i>(<a href='https://developer.mozilla.org/en-US/docs/Web/Apps/Security_guidelines?redirectlocale=en-US&redirectslug=Apps%2FSecurity_guidelines#Location_sinks'>Mozilla Developer Network</a>, 2013)</li>
						<li><i>&quot;URL escape then Javascript escape Before inserting 
						untrusted data into URL attribute subcontext within the execution context.&quot</i> (
						<a href='https://www.owasp.org/index.php/DOM_based_XSS_Prevention_Cheat_Sheet#RULE_.235_-_URL_Escape_then_Javascript_Escape_Before_Inserting_Untrusted_Data_into_URL_Attribute_Subcontext_within_the_Execution_Context'>OWASP</a>, 2012)</li>
						<li><i>&quot;Perform cannonicalize input, URL validation, safe URL verification, whitelist http and https URL's only (Avoid the JavaScript Protocol to Open a new Window), or attribute encoder&quot;</i> (<a href='https://www.owasp.org/index.php/XSS_%28Cross_Site_Scripting%29_Prevention_Cheat_Sheet#XSS_Prevention_Rules_Summary'>OWASP</a>. 2013)</li></ul> "
	
		elsif sig_name == '\.data'
			message = "<ul><li><i>&quot;Check for Javascript which assigns input to src attribute on supported elements</li>
						<li>Check for Javascript which settings window.location, document.location, and etc.&quot;</i>(<a href='https://developer.mozilla.org/en-US/docs/Web/Apps/Security_guidelines?redirectlocale=en-US&redirectslug=Apps%2FSecurity_guidelines#Location_sinks'>Mozilla Developer Network</a>, 2013)</li>
						<li>Ensure any user-controlled data must be escaped properly for the HTML context where it is being inserted.</li>
						<li>Sanitized the data value so that it does not contain any dangerious Javascript tags</li></ul>"
		
		elsif sig_name == '\.href'
			message = "<ul><li><li><i>&quot;Check for Javascript which assigns input to src attribute on supported elements</li>
						<li>Check for Javascript which settings window.location, document.location, and etc.&quot;</i>(<a href='https://developer.mozilla.org/en-US/docs/Web/Apps/Security_guidelines?redirectlocale=en-US&redirectslug=Apps%2FSecurity_guidelines#Location_sinks'>Mozilla Developer Network</a>, 2013)</li>
						<i>&quot;URL escape then Javascript escape Before inserting 
						untrusted data into URL attribute subcontext within the execution context.&quot</i> (
						<a href='https://www.owasp.org/index.php/DOM_based_XSS_Prevention_Cheat_Sheet#RULE_.235_-_URL_Escape_then_Javascript_Escape_Before_Inserting_Untrusted_Data_into_URL_Attribute_Subcontext_within_the_Execution_Context'>OWASP</a>, 2012)</li>
						<li><i>&quot;Perform cannonicalize input, URL validation, safe URL verification, whitelist http and https URL's only (Avoid the JavaScript Protocol to Open a new Window), or attribute encoder&quot;</i> (<a href='https://www.owasp.org/index.php/XSS_%28Cross_Site_Scripting%29_Prevention_Cheat_Sheet#XSS_Prevention_Rules_Summary'>OWASP</a>. 2013)</li></ul> "
		
		elsif sig_name == '\.action'
	 		message = "<ul><li><i>&quot;Check for Javascript which assigns input to src attribute on supported elements</li>
						<li>Check for Javascript which settings window.location, document.location, and etc.&quot;</i>(<a href='https://developer.mozilla.org/en-US/docs/Web/Apps/Security_guidelines?redirectlocale=en-US&redirectslug=Apps%2FSecurity_guidelines#Location_sinks'>Mozilla Developer Network</a>, 2013)</li>
						<li>Ensure user's inputs from form are validated and sanitized before summiting</li></ul>"

	 	elsif sig_name == 'document.URL'
	 		message = "<ul><li>Make sure user input are properly sanitized before passing the value.</li>
	 					<li><i>&quot;a document object or a window property may be referenced syntactically 
	 					in many ways explicitly through window.location or implicitly through location. 
	 					Special concentration should be given to patterns wherein the DOM is modifed, either explicitly or potentially, either via 
						raw access to the HTML or via access to the DOM itself.&quot;</i> 
						(<a href = 'http://pagesperso-systeme.lip6.fr/Suman.Saha/src/isa12.pdf'>Saha, Jin & Doh.</a> 2010)</li><ul>"		
		
		elsif sig_name =='document.referrer'
		    message = "<ul><li>Make sure user input are properly sanitized before passing the value.</li></ul>"
	 	
	 	elsif sig_name == 'document.URLUnencoded'
	 		message = "<ul><li>Make sure user input are properly sanitized before passing the value.</li><li><i>&quot;a document object or a window property may be referenced syntactically 
	 					in many ways explicitly through window.location or implicitly through location. 
	 					Special concentration should be given to patterns wherein the DOM is modifed, either explicitly or potentially, either via 
						raw access to the HTML or via access to the DOM itself.&quot;</i> 
						(<a href = 'http://pagesperso-systeme.lip6.fr/Suman.Saha/src/isa12.pdf'>Saha, Jin & Doh.</a> 2010)</li><ul>"		

	 	elsif sig_name == 'document.location'
	 		message = "<ul><li>Make sure user input are properly sanitized before passing the value.</li>
	 					<li><i>&quot;a document object or a window property may be referenced syntactically in many ways explicitly through window.location or implicitly through location. 
	 					Special concentration should be given to patterns wherein the DOM is modfed, either explicitly or potentially, either via 
						raw access to the HTML or via access to the DOM itself.&quot;</i> 
						(<a href = 'http://pagesperso-systeme.lip6.fr/Suman.Saha/src/isa12.pdf'>Saha, Jin & Doh.</a> 2010)</li></ul>"		

	 	elsif sig_name == 'window.location'
	 		message = "<ul><li>Make sure user input are properly sanitized before passing the value.</li>
	 					<li><i>&quot;[a document object or a window property may be referenced syntactically 
	 					in many ways explicitly through window.location or implicitly through location. 
	 					Special concentration should be given to patterns wherein the DOM is modifed, either explicitly or potentially, either via 
						raw access to the HTML or via access to the DOM itself.&quot;</i> 
						(<a href = 'http://pagesperso-systeme.lip6.fr/Suman.Saha/src/isa12.pdf'>Saha, Jin & Doh.</a> 2010)</li></ul>"	
		
		else
		
			message = "No info available"
			
			
		end
 	
	end
end

