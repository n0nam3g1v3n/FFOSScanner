class CSSSignatureDescription #Provides description, vulnerabilities, and solutions for each signature within client side storage signature group
attr_accessor :sig_name, :message

	
	def initialize (sig_name, message)
		@sig_name = sig_name
		@message = message
	end

	def displayClientSideStorage #Provides description and vulnerabilities for each signature within client side storage
		if sig_name == 'localStorage'
			message = "LocalStorage is used for storing key value pairs on the client side. These key value pairs can be retrieved in HTML pages originating from the same domain. The Local storage data is stored on the disk and persists across application restarts. Problem with localStorage is that <i>&quot;the data remains on disk until either the site removes it or until the user explicitly tells the browser to remove it. That means the data may remain on disk permanently otherwise&quot;</i>(<a href='http://www.nczonline.net/blog/2010/04/13/towards-more-secure-client-side-data-storage/'>Zakas</a>, 2010).<br><br><b>Permissions:</b><br>Web Content: None (DENY_ACTION)<br>Installed Web App: Implicit (ALLOW_ACTION)<br>Privileged Web App: Implicit (ALLOW_ACTION)
						<br>Certified Web App: Implicit (ALLOW_ACTION)<br><br><a href='https://developer.mozilla.org/en-US/docs/Web/Guide/DOM/Storage'>Click here for more information on localStorage</a>"
		
		elsif sig_name == 'indexedDB' 
			message = "IndexedDB is an API for client-side storage used to store significant amounts of structured data and for high performance searches on this data using indexes.  
						You must need <i>&quot;...to ensure data consistency and integrity, since data is effectively unstructured.&quot;</i>
						(<a href='http://www.html5rocks.com/en/tutorials/offline/storage/#indexed-db'>Mahemoff</a>)<br><br><b>Permissions:</b><br>Web Content: None (DENY_ACTION)<br>Installed Web App: Implicit (ALLOW_ACTION)<br>Privileged Web App: Implicit (ALLOW_ACTION)
						<br>Certified Web App: Implicit (ALLOW_ACTION)<br><br><a href='https://developer.mozilla.org/en-US/docs/IndexedDB'>Click here for more information on indexedDB</a>"
		
		elsif sig_name == 'indexeddb'
			message = "IndexedDB is an API for client-side storage used to store significant amounts of structured data and for high performance searches on this data using indexes.  You must need <i>&quot;...to ensure data consistency and integrity, since data is effectively unstructured.&quot;</i>
						(<a href='http://www.html5rocks.com/en/tutorials/offline/storage/#indexed-db'>Mahemoff</a>)<br><br><b>Permissions:</b><br>Web Content: None (DENY_ACTION)<br>Installed Web App: Implicit (ALLOW_ACTION)<br>Privileged Web App: Implicit (ALLOW_ACTION)
						<br>Certified Web App: Implicit (ALLOW_ACTION)<br><br><a href='https://developer.mozilla.org/en-US/docs/IndexedDB'>Click here for for information on indexedDB</a>"
		
		elsif sig_name == 'mozSetMessageHandler'
			message = "This method is used to allow applications to register a function handler to message from the system in order to react to them.  
						Any application is allowed to register to any message but some messages will only be delivered to applications that have the corresponding 
						permission.<br><br><a href='https://developer.mozilla.org/en-US/docs/Web/API/window.navigator.mozSetMessageHandler'>Click here for more 
						information about mozSetMessageHandler</a>"
	
		elsif sig_name =='document.cookie'
			message = "document.cookie is used to get and set the cookies associated with the current document.  Cookie can contain sensitive user's information such as username, password, session cookie, or credit card number, it is important to secure the information stored because attacker can use malicious Javascript code to steal cookie data. <br><br><a href='https://developer.mozilla.org/en-US/docs/Web/API/document.cookie'>Click here for more information on document.cookie</a>"
		
		else	
			message = "No info available"
	
		
		end	
	
 	
	end

	def displayClientSideStorageSolutions #Provides solutions to DOM XSS for each signature within client side storage
		if sig_name == 'localStorage'
			message = "<ul><li>&quot;<i>Keep user data to a minimum and avoid storage of private user information where possible.</li>    				
						<li>Provide users with a way to clear sensitive data.</il>
						<li>Consider encryption prior to storage for particularly sensitive data.</li>
						<li> Mind that keys stored on the device can be recovered even after deletion.</i>&quot; (<a href='https://developer.mozilla.org/en-US/docs/Web/Apps/Security_guidelines'>Mozilla Developer Network:Security Guidelines</a>, 2013)</li></ul>"
		
		elsif sig_name == 'indexedDB' 
			message = "<ul><li>&quot;<i>Keep user data to a minimum and avoid storage of private user information where possible.</li>    				
						<li>Provide users with a way to clear sensitive data.</il>
						<li>Consider encryption prior to storage for particularly sensitive data.</li>
						<li> Mind that keys stored on the device can be recovered even after deletion.</i>&quot;(<a href='https://developer.mozilla.org/en-US/docs/Web/Apps/Security_guidelines'>Mozilla Developer Network:Security Guidelines</a>, 2013)</li></ul>"
		
		elsif sig_name == 'indexeddb'
			message = "<ul><li>&quot;<i>Keep user data to a minimum and avoid storage of private user information where possible.</li>    				
						<li>Provide users with a way to clear sensitive data.</il>
						<li>Consider encryption prior to storage for particularly sensitive data.</li>
						<li> Mind that keys stored on the device can be recovered even after deletion.</i>&quot; (<a href='https://developer.mozilla.org/en-US/docs/Web/Apps/Security_guidelines'>Mozilla Developer Network:Security Guidelines</a>, 2013)</li></ul>"
		
		elsif sig_name == 'mozSetMessageHandler'
			message = "<ul><li>&quot;<i>Keep user data to a minimum and avoid storage of private user information where possible.</li>    				
						<li>Provide users with a way to clear sensitive data.</il>
						<li>Consider encryption prior to storage for particularly sensitive data.</li>
						<li> Mind that keys stored on the device can be recovered even after deletion.</i>&quot; (<a href='https://developer.mozilla.org/en-US/docs/Web/Apps/Security_guidelines'>Mozilla Developer Network:Security Guidelines</a>, 2013)</li></ul>"
		
		elsif sig_name =='document.cookie'
			message = "<ul><li>&quot;<i>Keep user data to a minimum and avoid storage of private user information where possible.</li>    				
						<li>Provide users with a way to clear sensitive data.</il>
						<li>Consider encryption prior to storage for particularly sensitive data.</li>
						<li> Mind that keys stored on the device can be recovered even after deletion.</i>&quot; (<a href='https://developer.mozilla.org/en-US/docs/Web/Apps/Security_guidelines'>Mozilla Developer Network:Security Guidelines</a>, 2013)</li></ul>"
	
		else
			message = "No info available"
	
		
		end	
	
 	
	end
end
