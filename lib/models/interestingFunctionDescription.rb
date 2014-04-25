class InterestingFunctionDescription #Provides description, vulnerabilities, and solutions for each signature within Interesting Functions signature group

attr_accessor :sig_name, :message

		
	def initialize (sig_name, message)
		@sig_name = sig_name
		@message = message
	end

	def displayinterestingFunction #Provides description and vulnerabilities for each signature within Interesting Functions group
		if sig_name == 'escapeHTML'
			message = "The escapeHTML function converts HTML special characters to their equivalent entity representations.  If the data is not santizied prior to passing it to the escapeHTML function,  this function can convert dangerous characters used in script injection into harmless HTML entities."
		
		elsif sig_name == 'window.open' 
			message = "The window.open method opens a new browser window. Malicious Javascript code can be passed in the window.open method.<br><br>Example:<br><center>window.open(&quot;http://www.victim.com/domxss.html&quot;, &quot;&lt;script&gt;malicious code&lt;script&gt&quot;);
						<br><br><a href='https://developer.mozilla.org/en-US/docs/Web/API/window.open'>Click here for more information on window.open</a>"
		
		elsif sig_name == 'indexeddb'
			message = "Indexeddb is an API for client-side storage of significant amounts of structured data and for high performance searches on this data using indexes.  Since indexeddb can contain sensitive user information, it is important to to ensure data consistency and integrity when using client side storage with indexeddb<br><br><a href='https://developer.mozilla.org/en-US/docs/IndexedDB'>Click here for for information on indexedDB</a>"
		
		elsif sig_name == 'mozSetMessageHandler'
			message = "This method is used to allow applications to register a function handler to message from the system in order to react to them.  
						Any application is allowed to register to any message but some messages will only be delivered to applications that have the corresponding 
						permission.<br><br><a href='https://developer.mozilla.org/en-US/docs/Web/API/window.navigator.mozSetMessageHandler'>Click here for more 
						information about mozSetMessageHandler</a>"
		
		elsif sig_name =='.insertAdjacentHTML'
			message = "Alternative to innerHTML, <i>&quot;insertAdjacentHTML() parses the specified text as HTML or XML and inserts the resulting nodes into the DOM tree at a specified position. It does not reparse the element it is being used on and thus it does not corrupt the existing elements inside the element. This, and avoiding the extra step of serialization make it much faster than direct innerHTML manipulation.&quot;</i>(Mozilla Developer Network)  
						With insertAdjacentHTML(),  it can enable faster HTML snippet injection. <br><br><a href='https://developer.mozilla.org/en-US/docs/Web/API/element.insertAdjacentHTML'>Click here for more information on insertAjacentHTML</a>"		
		else
			message = "No info available"
		
		end
	end

	def displayinterestingFunctionSolutions #Provides solutions for each signature within Interesting Functions
		if sig_name == 'escapeHTML'
			message = "<ul><li>Use string replacement by using quoted attributes and specifying charsets.(<a href='http://benv.ca/2012/10/4/you-are-probably-misusing-DOM-text-methods/'>&quot;You are probably misusing DOM text methods&quot;</a>)</li>
						<li><i>&quot;Escape the following characters (&amp;, &lt;, &gt;, &quot;, &#x27;, &#x2F;) with HTML entity encoding to prevent switching into any execution context, such as script, style, or event handlers. Using hex entities is recommended in the spec. In addition to the 5 characters significant in XML (&, <, >, &quot;, '), the forward slash is included as it helps to end an HTML entity.</i><a href='https://www.owasp.org/index.php/XSS_(Cross_Site_Scripting)_Prevention_Cheat_Sheet#RULE_.231_-_HTML_Escape_Before_Inserting_Untrusted_Data_into_HTML_Element_Content'>(OWASP)</a></li></ul>" 

		elsif sig_name == 'window.open' 
			message = "<ul><li>Use string replacement by using quoted attributes and specifying charsets.(<a href='http://benv.ca/2012/10/4/you-are-probably-misusing-DOM-text-methods/'>&quot;You are probably misusing DOM text methods&quot;</a>)</li>
						<li><i>&quot;Escape the following characters (&amp;, &lt;, &gt;, &quot;, &#x27;, &#x2F;) with HTML entity encoding to prevent switching into any execution context, such as script, style, or event handlers. Using hex entities is recommended in the spec. In addition to the 5 characters significant in XML (&, <, >, &quot;, '), the forward slash is included as it helps to end an HTML entity.</i><a href='https://www.owasp.org/index.php/XSS_(Cross_Site_Scripting)_Prevention_Cheat_Sheet#RULE_.231_-_HTML_Escape_Before_Inserting_Untrusted_Data_into_HTML_Element_Content'>(OWASP)</a></li></ul>" 
		
		elsif sig_name == 'indexeddb'
			message = "<ul><li>&quot;<i>Keep user data to a minimum and avoid storage of private user information where possible.</li>    				
						<li>Provide users with a way to clear sensitive data.</il>
						<li>Consider encryption prior to storage for particularly sensitive data.</li>
						<li> Mind that keys stored on the device can be recovered even after deletion.</i>&quot;</li></ul>(Mozilla Developer Network:Security Guidelines, 2013)"
		
		elsif sig_name == 'mozSetMessageHandler'
			message = "<ul><li>Carefully examine the handler function for the activity within the mozSetMessageHandler </li></ul>"
		
		elsif sig_name =='.insertAdjacentHTML'
			message = "<ul><li>Use insertAdjacentHTML instead of innerHTML because it is faster and it does not corrupt the data that are already in the DOM.</li></ul>"	
		
		else
			message = "No info available"
		
		end
	end
end
