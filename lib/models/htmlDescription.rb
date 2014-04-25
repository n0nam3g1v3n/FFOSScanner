class HtmlSignatureDescription #Provides description, vulnerabilities, and solutions for each signature within HTML signature file

attr_accessor :sig_name, :message

	
	def initialize (sig_name, message)
		@sig_name = sig_name
		@message = message
	end

	def displayHtmlInputs #Provides description and vulnerabilities for each signature within HTML inputs group
			if sig_name == '<form'
			message = "HTML form is used to accept user input and pass the value to a server. A form within the HTML document can contain input elements such as textboxes, checkboxes,and radio-buttons."  
		
		elsif sig_name == '<input'		
			message = "The &lt;input&gt; tag is used to create interactive controls where the user can enter data in a HTML form.  If the data entered by user are not sanitized properly, attacker can perform DOM XSS attack by injecting dangerous Javascript code in the input field.<br><br><a href='https://developer.mozilla.org/en-US/docs/Web/HTML/Element/Input'>Click here for more information on &lt;input&gt; tag</a>"
		
		elsif sig_name == '<select'
			message = "The &lt;select&gt; tag is used to create a drop-down list within a HTML form.  This tag can be used to collect user input."
		
		elsif sig_name == '<script'
			message = "The &lt;script&gt; tag is used to define a client-side script within a HTML document.  The &lt;script&gt; element either 
						contains inline scripts, or points to a remote script file through the src attribute.  Under Mozilla's Content Security Policy, remote script 
						and inline script are banned on privileged and certified apps.  Javascript should be escaped before inserting untrusted data into Javascript 
						data values. The only safe place to put untrusted data into the code is inside a quoted &quot;data value.&quot; Including untrusted data 
						inside any other Javascript context is quite dangerous, as it is extremely easy to switch into an execution context with characters including 
						&#40;but not limited to&#41; semi-colon, equals, space, plus, and many more, so use with caution.<br><br><center>&quot;<i>&lt;script&gt;...
						NEVER PUT UNTRUSTED DATA HERE...&lt;&frasl;script&gt;directly in a script.</i>&quot;(OWASP)</center>"
		
		elsif sig_name == '<textarea'
			message = "The &lt;textarea&gt; tag defines a multi-line text input control.  Attacker can inject malicious script into the textarea to trigger XSS."
		
		else
		
			message = "No info available"
		
		end
 	
	end

	def displayDangerousHtml #Provides description and vulnerabilities for each signature within dangerous HTML signature group
			
		if sig_name == '<applet'
			message = "The &lt;applet&gt; tag defines an embedded applet.  It is not supported in HTML5.  There are security issues with poorly signed applet.  If an applet &quot;<i>... is launched using an &lt;applet&gt;, &lt;object&gt;, or &lt;embed&gt; HTML tag, the applet is given full privileges by default.&quot;</i> (a href='https://www.cert.org/blogs/certcc/2013/04/dont_sign_that_applet.html'>Dormann</a>. 2013)"
		
		elsif sig_name == '<embed'
			message = "The &lt;embed&gt; tag defines a container for an external application or plug-in content.  When you are using &lt;embed&gt; HTML tag to launch an signed applet, the applet will be given full privileged by default."
		
		elsif sig_name == '<iframe'
			message = "The &lt;iframe&gt; tag is used to embed another HTML document within the current HTML document.  
						Attacker can load XSS code by manipulating the &lt;iframe&gt; tags through the src attribute.<br><br>Example:<br><br><center><i>&quot;&lt;IFRAME SRC=&quot;javascript:alert('XSS');&quot;&gt;&lt;/IFRAME&gt;&quot;</i> (a href='https://www.owasp.org/index.php/XSS_Filter_Evasion_Cheat_Sheet#IFRAME'>OWASP</a>, 2013)</center>
						<br><br><a href='https://developer.mozilla.org/en-US/docs/Web/HTML/Element/iframe'>Click here for more information on &lt;iframe&gt; tag</a>"
		
		elsif sig_name == '<noscript'
			message = "<i>&quot;The &lt;noscript&gt; tag is used to provide an alternate content for users that have disabled scripts in their browser or have a browser that does not support client-side scripting.&quot;</i>(<a href='http://www.w3schools.com/tags/tag_noscript.asp'>W3Schools</a>. 2013)  Attacker can insert a &lt;/noscript&gt; tag before and a HTML comment tag after the XSS script to trick the browser to exit the &lt;noscript&gt; tag to perform XSS attack.  <br><br>Example:<br><br><center><i>&quot;&quot&gt;&lt;/noscript&gt;&lt;script&gt;alert(&#39;XSS&#39;)&lt;/script&gt;&lt;!--&quot;</i> (<a href='http://securethoughts.com/2009/02/hacking-for-xss-inside-noscript-html-tags/'>SecureThoughts.com</a>, 2009)</center>"
		
		elsif sig_name == '<object'
			message = "The &lt;object&gt; tag defines an embedded object such as multimedia and webpage into an HTML document.When you are using &lt;object&gt; HTML tag to launch an signed applet, the applet will be given full privileged by default.  Attacker can inject virus payloads to infect the users with the data attribute by redirecting the linked file to a HTML site that contain XSS code.<br><br>Example:<br><br><center><i>&lt;OBJECT TYPE=&quot;text/x-scriptlet&qupt; DATA=&quot;http://XSS.html&quot;&gt;&lt;/OBJECT&gt;</i></center>"
		
		elsif sig_name == '<style'
			message = "The &lt;style&gt; tag is used to define style information for an HTML document on how the HTML elements should render in a browser.  HTML's style tag can be vulnerable to Javascript injection.
<br><br>Example:<br><br><center><i>&lt;style type=text/javascript&gt;alert(&#39;malicious code&#39;)&lt;/style&gt;</i></center>"
		
		elsif sig_name == '<xml'
			message = "<i>&quot;XML was designed to transport and store data&quot;</i>(<a href='http://www.w3schools.com/xml/'>W3Schools</a>. 2013) Impropered XML coding ca nbe subjected to XML Injection"
		
		else
			message = "No info available"
		end
 	
	end

	def displayHtmlComments #Provides description and vulnerabilities for HTML comment tag
		if sig_name == '<!--'
			message = "The HTML 'comments' tag allows developer to create comments within the HTML code.  Comments can assist HTML developer to write notes to explain what the code does but they are not displayed in the browsers. It is possible to execute Javascript within the HTML comment tag."
		
		else
			message = "No info available"
		
		end
	end

	def displayHtmlInputSolutions #Provides solutions for each signature within HTML input signature group
			
		if sig_name == '<form'
			message = "<ul><li>Make sure user&#39;s inputs are properly sanitized before passing the value.</li></ul>"
   	 	
   	 	elsif sig_name == '<input'
			message = "<ul><li><i>&quot;Untrusted data should only be treated as displayable text. Never treat untrusted data as code or markup within Javascript code.</li>
						<li>Always Javascript encode and delimit untrusted data as quoted strings when entering the application&quot;</i>(OWSAP)</li></ul>"
		
		elsif sig_name == '<select'
			message = "<ul><li>Make sure user&#39;s inputs are properly sanitized before passing the value.</li></ul>"
	 	
		elsif sig_name == '<script'
			message = "<ul>
                   <li><i>&quot;&lt;script&gt;alert&#40;&#39;...ESCAPE UNTRUSTED DATA BEFORE PUTTING HERE...&#39;&#41;&lt;&#47;script&gt;     inside a quoted string</i></li> 
                   <li><i>&lt;script&gt;x=&#39;...ESCAPE UNTRUSTED DATA BEFORE PUTTING HERE...&#39;&#41;&lt;&#47;script&gt;          one side of a quoted expression</i>&quot;(OWASP)</li>
                   <li>Developers are not allowed to point a &lt;script&gt; at a remote Javascript file.  All JS files that are referenced must be included in your app's package.</li>
                   <li><i>All &lt;script&gt; tags must have an src=&quot;&quot; attribute. You may not use script attributes like onclick=&quot;&quot; or onload=&quot;&quot;.</i></li>(Mozilla Developer Network:App CSP)
                   <li>Avoid doing inline scripting</li></ul>"
		
		elsif sig_name == '<textarea'
			message = "<ul><li>Make sure user&#39;s inputs are properly sanitized before passing the value.</li></ul>"
		
		else
			message = "No info available"
		end
 	
	end
	
	def displayDangerousHtmlSolutions #Provides solutions for each signature within dangerous HTML signature group
			
		if sig_name == '<applet'
			message = "<ul><li>Disallow any data to be submitted to the application that can be controlled or manipulated by user</li></ul>"
		
		elsif sig_name == '<embed'
			message = "<ul><li><i>&quot;Make sure user submitted HTML cannot contain &lt;EMBED&gt; tags or only whitelisted &lt;EMBED&gt; &quot;src&quot; values.&quot;</i> (<a href='http://html5sec.org/'>HTML5 Security CheatSheet</a>, 2013)</li></ul>"
		
		elsif sig_name == '<iframe'
			message = "<ul><li><i>&quot;URL escape then Javascript escape Before inserting 
						untrusted data into URL attribute subcontext within the execution context.&quot</i> (
						<a href='https://www.owasp.org/index.php/DOM_based_XSS_Prevention_Cheat_Sheet#RULE_.235_-_URL_Escape_then_Javascript_Escape_Before_Inserting_Untrusted_Data_into_URL_Attribute_Subcontext_within_the_Execution_Context'>OWASP</a>, 2012)</li>
						<li><i>&quot;Perform cannonicalize input, URL validation, safe URL verification, whitelist http and https URL's only (Avoid the JavaScript Protocol to Open a new Window), or attribute encoder&quot; (<a href='https://www.owasp.org/index.php/XSS_%28Cross_Site_Scripting%29_Prevention_Cheat_Sheet#XSS_Prevention_Rules_Summary'>OWASP</a>. 2013)</li></ul>"
	
		
		elsif sig_name == '<noscript'
			message = "<ul><li>Ensure the &lt;noscript&gt; tag does not contain input values that can be controlled or manipulated by user</li></ul>"
		
		elsif sig_name == '<object'
			message = "<ul><li>Disallow any data to be submitted to the application that can be controlled or manipulated by user</li></ul>"
		
		elsif sig_name == '<style'
			message = "<ul><li>Never put untrusted data inside the style tags</li>
						<li><i>&quot;Only use untrusted data in a property value and not into other places in style data&quot;</i> (<a href='https://www.owasp.org/index.php/XSS_%28Cross_Site_Scripting%29_Prevention_Cheat_Sheet#RULE_.234_-_CSS_Escape_And_Strictly_Validate_Before_Inserting_Untrusted_Data_into_HTML_Style_Property_Values'>OWASP</a>, 2013)</li></ul>"
		
		elsif sig_name == '<xml'
			message = "Ensure the &lt;noscript&gt; tag does not contain input values that can be controlled or manipulated by user</li></ul>"
		
		else
			message = "<ul><li><a href='https://www.owasp.org/index.php/Testing_for_XML_Injection_%28OWASP-DV-008%29'>Click here for OWASP's guide on how to test for XML Injection</a></li></ul>"
		end
 	
	end

	def displayHtmlCommentsSolutions #Provides solutions for each signature within HTML comment tag
		if sig_name == '<!--'
			message = "<ul><li><i>&quot;<&lt;	&#33;--...NEVER PUT UNTRUSTED DATA HERE...--&gt;             inside an HTML comment&quot;</i> (<a href='https://www.owasp.org/index.php/XSS_%28Cross_Site_Scripting%29_Prevention_Cheat_Sheet'>OWASP</a>)"
		
		else
			message = "No info available"
		end
	end

end
