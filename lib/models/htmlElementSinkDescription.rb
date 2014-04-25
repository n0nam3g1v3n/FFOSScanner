class HtmlElemetSinkDescription #Provides description, vulnerabilities, and solutions for each signature within HTML Element Sink signature file

attr_accessor :sig_name, :message

	
	def initialize (sig_name, message)
		@sig_name = sig_name
		@message = message
	end

	def displayHtmlElementSink #Provides descriptions and vulnerabilities for each signature within HTML Element Sinks signature group
			
		if sig_name == 'document.write'
			message = "The document.write element &quot;<i>...writes a string of text to a document stream opened by document.open()</i>&quot;(Mozilla Developer Network). If the document referrer string contains malicious Javascript code and it not sanitized, this code executed in the current context and cause XSS attack.<br><br><a href='https://developer.mozilla.org/en-US/docs/Web/API/document.write'>Click here for more information on document.write</a><br><a href='https://www.owasp.org/index.php/DOM_Based_XSS'>Click here for example of an DOM based XSS attack using document.write</a>"
		
		elsif sig_name == 'document.writeln'
			message = "The document.writeln element &quot;<i>...writes a string of text followed by a newline character to a document.</i>&quot;(Mozilla Developer Network).   With poor Javascript coding practices, malicious Javascript code can be injected to the document if the input were not sanitized correctly.<br><br><a href='https://developer.mozilla.org/en-US/docs/Web/API/document.write'>Click here for more information on document.write</a>"
				
		elsif sig_name == '.innerHTML'
			message = "The innerHTML element is used to &quot;<i>...set or get the HTML syntax describing the element&rsquo;s descendants</i>&quot;(Mozilla Developer Network).  It renders HTML content within Javascript and creates the HTML Subcontext within the Execution Context. If  untrusted input is passed to innerHTML, DOM based XSS vulnerability could result.<br><br>
						If you are doing <i>element.innerHTML += &quot;markup&quot;</i>, The may create DOM corruption issue. <i>&quot;When browser parses the new string that contains the serialization of the old descendants followed by some new markup.  The old descendants might have been script-inserted to form a subtree that does not round-trip when serialized as HTML and reparsed. In that case, after the operation, the tree would have a different shape even for the &quot;old&quot; parts&quot;</i>(<a href='https://hacks.mozilla.org/2011/11/insertadjacenthtml-enables-faster-html-snippet-injection/'>Sivonen</a>, 2011)  
						In addition, the nodes created by the parser would be different nodes compared to the children nodes at first even though they may looked the same after serializing and reparsing.  innerHTML can be vulnerable to DOM based XSS if the data passes through contains malicious Javascript code.<br><br>Example:<br><br><center><i>&quot;divEl.innerHTML = &quot;htmlString&quot;+ usercontrolledVal&quot;</i></center><br><br>
						<i>&quot;If it is possible to control, even partially, the vulnerable argument, then it is possible to manipulate, to some extent the HTML and consequently, gain control of the user interface or execute JavaScript using classic Cross Site Scripting attacks.&quot;</i>(<a href='http://code.google.com/p/domxsswiki/wiki/HTMLElementSinks'>DomXSSWiki</a>)<br><br><a href='https://developer.mozilla.org/en-US/docs/Web/API/element.innerHTML'>Click here for more information about innerHTML</a>"
		elsif sig_name == '.createContextualFragment'
			message = ".createContextualFragment &quot;<i>returns a document fragment by invoking the HTML fragment parsing algorithm or the XML fragment parsing algorithm with the start of the range (the parent of the selected node) as the context node. The HTML fragment parsing algorithm is used if the range 
						belongs to a Document whose HTMLness bit is set. In the HTML case, if the context node would be html, for historical reasons the fragment parsing 
						algorithm is invoked with body as the context instead.</i>&quot;(Mozilla Developer Network)  If a vulnerable argument is passed to the setInterval function without sanitization, it is possible to execute Javascript.<br><br>Example:<br><br><center><i>&quot;range.createContextualFragment(&quot;htmlString&quot;+ usercontrolledVal )&quot;<br><br>
						<i>&quot;If it is possible to control, even partially, the vulnerable argument, then it is possible to manipulate, to some extent the HTML and consequently, gain control of the user interface or execute JavaScript using classic Cross Site Scripting attacks.&quot;</i>(<a href='http://code.google.com/p/domxsswiki/wiki/HTMLElementSinks'>DomXssWiki</a>)<br><br><a href='https://developer.mozilla.org/en-US/docs/Web/API/range.createContextualFragment'>Click here for more information on .createContextualFragment</a>"
		
		elsif sig_name == '.outerHTML'
			message = "<i>&quot;The outerHTML attribute of the element DOM interface gets the serialized HTML fragment describing the element including its descendants. It can be set to replace the element with nodes parsed from the given string.&quot;</i> (Mozilla Developer Network)  Similar to innerHTML, outerHTML can be vulnerable to DOM based XSS if the data passes through contains malicious Javascript code.<br><br>Example:<br><br><i>&quot;element.outerHTML = &quot;&lt;HTML&gt; Tags and markup&quot;</i> (<a href='https://www.owasp.org/index.php/DOM_based_XSS_Prevention_Cheat_Sheet'>OWASP</a>. 2013)<br><br><a href='https://developer.mozilla.org/en-US/docs/Web/API/element.outerHTML'>Click here for more information on element.outerHTML</a>"		
		
		elsif sig_name == '.parseFromString'
			message = "parseFromString is a method which parses XML from a string for the DOMParser object.  If the a string contains malicious Javascript code, the code can be executed in the DOMParser. <br><br><a href='https://developer.mozilla.org/en-US/docs/Web/API/DOMParser'>Click here for more information on DOMParser</a>"
				
		elsif sig_name == '.createHTMLDocument'
			message = "The createHTMLDocument method creates a non rendered document outside of the current document tree.  If  untrusted input is passed to createHTMLDocument, DOM based XSS vulnerability could result."
		
		else
			message = "No info available"
		
		end

	end

	def displayHtmlElementSinkSolutions #Provides solutions for each signature within HTML Element Sinks signature group
			
		
			
		if sig_name == 'document.write'
			message = "<ul><li>To make dynamic updates to HTML in the DOM safe environment, HTML encoding should be first and then Javascript encoding all untrusted input<br>Example:<br><center><i>document.write(&quot; &lt;%=Encoder.encodeForJS(Encoder.encodeForHTML(untrustedData))%&gt; &quot;)&#59;</i></center></li><br>
						<li>Avoid using document.write(...);, use document.createElement(&quot;...&quot;), element.setAttribute(&quot...&quot;,&quot;value&quot;), 
						element.appendChild(...), etc. to build dynamic interfaces instead.</li></ul>"
		
		elsif sig_name == 'document.writeln'
			message = "<ul><li>To make dynamic updates to HTML in the DOM safe environment, HTML encoding should be first and then Javascript encoding all untrusted input<br>Example:<br><i>document.writeln(&quot; &lt;%=Encoder.encodeForJS(Encoder.encodeForHTML(untrustedData))%&gt; &quot;)&#59;</i></li><br>
						<li>Avoid using document.writeln(...);, use document.createElement(&quot;...&quot;), element.setAttribute(&quot;...&quot;,&quot;value&quot;), element.appendChild(...), etc. to build dynamic interfaces instead.</li></ul>"
		
		elsif sig_name == '.innerHTML'
			message = "<ul><li>The element.innerHTML element should be avoided if possible. They can be made secure, but require an understanding of how each browser&#39;s Javascript engine works to make sure that all XSS vectors have been mitigated.  
						One of them is to make dynamic updates to HTML in the DOM safe, HTML encoding should be before Javascript encoding all untrusted input.<br><br>Examples:<br><i>element.innerHTML = &quot;	&lt;%=Encoder.encodeForJS(Encoder.encodeForHTML(untrustedData))%&gt;	&quot;&#59;</i></li><br>
						<li>Since there are ways to execute Javascript without using &lt;script&gt; elements, there will be a security risk when using innerHTML to set strings which you have no control over.</li>  
						<li>Use element.textContent instead.  textContent does not interpret the passed content as HTML, but instead inserts it as raw text.</li>
						<li>Avoid using element.innerHTML = &quot;...&quot;;, use document.createElement(&quot;...&quot;), element.setAttribute(&quot;...&quot;,&quot;value&quot;), element.appendChild(...), etc. to build dynamic interfaces instead.</li>
						<li>When using element.setAttribute, avoid using command execution context attributes because the are considered dangerious. Ex: onclick or onblur</li>
						<li>Use innerText as an alternative to mitigate against XSS in innerHTML. However, malicious code can still be executed depending on the tag which innerText is applied.</li>
						<li>Instead of using element.innerHTML += &quot;markup&quot;, use element.insertAdjacentHTML(&quot;beforeend&quot;, &quot;markup&quot;)</li>
						<li>anyElement.innerHTML is prevented by CSP</li></ul>"
		
		elsif sig_name == '.outerHTML'
			message = "<ul><li>anyElement.outerHTML is prevented by CSP</li>
						<li><i>&quot;To make dynamic updates to HTML in the DOM safe, we recommend a) HTML encoding, and then b) JavaScript encoding all untrusted input:</li></ul>
						<center>&quot;element.outerHTML = &quot;&lt;%=Encoder.encodeForJS(Encoder.encodeForHTML(untrustedData))%&gt;&quot;;&quot;</i> (<a href='https://www.owasp.org/index.php/DOM_based_XSS_Prevention_Cheat_Sheet'>OWASP</a>. 2013)</center>"
		
		elsif sig_name == '.createContextualFragment'
			message = "<ul><li>Range.createContextualFragment is prevented by CSP</li></ul>"
		
		elsif sig_name == '.parseFromString'
			message = "<ul><li>parseFromString (DOMParser) is prevented by CSP</li></ul>"
		
		elsif sig_name == '.createHTMLDocument'
			message = "<ul><li>All the dangerous tags and attributes must be stripped before passing the information to createHTMLDocument</li></ul>"
		
		else
			message = "No info available"
		end

	end
end
