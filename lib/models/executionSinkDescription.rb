class ExecutionSinkDescription #Provides description, vulnerabilities, and solutions for each signature within HTML Execution Sink signature file

attr_accessor :sig_name, :message

	
	def initialize (sig_name, message)
		@sig_name = sig_name
		@message = message
	end

	def displayExecutionSink #Provides description and vulnerabilities for each signature within execution sinks
		if sig_name == 'eval('
			message = "The Javascript's eval() function evaluates or executes an argument.  Executing code with unsafe eval() function can make your application vulnerable to DOM XSS attacks.<br>
						Example of unsafe DOM manipulation using eval():<br><br>&quot;<i>var txtField =&quot;field1&quot;;<br>
						var txtUserInput = &quot;&#39;test@csnc.ch&#39;;alert(1);&quot;;<br>
						eval(<br>&quot;document.forms[0].&quot; + txtField + &quot;.value =&quot; + txtUserInput<br>
						);&quot;</i><br><br>The last double quote causes the user input to be treated as Javascript. </i>  (<a href='http://blog.csnc.ch/2013/01/dom-based-xss-unsafe-Javascript-functions/#section1'>R&#246;thllsberger</a>. 2103</a>)<br><br>
						This can execute the Javascript within texUserInput."
		
		elsif sig_name == 'setTimeout('
			message = "The Javascript's setTimeout() method is a time event which executes a function once after a specified time delay in milliseconds.  If an argument that is passed to the setTimeout function can be to control or manipulate by user, without any sanitization to the argument, attacker can use malicious Javascript to execute DOM XSS attack.<br><br>Example:<br><br><center><i>&quot;setTimeout(&quot;jsCode&quot;+usercontrolledVal ,timeMs);&quot;</i> (<a href='http://code.google.com/p/domxsswiki/wiki/ExecutionSinks'>DomXSSWiki</a>)</center><br><br>"
		
		elsif sig_name == 'setInterval('
			message = "The Javascript's setInterval() method is a time event which executes a function repeatedly at specified time intervals.  If an argument that is passed to the setInterval function can be to control or manipulate by user, without any sanitization to the argument, attacker can use malicious Javascript to execute DOM XSS attack.<br><br>Example:<br><br><center><i>&quot;setInterval(&quot;jsCode&quot;+usercontrolledVal ,timeMs);&quot;</i> (<a href='http://code.google.com/p/domxsswiki/wiki/ExecutionSinks'>DomXSSWiki</a>)</center>"
		
		elsif sig_name == 'Function('
			message = "A Javascript's Function contains a block of code that will be executed when it is called.  If the argument is being used within the function can be control or manipulate by user without sanitization, any vulnerable argument that is passed to the function can be subjected to DOM XSS.<br><br>Example:<br><br><i><ul><li>&quot;Function(&quot;jsCode&quot;+usercontrolledVal ),</li>
						<li>Function(&quot;arg&quot;,&quot;arg2&quot;,&quot;jsCode&quot;+usercontrolledVal )&quot;</i>(<a href='http://code.google.com/p/domxsswiki/wiki/ExecutionSinks'>DomXssWiki</a>, 2012)</li></ul><br><br><a href='https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Function'>Click here for more information on Function()</a>"
		
		elsif sig_name == 'crypto.generateCRMFRequest' 
			message = "<i>&quot;This method will generate a sequence of CRMF requests that has N requests. One request for each key pair that is 
						generated. The first three parameters will be applied to every request. The &quot;escrowAuthorityCert&quot; parameter will only be used for 
						requests that pertain to a key that is being escrowed. After the &quot;escrowAuthorityCert&quot; parameter, the method takes some Javascript 
						code that is invoked when the CRMF request is ready. Finally, there are 1 or more sets of key generation arguments. 
						Each key generation will be associated with its own request. All the requests will have the same DN.&quot;</i>(Mozilla Developer Network)  If a vulnerable argument is passed to the setInterval function without sanitization, it is possible to execute Javascript.<br><br>Example:<br><br><center><i>&quot;crypto.generateCRMFRequest(&#39;CN=0&#39;,0,0,null,&#39;jsCode&#39;+usercontrolledVal,384,null,&#39;rsa-dual-use&#39;)&quot;</i> (<a href='http://code.google.com/p/domxsswiki/wiki/ExecutionSinks'>DomXssWiki</a>)</center> <br><br><a href='https://developer.mozilla.org/en-US/docs/JavaScript_crypto/generateCRMFRequest'>Click here for more information on crypto.generateCRMFRequest</a> "
	
		else
			message = "No info available"
		
		end
	end

	def displayExecutionSinkSolutions#Provides solutions for each signature within execution sinks
		if sig_name == 'eval('
			message = "<ul><li><i>&quot;Limit the usage of dynamic untrusted data to right side operations. And be aware of data which may be passed to the application which look like code (eg. location, eval()).</li>
						<li>Use JSON.parse() instead for JSON parsing</li>
						<li>Make sure that any untrusted data passed to these methods is delimited with string delimiters and enclosed within a closure or Javascript encoded to N-levels based on usage, and wrapped in a custom function.&quot;</i>(<a href='https://www.owasp.org/index.php/DOM_based_XSS_Prevention_Cheat_Sheet#Guidelines_for_Developing_Secure_Applications_Utilizing_JavaScript'>OWASP</a>. 2013)</li></ul>"
		
		elsif sig_name == 'setTimeout('
			message = "<ul><li>setTimeout (with a string argument) should actually be prevented by the default CSP policy, and it should not be present in a privileged or certified web app</li></ul>"
		
		elsif sig_name == 'setInterval('
			message = "<ul><li>setInterval (with a string argument) should actually be prevented by the default CSP policy, and it should not be present in a privileged or certified web app</li></ul>"
		
		elsif sig_name == 'Function('
			message = "<ul><li>new_function should actually be prevented by the default CSP policy, and it should not be present in a privileged or certified web app</li></ul>"
		
		elsif sig_name == 'crypto.generateCRMFRequest' 
			message = "<ul><li>crypto.generateCRMFRequest (5th argument is eval'd) should actually be prevented by the default CSP policy, and it should not be present in a privileged or certified web app</li></ul>"
		
		else
			message = "No info available"
		
		end
	end
end
