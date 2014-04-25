class PrivilegedApiDescription #Provides description, vulnerabilities, and solutions for each signature within privileged apis signature group
attr_accessor :sig_name, :message

	
	def initialize (sig_name,message)
		@sig_name = sig_name
		@message = message
	end



	def displayPrivilegedApis #Provides description and vulnerabilities for each signature for each API
		if sig_name == '.mozAlarms'
			message = "Alarm API provide DOM API access to the device alarm settings, which can schedule a notification or for an application to be 
						started at a specific time. For example, some applications like alarm-clock, calendar or auto-update might need to utilize Alarm API to trigger 
						particular device behaviors at specified time points.  Firing frequent alarms to prevent an app from being shutown. Draining battery life or consume CPU time.<br><br><b>Permissions:</b><br>Web Content:None (DENY_ACTION)<br>Installed Web App: Implicit (ALLOW_ACTION)<br>
						Privileged Web App: Implicit (ALLOW_ACTION)<br>Certified Web App:  Implicit (ALLOW_ACTION)<br><br>
						<a href='https://developer.mozilla.org/en-US/docs/WebAPI/Alarm?redirectlocale=en-US&redirectslug=API%2FAlarm_API'>Click here for more information on mozAlarms</a>"
		
		elsif sig_name == '\'attention\''
			message = "Allow content to open a window in front of all other content. Used by telephone and SMS.<br><br><b>Permissions:</b><br>Web Content: None (DENY_ACTION)<br>Installed Web App: None (DENY_ACTION)<br>Privileged Web App: None (DENY_ACTION)<br>Certified Web App:  Implicit (ALLOW_ACTION)"
		
		elsif sig_name == 'mozaudiochannel'
			message = "<i>&quot;This API introduces the concept of a hierarchy of audio channels. The channels are prioritized as to allow 'silencing all channels with priority lower than X'.&quot;</i>(Mozilla Wiki)  <i>&quot;Poorly designed or belligerent channels which block other sound from being played, blocking the notification or alarm channels for extended periods of time. Using the content channel for playing sounds that aren't expected to be played when the user isn't handling the app.&quot;</i>(<a href='https://developer.mozilla.org/en-US/docs/Web/Apps/Security_guidelines'>Mozilla Developer Network:Security Guideline</a>, 2013)<br><br>
						<b>Permissions:</b><br><b>audio-channel-normal, audio-channel-content</b><br>Web Content: None (DENY_ACTION)
						<br>Installed Web App: Implicit (ALLOW_ACTION)<br>Privileged Web App: Implicit (ALLOW_ACTION)<br>Certified Web App: Implicit (ALLOW_ACTION)<br><br>
						<b>audio-channel-notification, audio-channel-alarm</b><br>Web Content: None (DENY_ACTION)<br>Installed Web App: None (DENY_ACTION)<br>Privileged Web App: Implicit (ALLOW_ACTION)<br>Certified Web App: Implicit (ALLOW_ACTION)<br><br>
						<b>audio-channel-ringer, audio-channel-telephony, audio-channel-publicnotification</b>
						<br>Web Content: None (DENY_ACTION)<br>Installed Web App: None (DENY_ACTION)<br>Privileged Web App: None (DENY_ACTION)
						<br>Certified Web App: Implicit (ALLOW_ACTION) <br><br><a href='https://wiki.mozilla.org/WebAPI/AudioChannels'>Click here for more information on mozaudiochannel</a> "
		
		elsif sig_name === '.mozBluetooth' 
			message = "Low level access to Bluetooth hardware.<br><br><b>Permissions:</b><br><br>Web Content: None (DENY_ACTION)<br>Installed Web App: None (DENY_ACTION)<br>Privileged Web App: None (DENY_ACTION)<br>Certified Web App: Implicit (ALLOW_ACTION)<br><br><a href='https://wiki.mozilla.org/WebAPI/WebBluetooth'>Click here for more information on WebBluetooth</a>"
	
		elsif sig_name == '.mozCamera'
			message = "<i>&quot;Window.navigator.mozCamera returns a CameraManager object you can use to access the cameras available on the user's device.&quot;</i>(Mozilla Developer Network)<br><br>
						<b>Permissions:</b><br>Web Content:  None (DENY_ACTION)<br>Installed Web App:  None (DENY_ACTION)<br>Privileged Web App:  None (DENY_ACTION)<br>
						Certified Web App: Implicit (ALLOW_ACTION)<br><br> <a href='https://developer.mozilla.org/en-US/docs/DOM/window.navigator.mozCameras'>Click here for more information on mozCameras</a>"
		
		elsif sig_name == '.mozCellBroadcast'
			message = "Fires an event when a specific type of cell network message is received (an emergency network notification).<br><br><b>Permissions:</b><br>Web Content:  None (DENY_ACTION)<br>Installed Web App:  None (DENY_ACTION)<br>Privileged Web App:  None (DENY_ACTION)<br>Certified Web App: Implicit (ALLOW_ACTION)"
		
		elsif sig_name == '.mozContacts'
			message = "<i>&quot;The Contacts API provides a simple interface to manage user's contacts stored in the system's address book. A typical use case of the Contacts API is the 
						implementation of an application to manage said address book.&quot;</i>(Mozilla Developer Network>In proper assignment of mozContact API can result in scrape user's contact list and send it to third party server. It can also modify its contents without user consent.<br><br>
						<b>Permissions:</b><br>Web Content:  None (DENY_ACTION)<br>Installed Web App:  None (DENY_ACTION)<br>Privileged Web App: Explicit (PROMPT_ACTION)<br>Certified Web App: Implicit (ALLOW_ACTION)<br><br><a href='https://developer.mozilla.org/en-US/docs/WebAPI/Contacts'>Click here to for more information on mozContacts</a>"
		
		elsif sig_name == '.mozNotifications'
			message = "mozNotifications provides support for creating notification objects, which are used to display desktop notification alerts to the user.  If nofication API is not assigned correctly, it can spam the user.<br><br><b>Permissions:</b><br>Web Content: Explicit (PROMPT_ACTION)<br>Installed Web App: Implicit (ALLOW_ACTION)<br>Privileged Web App: Implicit (ALLOW_ACTION)<br>   
						Certified Web App: Implicit (ALLOW_ACTION)<br><br><a href='https://developer.mozilla.org/en-US/docs/DOM/navigator.mozNotification'>Mozilla developer Network: navigator.mozNotification</a>"
		
		elsif sig_name == '.getDeviceStorage'
			message = "<i>&quot;The getDeviceStorages method is used to access individual storage area available on the device.
						This method return an Array of DeviceStorage object, one per physical storage area. To access to a unfied view of the storage area (as if there were only one physical storage area) it's recommanded to use the getDeviceStorage method.
						&quot;</i> (Mozilla Developer Network)Improper assignment of storage API can allow unauthorized access to storage area.<br><br><b>Permissions:</b><br><b>device-storage:apps</b><br>
						Web Content: None (DENY_ACTION)<br>Installed Web App: None (DENY_ACTION)<br>Privileged Web App: None (DENY_ACTION)
						<br>Certified Web App: Implicit (ALLOW_ACTION) for read only. Write and create should not be permitted
						<br><br><b>device-storage:music</b><br>Web Content: None (DENY_ACTION)<br>Installed Web App: None (DENY_ACTION)<br>Privileged Web App: Explicit (PROMPT_ACTION)
						<br>Certified Web App: Implicit (ALLOW_ACTION)<br><br><b>device-storage:pictures</b><br>Web Content: None (DENY_ACTION)<br>Installed Web App: None (DENY_ACTION)
						<br>Privileged Web App: Explicit (PROMPT_ACTION)<br>Certified Web App: Implicit (ALLOW_ACTION)
						<br><br><b>device-storage:sdcard</b><br>Web Content: None (DENY_ACTION)<br>Installed Web App: None (DENY_ACTION)<br>Privileged Web App: Explicit (PROMPT_ACTION)
						<br>Certified Web App: Implicit (ALLOW_ACTION)<br><br><b>device-storage:videos</b><br>Web Content: None (DENY_ACTION)
						<br>Installed Web App: None (DENY_ACTION)<br>Privileged Web App: Explicit (PROMPT_ACTION)<br>Certified Web App: Implicit (ALLOW_ACTION)
						<br><br><a href='https://developer.mozilla.org/en-US/docs/Web/API/window.navigator.getDeviceStorages'>Click here for more information on getDeviceStorages method</a>"
		
		elsif sig_name == 'mozapp'
			message = "Ability to embed mozapp frames(iframes)<br><br><b>Permissions:</b><br>
						Web Content: None (DENY_ACTION)<br>Installed Web App: None (DENY_ACTION)<br>Privileged Web App: None (DENY_ACTION)<br>Certified Web App: Implicit (ALLOW_ACTION)"
		
		elsif sig_name == 'mozFMRadio'
			message = "mozFMRadio allows to access FM radio on device.  Improper assignment of this API can cause privacy issues due to potential side-channel geolocation through the use of FM band.  It may also drain a lot of power from device.<br><br><b>Permissions:</b><br>Web Content: None (DENY_ACTION)
						<br>Installed Web App: Implicit (ALLOW_ACTION)<br>Privileged Web App: Implicit (ALLOW_ACTION)<br>Certified Web App: Implicit (ALLOW_ACTION)<br><br>
						<a href='https://developer.mozilla.org/en-US/docs/Web/API/window.navigator.mozFMRadio'>Click here for more information on mozFMRadio</a>"
		
		elsif sig_name == 'geolocation'
			message = "The geolocation API allows the user to provide their location to web applications if they so desire.  Since geoLocation API logs and store user's location, it is important to make sure there will be any unauthorized access to these data. <br><br><b>Permissions:</b><br>Web Content: Explicit (PROMPT_ACTION)<br>Installed Web App: Explicit (PROMPT_ACTION)
						<br>Privileged Web App: Explicit (PROMPT_ACTION)<br>Certified Web App: Explicit (PROMPT_ACTION)<br><br><a href='https://developer.mozilla.org/en-US/docs/WebAPI/Using_geolocation?redirectlocale=en-US&redirectslug=Using_geolocation'>Click here for more information on geolocation</a>"
		
		elsif sig_name == 'addIdleObserver'
			message = "<i>&quot;This method is used to add an observer that will check if the user is idle and will act accordingly.&quot;</i><Mozilla Developer Network)<br><br><b>Permissions:</b><br>Web Content: None (DENY_ACTION)
						<br>Installed Web App: None (DENY_ACTION)<br>Privileged Web App: None (DENY_ACTION)<br>Certified Web App: Implicit (ALLOW_ACTION)<br><br><a href='https://developer.mozilla.org/en-US/docs/WebAPI/Idle#Idle_observer'>Click here for more information on addIdleObserver</a>"
		elsif sig_name == 'mozMobileConnection'
			message = "<i>&quot;mozMobileConnection is used to obtain information about the current mobile voice and data connection&quot;</i> and exposes information to (certain) HTML content.(Mozilla Wiki)<br><br><b>Permissions:</b><br>Web Content: None (DENY_ACTION)
						<br>Installed Web App: None (DENY_ACTION)<br>Privileged Web App: None (DENY_ACTION)<br>Certified Web App: Implicit (ALLOW_ACTION)<br><br><a href='https://wiki.mozilla.org/WebAPI/WebMobileConnection'>Click here for more information on mozMobileConnection</a>"
		
		elsif sig_name == 'moznetworkupload' 
			message = "moznetworkupload monitors network uploads.<br><br><b>Permissions:</b><br>Web Content: None (DENY_ACTION)
						<br>Installed Web App: None (DENY_ACTION)<br>Privileged Web App: None (DENY_ACTION)<br>Certified Web App: Implicit (ALLOW_ACTION)"
		
		elsif sig_name == 'moznetworkdownload'
			message = "moznetworkdownload monitors network downloads.<br><br><b>Permissions:</b><br>Web Content: None (DENY_ACTION)
						<br>Installed Web App: None (DENY_ACTION)<br>Privileged Web App: None (DENY_ACTION)<br>Certified Web App: Implicit (ALLOW_ACTION)"
		
		elsif sig_name == 'mozPermissionSettings'
			message = "mozPermissionSettings allows an app to manage other permissions of other apps.<br><br><b>Permissions:</b><br>Web Content: None (DENY_ACTION)
						<br>Installed Web App: None (DENY_ACTION)<br>Privileged Web App: None (DENY_ACTION)<br>Certified Web App: Implicit (ALLOW_ACTION)<br><br>"
		
		elsif sig_name == 'mozPower'
			message = "<i>&quot;mozPower is used to turn the screen on or off, control CPU, device power, and so on. Listen for and inspect resource lock 
						events.&quot;</i><br><br><b>Permissions:</b><br>Web Content: None (DENY_ACTION)
						<br>Installed Web App: None (DENY_ACTION)<br>Privileged Web App: None (DENY_ACTION)<br>Certified Web App: Implicit (ALLOW_ACTION)<br><br><a href='https://developer.mozilla.org/en-US/docs/DOM/window.navigator.mozPower'>Click here for more information on mozPower</a>"
		
		elsif sig_name == 'mozSettings' 
			message = "<i>&quot;navigator.mozSettings is a SettingsManager object you can use to access and change the device's settings.&quot;</i>(Mozilla Developer Network)<br><br><b>Permissions:</b><br>Web Content: None (DENY_ACTION)
						<br>Installed Web App: None (DENY_ACTION)<br>Privileged Web App: None (DENY_ACTION)<br>Certified Web App: Implicit (ALLOW_ACTION)<br><br>
						<a href='https://developer.mozilla.org/en-US/docs/DOM/window.navigator.mozSettings'>Click here for more information on mozSettings</a>"
		
		elsif sig_name == 'mozSms'
			message = "mozSms is used to send and receive SMS messages.<br><br><b>Permissions:</b><br>Web Content: None (DENY_ACTION)
						<br>Installed Web App: None (DENY_ACTION)<br>Privileged Web App: None (DENY_ACTION)<br>Certified Web App: Implicit (ALLOW_ACTION)<br><br>
						<a href='https://developer.mozilla.org/en-US/docs/WebAPI/WebSMS?redirectlocale=en-US&redirectslug=API%2FWebSMS'>Click here for more information on WebSMS</a>"
		
		elsif sig_name == 'mozSystem'
			message = "Allows anonymous (no cookies) cross-origin XHR without the target site having CORS enabled. Similar to TCP-Socket API but restrcited to XHR, not just raw sockets so slightly less risky.<br><br><Permissions:</b><br>
						Web Content: None (DENY_ACTION)<br>Installed Web App: None (DENY_ACTION)<br>Privileged Web App: Implicit (ALLOW_ACTION)<br>Certified Web App: Implicit (ALLOW_ACTION)"
		
		elsif sig_name == 'mozTCPSocket'
			message = "<i>&quot;mozTCPSocket provides access to a raw TCP socket API in Javascript. This API is currently only available to FirefoxOS 
						privileged and certified apps.&quot;</i>(Mozilla Developer Network)<br><br><Permissions:</b><br>
						Web Content: None (DENY_ACTION)<br>Installed Web App: None (DENY_ACTION)<br>Privileged Web App: Implicit (ALLOW_ACTION)<br>Certified Web App: Implicit (ALLOW_ACTION)<br><br><a href='https://developer.mozilla.org/en-US/docs/DOM/TCPSocket'>Click here for more information on mozTCPSocket</a>"
		
		elsif sig_name == 'mozTelephony'
			message = "<i>&quot;navigator.mozTelephony is a Telephony object you can use to control the phone features of the device on which the browser is running.&quot;</i>(Mozilla Developer Network)<br><br><b>Permissions:</b><br>
						Web Content: None (DENY_ACTION)<br>Installed Web App: None (DENY_ACTION)<br>Privileged Web App: None (DENY_ACTION)<br>Certified Web App: Implicit (ALLOW_ACTION)<br><br> 
						<a href='https://developer.mozilla.org/en-US/docs/DOM/window.navigator.mozTelephony'>Click here for more information on mozTelephony</a>"
		
		elsif sig_name == 'mozTime'
			message = "<i>&quot;mozTime is used to set the system time on a device.  The API also exposes an event so that any application can be notified when the time is changed.&quot;</i>(Mozilla Developer Network)<br><br><b>Permissions:</b><br>
						Web Content: None (DENY_ACTION)<br>Installed Web App: None (DENY_ACTION)<br>Privileged Web App: None (DENY_ACTION)<br>Certified Web App: Implicit (ALLOW_ACTION)<br><br>
						<a href='https://developer.mozilla.org/en-US/docs/DOM/MozTimeManager?redirectlocale=en-US&redirectslug=DOM%2FTIme'>Click here for more information on mozTime</a>"
		
		elsif sig_name == 'mozVoicemail' 
			message = "mozvoicemail is used to access voicemail."
		
		elsif sig_name == 'mozApps.mgmt'
			message = "<i>&quot;mozApps.mgmt is privileged. It is intended to grant access to trusted pages, also called &quot;dashboards&quot;. The management API exposes functions that let dashboards manage and launch apps on a user's behalf. Additionally, the API exposes functions for app sync, which lets the dashboard display the logged-in state of the user and allows the user to sign up or register for an account to synchronize apps across devices.&quot;</i>(Mozilla Developer Network)
						<br><br><b>Permissions:</b><br>Web Content: None (DENY_ACTION)<br>Installed Web App: None (DENY_ACTION)<br>Privileged Web App: None (DENY_ACTION)<br>Certified Web App: Implicit (ALLOW_ACTION)
						<br><br><a href='https://developer.mozilla.org/en-US/docs/Javascript_API#Management_API'>Click here for more information on Management API (navigator.mozApps.mgmt.*)</a>"
		
		elsif sig_name == 'mozWifiManager'
			message = "<i>&quot;mozwifiManager is used to enumerate available WiFi networks, get signal strength, connect to a network.&quot;</i>(Mozilla Developer Network)<br><br><b>Permissions:</b><br>
						Web Content: None (DENY_ACTION)<br>Installed Web App: None (DENY_ACTION)<br>Privileged Web App: None (DENY_ACTION)<br>Certified Web App: Implicit (ALLOW_ACTION)<br><br>"
		
		elsif sig_name == 'mozKeyboard'
			message = "<i>&quot;mozKeyboard allows the app to act as a virtual keyboard by listening to focus change events in other apps.&quot;</i>(Mozilla Wiki)<br><br><b>Permissions:</b><br>
						Web Content: None (DENY_ACTION)<br>Installed Web App: None (DENY_ACTION)<br>Privileged Web App: None (DENY_ACTION)<br>Certified Web App: Implicit (ALLOW_ACTION)<br><br><a href='https://wiki.mozilla.org/WebAPI/KeboardIME'>Click here for more information on WebAPI/KeboardIME</a>"
		else
			message = "No info available"
		end
	end
	def displayPrivilegedApisSolutions #Provides solutions for each signature for each API
		if sig_name == 'mozAlarms'
			message = "<ul><li>Make sure the alarm handler finishes quickly and does not do a lot of processing power</li>
						<li><i>&quot;Declare stricter-than-default CSP, using the manifest's CSP directive.&quot;</i> (<a href='https://developer.mozilla.org/en-US/docs/Web/Apps/Security_guidelines#HTML.2FJavascript.2FCSS_injection_and_XSS'>Mozilla Developer Network:Security Guidelines</a>. 2013)</li>
						<li><i>&quot;Only request the bare minimum of permissions necessary for your application to work.</li>
						<li>Use access restrictions like read-only where the API supports them&quot;</i> (<a href='https://developer.mozilla.org/en-US/docs/Web/Apps/Security_guidelines#Permissions'>Mozilla Developer Network</a>. 2013)</li></ul>"
	
		elsif sig_name == '\'attention\''
			message = "<ul><li><i>&quot;Declare stricter-than-default CSP, using the manifest's CSP directive.&quot;</i> (<a href='https://developer.mozilla.org/en-US/docs/Web/Apps/Security_guidelines#HTML.2FJavascript.2FCSS_injection_and_XSS'>Mozilla Developer Network:Security Guidelines</a>. 2013)</li>
						<li><i>&quot;Only request the bare minimum of permissions necessary for your application to work.</li>
						<li>Use access restrictions like read-only where the API supports them&quot;</i> (<a href='https://developer.mozilla.org/en-US/docs/Web/Apps/Security_guidelines#Permissions'>Mozilla Developer Network</a>. 2013)</li></ul>"
	
		elsif sig_name == 'mozaudiochannel'
			message = "<ul><li><i>&quot;Examine the use of audio channels.&quot;</i>(a href='https://developer.mozilla.org/en-US/docs/Web/Apps/Security_guidelines'>Mozilla Developer Network:Security Guidelines</a>, 2013)<</li>
						<li><i>&quot;Declare stricter-than-default CSP, using the manifest's CSP directive.&quot;</i> (<a href='https://developer.mozilla.org/en-US/docs/Web/Apps/Security_guidelines#HTML.2FJavascript.2FCSS_injection_and_XSS'>Mozilla Developer Network:Security Guidelines</a>. 2013)</li>
						<li><i>&quot;Only request the bare minimum of permissions necessary for your application to work.</li>
						<li>Use access restrictions like read-only where the API supports them&quot;</i> (<a href='https://developer.mozilla.org/en-US/docs/Web/Apps/Security_guidelines#Permissions'>Mozilla Developer Network</a>. 2013)</li></ul>"
	
		elsif sig_name == 'mozBluetooth'
			message = "<ul><li><i>&quot;Declare stricter-than-default CSP, using the manifest's CSP directive.&quot;</i> (<a href='https://developer.mozilla.org/en-US/docs/Web/Apps/Security_guidelines#HTML.2FJavascript.2FCSS_injection_and_XSS'>Firefox Developer Network:Security Guidelines</a>. 2013)</li>
						<li><i>&quot;Declare stricter-than-default CSP, using the manifest's CSP directive.&quot;</i> (<a href='https://developer.mozilla.org/en-US/docs/Web/Apps/Security_guidelines#HTML.2FJavascript.2FCSS_injection_and_XSS'>Mozilla Developer Network:Security Guidelines</a>. 2013)</li>
						<li><i>&quot;Only request the bare minimum of permissions necessary for your application to work.</li>
						<li>Use access restrictions like read-only where the API supports them&quot;</i> (<a href='https://developer.mozilla.org/en-US/docs/Web/Apps/Security_guidelines#Permissions'>Mozilla Developer Network</a>. 2013)</li></ul>"
	
		elsif sig_name == 'mozCamera'
			message = "<ul><li><i>&quot;Declare stricter-than-default CSP, using the manifest's CSP directive.&quot;</i> (<a href='https://developer.mozilla.org/en-US/docs/Web/Apps/Security_guidelines#HTML.2FJavascript.2FCSS_injection_and_XSS'>Firefox Developer Network:Security Guidelines</a>. 2013)</li>
						<li><i>&quot;Declare stricter-than-default CSP, using the manifest's CSP directive.&quot;</i> (<a href='https://developer.mozilla.org/en-US/docs/Web/Apps/Security_guidelines#HTML.2FJavascript.2FCSS_injection_and_XSS'>Mozilla Developer Network:Security Guidelines</a>. 2013)</li>
						<li><i>&quot;Only request the bare minimum of permissions necessary for your application to work.</li>
						<li>Use access restrictions like read-only where the API supports them&quot;</i> (<a href='https://developer.mozilla.org/en-US/docs/Web/Apps/Security_guidelines#Permissions'>Mozilla Developer Network</a>. 2013)</li></ul>"
	
    	elsif sig_name == 'mozCellBroadcast'
			message = "<ul><li><i>&quot;Declare stricter-than-default CSP, using the manifest's CSP directive.&quot;</i> (<a href='https://developer.mozilla.org/en-US/docs/Web/Apps/Security_guidelines#HTML.2FJavascript.2FCSS_injection_and_XSS'>Firefox Developer Network:Security Guidelines</a>. 2013)</li>
						<li><i>&quot;Declare stricter-than-default CSP, using the manifest's CSP directive.&quot;</i> (<a href='https://developer.mozilla.org/en-US/docs/Web/Apps/Security_guidelines#HTML.2FJavascript.2FCSS_injection_and_XSS'>Mozilla Developer Network:Security Guidelines</a>. 2013)</li>
						<li><i>&quot;Only request the bare minimum of permissions necessary for your application to work.</li>
						<li>Use access restrictions like read-only where the API supports them&quot;</i> (<a href='https://developer.mozilla.org/en-US/docs/Web/Apps/Security_guidelines#Permissions'>Mozilla Developer Network</a>. 2013)</li></ul>"
	
		elsif sig_name == 'mozContacts'
			message = "<ul><li><i>&quot;Should compare description to access requested.  If different, that should be flagged. Carefully review any code which changes contacts, especially functions which can be used to globally modify contacts.&quot;</i>(<a href='https://developer.mozilla.org/en-US/docs/Web/Apps/Security_guidelines'>Mozilla Developer Network:Security Guidelines</a>, 2013)<li></ul>"
		
		elsif sig_name == 'mozNotifications'
			message = "<ul><li><i>&quot;Declare stricter-than-default CSP, using the manifest's CSP directive.&quot;</i> (<a href='https://developer.mozilla.org/en-US/docs/Web/Apps/Security_guidelines#HTML.2FJavascript.2FCSS_injection_and_XSS'>Firefox Developer Network:Security Guidelines</a>. 2013)</li>
						<li><i>&quot;Declare stricter-than-default CSP, using the manifest's CSP directive.&quot;</i> (<a href='https://developer.mozilla.org/en-US/docs/Web/Apps/Security_guidelines#HTML.2FJavascript.2FCSS_injection_and_XSS'>Mozilla Developer Network:Security Guidelines</a>. 2013)</li>
						<li><i>&quot;Only request the bare minimum of permissions necessary for your application to work.</li>
						<li>Use access restrictions like read-only where the API supports them&quot;</i> (<a href='https://developer.mozilla.org/en-US/docs/Web/Apps/Security_guidelines#Permissions'>Mozilla Developer Network</a>. 2013)</li></ul>"
	
		elsif sig_name == '.getDeviceStorage'
			message = "<ul><li><i>&quot;Declare stricter-than-default CSP, using the manifest's CSP directive.&quot;</i> (<a href='https://developer.mozilla.org/en-US/docs/Web/Apps/Security_guidelines#HTML.2FJavascript.2FCSS_injection_and_XSS'>Mozilla Developer Network:Security Guidelines</a>. 2013)</li>
						<li><i>&quot;Only request the bare minimum of permissions necessary for your application to work.</li>
						<li>Use access restrictions like read-only where the API supports them&quot;</i></li> (a href='https://developer.mozilla.org/en-US/docs/Web/Apps/Security_guidelines#Permissions'>Mozilla Developer Network</a>. 2013)</li>
						<li>Be careful not to modify or delete user data.</li>
						<li>Require permission for navigator.getDeviceStorage(...)</li><ul>"
	
		elsif sig_name == 'mozapp'
			message = "<ul><li><i>&quot;Declare stricter-than-default CSP, using the manifest's CSP directive.&quot;</i> (<a href='https://developer.mozilla.org/en-US/docs/Web/Apps/Security_guidelines#HTML.2FJavascript.2FCSS_injection_and_XSS'>Mozilla Developer Network:Security Guidelines</a>. 2013)</li>
						<li><i>&quot;Only request the bare minimum of permissions necessary for your application to work.</li>
						<li>Use access restrictions like read-only where the API supports them&quot;</i> (<a href='https://developer.mozilla.org/en-US/docs/Web/Apps/Security_guidelines#Permissions'>Mozilla Developer Network</a>. 2013)</li></ul>"
	
		elsif sig_name == 'mozFMRadio'
			message = "<ul><li>Ensure mozFMRadio API is not used as a tracking mechanism. If it does, user must be informed.</li>
						<li><i>&quot;Declare stricter-than-default CSP, using the manifest's CSP directive.&quot;</i> (<a href='https://developer.mozilla.org/en-US/docs/Web/Apps/Security_guidelines#HTML.2FJavascript.2FCSS_injection_and_XSS'>Mozilla Developer Network:Security Guidelines</a>. 2013)</li>
						<li><i>&quot;Only request the bare minimum of permissions necessary for your application to work.</li>
						<li>Use access restrictions like read-only where the API supports them&quot;</i> (<a href='https://developer.mozilla.org/en-US/docs/Web/Apps/Security_guidelines#Permissions'>Mozilla Developer Network</a>. 2013)</li></ul>"
	
		elsif sig_name == 'geolocation'
			message = "<ul><li>For privacy reasons, the user is asked to confirm permission to report location information.</li>
						<li><i>&quot;Examine when geolocation will be prompted for (is it at an appropriate time). Examine what is done with geolocation data, is it stored, how frequently is it accessed etc.&quot;</i>(<a href='https://developer.mozilla.org/en-US/docs/Web/Apps/Security_guidelines>Mozilla Developer Network:Security Guidelines</a>, 2013)</li>
						<li><i>&quot;Declare stricter-than-default CSP, using the manifest's CSP directive.&quot;</i> (<a href='https://developer.mozilla.org/en-US/docs/Web/Apps/Security_guidelines#HTML.2FJavascript.2FCSS_injection_and_XSS'>Mozilla Developer Network:Security Guidelines</a>. 2013)</li>
						<li><i>&quot;Only request the bare minimum of permissions necessary for your application to work.</li>
						<li>Use access restrictions like read-only where the API supports them&quot;</i> (<a href='https://developer.mozilla.org/en-US/docs/Web/Apps/Security_guidelines#Permissions'>Mozilla Developer Network</a>. 2013)</li></ul>"
	
		elsif sig_name == 'addIdleObserver'
			message = "<ul><li><i>&quot;Declare stricter-than-default CSP, using the manifest's CSP directive.&quot;</i> (<a href='https://developer.mozilla.org/en-US/docs/Web/Apps/Security_guidelines#HTML.2FJavascript.2FCSS_injection_and_XSS'>Mozilla Developer Network:Security Guidelines</a>. 2013)</li>
						<li><i>&quot;Only request the bare minimum of permissions necessary for your application to work.</li>
						<li>Use access restrictions like read-only where the API supports them&quot;</i>(a href='https://developer.mozilla.org/en-US/docs/Web/Apps/Security_guidelines#Permissions'>Mozilla Developer Network</a>. 2013)</li>
						<li><i>&quot;Declare stricter-than-default CSP, using the manifest's CSP directive.&quot;</i> (<a href='https://developer.mozilla.org/en-US/docs/Web/Apps/Security_guidelines#HTML.2FJavascript.2FCSS_injection_and_XSS'>Mozilla Developer Network:Security Guidelines</a>. 2013)</li>
						<li><i>&quot;Only request the bare minimum of permissions necessary for your application to work.</li>
						<li>Use access restrictions like read-only where the API supports them&quot;</i> (<a href='https://developer.mozilla.org/en-US/docs/Web/Apps/Security_guidelines#Permissions'>Mozilla Developer Network</a>. 2013)</li></ul>"
	
		elsif sig_name == 'mozMobileConnection'
			message = "<ul><li><i>&quot;Declare stricter-than-default CSP, using the manifest's CSP directive.&quot;</i> (<a href='https://developer.mozilla.org/en-US/docs/Web/Apps/Security_guidelines#HTML.2FJavascript.2FCSS_injection_and_XSS'>Mozilla Developer Network:Security Guidelines</a>. 2013)</li>
						<li><i>&quot;Only request the bare minimum of permissions necessary for your application to work.</li>
						<li>Use access restrictions like read-only where the API supports them&quot;</i></li> (a href='https://developer.mozilla.org/en-US/docs/Web/Apps/Security_guidelines#Permissions'>Mozilla Developer Network</a>. 2013)
						<li><i>&quot;Declare stricter-than-default CSP, using the manifest's CSP directive.&quot;</i> (<a href='https://developer.mozilla.org/en-US/docs/Web/Apps/Security_guidelines#HTML.2FJavascript.2FCSS_injection_and_XSS'>Mozilla Developer Network:Security Guidelines</a>. 2013)</li>
						<li><i>&quot;Only request the bare minimum of permissions necessary for your application to work.</li>
						<li>Use access restrictions like read-only where the API supports them&quot;</i> (<a href='https://developer.mozilla.org/en-US/docs/Web/Apps/Security_guidelines#Permissions'>Mozilla Developer Network</a>. 2013)</li></ul>"
	
   		 elsif sig_name == 'moznetworkupload'
			message = "<ul><li><i>&quot;Declare stricter-than-default CSP, using the manifest's CSP directive.&quot;</i> (<a href='https://developer.mozilla.org/en-US/docs/Web/Apps/Security_guidelines#HTML.2FJavascript.2FCSS_injection_and_XSS'>Mozilla Developer Network:Security Guidelines</a>. 2013)</li>
						<li><i>&quot;Only request the bare minimum of permissions necessary for your application to work.</li>
						<li>Use access restrictions like read-only where the API supports them&quot;</i> (<a href='https://developer.mozilla.org/en-US/docs/Web/Apps/Security_guidelines#Permissions'>Mozilla Developer Network</a>. 2013)</li>
						<li><i>&quot;Declare stricter-than-default CSP, using the manifest's CSP directive.&quot;</i> (<a href='https://developer.mozilla.org/en-US/docs/Web/Apps/Security_guidelines#HTML.2FJavascript.2FCSS_injection_and_XSS'>Mozilla Developer Network:Security Guidelines</a>. 2013)</li>
						<li><i>&quot;Only request the bare minimum of permissions necessary for your application to work.</li>
						<li>Use access restrictions like read-only where the API supports them&quot;</i> (<a href='https://developer.mozilla.org/en-US/docs/Web/Apps/Security_guidelines#Permissions'>Mozilla Developer Network</a>. 2013)</li></ul>"
		
		elsif sig_name == 'moznetworkdownload'
			message = "<ul><li><i>&quot;Declare stricter-than-default CSP, using the manifest's CSP directive.&quot;</i> (<a href='https://developer.mozilla.org/en-US/docs/Web/Apps/Security_guidelines#HTML.2FJavascript.2FCSS_injection_and_XSS'>Mozilla Developer Network:Security Guidelines</a>. 2013)</li>
						<li><i>&quot;Only request the bare minimum of permissions necessary for your application to work.</li>
						<li>Use access restrictions like read-only where the API supports them&quot;</i> (<a href='https://developer.mozilla.org/en-US/docs/Web/Apps/Security_guidelines#Permissions'>Mozilla Developer Network</a>. 2013)</li></ul>"
	
		elsif sig_name == 'mozPermissionSettings'
			message = "<ul><li><i>&quot;Declare stricter-than-default CSP, using the manifest's CSP directive.&quot;</i> (<a href='https://developer.mozilla.org/en-US/docs/Web/Apps/Security_guidelines#HTML.2FJavascript.2FCSS_injection_and_XSS'>Mozilla Developer Network:Security Guidelines</a>. 2013)</li>
						<li><i>&quot;Only request the bare minimum of permissions necessary for your application to work.</li>
						<li>Use access restrictions like read-only where the API supports them&quot;</i> (<a href='https://developer.mozilla.org/en-US/docs/Web/Apps/Security_guidelines#Permissions'>Mozilla Developer Network</a>. 2013)</li></ul>"
	
		elsif sig_name == 'mozPower'
			message = "<ul><li><i>&quot;Declare stricter-than-default CSP, using the manifest's CSP directive.&quot;</i> (<a href='https://developer.mozilla.org/en-US/docs/Web/Apps/Security_guidelines#HTML.2FJavascript.2FCSS_injection_and_XSS'>Mozilla Developer Network:Security Guidelines</a>. 2013)</li>
						<li><i>&quot;Only request the bare minimum of permissions necessary for your application to work.</li>
						<li>Use access restrictions like read-only where the API supports them&quot;</i> (<a href='https://developer.mozilla.org/en-US/docs/Web/Apps/Security_guidelines#Permissions'>Mozilla Developer Network</a>. 2013)</li></ul>"
	
		elsif sig_name == 'mozSettings' 
			message = "<ul><li><i>&quot;Declare stricter-than-default CSP, using the manifest's CSP directive.&quot;</i> (<a href='https://developer.mozilla.org/en-US/docs/Web/Apps/Security_guidelines#HTML.2FJavascript.2FCSS_injection_and_XSS'>Mozilla Developer Network:Security Guidelines</a>. 2013)</li>
						<li><i>&quot;Only request the bare minimum of permissions necessary for your application to work.</li>
						<li>Use access restrictions like read-only where the API supports them&quot;</i></li>
						<li>Declare stricter-than-default CSP, using the manifest's CSP directive.&quot;</i>&quot; (<a href='https://developer.mozilla.org/en-US/docs/Web/Apps/Security_guidelines#HTML.2FJavascript.2FCSS_injection_and_XSS'>Firefox Developer Network:Security Guidelines</a>. 2013)</li></ul>"
	
		elsif sig_name == 'mozSms'
			message = "<ul><li><i>&quot;Declare stricter-than-default CSP, using the manifest's CSP directive.&quot;</i> (<a href='https://developer.mozilla.org/en-US/docs/Web/Apps/Security_guidelines#HTML.2FJavascript.2FCSS_injection_and_XSS'>Mozilla Developer Network:Security Guidelines</a>. 2013)</li>
						<li><i>&quot;Only request the bare minimum of permissions necessary for your application to work.</li>
						<li>Use access restrictions like read-only where the API supports them&quot;</i> (<a href='https://developer.mozilla.org/en-US/docs/Web/Apps/Security_guidelines#Permissions'>Mozilla Developer Network</a>. 2013)</li></ul>"
	
		elsif sig_name == 'mozSystem'
			message = "<ul><li><i>&quot;Declare stricter-than-default CSP, using the manifest's CSP directive.&quot;</i> (<a href='https://developer.mozilla.org/en-US/docs/Web/Apps/Security_guidelines#HTML.2FJavascript.2FCSS_injection_and_XSS'>Mozilla Developer Network:Security Guidelines</a>. 2013)</li>
						<li><i>&quot;Only request the bare minimum of permissions necessary for your application to work.</li>
						<li>Use access restrictions like read-only where the API supports them&quot;</i> (<a href='https://developer.mozilla.org/en-US/docs/Web/Apps/Security_guidelines#Permissions'>Mozilla Developer Network</a>. 2013)</li></ul>"
	
		elsif sig_name == 'mozTCPSocket'
			message = "<ul><li><i>&quot;Declare stricter-than-default CSP, using the manifest's CSP directive.&quot;</i> (<a href='https://developer.mozilla.org/en-US/docs/Web/Apps/Security_guidelines#HTML.2FJavascript.2FCSS_injection_and_XSS'>Mozilla Developer Network:Security Guidelines</a>. 2013)</li>
						<li><i>&quot;Only request the bare minimum of permissions necessary for your application to work.</li>
						<li>Use access restrictions like read-only where the API supports them&quot;</i> (<a href='https://developer.mozilla.org/en-US/docs/Web/Apps/Security_guidelines#Permissions'>Mozilla Developer Network</a>. 2013)</li></ul>"
	
		elsif sig_name == 'mozTelephony'
			message = "<ul><li><i>&quot;Declare stricter-than-default CSP, using the manifest's CSP directive.&quot;</i> (<a href='https://developer.mozilla.org/en-US/docs/Web/Apps/Security_guidelines#HTML.2FJavascript.2FCSS_injection_and_XSS'>Mozilla Developer Network:Security Guidelines</a>. 2013)</li>
						<li><i>&quot;Only request the bare minimum of permissions necessary for your application to work.</li>
						<li>Use access restrictions like read-only where the API supports them&quot;</i> (<a href='https://developer.mozilla.org/en-US/docs/Web/Apps/Security_guidelines#Permissions'>Mozilla Developer Network</a>. 2013)</li></ul>"
	
   		elsif sig_name == 'mozTime'
			message = "<ul><li><i>&quot;Declare stricter-than-default CSP, using the manifest's CSP directive.&quot;</i> (<a href='https://developer.mozilla.org/en-US/docs/Web/Apps/Security_guidelines#HTML.2FJavascript.2FCSS_injection_and_XSS'>Mozilla Developer Network:Security Guidelines</a>. 2013)</li>
						<li><i>&quot;Only request the bare minimum of permissions necessary for your application to work.</li>
						<li>Use access restrictions like read-only where the API supports them&quot;</i> (<a href='https://developer.mozilla.org/en-US/docs/Web/Apps/Security_guidelines#Permissions'>Mozilla Developer Network</a>. 2013)</li></ul>"
	
		elsif sig_name == 'mozVoicemail' 
			message = "<ul><li><i>&quot;Declare stricter-than-default CSP, using the manifest's CSP directive.&quot;</i> (<a href='https://developer.mozilla.org/en-US/docs/Web/Apps/Security_guidelines#HTML.2FJavascript.2FCSS_injection_and_XSS'>Mozilla Developer Network:Security Guidelines</a>. 2013)</li>
						<li><i>&quot;Only request the bare minimum of permissions necessary for your application to work.</li>
						<li>Use access restrictions like read-only where the API supports them&quot;</i> (<a href='https://developer.mozilla.org/en-US/docs/Web/Apps/Security_guidelines#Permissions'>Mozilla Developer Network</a>. 2013)</li></ul>"
	
		elsif sig_name == 'mozApps.mgmt'
			message = "<ul><li><i>&quot;Declare stricter-than-default CSP, using the manifest's CSP directive.&quot;</i> (<a href='https://developer.mozilla.org/en-US/docs/Web/Apps/Security_guidelines#HTML.2FJavascript.2FCSS_injection_and_XSS'>Mozilla Developer Network:Security Guidelines</a>. 2013)</li>
						<li><i>&quot;Only request the bare minimum of permissions necessary for your application to work.</li>
						<li>Use access restrictions like read-only where the API supports them&quot;</i> (<a href='https://developer.mozilla.org/en-US/docs/Web/Apps/Security_guidelines#Permissions'>Mozilla Developer Network</a>. 2013)</li></ul>"
	
    	elsif sig_name == 'mozWifiManager'
			message = "<ul><li><i>&quot;Declare stricter-than-default CSP, using the manifest's CSP directive.&quot;</i> (<a href='https://developer.mozilla.org/en-US/docs/Web/Apps/Security_guidelines#HTML.2FJavascript.2FCSS_injection_and_XSS'>Mozilla Developer Network:Security Guidelines</a>. 2013)</li>
						<li><i>&quot;Only request the bare minimum of permissions necessary for your application to work.</li>
						<li>Use access restrictions like read-only where the API supports them&quot;</i> (<a href='https://developer.mozilla.org/en-US/docs/Web/Apps/Security_guidelines#Permissions'>Mozilla Developer Network</a>. 2013)</li></ul>"
	
    elsif sig_name == 'mozKeyboard'
			message = "<ul><li><i>&quot;Declare stricter-than-default CSP, using the manifest's CSP directive.&quot;</i> (<a href='https://developer.mozilla.org/en-US/docs/Web/Apps/Security_guidelines#HTML.2FJavascript.2FCSS_injection_and_XSS'>Mozilla Developer Network:Security Guidelines</a>. 2013)</li>
						<li><i>&quot;Only request the bare minimum of permissions necessary for your application to work.</li>
						<li>Use access restrictions like read-only where the API supports them&quot;</i> (<a href='https://developer.mozilla.org/en-US/docs/Web/Apps/Security_guidelines#Permissions'>Mozilla Developer Network</a>. 2013)</li></ul>"
	
    else
			message = "No info available"
		end
	end

end
