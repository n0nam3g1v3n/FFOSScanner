###############################################################
#Signatures used specifically for Firefox OS
###############################################################

$signatures[:js] ||= {}

$signatures[:js][:execution_sinks] = [
	Signature.new({:literal => 'eval('}),
	Signature.new({:literal => 'setTimeout('}),
	Signature.new({:literal => 'setInterval('}),
	Signature.new({:literal => 'Function('}),
	Signature.new({:literal => 'crypto.generateCRMFRequest('})
]

$signatures[:js][:HTMLElement_sinks] = [
	Signature.new({:literal => 'document.write'}),
	Signature.new({:literal => 'document.writeln'}),
	Signature.new({:literal => '.innerHTML'}),
	Signature.new({:literal => '.outerHTML'}),
	Signature.new({:literal => '.createContextualFragment'}),
	Signature.new({:literal => '.parseFromString'}),
	Signature.new({:literal => '.createHTMLDocument'})
	
]

$signatures[:js][:url_sinks] = [
	Signature.new({:literal => '\.src'}),
	Signature.new({:literal => '\.data'}),
	Signature.new({:literal => '\.href'}),
	Signature.new({:literal => '\.action'}),
	Signature.new({:literal => 'document.URL'}),
	Signature.new({:literal => 'document.referrer'}),
	Signature.new({:literal => 'document.URLUuencoded'}),
	Signature.new({:literal => 'document.location'}),
	Signature.new({:literal => 'window.location'})	
]

$signatures[:js][:interesting_functions] = [
	Signature.new({:literal => 'escapeHTML'}),
	Signature.new({:literal => 'window.open'}),
	Signature.new({:literal => 'indexeddb'}),
 
	Signature.new({:literal => '.insertAdjacentHTML'}),
	Signature.new({:literal => 'mozSetMessageHandler'})
]

$signatures[:js][:privileged_functions] = [
	Signature.new({:literal => '.mozAlarms'}),
	Signature.new({:literal => '\'attention\''}),
	Signature.new({:literal => 'mozaudiochannel'}),
	Signature.new({:literal => '.mozBluetooth'}),
	Signature.new({:literal => '.mozCameras'}),
	Signature.new({:literal => '.mozCellBroadcast'}),
	Signature.new({:literal => '.mozContacts'}),
	Signature.new({:literal => '.mozNotification'}),
	Signature.new({:literal => '.getDeviceStorage'}), # might be better to use regex, and match the device storage type
	#Signature.new({:literal => 'mozapp'}),  #to check embed-apps. this may generate positives, and we should probably use a regex (mozApp etc). But this perm should nbever be used, except for the system app.
	Signature.new({:literal => 'mozFMRadio'}),
	Signature.new({:literal => 'geolocation'}),
	Signature.new({:literal => 'addIdleObserver'}),
	Signature.new({:literal => 'mozMobileConnection'}),
	Signature.new({:literal => 'moznetworkupload'}), # window event
	Signature.new({:literal => 'moznetworkdownload'}),  # window event
	Signature.new({:name => 'remote',  :regex => '/open\(.*remote/m'}), #this is broken
	Signature.new({:literal => 'mozPermissionSettings'}),
	Signature.new({:literal => 'mozPower'}),
	Signature.new({:literal => 'mozSettings'}),
	Signature.new({:literal => 'mozSms'}),    # cant check for "storage" permission really
	Signature.new({:literal => 'mozSystem'}),
	Signature.new({:literal => 'mozTCPSocket'}),
	Signature.new({:literal => 'mozTelephony'}),
	Signature.new({:literal => 'mozTime'}),
	Signature.new({:literal => 'mozVoicemail'}),
	Signature.new({:literal => 'mozApps.mgmt'}),
	Signature.new({:literal => 'mozWifiManager'}),
	Signature.new({:literal => 'mozKeyboard'})
]

$signatures[:js][:client_side_storage] = [
	Signature.new({:literal => 'localStorage'}),
	Signature.new({:literal => 'indexedDB'}),
	Signature.new({:literal => 'indexeddb'}),
	Signature.new({:literal => 'mozSetMessageHandler'}),
	Signature.new({:literal => 'document.cookie'})
]

