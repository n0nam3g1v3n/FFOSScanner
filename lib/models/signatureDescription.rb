class SignatureDescription  #Determine which signature's description and solutions to call based on group signatures

attr_accessor :sig_name, :sig_group, :message, :css_sig_name
	
	def initialize (sig_name, sig_group)
		@sig_name = sig_name
		@sig_group = sig_group
		@@message = nil
		@css_sig_name = nil
	end

	def display_description #Determine which class to call based on the group signature and display the corresponding description
		
		
		if sig_group == 'inputs' 
			inputsDes = HtmlSignatureDescription.new(sig_name, message)
			message = inputsDes.displayHtmlInputs
		elsif sig_group == 'dangerous'
			inputsDes = HtmlSignatureDescription.new(sig_name, message)
			message = inputsDes.displayDangerousHtml
		elsif sig_group == 'comments'
			inputsDes = HtmlSignatureDescription.new(sig_name, message)
			message = inputsDes.displayHtmlComments
		elsif sig_group == 'execution_sinks' 
			exSinkDes = ExecutionSinkDescription.new(sig_name, message)
			message = exSinkDes.displayExecutionSink
		elsif sig_group == 'HTMLElement_sinks' 
			htmlSinkDes = HtmlElemetSinkDescription.new(sig_name, message)
			message = htmlSinkDes.displayHtmlElementSink
		elsif sig_group == 'url_sinks' 
			uSDes = UrlSinkDescription.new(sig_name, message)
			message = uSDes.displayUrlSink
		elsif sig_group == 'interesting_functions'
			iFDes = InterestingFunctionDescription.new(sig_name, message)
			message = iFDes.displayinterestingFunction
		elsif sig_group == 'privileged_functions'  
			apiDes = PrivilegedApiDescription.new(sig_name, message)
			message = apiDes.displayPrivilegedApis
		elsif sig_group == 'client_side_storage'  
			cssDes = CSSSignatureDescription.new(sig_name, message)
			message = cssDes.displayClientSideStorage
		else
			message = "No info available"		
		end
	return message
	end

def display_solutions #Determine which class to call based on the signature and display the corresponding solutions
		
		if sig_group == 'inputs' 
			inputsDes = HtmlSignatureDescription.new(sig_name, message)
			message = inputsDes.displayHtmlInputSolutions
		elsif sig_group == 'dangerous'
			inputsDes = HtmlSignatureDescription.new(sig_name, message)
			message = inputsDes.displayDangerousHtmlSolutions
		elsif sig_group == 'comments'
			inputsDes = HtmlSignatureDescription.new(sig_name, message)
			message = inputsDes.displayHtmlCommentsSolutions
		elsif sig_group == 'execution_sinks' 
			exSinkDes = ExecutionSinkDescription.new(sig_name, message)
			message = exSinkDes.displayExecutionSinkSolutions
		elsif sig_group == 'HTMLElement_sinks' 
			htmlSinkDes = HtmlElemetSinkDescription.new(sig_name, message)
			message = htmlSinkDes.displayHtmlElementSinkSolutions
		elsif sig_group == 'url_sinks' 
			uSDes = UrlSinkDescription.new(sig_name, message)
			message = uSDes.displayUrlSinkSolutions
		elsif sig_group == 'interesting_functions'
			iFDes = InterestingFunctionDescription.new(sig_name, message)
			message = iFDes.displayinterestingFunctionSolutions
		elsif sig_group == 'privileged_functions'  
			apiDes = PrivilegedApiDescription.new(sig_name, message)
			message = apiDes.displayPrivilegedApisSolutions
		elsif sig_group == 'client_side_storage'  
			cssDes = CSSSignatureDescription.new(sig_name, message)
			message = cssDes.displayClientSideStorageSolutions
		else
			message = "No info available"			
		end
	return message
	end				
end




