<?php

/**
* API from: VirusTotal.com
* Author: MuhBayu
* Website: 
* - http://bayuu.net
* - http://girhub.com/MuhBayu
*/

class VirusTotal
{
	protected $_APIKEY;
	private $_HOST_URLSCAN 			= 'https://www.virustotal.com/vtapi/v2/url/scan';
	private $_HOST_FILESCAN 		= 'https://www.virustotal.com/vtapi/v2/file/scan';
	private $_HOST_URLSCAN_REPORT 	= 'https://www.virustotal.com/vtapi/v2/url/report';
	private $_HOST_FILESCAN_REPORT 	= 'https://www.virustotal.com/vtapi/v2/file/report';
	protected $_SSL_VERIFY;

	function __construct()
	{
		$this->_SSL_VERIFY = False; // Default set False
	}
	public function setApiKey($key) {
		$this->_APIKEY = getenv('VT_API_KEY') ? getenv('VT_API_KEY') : $key;
	}
	public function setSSL($val) {
		$this->_SSL_VERIFY = $val;
	}
	public function cURL($url, $data) {
		$ch = curl_init();
		curl_setopt_array($ch, array(
			CURLOPT_URL => $url,
			CURLOPT_POST => True,
			CURLOPT_SSL_VERIFYPEER => $this->_SSL_VERIFY,
			CURLOPT_VERBOSE => 0,
			CURLOPT_ENCODING => 'gzip,deflate',
			CURLOPT_USERAGENT => 'gzip, My php curl client',
			CURLOPT_RETURNTRANSFER => True,
			CURLOPT_POSTFIELDS => $data
		));
		$result		 = curl_exec($ch);
		$status_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);;
		if ($status_code == 200) { // OK
		  	$json = json_decode($result, true);
		  	return (json_encode($json, JSON_PRETTY_PRINT)); // Convert JSON to Pretty View
		} else {  // Error occured
		  	return ($result);
		}
			curl_close ($ch);	
	}
	public function ScanURL($scan_url) {
		$post = array('apikey' => $this->_APIKEY,'url'=> $scan_url);
		return Self::cURL($this->_HOST_URLSCAN, $post);
	}
	public function ScanURL_Report($scan_url) {
		$post = array('apikey' => $this->_APIKEY,'resource'=> $scan_url);
		return Self::cURL($this->_HOST_URLSCAN_REPORT, $post);
	}
	public function getBaseDomain($url) {
		return parse_url($url)['host'];
	}
}

?>