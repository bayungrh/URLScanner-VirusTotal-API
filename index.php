<?php
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: GET, POST");
header("Content-type: Application/Json");
require_once('lib/VirusTotal.php');

$scan_url = 'http://github.com';
$virustotal = new VirusTotal();
$virustotal->setSSL(false); // True if your site is HTTPS
$virustotal->setApiKey('YOUR_API_KEY'); // Your API KEY here...

$basedomain = (filter_var($scan_url, FILTER_VALIDATE_URL)) ? $virustotal->getBaseDomain($scan_url) : $scan_url;
$scanner 	= $virustotal->ScanURL($basedomain);
if($scanner) { //Report URL Scanner
	$report = $virustotal->ScanURL_Report($basedomain); 
	print_r($report);
}
?>